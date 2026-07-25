using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Cda.Core.Process;

namespace Cda.App
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Enable SeDebugPrivilege so the tool can attach to and instrument
            // other processes. Harmless if it fails (some operations just won't
            // be permitted); attach will report the error if so.
            Privileges.EnableDebugPrivilege();

            // Surface unhandled exceptions instead of letting the app die silently
            // ("has stopped working"): show a dialog AND append the full detail to
            // cda-error.log next to the exe, so a crash is both visible live and
            // recoverable after the fact (the dialog is gone once dismissed).
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        }

        private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            string text = e.Exception.ToString();
            LogCrash("UI thread (fatal)", e.Exception);
            try
            {
                MessageBox.Show(text + LogHint(), "CDA — fatal UI error",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch { /* preserve the original exception */ }

            // Unknown dispatcher failures may indicate corrupted capture/UI state.
            // Log and surface them, then let WPF terminate instead of continuing.
            e.Handled = false;
        }

        private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            // Non-UI-thread failures can't always be recovered, but at least log + show them.
            var ex = e.ExceptionObject as Exception;
            LogCrash(e.IsTerminating ? "fatal (terminating)" : "background", ex);
            if (ex != null)
                MessageBox.Show(ex + LogHint(), "CDA — fatal error", MessageBoxButton.OK, MessageBoxImage.Error);
        }

        private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            // A faulted Task whose exception was never observed (e.g. a fire-and-forget
            // poll/scan continuation). Log it and mark observed so it can't escalate.
            LogCrash("unobserved task", e.Exception);
            e.SetObserved();
        }

        // --- crash log -------------------------------------------------------

        private static readonly object _logLock = new();

        // Append a timestamped, build-stamped record of a crash to the log file.
        // Best-effort and utterly non-throwing: a failure here must never mask or
        // compound the original crash.
        private static void LogCrash(string kind, Exception? ex)
        {
            try
            {
                string entry =
                    $"==== {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} · {kind} · CDA {BuildVersion()} · " +
                    $"{(Environment.Is64BitProcess ? "x64" : "x86")} · {Environment.OSVersion.VersionString} ====" +
                    Environment.NewLine +
                    (ex?.ToString() ?? "(no exception object)") + Environment.NewLine + Environment.NewLine;

                foreach (string path in LogPaths())
                {
                    try
                    {
                        string? dir = Path.GetDirectoryName(path);
                        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                        lock (_logLock)
                        {
                            // Keep the log bounded across many sessions: start fresh once
                            // it grows past ~512 KB (crashes are rare; history isn't vital).
                            try
                            {
                                if (File.Exists(path) && new FileInfo(path).Length > 512 * 1024)
                                    File.Delete(path);
                            }
                            catch { /* ignore rotation errors */ }

                            File.AppendAllText(path, entry);
                        }
                        return; // first writable location wins
                    }
                    catch { /* fall through to the next candidate location */ }
                }
            }
            catch { /* logging must never itself throw out of a crash handler */ }
        }

        // Where to write, in order of preference:
        //   1) next to the exe — the app runs elevated so its (Program Files) dir is
        //      writable, and this matches cda_hook_skip.txt and the installer's
        //      UninstallDelete of cda-error.log;
        //   2) per-user LocalAppData, in case the install dir is ever read-only.
        private static IEnumerable<string> LogPaths()
        {
            yield return Path.Combine(AppContext.BaseDirectory, "cda-error.log");
            yield return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Cda.Modern", "cda-error.log");
        }

        private static string LogPath()
        {
            foreach (string p in LogPaths()) return p; // the primary (exe-dir) path, for the hint
            return "cda-error.log";
        }

        private static string LogHint() =>
            Environment.NewLine + Environment.NewLine + "(Full detail written to " + LogPath() + ")";

        private static string BuildVersion()
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                return asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                       ?? asm.GetName().Version?.ToString()
                       ?? "?";
            }
            catch { return "?"; }
        }
    }
}
