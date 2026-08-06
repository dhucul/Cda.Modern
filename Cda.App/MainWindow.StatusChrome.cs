using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace Cda.App
{
    // ------------------------------------------------------------------------
    // Status-bar chrome.
    //
    // The status bar's left-hand pill (grey "idle" / green "attached" / red
    // "capturing") and its right-hand counters are derived state: they answer
    // "are there hooks in a target right now, and how much have I got?" without
    // the user having to read back through StatusText's running commentary.
    //
    // This lives in its own partial file on purpose. StatusText is written from
    // ~100 places in MainWindow.xaml.cs; rather than touch every one of them to
    // also refresh the chrome, a low-priority timer polls the same predicates
    // the capture code already uses (IsCaptureRunning(), _session, _offlineTrace,
    // _captured). Poll cost is a few field reads every 400 ms.
    //
    // Entry point is Window.Loaded, wired in MainWindow.xaml — the existing
    // constructor and its own Loaded handler are left alone.
    // ------------------------------------------------------------------------
    public partial class MainWindow
    {
        private DispatcherTimer? _statusChromeTimer;

        // Resolving a PID to an image name costs a process-table lookup, so the
        // answer is cached until the PID changes (or the process exits).
        private int _statusChromePid = -1;
        private string _statusChromeName = "";

        // Only touch the UI when something actually changed — the timer runs
        // while a capture is flooding, and needless invalidation there is waste.
        private string _lastPillText = "";
        private string _lastStatsText = "";

        private void OnStatusChromeLoaded(object sender, RoutedEventArgs e)
        {
            if (_statusChromeTimer != null) return;   // Loaded can fire more than once

            _statusChromeTimer = new DispatcherTimer(DispatcherPriority.Background)
            {
                Interval = TimeSpan.FromMilliseconds(400)
            };
            _statusChromeTimer.Tick += (_, _) => RefreshStatusChrome();
            _statusChromeTimer.Start();

            RefreshStatusChrome();
        }

        // Never allowed to throw: it runs on a timer, and a status decoration
        // failing must not take down a live capture.
        private void RefreshStatusChrome()
        {
            try
            {
                bool live = IsCaptureRunning();
                bool attached = _session != null;

                string state = live ? "capturing"
                             : attached ? "attached"
                             : _offlineTrace ? "trace loaded"
                             : "idle";

                if (state != _lastPillText)
                {
                    _lastPillText = state;
                    var brush = live ? Res("Danger")
                              : attached ? Res("Success")
                              : _offlineTrace ? Res("Accent")
                              : Res("TextMuted");

                    CaptureStateText.Text = state;
                    CaptureStateText.Foreground = brush;
                    CaptureLed.Fill = brush;
                    CapturePill.BorderBrush = live ? brush : (Brush)Res("OutlineStrong");
                }

                string stats = BuildStatsText(attached);
                if (stats != _lastStatsText)
                {
                    _lastStatsText = stats;
                    TraceStatsText.Text = stats;
                }
            }
            catch
            {
                // Deliberately swallowed — see above.
            }
        }

        private string BuildStatsText(bool attached)
        {
            string? target = attached ? TargetImageName() : null;
            int calls = _captured.Count;

            if (target != null && calls > 0) return $"{target}  ·  {calls:N0} calls";
            if (target != null) return target;
            if (calls > 0) return $"{calls:N0} calls";
            return "";
        }

        // Best-effort image name for the attached PID. Returns null rather than
        // guessing if the process has exited or the lookup is denied.
        private string? TargetImageName()
        {
            try
            {
                var session = _session;
                if (session == null) return null;

                int pid = Convert.ToInt32(session.Process.Pid);
                if (pid == _statusChromePid) return _statusChromeName.Length > 0 ? _statusChromeName : null;

                _statusChromePid = pid;
                _statusChromeName = "";
                using var p = System.Diagnostics.Process.GetProcessById(pid);
                _statusChromeName = p.ProcessName + ".exe";
                return _statusChromeName;
            }
            catch
            {
                return _statusChromeName.Length > 0 ? _statusChromeName : null;
            }
        }

        private Brush Res(string key) => (Brush)FindResource(key);
    }
}
