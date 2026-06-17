using System;
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

            // Surface unhandled UI-thread exceptions as a dialog instead of letting
            // the app die silently ("has stopped working"). This makes a crash in,
            // say, the hex view on a function click visible and actionable.
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
        }

        private bool _errorDialogOpen;
        private string? _lastErrorText;

        private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            e.Handled = true; // keep the app alive

            // A failing layout pass or poll tick can throw on EVERY render/tick.
            // Never stack modal dialogs for that — it produces a wall of windows
            // and an effective hang. Show at most one at a time, and don't repeat
            // an identical error (so a recurring fault surfaces once, readably,
            // instead of crashing the app).
            string text = e.Exception.ToString();
            if (_errorDialogOpen || text == _lastErrorText) return;

            _lastErrorText = text;
            _errorDialogOpen = true;

            // Show the dialog AFTER the failed operation unwinds, never inline.
            // The exception often fires mid-layout/-render; popping a modal dialog
            // there re-enters WPF's dispatcher during a layout pass and can turn a
            // recoverable error into a hard crash. Deferring to Background priority
            // lets the current pass finish first.
            Dispatcher.BeginInvoke(new Action(() =>
            {
                try
                {
                    MessageBox.Show(text, "CDA — unexpected error (recovered)",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                finally { _errorDialogOpen = false; }
            }), DispatcherPriority.Background);
        }

        private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            // Non-UI-thread failures can't always be recovered, but at least show them.
            if (e.ExceptionObject is Exception ex)
            {
                MessageBox.Show(ex.ToString(), "CDA — fatal error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
