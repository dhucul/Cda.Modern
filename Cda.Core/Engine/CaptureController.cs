using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using Cda.Core.Model;

namespace Cda.Core.Engine
{
    /// <summary>
    /// A headless, scriptable façade over the capture engine, for automation and
    /// embedding (CLIs, CI jobs, batch analysis). It wraps the interactive app's
    /// attach → discover → hook → poll → stop → dataset flow into a few synchronous
    /// calls, reusing the exact same engine pieces (<see cref="LiveSession"/>,
    /// <see cref="ApiImportScanner"/>, <see cref="CaptureSession"/>,
    /// <see cref="RingBufferReader"/>) — so a scripted capture is the same capture.
    ///
    /// Example:
    /// <code>
    /// using var c = CaptureController.Attach(pid);
    /// var cond = CaptureCondition.Parse("name~CreateFile", out _);
    /// var trace = c.CaptureApis(
    ///     TimeSpan.FromSeconds(5),
    ///     filter: cond == null ? null : r => cond.Matches(r, _ => null));
    /// TraceArchive.Save("run.cdatrace", trace);
    /// </code>
    ///
    /// Discovery and hooking happen on the calling thread; the capture runs
    /// synchronously for the requested duration. Not thread-safe; dispose when done.
    /// </summary>
    public sealed class CaptureController : IDisposable
    {
        private readonly LiveSession _session;

        private CaptureController(LiveSession session) => _session = session;

        /// <summary>The underlying discovery session (process, modules, functions).</summary>
        public LiveSession Session => _session;

        /// <summary>Attach to a running process for read-only discovery.</summary>
        public static CaptureController Attach(int pid) => new(LiveSession.Attach(pid));

        /// <summary>
        /// Hook the Windows API entries the target imports and record every call to
        /// them for <paramref name="duration"/>, returning the calls that pass
        /// <paramref name="filter"/> (null = all) as a <see cref="TraceDataset"/>
        /// ready to save with <see cref="TraceArchive"/>.
        /// </summary>
        public TraceDataset CaptureApis(
            TimeSpan duration, Func<CallRecord, bool>? filter = null,
            int maxFunctions = 512, int bufferRecords = 65536, int pollMs = 100)
        {
            var api = ApiImportScanner.Discover(_session.Process, _session.Modules);
            var addresses = new List<ulong>(api.Functions.Count);
            foreach (var f in api.Functions) addresses.Add(f.Address);
            return CaptureAddresses(addresses, api.ApiModules, api.Functions,
                                    duration, filter, maxFunctions, bufferRecords, pollMs);
        }

        /// <summary>
        /// Hook an explicit set of function entry addresses and record calls for
        /// <paramref name="duration"/>. <paramref name="modules"/> /
        /// <paramref name="functions"/> describe the entries for the returned
        /// dataset's views (null = use the session's modules / none).
        /// </summary>
        public TraceDataset CaptureAddresses(
            IReadOnlyList<ulong> addresses,
            IReadOnlyList<ModuleInfo>? modules,
            IReadOnlyList<TracedFunction>? functions,
            TimeSpan duration, Func<CallRecord, bool>? filter = null,
            int maxFunctions = 512, int bufferRecords = 65536, int pollMs = 100)
        {
            var records = new List<CallRecord>();
            if (addresses.Count > 0)
            {
                var capture = CaptureSession.Start(
                    _session.Process.Pid, addresses, maxFunctions, bufferRecords,
                    out _, out _, out _);
                try
                {
                    var sw = Stopwatch.StartNew();
                    while (sw.Elapsed < duration)
                    {
                        Thread.Sleep(pollMs);
                        Collect(capture.Poll(), records, filter);
                    }
                    Collect(capture.Poll(), records, filter); // final drain
                }
                finally { capture.Dispose(); }
            }
            return BuildDataset(modules, functions, records);
        }

        private static void Collect(List<CallRecord> polled, List<CallRecord> sink, Func<CallRecord, bool>? filter)
        {
            if (polled.Count == 0) return;
            if (filter == null) { sink.AddRange(polled); return; }
            foreach (var r in polled) if (filter(r)) sink.Add(r);
        }

        private TraceDataset BuildDataset(
            IReadOnlyList<ModuleInfo>? modules, IReadOnlyList<TracedFunction>? functions,
            List<CallRecord> records)
        {
            records.Sort((a, b) => a.Time.CompareTo(b.Time));
            var ds = new TraceDataset
            {
                Records = records,
                TimeStart = records.Count > 0 ? records[0].Time : 0,
                TimeEnd = records.Count > 0 ? records[records.Count - 1].Time : 1,
            };
            if (modules != null) ds.Modules.AddRange(modules);
            else ds.Modules.AddRange(_session.Modules.Modules);
            if (functions != null) ds.Functions.AddRange(functions);
            return ds;
        }

        public void Dispose() => _session.Dispose();
    }
}
