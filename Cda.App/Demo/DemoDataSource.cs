using System;
using System.Collections.Generic;
using System.Text;
using Cda.Core.Model;

namespace Cda.App.Demo
{
    /// <summary>
    /// Synthesizes a realistic-looking trace so the visualization is fully
    /// exercisable before the live analysis engine exists. It fabricates a set
    /// of modules, scatters functions through them, and emits a time-ordered
    /// stream of calls with bursty activity — so scrubbing the playback bar
    /// lights up different regions of the graph, exactly as a real capture would.
    ///
    /// This is purely a stand-in: it touches no external process and performs no
    /// instrumentation. It is replaced by the engine's real capture in Phase 2+.
    /// </summary>
    public static class DemoDataSource
    {
        public static TraceDataset Generate(int seed = 1234)
        {
            var rng = new Random(seed);
            var data = new TraceDataset();

            (string name, ulong size, int funcs)[] mods =
            {
                ("app.exe",      0x60000, 220),
                ("ntdll.dll",    0xA0000, 380),
                ("kernel32.dll", 0x80000, 300),
                ("user32.dll",   0x70000, 260),
                ("gdi32.dll",    0x50000, 180),
                ("msvcrt.dll",   0x60000, 200),
                ("ole32.dll",    0x90000, 240),
            };

            ulong baseAddr = 0x140000000UL; // 64-bit-style base to prove width
            var fnByModule = new List<List<TracedFunction>>();

            foreach (var (name, size, funcs) in mods)
            {
                var module = new ModuleInfo(name, baseAddr, size);
                data.Modules.Add(module);

                var list = new List<TracedFunction>(funcs);
                for (int i = 0; i < funcs; i++)
                {
                    ulong addr = baseAddr + (ulong)(0x40 + rng.Next((int)size - 0x80));
                    var fn = new TracedFunction(addr, baseAddr, name + "!sub_" + addr.ToString("X"));
                    data.Functions.Add(fn);
                    list.Add(fn);
                }
                fnByModule.Add(list);
                baseAddr += size + 0x100000UL;
            }

            // Emit calls over a 6-second window with three activity bursts.
            const double duration = 6.0;
            int callCount = 12000;
            data.TimeStart = 0;
            data.TimeEnd = duration;

            double[] burstCenters = { 1.0, 3.0, 5.0 };
            string[] sampleStrings =
            {
                "C:\\Windows\\System32\\kernel32.dll",
                "GET /api/status HTTP/1.1",
                "SELECT * FROM sessions WHERE id=?",
                "HKLM\\Software\\Microsoft\\Windows",
                "config.ini", "user32.dll", "OpenProcess", "\\\\.\\PIPE\\cda"
            };

            for (int i = 0; i < callCount; i++)
            {
                // Cluster times around bursts so scrubbing reveals structure.
                double bc = burstCenters[rng.Next(burstCenters.Length)];
                double t = Math.Clamp(bc + NextGaussian(rng) * 0.6, 0, duration);

                // Bias calls to flow app.exe -> libraries -> ntdll.
                var srcList = fnByModule[rng.Next(2)];                 // app.exe / ntdll
                var dstList = fnByModule[rng.Next(fnByModule.Count)];  // anywhere

                var src = srcList[rng.Next(srcList.Count)];
                var dst = dstList[rng.Next(dstList.Count)];

                var rec = new CallRecord(t, src.Address, dst.Address)
                {
                    StackPointer = 0x7FF000000000UL + (ulong)(uint)rng.Next(),
                };

                int argc = rng.Next(2, 6);
                var args = new ulong[argc];
                for (int k = 0; k < argc; k++)
                    args[k] = (k % 2 == 0)
                        ? (ulong)rng.Next(1, 0xFFFF)                       // count / flags / handle
                        : 0x000001D800000000UL + (ulong)(uint)rng.Next(); // pointer-ish
                rec.IntegerArgs = args;

                // ~40% of calls carry a string pointer in the second argument.
                if (argc > 1 && rng.NextDouble() < 0.4)
                {
                    string s = sampleStrings[rng.Next(sampleStrings.Length)];
                    rec.Dereferences = new[]
                    {
                        new Dereference
                        {
                            ArgumentIndex = 1,
                            Kind = DereferenceKind.AnsiString,
                            Pointer = args[1],
                            Data = Encoding.ASCII.GetBytes(s + "\0"),
                        }
                    };
                }

                data.Records.Add(rec);
            }

            data.Records.Sort((a, b) => a.Time.CompareTo(b.Time));
            return data;
        }

        private static double NextGaussian(Random rng)
        {
            double u1 = 1.0 - rng.NextDouble();
            double u2 = 1.0 - rng.NextDouble();
            return Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Sin(2.0 * Math.PI * u2);
        }
    }
}
