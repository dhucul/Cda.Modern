using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using Cda.Core.Engine;
using Cda.Core.Memory;
using Cda.Core.Pe;
using Cda.Core.Process;
using Iced.Intel;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Cda.Core.Tests
{
    public sealed class EmbeddedSelfTests
    {
        [Fact]
        public void CallDiscovery() => Pass(CallDiscoverySelfTest.Run());

        [Fact]
        public void CaptureReturn() => Pass(CaptureReturnSelfTest.Run());

        [Fact]
        public void CaptureStub() => Pass(CaptureStubSelfTest.Run());

        [Fact]
        public void CaptureVeh() => Pass(CaptureVehSelfTest.Run());

        [Fact]
        public void DialogBranchConfirmer() => Pass(DialogBranchConfirmerSelfTest.Run());

        [Fact]
        public void Hook() => Pass(HookSelfTest.Run());

        [Fact]
        public void PtDecoder() => Pass(PtDecoderSelfTest.Run());

        private static void Pass(string result) =>
            Assert.True(result.StartsWith("PASS", StringComparison.Ordinal), result);
    }

    public sealed class BoundaryRegressionTests
    {
        [Fact]
        public void BufferMemorySourceRejectsWrappedAddressRange()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                new BufferMemorySource(new byte[2], ulong.MaxValue - 1));
        }

        [Fact]
        public void StackUnwinderHonorsZeroFrameLimit()
        {
            var unwinder = new StackUnwinder(null!, null!);
            Assert.Empty(unwinder.Unwind(0x1000, new[] { 0x2000UL }, maxFrames: 0));
        }

        [Fact]
        public void DialogCandidateLimitsRejectNegativeValues()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                DialogBranchAnalyzer.CollectCandidates(
                    0x1000, null, true, static (_, _) => 0, maxCandidates: -1));
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                DialogBranchAnalyzer.CollectCandidates(
                    0x1000, null, true, static (_, _) => 0, maxFrames: -1));
        }

        [Fact]
        public void DialogBranchAppearsBeforeFunctionMetadataIsAvailable()
        {
            const ulong imageBase = 0x1000;
            var code = new byte[64];
            Array.Fill(code, (byte)0x90);
            code[8] = 0xC3;                  // stale index points into prior function
            code[16] = 0x85; code[17] = 0xC0; // test eax,eax
            code[18] = 0x75; code[19] = 0x05; // jne past the call
            code[20] = 0xE8;                 // call rel32
            code[25] = 0xC3;                 // return address / skip target

            int Read(ulong address, byte[] destination)
            {
                if (address < imageBase) return 0;
                ulong offset = address - imageBase;
                if (offset > (ulong)code.Length ||
                    (ulong)destination.Length > (ulong)code.Length - offset)
                    return 0;
                Array.Copy(code, (int)offset, destination, 0, destination.Length);
                return destination.Length;
            }

            ulong returnAddress = imageBase + 25;
            DialogBranchAnalyzer.BranchInfo? branch = DialogBranchAnalyzer.Analyze(
                returnAddress, null, true, Read);
            DialogBranchAnalyzer.BranchInfo? staleIndexBranch =
                DialogBranchAnalyzer.Analyze(
                    returnAddress, null, true, Read,
                    resolveFunctionStart: static _ => imageBase);
            IReadOnlyList<DialogBranchAnalyzer.BranchInfo> candidates =
                DialogBranchAnalyzer.CollectCandidates(
                    returnAddress, null, true, Read, maxFrames: 0);

            Assert.NotNull(branch);
            Assert.Equal(imageBase + 18, branch!.Address);
            Assert.True(branch.WouldSkip);
            Assert.NotNull(staleIndexBranch);
            Assert.Equal(branch.Address, staleIndexBranch!.Address);
            Assert.Single(candidates);
            Assert.Equal(branch.Address, candidates[0].Address);
        }

        [Fact]
        public void TruncatedLongTntPacketDoesNotEscape()
        {
            byte[] trace = BuildTraceWithTruncatedLongTnt();
            var candidates = new[]
            {
                new DialogBranchConfirmer.Candidate(
                    0x140001000, Code.Jne_rel32_64,
                    BranchRole.SkipOver, "jne 0x140001200"),
            };

            DialogBranchConfirmer.Confirmation? result = PtDecoder.TryConfirm(
                trace, 0x7FFF00001000, 0x140001100, candidates, true,
                static (_, _) => 0);

            Assert.Null(result);
        }

        [Fact]
        public void TruncatedExportDirectoryReturnsNoExports()
        {
            PeImage image = PeImage.FromFile(BuildPeWithTruncatedExportDirectory());
            Assert.Empty(image.ReadExports());
        }

        [Fact]
        public void MalformedTraceCountIsRejectedBeforeAllocation()
        {
            string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".cdatrace");
            try
            {
                using (var stream = File.Create(path))
                using (var writer = new BinaryWriter(stream))
                {
                    writer.Write(0x54414443u);
                    writer.Write(3);
                    writer.Write(0.0);
                    writer.Write(1.0);
                    writer.Write(int.MaxValue);
                }

                Assert.Throws<InvalidDataException>(() => TraceArchive.Load(path));
            }
            finally
            {
                try { File.Delete(path); } catch { }
            }
        }

        [Fact]
        public void WindowsDirectoryChecksRespectPathBoundariesAndDevicePrefixes()
        {
            Assert.False(PathClassifier.IsUnderDirectory(
                @"C:\WindowsMalware\app.exe", @"C:\Windows"));
            Assert.True(PathClassifier.IsUnderDirectory(
                @"\\?\C:\Windows\System32\kernel32.dll", @"C:\Windows"));
        }

        private static byte[] BuildTraceWithTruncatedLongTnt()
        {
            const int threadHeader = 28;
            const int packetBytes = 18;
            var trace = new byte[8 + threadHeader + packetBytes];
            BinaryPrimitives.WriteUInt32LittleEndian(trace.AsSpan(8 + 24), packetBytes);

            int packet = 8 + threadHeader;
            for (int i = 0; i < 16; i += 2)
            {
                trace[packet + i] = 0x02;
                trace[packet + i + 1] = 0x82;
            }
            trace[packet + 16] = 0x02;
            trace[packet + 17] = 0xA3;
            return trace;
        }

        private static byte[] BuildPeWithTruncatedExportDirectory()
        {
            var image = new byte[0x220];
            BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0), 0x5A4D);
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(0x3C), 0x80);
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(0x80), 0x00004550);

            int coff = 0x84;
            BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(coff), (ushort)PeMachine.Amd64);
            BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(coff + 2), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(coff + 16), 0xF0);

            int optional = coff + 20;
            BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(optional), 0x20B);
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(optional + 56), 0x1000);
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(optional + 108), 16);
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(optional + 112), 0x200);
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(optional + 116), 40);

            int section = optional + 0xF0;
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(section + 8), 0x20);
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(section + 12), 0x200);
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(section + 16), 0x20);
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(section + 20), 0x200);
            return image;
        }
    }

    public sealed class LaunchRegressionTests
    {
        [Fact]
        public void DialogLaunchArmsAndRecordsStartupDialog() =>
            RunPowerShellLaunchProbe(
                LaunchApiCapture.HookMode.Dialogs,
                "$s='using System; using System.Runtime.InteropServices; " +
                "public static class CdaDialogProbe { " +
                "[DllImport(\"user32.dll\", CharSet=CharSet.Unicode)] " +
                "public static extern int MessageBox(IntPtr h, string t, string c, uint u); }'; " +
                "Add-Type -TypeDefinition $s; " +
                "[CdaDialogProbe]::MessageBox([IntPtr]::Zero,'CDA probe body','CDA probe caption',0)",
                "Dialog hooks were never armed.",
                "The startup dialog call did not reach the capture ring.");

        [Fact]
        public void InlineLaunchArmsAndRecordsStartupApi()
        {
            string source = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
            string tempDir = Path.Combine(Path.GetTempPath(), "cda-launch-" + Guid.NewGuid());
            string target = Path.Combine(tempDir, "cda-launch-probe.exe");
            Directory.CreateDirectory(tempDir);
            File.Copy(source, target);
            try
            {
                RunLaunchProbe(
                    target,
                    $"\"{target}\" /d /c \"ping -n 2 127.0.0.1 >nul\"",
                    LaunchApiCapture.HookMode.Inline,
                    "Startup API hooks were never armed.",
                    "No startup API call reached the capture ring.");
            }
            finally
            {
                try { Directory.Delete(tempDir, recursive: true); } catch { }
            }
        }

        private static void RunPowerShellLaunchProbe(
            LaunchApiCapture.HookMode mode,
            string script,
            string armFailure,
            string recordFailure)
        {
            string powerShell = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"WindowsPowerShell\v1.0\powershell.exe");
            Assert.True(File.Exists(powerShell), $"Test target not found: {powerShell}");

            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            string commandLine =
                $"\"{powerShell}\" -NoProfile -NonInteractive -EncodedCommand {encoded}";
            RunLaunchProbe(powerShell, commandLine, mode, armFailure, recordFailure);
        }

        private static void RunLaunchProbe(
            string executable,
            string commandLine,
            LaunchApiCapture.HookMode mode,
            string armFailure,
            string recordFailure)
        {
            var armed = new ManualResetEventSlim();
            var exited = new ManualResetEventSlim();
            var logGate = new object();
            var logs = new List<string>();
            CaptureSession? session = null;
            int pid = 0;

            using var worker = new LaunchApiCapture(
                executable, commandLine, mode,
                maxFunctions: 256, bufferRecords: 8192);
            worker.Log += message =>
            {
                lock (logGate) logs.Add(message);
            };
            worker.Hooked += hooked =>
            {
                session = hooked.Session;
                pid = hooked.Pid;
                armed.Set();
            };
            worker.TargetExited += () => exited.Set();

            worker.Start();
            try
            {
                int signal = WaitHandle.WaitAny(
                    new[] { armed.WaitHandle, exited.WaitHandle },
                    TimeSpan.FromSeconds(30));
                Assert.True(
                    signal == 0,
                    armFailure + "\n" + SnapshotLogs(logGate, logs));

                bool recorded = false;
                var deadline = Stopwatch.StartNew();
                while (deadline.Elapsed < TimeSpan.FromSeconds(20))
                {
                    List<Cda.Core.Model.CallRecord> records = session!.Poll();
                    if (records.Count > 0)
                    {
                        recorded = true;
                        break;
                    }
                    if (exited.IsSet) break;
                    Thread.Sleep(25);
                }

                Assert.True(
                    recorded,
                    recordFailure + "\n" + SnapshotLogs(logGate, logs));
            }
            finally
            {
                if (pid != 0)
                {
                    try
                    {
                        using System.Diagnostics.Process process =
                            System.Diagnostics.Process.GetProcessById(pid);
                        if (!process.HasExited) process.Kill(entireProcessTree: true);
                    }
                    catch { }
                }

                worker.Stop();
                Assert.True(worker.WaitForExit(10_000), "Launch debugger did not stop.");
                session?.Dispose();
            }
        }

        private static string SnapshotLogs(object gate, List<string> logs)
        {
            lock (gate) return string.Join(Environment.NewLine, logs);
        }
    }
}
