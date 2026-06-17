using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Cda.Core.Process
{
    public sealed class ProcessEntry
    {
        public int Pid;
        public string Name = "";
        public string? FilePath;
        public TargetProcess.PeMachineKind Machine = TargetProcess.PeMachineKind.Unknown;

        public string Display =>
            $"{Name} ({Pid})" + Machine switch
            {
                TargetProcess.PeMachineKind.X86 => "  [x86]",
                TargetProcess.PeMachineKind.X64 => "  [x64]",
                TargetProcess.PeMachineKind.Arm64 => "  [arm64]",
                _ => ""
            };
    }

    /// <summary>
    /// Enumerates running processes with best-effort bitness, replacing the
    /// legacy process-picker. Uses <see cref="System.Diagnostics.Process"/> for
    /// the list and a light handle probe for architecture.
    /// </summary>
    public static class ProcessList
    {
        public static List<ProcessEntry> Enumerate()
        {
            var result = new List<ProcessEntry>();
            foreach (var p in System.Diagnostics.Process.GetProcesses())
            {
                var entry = new ProcessEntry { Pid = p.Id, Name = p.ProcessName };
                try { entry.FilePath = p.MainModule?.FileName; } catch { /* access denied */ }
                entry.Machine = ProbeMachine(p.Id);
                result.Add(entry);
                p.Dispose();
            }
            result.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
            return result;
        }

        private static TargetProcess.PeMachineKind ProbeMachine(int pid)
        {
            IntPtr h = NativeMethods.OpenProcess(
                NativeMethods.ProcessAccess.QueryLimitedInformation, false, pid);
            if (h == IntPtr.Zero) return TargetProcess.PeMachineKind.Unknown;
            try
            {
                if (NativeMethods.IsWow64Process2(h, out ushort proc, out ushort native))
                {
                    ushort machine = proc != NativeMethods.IMAGE_FILE_MACHINE_UNKNOWN ? proc : native;
                    return machine switch
                    {
                        NativeMethods.IMAGE_FILE_MACHINE_I386 => TargetProcess.PeMachineKind.X86,
                        NativeMethods.IMAGE_FILE_MACHINE_AMD64 => TargetProcess.PeMachineKind.X64,
                        NativeMethods.IMAGE_FILE_MACHINE_ARM64 => TargetProcess.PeMachineKind.Arm64,
                        _ => TargetProcess.PeMachineKind.Unknown,
                    };
                }
            }
            finally { NativeMethods.CloseHandle(h); }
            return TargetProcess.PeMachineKind.Unknown;
        }
    }
}
