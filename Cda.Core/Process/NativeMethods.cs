using System;
using System.Runtime.InteropServices;

namespace Cda.Core.Process
{
    /// <summary>
    /// P/Invoke surface for process inspection. Kept private to the engine. The
    /// modern equivalent of the scattered Win32 declarations in the legacy
    /// <c>Function_Debugger.Classes</c> (SYSTEM_INFO, MEMORY_BASIC_INFORMATION,
    /// TOKEN_PRIVILEGES, etc.), trimmed to what the reader actually needs.
    /// </summary>
    internal static class NativeMethods
    {
        [Flags]
        public enum ProcessAccess : uint
        {
            Terminate = 0x0001,
            QueryInformation = 0x0400,
            QueryLimitedInformation = 0x1000,
            VmRead = 0x0010,
            VmWrite = 0x0020,
            VmOperation = 0x0008,
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccess access, bool inherit, int pid);

        // Used by the startup trace's auto-bisection to discard a hidden test instance
        // that ran clean (we only want the search verdict, not a survivor left running).
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TerminateProcess(IntPtr process, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(
            IntPtr process, IntPtr baseAddress, byte[] buffer, IntPtr size, out IntPtr read);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(
            IntPtr process, IntPtr baseAddress, byte[] buffer, IntPtr size, out IntPtr written);

        // IsWow64Process2 (Win 10+) distinguishes the *target* machine from the
        // host, which is exactly what we need to pick the x86 vs x64 decoder.
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process2(IntPtr process, out ushort processMachine, out ushort nativeMachine);

        // Liveness check: GetExitCodeProcess works with the QueryLimitedInformation
        // right we already hold; a still-running process reports STILL_ACTIVE.
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

        public const uint STILL_ACTIVE = 259;

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumProcessModulesEx(
            IntPtr process, [Out] IntPtr[] modules, uint cb, out uint needed, uint filterFlag);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetModuleFileNameExW(
            IntPtr process, IntPtr module, [Out] char[] baseName, uint size);

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetModuleInformation(
            IntPtr process, IntPtr module, out MODULEINFO info, uint cb);

        [StructLayout(LayoutKind.Sequential)]
        public struct MODULEINFO
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        public const uint LIST_MODULES_ALL = 0x03; // 32-bit + 64-bit modules
        public const ushort IMAGE_FILE_MACHINE_UNKNOWN = 0;
        public const ushort IMAGE_FILE_MACHINE_I386 = 0x014C;
        public const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        public const ushort IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

        // --- remote memory (instrumentation path) ---------------------------

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr process, IntPtr address, IntPtr size, uint allocationType, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFreeEx(IntPtr process, IntPtr address, IntPtr size, uint freeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtectEx(
            IntPtr process, IntPtr address, IntPtr size, uint newProtect, out uint oldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlushInstructionCache(IntPtr process, IntPtr address, IntPtr size);

        // Walk the target's virtual address space a region at a time. Used to find
        // a free reservation within +/-2GB of a hooked module so an x64 entry
        // detour (E9 rel32) and its trampoline are reachable from the patch site.
        // Returns the number of bytes written to <paramref name="buffer"/> (the
        // struct size) on success, 0 on failure.
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualQueryEx(
            IntPtr process, IntPtr address, out MEMORY_BASIC_INFORMATION buffer, IntPtr length);

        // Native-pointer-sized fields are declared IntPtr so the layout is correct
        // for the host bitness (the near-allocation path runs only for x64 targets,
        // where the host is also x64). On x64 the CLR inserts 4 bytes of padding
        // after AllocationProtect to 8-align RegionSize, matching the OS struct.
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_RESERVE = 0x2000;
        public const uint MEM_RELEASE = 0x8000;
        public const uint MEM_FREE = 0x10000;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        // --- in-process memory (for the codegen self-test) ------------------

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr address, IntPtr size, uint allocationType, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtect(IntPtr address, IntPtr size, uint newProtect, out uint oldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualFree(IntPtr address, IntPtr size, uint freeType);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        // --- thread suspension (safe hook install / teardown) ----------------

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Thread32First(IntPtr snapshot, ref THREADENTRY32 entry);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Thread32Next(IntPtr snapshot, ref THREADENTRY32 entry);

        [StructLayout(LayoutKind.Sequential)]
        public struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint access, bool inherit, uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr thread);

        public const uint TH32CS_SNAPTHREAD = 0x00000004;
        public const uint THREAD_SUSPEND_RESUME = 0x0002;
        public const uint THREAD_GET_CONTEXT = 0x0008;
        public const uint THREAD_SET_CONTEXT = 0x0010;
        public const uint THREAD_QUERY_INFORMATION = 0x0040;
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        // Per-thread debug registers (hardware breakpoints) are read/written through
        // the thread CONTEXT. On x64 the CONTEXT buffer must be 16-byte aligned (the
        // caller aligns it) and its fields are accessed by offset.
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetThreadContext(IntPtr thread, IntPtr context);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadContext(IntPtr thread, IntPtr context);

        // --- suspended launch (capture from the first instruction) -----------

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessW(
            string? lpApplicationName, string? lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        // --- ASLR-disable launch (reproducible module bases) -----------------
        // Launch a target with bottom-up + high-entropy ASLR forced OFF via a
        // per-process creation mitigation policy, so its modules load at the same
        // base every run and absolute addresses line up across runs and across
        // saved traces. The policy rides along in an EXTENDED STARTUPINFO attribute
        // list; it touches nothing global. (If an admin has forced system-wide
        // mandatory ASLR on, that still wins for the main image — the common
        // default config honors this per-process opt-out.)

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        // The same CreateProcessW entry point, taking the EXTENDED STARTUPINFO so an
        // attribute list (the mitigation policy) can be attached. Requires the
        // EXTENDED_STARTUPINFO_PRESENT creation flag.
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcessW(
            string? lpApplicationName, string? lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string? lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;

        // ProcThreadAttributeValue(ProcThreadAttributeMitigationPolicy=7, Input=TRUE).
        public static readonly IntPtr PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = (IntPtr)0x00020007;

        // PROCESS_CREATION_MITIGATION_POLICY_* (winnt.h): each policy is a 2-bit
        // field where value 0x2 = ALWAYS_OFF. Bottom-up randomization occupies bits
        // 16-17; high-entropy ASLR (the 64-bit top-down entropy) bits 20-21. Forcing
        // both off is what makes a target's loads deterministic.
        public const ulong PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF = 0x2UL << 16;
        public const ulong PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_OFF = 0x2UL << 20;

        /// <summary>
        /// CreateProcess wrapper shared by every launch path (suspended startup
        /// trace, DLL-at-load, child-follow). When <paramref name="disableAslr"/> is
        /// false this is a plain CreateProcessW with exactly the previous semantics.
        /// When true it attaches a process-creation mitigation policy that forces
        /// bottom-up and high-entropy ASLR off for the new process, so module bases —
        /// and therefore the absolute addresses in a trace — are reproducible across
        /// runs. <paramref name="hideWindow"/> launches the target hidden (used by the
        /// auto-bisection test runs). The policy value buffer and attribute list are
        /// kept alive until CreateProcess returns — the OS reads them at that point —
        /// then released.
        /// </summary>
        public static bool CreateProcessGuarded(
            string? appName, string? cmdLine, uint creationFlags, string? workDir,
            bool disableAslr, bool hideWindow, out PROCESS_INFORMATION pi)
        {
            int dwFlags = hideWindow ? (int)STARTF_USESHOWWINDOW : 0;
            short wShow = hideWindow ? SW_HIDE : (short)0;
            if (hideWindow) creationFlags |= CREATE_NO_WINDOW;

            // Plain launch (no mitigation attribute list). Used directly when ASLR
            // isn't being disabled, AND as the fallback if the attribute-list setup
            // ever fails — so a mitigation-policy hiccup can't abort an otherwise-fine
            // launch (the caller's DYNAMICBASE image strip is the primary fixed-base
            // mechanism; the policy is a complementary bottom-up tweak).
            bool LaunchPlain(out PROCESS_INFORMATION p)
            {
                var si = new STARTUPINFO
                {
                    cb = Marshal.SizeOf<STARTUPINFO>(),
                    dwFlags = dwFlags,
                    wShowWindow = wShow,
                };
                return CreateProcessW(appName, cmdLine, IntPtr.Zero, IntPtr.Zero, false,
                    creationFlags, IntPtr.Zero, workDir, ref si, out p);
            }

            if (!disableAslr)
                return LaunchPlain(out pi);

            pi = default;
            IntPtr attrList = IntPtr.Zero;
            IntPtr policyBuf = IntPtr.Zero;
            bool listInited = false;
            try
            {
                // Size, allocate, then initialize a one-entry attribute list. The
                // first sizing call is EXPECTED to "fail" with ERROR_INSUFFICIENT_BUFFER
                // while reporting the required size, so its result is ignored on purpose.
                IntPtr size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                attrList = Marshal.AllocHGlobal(size);
                if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref size))
                    return LaunchPlain(out pi);
                listInited = true; // only now is the list safe to Delete

                ulong policy = PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF
                             | PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_OFF;
                policyBuf = Marshal.AllocHGlobal(sizeof(ulong));
                Marshal.WriteInt64(policyBuf, unchecked((long)policy));

                // UpdateProcThreadAttribute stores the POINTER to the value, not a
                // copy, so policyBuf must outlive the CreateProcess call below (it
                // does — both buffers are freed in the finally, after the call).
                if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                        policyBuf, (IntPtr)sizeof(ulong), IntPtr.Zero, IntPtr.Zero))
                    return LaunchPlain(out pi);

                var six = new STARTUPINFOEX
                {
                    StartupInfo = new STARTUPINFO
                    {
                        cb = Marshal.SizeOf<STARTUPINFOEX>(),
                        dwFlags = dwFlags,
                        wShowWindow = wShow,
                    },
                    lpAttributeList = attrList,
                };
                return CreateProcessW(appName, cmdLine, IntPtr.Zero, IntPtr.Zero, false,
                    creationFlags | EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, workDir,
                    ref six, out pi);
            }
            finally
            {
                // Delete only an initialized list; a raw (alloc'd but not yet
                // initialized) buffer must just be freed, never "deleted".
                if (listInited) DeleteProcThreadAttributeList(attrList);
                if (attrList != IntPtr.Zero) Marshal.FreeHGlobal(attrList);
                if (policyBuf != IntPtr.Zero) Marshal.FreeHGlobal(policyBuf);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(
            IntPtr process, int infoClass, ref PROCESS_BASIC_INFORMATION info, int size, out int returnLength);

        public const uint CREATE_SUSPENDED = 0x00000004;
        public const uint CREATE_NO_WINDOW = 0x08000000; // suppress a console window (console targets)

        // Launch a target with its window hidden (used for auto-bisection TEST runs, so
        // the repeatedly-relaunched target doesn't pop up / steal focus).
        public const uint STARTF_USESHOWWINDOW = 0x00000001;
        public const short SW_HIDE = 0;

        // --- debugger loop (capture a DLL from the moment it loads) -----------
        // All of these must be called from the one thread that created the
        // debuggee (CreateProcess with a DEBUG flag); that's why the loop runs on
        // its own dedicated thread.

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WaitForDebugEvent(IntPtr lpDebugEvent, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ContinueDebugEvent(uint processId, uint threadId, uint continueStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DebugActiveProcessStop(uint processId);

        // Attach the debugger to an already-running process (for hardware-breakpoint
        // capture: set debug registers and catch the resulting #DB exceptions).
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DebugActiveProcess(uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DebugSetProcessKillOnExit([MarshalAs(UnmanagedType.Bool)] bool killOnExit);

        // Resolve the on-disk path behind the file handle handed out with a
        // LOAD_DLL debug event, so we can tell whether it's the DLL we're after.
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint GetFinalPathNameByHandleW(IntPtr hFile, [Out] char[] path, uint cchPath, uint flags);

        public const uint DEBUG_PROCESS = 0x00000001;
        public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;

        // dwDebugEventCode values
        public const uint EXCEPTION_DEBUG_EVENT = 1;
        public const uint CREATE_THREAD_DEBUG_EVENT = 2;
        public const uint CREATE_PROCESS_DEBUG_EVENT = 3;
        public const uint EXIT_THREAD_DEBUG_EVENT = 4;
        public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
        public const uint LOAD_DLL_DEBUG_EVENT = 6;

        // ContinueDebugEvent status
        public const uint DBG_CONTINUE = 0x00010002;
        public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

        // Loader breakpoints we silently continue past (native + WOW64 initial bp)
        public const uint EXCEPTION_BREAKPOINT = 0x80000003;
        public const uint STATUS_WX86_BREAKPOINT = 0x4000001F;
        public const uint EXCEPTION_SINGLE_STEP = 0x80000004; // also a hardware-bp #DB

        public const int ERROR_SEM_TIMEOUT = 121;
    }
}
