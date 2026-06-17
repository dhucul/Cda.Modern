using System;
using System.Collections.Generic;

namespace Cda.Core.Engine
{
    /// <summary>How a captured argument should be presented for a known API.</summary>
    public enum ApiParamKind
    {
        Int,      // a small signed count / id / size — show as decimal
        Hex,      // a flags / access-mask / message id — show as 0x…
        Handle,   // a HANDLE / HWND / HKEY — show as 0x…
        String,   // a pointer to a string — show the decoded text if captured, else 0x…
        Bool,     // a BOOL — show TRUE / FALSE
        Pointer,  // an out / buffer / struct pointer — show as 0x…
    }

    /// <summary>A named parameter of a known API, with how to render it.</summary>
    public readonly struct ApiParam
    {
        public readonly string Name;
        public readonly ApiParamKind Kind;
        public ApiParam(string name, ApiParamKind kind) { Name = name; Kind = kind; }
    }

    /// <summary>
    /// A small, host-side database of common Win32 API signatures. Given a callee
    /// name, it supplies the parameter names + how each should be displayed, so the
    /// Calls log can show <c>CreateFileW(lpFileName="C:\x", dwDesiredAccess=0x80000000, …)</c>
    /// instead of a row of raw hex. This is purely cosmetic and never touches the
    /// target — it formats values already captured (and strings already decoded
    /// host-side). The ANSI/Wide ('A'/'W') suffix is folded away on lookup, and the
    /// actual decoded string (whichever charset) is preferred when rendering a
    /// String parameter, so one entry serves both variants.
    ///
    /// Only the first few integer arguments are captured per call, so a signature
    /// with more parameters than were captured is shown truncated with an ellipsis.
    /// </summary>
    public static class ApiSignatures
    {
        private static ApiParam P(string n, ApiParamKind k) => new ApiParam(n, k);

        // Keyed case-insensitively by the base API name (no A/W suffix).
        private static readonly Dictionary<string, ApiParam[]> Table =
            new(StringComparer.OrdinalIgnoreCase)
        {
            // --- files -------------------------------------------------------
            ["CreateFile"] = new[] { P("lpFileName", ApiParamKind.String), P("dwDesiredAccess", ApiParamKind.Hex), P("dwShareMode", ApiParamKind.Hex), P("lpSecurityAttributes", ApiParamKind.Pointer), P("dwCreationDisposition", ApiParamKind.Int), P("dwFlagsAndAttributes", ApiParamKind.Hex), P("hTemplateFile", ApiParamKind.Handle) },
            ["ReadFile"] = new[] { P("hFile", ApiParamKind.Handle), P("lpBuffer", ApiParamKind.Pointer), P("nNumberOfBytesToRead", ApiParamKind.Int), P("lpNumberOfBytesRead", ApiParamKind.Pointer), P("lpOverlapped", ApiParamKind.Pointer) },
            ["WriteFile"] = new[] { P("hFile", ApiParamKind.Handle), P("lpBuffer", ApiParamKind.Pointer), P("nNumberOfBytesToWrite", ApiParamKind.Int), P("lpNumberOfBytesWritten", ApiParamKind.Pointer), P("lpOverlapped", ApiParamKind.Pointer) },
            ["CloseHandle"] = new[] { P("hObject", ApiParamKind.Handle) },
            ["DeleteFile"] = new[] { P("lpFileName", ApiParamKind.String) },
            ["CopyFile"] = new[] { P("lpExistingFileName", ApiParamKind.String), P("lpNewFileName", ApiParamKind.String), P("bFailIfExists", ApiParamKind.Bool) },
            ["MoveFile"] = new[] { P("lpExistingFileName", ApiParamKind.String), P("lpNewFileName", ApiParamKind.String) },
            ["GetFileSize"] = new[] { P("hFile", ApiParamKind.Handle), P("lpFileSizeHigh", ApiParamKind.Pointer) },
            ["SetFilePointer"] = new[] { P("hFile", ApiParamKind.Handle), P("lDistanceToMove", ApiParamKind.Int), P("lpDistanceToMoveHigh", ApiParamKind.Pointer), P("dwMoveMethod", ApiParamKind.Int) },
            ["CreateDirectory"] = new[] { P("lpPathName", ApiParamKind.String), P("lpSecurityAttributes", ApiParamKind.Pointer) },
            ["FindFirstFile"] = new[] { P("lpFileName", ApiParamKind.String), P("lpFindFileData", ApiParamKind.Pointer) },
            ["CreateFileMapping"] = new[] { P("hFile", ApiParamKind.Handle), P("lpAttributes", ApiParamKind.Pointer), P("flProtect", ApiParamKind.Hex), P("dwMaximumSizeHigh", ApiParamKind.Hex), P("dwMaximumSizeLow", ApiParamKind.Hex), P("lpName", ApiParamKind.String) },
            ["MapViewOfFile"] = new[] { P("hFileMappingObject", ApiParamKind.Handle), P("dwDesiredAccess", ApiParamKind.Hex), P("dwFileOffsetHigh", ApiParamKind.Hex), P("dwFileOffsetLow", ApiParamKind.Hex), P("dwNumberOfBytesToMap", ApiParamKind.Int) },

            // --- modules / addresses ----------------------------------------
            ["LoadLibrary"] = new[] { P("lpLibFileName", ApiParamKind.String) },
            ["LoadLibraryEx"] = new[] { P("lpLibFileName", ApiParamKind.String), P("hFile", ApiParamKind.Handle), P("dwFlags", ApiParamKind.Hex) },
            ["GetModuleHandle"] = new[] { P("lpModuleName", ApiParamKind.String) },
            ["GetModuleFileName"] = new[] { P("hModule", ApiParamKind.Handle), P("lpFilename", ApiParamKind.Pointer), P("nSize", ApiParamKind.Int) },
            ["GetProcAddress"] = new[] { P("hModule", ApiParamKind.Handle), P("lpProcName", ApiParamKind.String) },
            ["FreeLibrary"] = new[] { P("hModule", ApiParamKind.Handle) },

            // --- memory ------------------------------------------------------
            ["VirtualAlloc"] = new[] { P("lpAddress", ApiParamKind.Pointer), P("dwSize", ApiParamKind.Int), P("flAllocationType", ApiParamKind.Hex), P("flProtect", ApiParamKind.Hex) },
            ["VirtualAllocEx"] = new[] { P("hProcess", ApiParamKind.Handle), P("lpAddress", ApiParamKind.Pointer), P("dwSize", ApiParamKind.Int), P("flAllocationType", ApiParamKind.Hex), P("flProtect", ApiParamKind.Hex) },
            ["VirtualProtect"] = new[] { P("lpAddress", ApiParamKind.Pointer), P("dwSize", ApiParamKind.Int), P("flNewProtect", ApiParamKind.Hex), P("lpflOldProtect", ApiParamKind.Pointer) },
            ["VirtualFree"] = new[] { P("lpAddress", ApiParamKind.Pointer), P("dwSize", ApiParamKind.Int), P("dwFreeType", ApiParamKind.Hex) },
            ["ReadProcessMemory"] = new[] { P("hProcess", ApiParamKind.Handle), P("lpBaseAddress", ApiParamKind.Pointer), P("lpBuffer", ApiParamKind.Pointer), P("nSize", ApiParamKind.Int), P("lpNumberOfBytesRead", ApiParamKind.Pointer) },
            ["WriteProcessMemory"] = new[] { P("hProcess", ApiParamKind.Handle), P("lpBaseAddress", ApiParamKind.Pointer), P("lpBuffer", ApiParamKind.Pointer), P("nSize", ApiParamKind.Int), P("lpNumberOfBytesWritten", ApiParamKind.Pointer) },

            // --- processes / threads ----------------------------------------
            ["OpenProcess"] = new[] { P("dwDesiredAccess", ApiParamKind.Hex), P("bInheritHandle", ApiParamKind.Bool), P("dwProcessId", ApiParamKind.Int) },
            ["CreateProcess"] = new[] { P("lpApplicationName", ApiParamKind.String), P("lpCommandLine", ApiParamKind.String), P("lpProcessAttributes", ApiParamKind.Pointer), P("lpThreadAttributes", ApiParamKind.Pointer), P("bInheritHandles", ApiParamKind.Bool), P("dwCreationFlags", ApiParamKind.Hex), P("lpEnvironment", ApiParamKind.Pointer), P("lpCurrentDirectory", ApiParamKind.String), P("lpStartupInfo", ApiParamKind.Pointer), P("lpProcessInformation", ApiParamKind.Pointer) },
            ["CreateThread"] = new[] { P("lpThreadAttributes", ApiParamKind.Pointer), P("dwStackSize", ApiParamKind.Int), P("lpStartAddress", ApiParamKind.Pointer), P("lpParameter", ApiParamKind.Pointer), P("dwCreationFlags", ApiParamKind.Hex), P("lpThreadId", ApiParamKind.Pointer) },
            ["CreateRemoteThread"] = new[] { P("hProcess", ApiParamKind.Handle), P("lpThreadAttributes", ApiParamKind.Pointer), P("dwStackSize", ApiParamKind.Int), P("lpStartAddress", ApiParamKind.Pointer), P("lpParameter", ApiParamKind.Pointer), P("dwCreationFlags", ApiParamKind.Hex), P("lpThreadId", ApiParamKind.Pointer) },
            ["WaitForSingleObject"] = new[] { P("hHandle", ApiParamKind.Handle), P("dwMilliseconds", ApiParamKind.Int) },
            ["TerminateProcess"] = new[] { P("hProcess", ApiParamKind.Handle), P("uExitCode", ApiParamKind.Int) },
            ["Sleep"] = new[] { P("dwMilliseconds", ApiParamKind.Int) },
            ["ExitProcess"] = new[] { P("uExitCode", ApiParamKind.Int) },
            ["GetLastError"] = Array.Empty<ApiParam>(),
            ["SetLastError"] = new[] { P("dwErrCode", ApiParamKind.Int) },
            ["OutputDebugString"] = new[] { P("lpOutputString", ApiParamKind.String) },

            // --- synchronization --------------------------------------------
            ["CreateMutex"] = new[] { P("lpMutexAttributes", ApiParamKind.Pointer), P("bInitialOwner", ApiParamKind.Bool), P("lpName", ApiParamKind.String) },
            ["CreateEvent"] = new[] { P("lpEventAttributes", ApiParamKind.Pointer), P("bManualReset", ApiParamKind.Bool), P("bInitialState", ApiParamKind.Bool), P("lpName", ApiParamKind.String) },

            // --- registry ----------------------------------------------------
            ["RegOpenKeyEx"] = new[] { P("hKey", ApiParamKind.Handle), P("lpSubKey", ApiParamKind.String), P("ulOptions", ApiParamKind.Hex), P("samDesired", ApiParamKind.Hex), P("phkResult", ApiParamKind.Pointer) },
            ["RegQueryValueEx"] = new[] { P("hKey", ApiParamKind.Handle), P("lpValueName", ApiParamKind.String), P("lpReserved", ApiParamKind.Pointer), P("lpType", ApiParamKind.Pointer), P("lpData", ApiParamKind.Pointer), P("lpcbData", ApiParamKind.Pointer) },
            ["RegSetValueEx"] = new[] { P("hKey", ApiParamKind.Handle), P("lpValueName", ApiParamKind.String), P("Reserved", ApiParamKind.Hex), P("dwType", ApiParamKind.Int), P("lpData", ApiParamKind.Pointer), P("cbData", ApiParamKind.Int) },
            ["RegCreateKeyEx"] = new[] { P("hKey", ApiParamKind.Handle), P("lpSubKey", ApiParamKind.String), P("Reserved", ApiParamKind.Hex), P("lpClass", ApiParamKind.String), P("dwOptions", ApiParamKind.Hex), P("samDesired", ApiParamKind.Hex) },
            ["RegCloseKey"] = new[] { P("hKey", ApiParamKind.Handle) },

            // --- windows / messages -----------------------------------------
            ["MessageBox"] = new[] { P("hWnd", ApiParamKind.Handle), P("lpText", ApiParamKind.String), P("lpCaption", ApiParamKind.String), P("uType", ApiParamKind.Hex) },
            ["GetWindowText"] = new[] { P("hWnd", ApiParamKind.Handle), P("lpString", ApiParamKind.Pointer), P("nMaxCount", ApiParamKind.Int) },
            ["SetWindowText"] = new[] { P("hWnd", ApiParamKind.Handle), P("lpString", ApiParamKind.String) },
            ["SendMessage"] = new[] { P("hWnd", ApiParamKind.Handle), P("Msg", ApiParamKind.Hex), P("wParam", ApiParamKind.Hex), P("lParam", ApiParamKind.Hex) },
            ["PostMessage"] = new[] { P("hWnd", ApiParamKind.Handle), P("Msg", ApiParamKind.Hex), P("wParam", ApiParamKind.Hex), P("lParam", ApiParamKind.Hex) },
            ["FindWindow"] = new[] { P("lpClassName", ApiParamKind.String), P("lpWindowName", ApiParamKind.String) },
            ["CreateWindowEx"] = new[] { P("dwExStyle", ApiParamKind.Hex), P("lpClassName", ApiParamKind.String), P("lpWindowName", ApiParamKind.String), P("dwStyle", ApiParamKind.Hex), P("x", ApiParamKind.Int), P("y", ApiParamKind.Int), P("nWidth", ApiParamKind.Int), P("nHeight", ApiParamKind.Int) },

            // --- strings -----------------------------------------------------
            ["lstrlen"] = new[] { P("lpString", ApiParamKind.String) },
            ["lstrcpy"] = new[] { P("lpString1", ApiParamKind.Pointer), P("lpString2", ApiParamKind.String) },
            ["lstrcat"] = new[] { P("lpString1", ApiParamKind.Pointer), P("lpString2", ApiParamKind.String) },

            // --- shell / exec / net -----------------------------------------
            ["WinExec"] = new[] { P("lpCmdLine", ApiParamKind.String), P("uCmdShow", ApiParamKind.Int) },
            ["ShellExecute"] = new[] { P("hwnd", ApiParamKind.Handle), P("lpOperation", ApiParamKind.String), P("lpFile", ApiParamKind.String), P("lpParameters", ApiParamKind.String), P("lpDirectory", ApiParamKind.String), P("nShowCmd", ApiParamKind.Int) },
            ["URLDownloadToFile"] = new[] { P("pCaller", ApiParamKind.Pointer), P("szURL", ApiParamKind.String), P("szFileName", ApiParamKind.String), P("dwReserved", ApiParamKind.Hex), P("lpfnCB", ApiParamKind.Pointer) },
            ["InternetOpen"] = new[] { P("lpszAgent", ApiParamKind.String), P("dwAccessType", ApiParamKind.Int), P("lpszProxy", ApiParamKind.String), P("lpszProxyBypass", ApiParamKind.String), P("dwFlags", ApiParamKind.Hex) },
            ["InternetOpenUrl"] = new[] { P("hInternet", ApiParamKind.Handle), P("lpszUrl", ApiParamKind.String), P("lpszHeaders", ApiParamKind.String), P("dwHeadersLength", ApiParamKind.Int), P("dwFlags", ApiParamKind.Hex), P("dwContext", ApiParamKind.Pointer) },
            ["InternetConnect"] = new[] { P("hInternet", ApiParamKind.Handle), P("lpszServerName", ApiParamKind.String), P("nServerPort", ApiParamKind.Int), P("lpszUserName", ApiParamKind.String), P("lpszPassword", ApiParamKind.String), P("dwService", ApiParamKind.Int) },
            ["connect"] = new[] { P("s", ApiParamKind.Int), P("name", ApiParamKind.Pointer), P("namelen", ApiParamKind.Int) },
            ["send"] = new[] { P("s", ApiParamKind.Int), P("buf", ApiParamKind.Pointer), P("len", ApiParamKind.Int), P("flags", ApiParamKind.Hex) },
            ["recv"] = new[] { P("s", ApiParamKind.Int), P("buf", ApiParamKind.Pointer), P("len", ApiParamKind.Int), P("flags", ApiParamKind.Hex) },
        };

        /// <summary>
        /// Parameters for <paramref name="functionName"/>, or null if unknown. An
        /// ANSI/Wide suffix is folded away when the base name is known.
        /// </summary>
        public static ApiParam[]? Lookup(string? functionName)
        {
            if (string.IsNullOrEmpty(functionName)) return null;
            if (Table.TryGetValue(functionName!, out var sig)) return sig;

            char last = functionName![functionName.Length - 1];
            if ((last == 'A' || last == 'W') && functionName.Length > 1)
            {
                string baseName = functionName.Substring(0, functionName.Length - 1);
                if (Table.TryGetValue(baseName, out var s2)) return s2;
            }
            return null;
        }

        /// <summary>Render a single non-string captured value per its kind.</summary>
        public static string FormatValue(ApiParamKind kind, ulong raw) => kind switch
        {
            ApiParamKind.Bool => raw == 0 ? "FALSE" : raw == 1 ? "TRUE" : "0x" + raw.ToString("X"),
            ApiParamKind.Int => raw <= int.MaxValue ? raw.ToString() : "0x" + raw.ToString("X"),
            _ => "0x" + raw.ToString("X"),
        };
    }
}
