@echo off
setlocal enabledelayedexpansion
rem ---------------------------------------------------------------------------
rem  Build CDA in Release|x64 and write the full compiler output to a log file
rem  next to the solution, so a failure can be read back verbatim instead of
rem  re-typed from the Error List.
rem
rem  Prefers the Visual Studio MSBuild (located via vswhere) because it always
rem  has the WPF markup-compile targets; falls back to `dotnet build` if no VS
rem  installation is found.
rem
rem  Usage: double-click, or run  tools\build-release.cmd
rem  Output: build-release.log  in the repository root.
rem ---------------------------------------------------------------------------

cd /d "%~dp0.."
set "SLN=Cda.Modern.sln"
set "LOG=%CD%\build-release.log"
set "MSB="

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -prerelease -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2^>nul`) do (
        set "MSB=%%i"
    )
)

echo Building %SLN%  (Release^|x64)
echo Log: %LOG%
echo.

if defined MSB (
    echo Using MSBuild: !MSB!
    "!MSB!" "%SLN%" /t:Rebuild /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo > "%LOG%" 2>&1
) else (
    where dotnet >nul 2>&1
    if errorlevel 1 (
        echo ERROR: neither Visual Studio MSBuild nor the .NET SDK was found on PATH.
        echo Install Visual Studio with the .NET desktop development workload, then re-run.
        pause
        exit /b 1
    )
    echo Using: dotnet build
    dotnet build "%SLN%" -c Release -p:Platform=x64 -v:minimal --nologo > "%LOG%" 2>&1
)

set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
    echo BUILD SUCCEEDED.
    echo Output: Cda.App\bin\x64\Release\net8.0-windows\Cda.App.exe
) else (
    echo BUILD FAILED  ^(exit code %RC%^) - errors follow:
    echo.
    findstr /i /c:": error" /c:": warning MC" "%LOG%"
)
echo.
echo Full log written to %LOG%
pause
exit /b %RC%
