# PEAnalyzer

Small Windows CLI tool for inspecting Portable Executable (PE) files.

## Requirements

- Windows
- Visual Studio (recommended) or MSBuild
- .NET Framework 4.8

## Build

From a Visual Studio Developer PowerShell/Command Prompt:

```powershell
msbuild .\PEAnalyzer.csproj /p:Configuration=Release
```

Output binary:

- `.\bin\Release\peanalyze.exe`

## Usage

```powershell
.\bin\Release\peanalyze.exe <command> <file>
```

Commands:

- `summary`
- `headers`
- `sections`
- `imports`
- `exports`

## JSON output

Add `--json` (or `-j`) to print a single JSON object to stdout.

```powershell
.\bin\Release\peanalyze.exe --json exports C:\Windows\System32\kernel32.dll | ConvertFrom-Json
```

Examples:

```powershell
# Export forwarders in advapi32.dll
.\bin\Release\peanalyze.exe --json exports C:\Windows\System32\advapi32.dll |
  ConvertFrom-Json |
  Select-Object -ExpandProperty result |
  Select-Object -ExpandProperty symbols |
  Where-Object { $_.forwarder } |
  Select-Object ordinal,name,forwarder |
  Format-Table -AutoSize
```
