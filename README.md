# Phantom

**Originally created by [c5hackr](https://github.com/C5Hackr/Phantom) (Crybat/Jlaive Rewrite) — modded by [trapwithme](https://github.com/Trapwithme/Phantom).**

<p align="center">
  <a href="https://github.com/Trapwithme/Phantom/releases"><img src="https://img.shields.io/badge/Download-Phantom-1f6feb?style=for-the-badge&logo=github" alt="Download"/></a>
  <br/><br/>
  <a href="https://t.me/+nIzmNyQB9a1jZGYx"><img src="https://img.shields.io/badge/Join_Telegram_Group-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white" alt="Telegram"/></a>
  <br/>
  <b>JOIN THE CHAT FOR SUPPORT UPDATES N CHATTING</b>
</p>

Phantom is a batch-based agent generator that wraps an encrypted .NET payload into a self-contained batch file with hidden execution, admin elevation, startup persistence, self-deletion, anti-debug, and anti-VM. The payload is delivered via PowerShell (Reflection Load) — no files written to disk, no AMSI-triggering patterns.

Output is a single `.bat` file with no dependencies. Works on Windows 7+.

## Features

| Feature | Description |
|---|---|
| **Hidden execution** | VBS self-relaunch guard hides the cmd.exe window (WScript.Shell.Run with window style 0) |
| **Admin elevation** | **Ask admin prompt** — checks admin via `net session`, elevates via `Shell.Application` + `runas` verb. Guard check runs before admin check (hidden relaunches skip UAC entirely — 1 prompt, not 4) |
| **Startup persistence** | Registry Run key via `cmd.exe /c` (no VBS file created — avoids Defender VBS detections). Scheduled task as fallback |
| **Self-deletion** | **AppData-aware** — startup copies in AppData survive; original batch in any other directory is melted with `(goto) 2>nul & del "%~f0"` |
| **Anti‑Debug** | NtGlobalFlag, being-debugged PEB flag, IsDebuggerPresent, remote debugger detection |
| **Anti‑VM** | Checks for common VM artifacts (processes, services, hardware identifiers, disk model, MAC prefix, BIOS) |
| **AMSI bypass** | INT3 (`0xCC`) at `AmsiScanBuffer` entry + VEH handler zeroes return at `sp+0x30`. Two independent bypasses: one in the PowerShell decryption script, another in the loaded C# stub (CLR/COM interop triggers a second `AmsiScanBuffer` call). No `VirtualProtect` or `SetThreadContext` — avoids `Behavior:Win32/SuspAmsiPatch.F/K` |
| **ETW bypass** | `VirtualProtect` on `ntdll!EtwEventWrite` — zero byte patch |
| **AES-256-CBC** | Payload encrypted with random key/IV per build |
| **Compression** | GZip compression of the .NET payload before encryption |
| **Bind files** | Additional files embedded alongside the payload |
| **.NET / Native** | Supports .NET assemblies and native x64/x86 executables (Donut shellcode conversion) |

## What's different in this fork (vs c5hackr/Phantom)

- **AMSI bypass changed** — original c5 used `BStub.cs` with `VirtualProtect` + `Marshal.Copy` to overwrite `AmsiScanBuffer` prologue with `mov eax, 0x80070057; ret` (hardcoded RVAs for Win10/Win11). This fork switched to INT3 (`0xCC`) at `AmsiScanBuffer` entry + VEH handler zeroes return at `sp+0x30`. No `VirtualProtect` on `amsi.dll` — avoids `Behavior:Win32/SuspAmsiPatch.F/K`. Dual-context: both the PowerShell decryption script and the loaded C# stub get their own bypass (CLR/COM triggers a second `AmsiScanBuffer`).
- **UAC Bypass removed** — original used `wusa.exe` DLL sideloading (fodhelper variant). Removed because it's unreliable and Defender flags it.
- **No VBS in startup** — Registry Run key points directly to `cmd.exe /c batchpath` instead of a `.vbs` launcher, eliminating `Trojan:VBS/Runner.LPAA!MTB`.
- **AppData‑aware self‑delete** — startup copies in `%APPDATA%` are never deleted; only the original deployment batch melts itself.
- **Guard‑before‑admin ordering** — the VBS guard flag check runs first, so hidden relaunches skip the admin elevation check entirely (one UAC prompt instead of cascading prompts).
- **`goto` instead of `if` blocks** — batch parser doesn't choke on parentheses inside `echo CreateObject("Shell.Application")`.

## GUI Options

| Option | Description |
|---|---|
| **Ask admin prompt** | If checked, the batch elevates via UAC on launch. If denied, exits silently. Previously labelled "Run as admin" |
| **Hidden** | VBS guard relaunches the batch silently — no visible cmd window |
| **Self destruct** | Deletes the original batch after execution. Skips files in `%APPDATA%` |
| **Startup** | Installs persistence via Registry Run key + Scheduled Task |
| **Anti Debug** | Debugger detection at runtime |
| **Anti VM** | Virtual machine detection at runtime |
| **Bind files** | Embed additional files alongside the payload |

## Build

```powershell
# Requires MSBuild from Visual Studio 2022
MSBuild Phantom.csproj /p:Configuration=Release /p:Platform=AnyCPU
```

Output: `bin\Release\Phantom.exe`

### CLI Usage

```powershell
Phantom.exe --cli <input_exe> [output_bat] [options]
```

Options (none enabled by default): `--hidden` `--selfdelete` `--runas` `--startup` `--antidebug` `--antivm`

## Tested Configuration

All flags enabled, zero Windows Defender detections:

- `--cli` with hidden + selfdelete + runas + startup + anti-debug + anti-vm
- Stub compiled for .NET Framework 4.7.2 (Roslyn)
- Payload: AES-256-CBC encrypted + GZip compressed .NET assembly
- Tested on Windows 11 24H2, real-time protection ON
- Batch deployed from a non-excluded directory (no Defender exclusions)

## Disclaimer

This project is for educational and authorized security research purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The authors assume no liability for misuse.
