# Windows lab prerequisites

On 11 November 2026 the user authorized downloading/installing WSL and Docker Desktop on this PC. Installer binaries and private installation logs belong under `../data/setup/`, which is ignored by Git. Installation state is separate from research/test completion.

| Component | Official pinned source | SHA-256 |
| --- | --- | --- |
| WSL 3.0.5 x64 | `https://github.com/microsoft/WSL/releases/download/3.0.5/wsl.3.0.5.0.x64.msi` | `2313efc5873e3f8552f42e77f950fabd913c0289078fa89d2100f3421a525eaa` |
| Docker Desktop 4.98.0 build 245422 x64 | `https://desktop.docker.com/win/main/amd64/245422/Docker%20Desktop%20Installer.exe` | `cd6273d9eaa4f07fa7593fc6813d37e1004381cebc3f26047a2554fa5db24388` |

Hashes were obtained from the [Microsoft WSL release API](https://api.github.com/repos/microsoft/WSL/releases/tags/3.0.5) and [Docker's versioned checksum file](https://desktop.docker.com/win/main/amd64/245422/checksums.txt). Verify the expected Microsoft/Docker Authenticode signature too before executing an installer. These pins record this installation; do not assume they remain the latest versions.

`enable-wsl.ps1` installs the verified MSI and enables VirtualMachinePlatform and Microsoft-Windows-Subsystem-Linux through ordinary administrator privileges. It uses `/norestart` and records structured status. Launch through Windows UAC, not an elevation workaround. It never restarts the PC or modifies BIOS settings. A pending restart means WSL/Docker are not yet verified operational.

Docker's verified installer is run in per-user mode with `install --user --quiet --accept-license --backend=wsl-2 --no-windows-containers`. See the [official Windows install instructions](https://docs.docker.com/desktop/setup/install/windows-install/) and [Microsoft WSL instructions](https://learn.microsoft.com/en-us/windows/wsl/install). Docker's WSL backend supplies its own Linux environment; a general-purpose Ubuntu distribution can be added later if needed.

Current checkpoint: the user completed the required restart. WSL 3.0.5.0 and Docker Desktop 4.98.0 are installed; Docker client/server 29.9.2, the Linux WSL2 engine and Compose 5.6.1 are verified. The earlier feature exit codes 3010 are historical installation outcomes, not a current pending restart. Docker's successful retry returned 0. No further restart is currently requested. See [runtime evidence](../results/development/docker_runtime_verification.json).

For a fresh installation/recovery where the package is absent, after any required Windows-feature restart, from `phase 3/` run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\setup\install-docker.ps1'
wsl --version
wsl --status
```

`install-docker.ps1` rechecks the pinned hash/signature, performs the authorized per-user WSL-backed installation and records status under `data/setup/`. It does not claim engine readiness or start traffic. Under a coding harness, use its authorized unsandboxed execution route for installation; the harness's sandbox can redirect LocalAppData. In normal Windows PowerShell, per-user logs are under `%LOCALAPPDATA%\Docker\install-log.txt`.

On the installed PC, Docker Desktop is already running. Later it can be started with `docker desktop start --timeout 120`; verify `docker version` (both client and server) and `docker compose version`. Under this harness, run WSL/Docker IPC commands through the authorized unsandboxed route; sandboxed WSL status may report access denied. A pre-install process may not have the refreshed PATH; resolve the CLI from the real Windows `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe`.

The initial controlled-profile scope/capture audits and selected v3 benign collection are now complete; see `../results/development/benign_batch_v3.json`. Broader benign conditions, public-source compatibility and full study/model integration remain open. All slow-attack lab traffic remains final-only until model freeze.
