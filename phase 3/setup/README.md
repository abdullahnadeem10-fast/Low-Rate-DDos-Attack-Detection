# Windows lab prerequisites

On 11 November 2026 the user authorized downloading/installing WSL and Docker Desktop on this PC. Installer binaries and private installation logs belong under `../data/setup/`, which is ignored by Git. Installation state is separate from research/test completion.

| Component | Official pinned source | SHA-256 |
| --- | --- | --- |
| WSL 3.0.5 x64 | `https://github.com/microsoft/WSL/releases/download/3.0.5/wsl.3.0.5.0.x64.msi` | `2313efc5873e3f8552f42e77f950fabd913c0289078fa89d2100f3421a525eaa` |
| Docker Desktop 4.98.0 build 245422 x64 | `https://desktop.docker.com/win/main/amd64/245422/Docker%20Desktop%20Installer.exe` | `cd6273d9eaa4f07fa7593fc6813d37e1004381cebc3f26047a2554fa5db24388` |

Hashes were obtained from the [Microsoft WSL release API](https://api.github.com/repos/microsoft/WSL/releases/tags/3.0.5) and [Docker's versioned checksum file](https://desktop.docker.com/win/main/amd64/245422/checksums.txt). Verify the expected Microsoft/Docker Authenticode signature too before executing an installer. These pins record this installation; do not assume they remain the latest versions.

`enable-wsl.ps1` installs the verified MSI and enables VirtualMachinePlatform and Microsoft-Windows-Subsystem-Linux through ordinary administrator privileges. It uses `/norestart` and records structured status. Launch through Windows UAC, not an elevation workaround. It never restarts the PC or modifies BIOS settings. A pending restart means WSL/Docker are not yet verified operational.

Docker's verified installer is run in per-user mode with `install --user --quiet --accept-license --backend=wsl-2 --no-windows-containers`. See the [official Windows install instructions](https://docs.docker.com/desktop/setup/install/windows-install/) and [Microsoft WSL instructions](https://learn.microsoft.com/en-us/windows/wsl/install). Docker's WSL backend supplies its own Linux environment; a general-purpose Ubuntu distribution can be added later if needed.

After any required restart, continue with `wsl --version`, `wsl --status`, then start Docker Desktop and verify `docker version` and `docker compose version`. Resolve first-run UI or firmware virtualization requirements if present. Do not claim the container lab is ready from a successful installer exit alone. Create and validate the isolated, non-published lab network with benign traffic before collecting sessions. All slow-attack lab traffic remains final-only until model freeze.
