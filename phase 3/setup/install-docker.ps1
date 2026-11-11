# Run after the Windows restart required by enable-wsl.ps1.
# Per-user installation; no automatic restart and no final research tests.
$ErrorActionPreference = 'Stop'
$dockerSetupData = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../data/setup'))
$dockerSetupStatusPath = Join-Path $dockerSetupData 'docker_install_status.json'
$dockerSetupStatus = [ordered]@{
    date = '2026-11-11'
    version = '4.98.0'
    state = 'starting'
    installer_exit_code = $null
    engine_verified = $false
    automatic_restart = $false
}
function Save-DockerSetupStatus {
    $dockerSetupStatus | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $dockerSetupStatusPath -Encoding UTF8
}
try {
    $dockerSetupInstaller = Join-Path $dockerSetupData 'DockerDesktop-4.98.0-Installer.exe'
    if ((Get-FileHash -LiteralPath $dockerSetupInstaller -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'cd6273d9eaa4f07fa7593fc6813d37e1004381cebc3f26047a2554fa5db24388') {
        throw 'Docker installer checksum differs from the official versioned digest.'
    }
    $dockerSetupSignature = Get-AuthenticodeSignature -LiteralPath $dockerSetupInstaller
    if ($dockerSetupSignature.Status -ne 'Valid' -or $dockerSetupSignature.SignerCertificate.Subject -notmatch 'O=Docker Inc') {
        throw 'Docker installer signature validation failed.'
    }
    $dockerSetupStatus.state = 'installing'; Save-DockerSetupStatus
    $dockerSetupProcess = Start-Process -FilePath $dockerSetupInstaller -ArgumentList 'install','--user','--quiet','--accept-license','--backend=wsl-2' -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dockerSetupData 'docker_retry.stdout.txt') -RedirectStandardError (Join-Path $dockerSetupData 'docker_retry.stderr.txt') -Wait -PassThru
    $dockerSetupStatus.installer_exit_code = $dockerSetupProcess.ExitCode
    if ($dockerSetupProcess.ExitCode -notin @(0,3010)) {
        throw "Docker installation failed ($($dockerSetupProcess.ExitCode)); inspect the actual Windows LocalAppData\Docker\install-log.txt. Ensure Windows has restarted after enabling its WSL features."
    }
    $dockerSetupStatus.state = 'installed_engine_check_pending'
    $dockerSetupStatus.restart_required = ($dockerSetupProcess.ExitCode -eq 3010)
    Save-DockerSetupStatus
    Write-Output 'Docker package installation succeeded. Start Docker Desktop and verify its Linux engine before collecting traffic.'
} catch {
    $dockerSetupStatus.state = 'failed'
    $dockerSetupStatus.error = $_.Exception.Message
    Save-DockerSetupStatus
    throw
}
