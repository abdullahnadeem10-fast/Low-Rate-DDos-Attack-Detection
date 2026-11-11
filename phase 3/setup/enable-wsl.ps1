# Run as Administrator. Installs the pinned WSL MSI and enables its Windows
# prerequisites without restarting the PC. Logs/installer files stay out of Git.
$ErrorActionPreference = 'Stop'
$setupData = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../data/setup'))
New-Item -ItemType Directory -Force -Path $setupData | Out-Null
$setupStatusPath = Join-Path $setupData 'wsl_install_status.json'
$setupStatus = [ordered]@{
    date = '2026-11-11'
    version = '3.0.5'
    state = 'starting'
    restart_required = $false
    msi_exit_code = $null
    features = @()
}
function Save-SetupStatus {
    $setupStatus | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $setupStatusPath -Encoding UTF8
}
try {
    $setupIdentity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $setupIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator rights are required; run this script through the normal Windows UAC prompt.'
    }
    $setupInstaller = Join-Path $setupData 'wsl.3.0.5.0.x64.msi'
    $setupExpectedHash = '2313efc5873e3f8552f42e77f950fabd913c0289078fa89d2100f3421a525eaa'
    if ((Get-FileHash -LiteralPath $setupInstaller -Algorithm SHA256).Hash.ToLowerInvariant() -ne $setupExpectedHash) {
        throw 'WSL MSI checksum differs from the official Microsoft release digest.'
    }
    $setupSignature = Get-AuthenticodeSignature -LiteralPath $setupInstaller
    if ($setupSignature.Status -ne 'Valid' -or $setupSignature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw 'WSL MSI Microsoft signature validation failed.'
    }
    $setupStatus.state = 'installing_msi'; Save-SetupStatus
    $setupMsiLog = Join-Path $setupData 'wsl_msi.log'
    $setupMsiArgs = @('/i', ('"' + $setupInstaller + '"'), '/qn', '/norestart', '/L*v', ('"' + $setupMsiLog + '"'))
    $setupMsiProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList $setupMsiArgs -WindowStyle Hidden -Wait -PassThru
    $setupStatus.msi_exit_code = $setupMsiProcess.ExitCode
    if ($setupMsiProcess.ExitCode -notin @(0,3010)) { throw "WSL MSI failed: $($setupMsiProcess.ExitCode)" }
    if ($setupMsiProcess.ExitCode -eq 3010) { $setupStatus.restart_required = $true }
    foreach ($setupFeature in @('VirtualMachinePlatform','Microsoft-Windows-Subsystem-Linux')) {
        $setupStatus.state = 'enabling_windows_features'; Save-SetupStatus
        $setupFeatureOut = Join-Path $setupData ($setupFeature + '.stdout.txt')
        $setupFeatureErr = Join-Path $setupData ($setupFeature + '.stderr.txt')
        $setupDismProcess = Start-Process -FilePath 'dism.exe' -ArgumentList '/Online','/Enable-Feature',"/FeatureName:$setupFeature",'/All','/NoRestart' -WindowStyle Hidden -RedirectStandardOutput $setupFeatureOut -RedirectStandardError $setupFeatureErr -Wait -PassThru
        $setupStatus.features += @{ name = $setupFeature; exit_code = $setupDismProcess.ExitCode }
        if ($setupDismProcess.ExitCode -notin @(0,3010)) { throw "$setupFeature failed: $($setupDismProcess.ExitCode)" }
        if ($setupDismProcess.ExitCode -eq 3010) { $setupStatus.restart_required = $true }
    }
    $setupStatus.state = if ($setupStatus.restart_required) { 'installed_restart_required' } else { 'installed_runtime_check_pending' }
    Save-SetupStatus
} catch {
    $setupStatus.state = 'failed'
    $setupStatus.error = $_.Exception.Message
    Save-SetupStatus
    exit 1
}
exit 0
