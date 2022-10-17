# Script Log Path

$scriptlog = "$env:SystemDrive\Windows\Installer\Updates.log"

# Start Logging

Start-Transcript $scriptlog -Append


# Trigger Defender Updates

Update-MpSignature -Verbose

Start-Sleep 30


# Trigger Store Updates

Write-Host "Triggering MS Store updates..."

Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" | Invoke-CimMethod -MethodName UpdateScanMethod

start ms-windows-store:

Start-Sleep 30


# Load PSWindowsUpdate module for additional updates

Copy-Item -Path "$PSScriptRoot\module\PSWindowsUpdate\" -Destination 'C:\Program Files\WindowsPowerShell\Modules' -Recurse -Force


if (Test-Path 'C:\Program Files\WindowsPowerShell\Modules\PSWindowsUpdate') {

    Write-Host "Searching for updates..."

    Get-WindowsUpdate -Title "Update for Microsoft Defender Antivirus antimalware platform*" -AcceptAll -Download -Install

} else {

    Write-Error "Error: Module not imported."

}


Stop-Transcript