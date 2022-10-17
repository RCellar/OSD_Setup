# Validate Hyper-V Status

$hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online

# Check if Hyper-V is enabled

if($hyperv.State -eq "Enabled") {

    Write-Host "Hyper-V is enabled."

} else {

    Write-Error "Hyper-V is disabled. Please install Hyper-V to continue running this script."

    Exit 1
}

# Add Forms Assembly

Add-Type -AssemblyName System.Windows.Forms

# Script Log Path

$scriptlog = "$PSScriptRoot\logs\WIM2VHD.log"

# Start Logging

Start-Transcript $scriptlog -Append


# Prompt user to select an image file

Write-Host "Please select an image file..."

$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
    InitialDirectory = [Environment]::GetFolderPath('Desktop') 
    Filter = 'Disc Image (*.wim)|*.wim'
    Title = 'Select a Microsoft MVLS ISO' 
}

$null = $FileBrowser.ShowDialog()

Write-Host "File selected: " $FileBrowser.FileName


# Validate image file was selected

if ($FileBrowser.FileName -eq "") {

    Write-Host "You did not select an image file. Run the application again when you have a valid image file."
    
    Exit 1      #Force close application if no image file is selected

} else {}


# Import WindowsImageTools Module


Import-Module ".\module\WindowsImageTools\1.9.30\WindowsImageTools.psd1" -ErrorAction SilentlyContinue


if (Get-Module -Name WindowsImageTools) {

    $date = Get-Date -Format yyyyMMdd
    #$vhd = "OSDB-$date"
    $vhd = $FileBrowser.SafeFileName.Substring(0,$FileBrowser.SafeFileName.Length-4)
    $vhdPath = "$PSScriptRoot\virtual disks"
    $vmPath = "$PSScriptRoot\virtual machines"

    Convert-Wim2VHD -Path "$vhdPath\$vhd.vhdx" -SourcePath $FileBrowser.FileName -Index 1 -Size 40GB -DiskLayout UEFI -Dynamic

    New-VM -Name "$vhd" -MemoryStartupBytes 8GB -VHDPath "$vhdPath\$vhd.vhdx" -Generation 2 -SwitchName 'Default Switch' -Path "$vmPath"

        Add-VMDvdDrive -VMName $vhd -Path "$PSScriptRoot\images\WinPE_amd64.iso"

        Set-VM -Name $vhd -CheckpointType Disabled


    Start-VM -Name "$vhd"

} else {

    Write-Error "Error: WindowsImageTools module not installed. Install the module and try again."
    
    Exit 1

}


Stop-Transcript