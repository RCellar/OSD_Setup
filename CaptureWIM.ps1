# Add Forms Assembly

Add-Type -AssemblyName System.Windows.Forms


# Script Log Path

$scriptlog = "$PSScriptRoot\logs\capture.log"


# Start Logging

Start-Transcript $scriptlog -Append


# Setting date variable

#$date = Get-Date -Format yyyyMMdd


# Prompt user to select an image file

Write-Host "Please select an image file..."

$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
    InitialDirectory = [Environment]::GetFolderPath('Desktop') 
    Filter = 'Disc Image (*.vhdx)|*.vhdx'
    Title = 'Select a Virtual Hard Disk' 
}

$null = $FileBrowser.ShowDialog()

Write-Host "File selected: " $FileBrowser.FileName


# Validate image file was selected

if ($FileBrowser.FileName -eq "") {

    Write-Host "You did not select an image file. Run the application again when you have a valid image file."
    
    Exit 1      #Force close application if no image file is selected

} else {}


$capture = $FileBrowser.SafeFileName.Substring(0,$FileBrowser.SafeFileName.Length-4)

# Mount Image

Mount-WindowsImage -ImagePath $FileBrowser.FileName -Index 1 -Path "C:\WIM Servicing\WIM2VHD\capture\VHDMount"

# Capture Image

New-WindowsImage -CapturePath "C:\WIM Servicing\WIM2VHD\capture\VHDMount" -Name "Windows 10 Enterprise" -ImagePath "C:\WIM Servicing\WIM2VHD\capture\$($capture).wim" -Description "Windows 10 Enterprise" -Verify -Verbose

# Dismount Image

Dismount-WindowsImage -Path "C:\WIM Servicing\WIM2VHD\capture\VHDMount" -Discard