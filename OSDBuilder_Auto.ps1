#Requires -Modules WindowsImageTools, OSD, OSDBuilder, OSDSUS, PSWriteHTML 
#Requires -RunAsAdministrator

$ErrorArray = @()
$SuccessArray = @()
$Credential = (Get-Credential BuildAdmin)

Function Write-SuccessArray {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]$Item
    )
    [PSCustomObject]@{
        Timestamp = (Get-Date -f "mm/dd HH:MM:ss zzz")
        Message = $Item
    }
}

$Paths = [PSCustomObject]@{
    OSDBPath = ($Env:SystemDrive + "\" + "Build2")
    OSDBWIM = ($Env:SystemDrive + "\" + "Windows\Temp\OSDB WIM")
    OSDBModule = (Get-Module -Name OSDBuilder -ErrorAction SilentlyContinue).Path
    WIMServicing = ($Env:SystemDrive + "\" + "Output")
    ISOPath = ($Env:SystemDrive + "\" + "Intake")
}

$ExtrasContent = "$($Paths.ISOPath)\PSWindowsUpdate"
$CMTrace = "$($Paths.IsoPath)\CMTrace.exe"

$CheckPaths = @()
#$CheckPaths += $WIM2VHD = "$($Paths.WIMServicing)\WIM2VHD"
$CheckPaths += $Paths.WimServicing
$CheckPaths += $vhdPath = "$($Paths.WimServicing)\Virtual Disks"
$CheckPaths += $vmPath = "$($Paths.WimServicing)\Virtual Machines"
$CheckPaths += $CapturePath = "$($Paths.WimServicing)\Capture"
$CheckPaths += $vhdMount = "$($Paths.WimServicing)\VHDMount"

$CheckPaths | ForEach-Object {
    $PathResult = Test-Path $_
    if ($PathResult -eq $false) {
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
    }
}

Function Get-EdgeEnterpriseMSI {
  <#
  .SYNOPSIS
    Get-EdgeEnterpriseMSI
  .DESCRIPTION
    Imports all device configurations in a folder to a specified tenant
  .PARAMETER Channel
    Channel to download, Valid Options are: Dev, Beta, Stable, EdgeUpdate, Policy.
  .PARAMETER Platform
    Platform to download, Valid Options are: Windows or MacOS, if using channel "Policy" this should be set to "any"
    Defaults to Windows if not set.
  .PARAMETER Architecture
    Architecture to download, Valid Options are: x86, x64, arm64, if using channel "Policy" this should be set to "any"
    Defaults to x64 if not set.
  .PARAMETER Version
    If set the script will try and download a specific version. If not set it will download the latest.
  .PARAMETER Folder
    Specifies the Download folder
  .PARAMETER Force
    Overwrites the file without asking.
  .NOTES
    Version:        1.3
    Author:         Mattias Benninge
    Modified by:    DM
    Creation Date:  2020-07-01
    Update Date: 2022-05-14
    Version history:
    1.0 -   Initial script development
    1.1 -   Fixes and improvements by @KarlGrindon
            - Script now handles multiple files for e.g. MacOS Edge files
            - Better error handling and formating
            - URI Validation
    1.2 -   Better compability on servers (force TLS and remove dependency to IE)
    1.3 -   Added version check function
    
    https://docs.microsoft.com/en-us/mem/configmgr/apps/deploy-use/deploy-edge
  .EXAMPLE
    
    Download the latest version for the Beta channel and overwrite any existing file
    .\Get-EdgeEnterpriseMSI.ps1 -Channel Beta -Folder D:\SourceCode\PowerShell\Div -Force
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $True, HelpMessage = 'Channel to download, Valid Options are: Dev, Beta, Stable, EdgeUpdate, Policy')]
    [ValidateSet('Dev', 'Beta', 'Stable', 'EdgeUpdate', 'Policy')]
    [string]$Channel,
    
    [Parameter(Mandatory = $false, HelpMessage = 'Folder where the file will be downloaded')]
    [ValidateNotNullOrEmpty()]
    [string]$Folder,
  
    [Parameter(Mandatory = $false, HelpMessage = 'Platform to download, Valid Options are: Windows or MacOS')]
    [ValidateSet('Windows', 'MacOS', 'any')]
    [string]$Platform = "Windows",
  
    [Parameter(Mandatory = $false, HelpMessage = "Architecture to download, Valid Options are: x86, x64, arm64, any")]
    [ValidateSet('x86', 'x64', 'arm64', 'any')]
    [string]$Architecture = "x64",
  
    [parameter(Mandatory = $false, HelpMessage = "Specifies which version to download")]
    [ValidateNotNullOrEmpty()]
    [string]$ProductVersion,
  
    [switch]$VersionCheck,
  
    [parameter(Mandatory = $false, HelpMessage = "Overwrites the file without asking")]
    [Switch]$Force
  )
  
  $ErrorActionPreference = "Stop"
  
  $edgeEnterpriseMSIUri = 'https://edgeupdates.microsoft.com/api/products?view=enterprise'
  
  # Validating parameters to reduce user errors
  if ($Channel -eq "Policy" -and ($Architecture -ne "Any" -or $Platform -ne "Any")) {
    Write-Warning ("Channel 'Policy' requested, but either 'Architecture' and/or 'Platform' is not set to 'Any'. 
                    Setting Architecture and Platform to 'Any'")
  
    $Architecture = "Any"
    $Platform = "Any"
  } 
  elseif ($Channel -ne "Policy" -and ($Architecture -eq "Any" -or $Platform -eq "Any")) {
    throw "If Channel isn't set to policy, architecture and/or platform can't be set to 'Any'"
  }
  elseif ($Channel -eq "EdgeUpdate" -and ($Architecture -ne "x86" -or $Platform -eq "Windows")) {
    Write-Warning ("Channel 'EdgeUpdate' requested, but either 'Architecture' is not set to x86 and/or 'Platform' 
                    is not set to 'Windows'. Setting Architecture to 'x86' and Platform to 'Windows'")
  
    $Architecture = "x86"
    $Platform = "Windows"
  }
  
  Write-Host "Enabling connection over TLS for better compability on servers" -ForegroundColor Green
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
  
  # Test if HTTP status code 200 is returned from URI
  try {
    Invoke-WebRequest $edgeEnterpriseMSIUri -UseBasicParsing | Where-Object StatusCode -match 200 | Out-Null
  }
  catch {
    throw "Unable to get HTTP status code 200 from $edgeEnterpriseMSIUri. Does the URL still exist?"
  }
  
  Write-Host "Getting available files from $edgeEnterpriseMSIUri" -ForegroundColor Green
  
  # Try to get JSON data from Microsoft
  try {
    $response = Invoke-WebRequest -Uri $edgeEnterpriseMSIUri -Method Get -ContentType "application/json" -UseBasicParsing -ErrorVariable InvokeWebRequestError
    $jsonObj = ConvertFrom-Json $([String]::new($response.Content))
    Write-Host "Succefully retrived data" -ForegroundColor Green
  }
  catch {
    throw "Could not get MSI data: $InvokeWebRequestError"
  }
  
  # Alternative is to use Invoke-RestMethod to get a Json object directly
  # $jsonObj = Invoke-RestMethod -Uri "https://edgeupdates.microsoft.com/api/products?view=enterprise" -UseBasicParsing
  
  $selectedIndex = [array]::indexof($jsonObj.Product, "$Channel")
  
  if (-not $ProductVersion) {
    try {
      Write-host "No version specified, getting the latest for $Channel" -ForegroundColor Green
      $script:selectedVersion = (([Version[]](($jsonObj[$selectedIndex].Releases |
              Where-Object { $_.Architecture -eq $Architecture -and $_.Platform -eq $Platform }).ProductVersion) |
          Sort-Object -Descending)[0]).ToString(4)
    
      Write-Host "Latest Version for channel $Channel is $selectedVersion`n" -ForegroundColor Green
      if ($VersionCheck) {
        #$selectedVersion = $script:selectedVersion
        return $SelectedVersion
        break
      }
      $selectedObject = $jsonObj[$selectedIndex].Releases |
      Where-Object { $_.Architecture -eq $Architecture -and $_.Platform -eq $Platform -and $_.ProductVersion -eq $selectedVersion }
    }
    catch {
      throw "Unable to get object from Microsoft. Check your parameters and refer to script help."
    }
  }
  else {
    Write-Host "Matching $ProductVersion on channel $Channel" -ForegroundColor Green
    $selectedObject = ($jsonObj[$selectedIndex].Releases |
      Where-Object { $_.Architecture -eq $Architecture -and $_.Platform -eq $Platform -and $_.ProductVersion -eq $ProductVersion })
  
    if (-not $selectedObject) {
      throw "No version matching $ProductVersion found in $channel channel for $Architecture architecture."
    }
    else {
      Write-Host "Found matching version`n" -ForegroundColor Green
    }
  }
  
  if (Test-Path $Folder) {
    foreach ($artifacts in $selectedObject.Artifacts) {
      # Not showing the progress bar in Invoke-WebRequest is quite a bit faster than default
      $ProgressPreference = 'SilentlyContinue'
      
      Write-host "Starting download of: $($artifacts.Location)" -ForegroundColor Green
      # Work out file name
      $fileName = Split-Path $artifacts.Location -Leaf
  
      if (Test-Path "$Folder\$fileName" -ErrorAction SilentlyContinue) {
        if ($Force) {
          Write-Host "Force specified. Will attempt to download and overwrite existing file." -ForegroundColor Green
          try {
            Invoke-WebRequest -Uri $artifacts.Location -OutFile "$Folder\$fileName" -UseBasicParsing
          }
          catch {
            throw "Attempted to download file, but failed: $error[0]"
          }    
        }
        else {
          # CR-someday: There should be an evaluation of the file version, if possible. Currently the function only
          # checks if a file of the same name exists, not if the versions differ
          Write-Host "$Folder\$fileName already exists!" -ForegroundColor Yellow
  
          do {
            $overWrite = Read-Host -Prompt "Press Y to overwrite or N to quit."
          }
          # -notmatch is case insensitive
          while ($overWrite -notmatch '^y$|^n$')
          
          if ($overWrite -match '^y$') {
            Write-Host "Starting Download" -ForegroundColor Green
            try {
              Invoke-WebRequest -Uri $artifacts.Location -OutFile "$Folder\$fileName" -UseBasicParsing
            }
            catch {
              throw "Attempted to download file, but failed: $error[0]"
            }
          }
          else {
            Write-Host "File already exists and user chose not to overwrite, exiting script." -ForegroundColor Red
            exit
          }
        }
      }
      else {
        Write-Host "Starting Download" -ForegroundColor Green
        try {
          Invoke-WebRequest -Uri $artifacts.Location -OutFile "$Folder\$fileName" -UseBasicParsing
        }
        catch {
          throw "Attempted to download file, but failed: $error[0]"
        }
      }
      if (((Get-FileHash -Algorithm $artifacts.HashAlgorithm -Path "$Folder\$fileName").Hash) -eq $artifacts.Hash) {
        Write-Host "Calculated checksum matches known checksum`n" -ForegroundColor Green
      }
      else {
        Write-Warning "Checksum mismatch!"
        Write-Warning "Expected Hash: $($artifacts.Hash)"
        Write-Warning "Downloaded file Hash: $((Get-FileHash -Algorithm $($artifacts.HashAlgorithm) -Path "$Folder\$fileName").Hash)`n"
      }
    }
  }
  else {
    throw "Folder $Folder does not exist"
  }
  Write-Host "-- Script Completed: File Downloaded -- " -ForegroundColor Green
  }

if (Test-Path $Paths.OSDBPath) {
    try {
        Write-Host "Removing existing OSDBuilder folder structure..." -ForegroundColor DarkMagenta 
        Remove-Item -Path $Paths.OSDBPath -Force -Recurse -ErrorAction Stop -Exclude ($Paths.OSDBPath + "\" + "Updates") | Out-Null
        $SuccessArray += (Write-Output "$($Paths.OSDBPATH) destroyed" | Write-SuccessArray)
    }
    catch {
        $ErrorArray += (Write-Output $_.Exception)
    }
}

### Update OSDSUS
try {
    Update-OSDSUS
    $VersionGet = (Get-Module -Name OSDBuilder).Version
    $SuccessArray += (Write-Output "OSDBuilder module version $VersionGet installed" | Write-SuccessArray)
}
catch {
    $ErrorArray += (Write-Output $_.Exception)
}

### Import OSDBuilder
Write-Host "Importing OSDBuilder Module..." -ForegroundColor Green 
try {
    Import-Module -Name OSDBuilder -ErrorAction Stop | Out-Null
    $SuccessArray += (Write-Output "OSDBuilder module version $VersionGet imported" | Write-SuccessArray)
}
catch {
    $ErrorArray += (Write-Output $_.Exception)
}

### Initialize OSDBuilder
Write-Host "Initializing OSDBuilder (Create Paths)..." -ForegroundColor Green 
try {
    #Initialize-OSDBuilder -SetHome $Paths.OSDBPath-ErrorAction Stop | Out-Null
    Get-OSDBuilder -SetPath $($Paths.OSDBPath) -CreatePaths -ErrorAction Stop | Out-Null
    $SuccessArray += (Write-Output "OSDBuilder initialized" | Write-SuccessArray)
}
catch {
    $ErrorArray += (Write-Output $_.Exception)
}

### Input ISO
try {
    $ISORelPath = $Paths.ISOPath + "\" + "*.ISO"
    $ISO = Get-Item $ISORelPath -ErrorAction Stop
    $ISOFullPath = ($($Paths.ISOPath) + "\" + $($ISO.Name))
    if ($ISO) {
        Mount-DiskImage -ImagePath $ISOFullPath | Out-Null
        $SuccessArray += (Write-Output "Mounted $($ISO.Name)" | Write-SuccessArray)
    }
}
catch {
    $ErrorArray += (Write-Output $_.Exception)
}

### Import OSMedia
try {
    Write-Host "Import OS Media: $($ISO.Name) and Update/Install .Net 3.5..." -ForegroundColor Green 
    Import-OSMedia -EditionId Enterprise -SkipGridView -Update -BuildNetFx -ErrorAction Stop | Out-Null
    $SuccessArray += (Write-Output "Imported OSMedia into $($ISO.Name)" | Write-SuccessArray)
}
catch {
    $ErrorArray += (Write-Output $_.Exception)
}

### Dismount Image
try {
    Write-Host "Dismounting OS Media: $($ISO.Name)..." -ForegroundColor DarkMagenta 
    Dismount-DiskImage -ImagePath $ISOFullPath -ErrorAction Stop | Out-Null
    $SuccessArray += (Write-Output "Dismounted $($ISO.Name)" | Write-SuccessArray)
}
catch {
    $ErrorArray += (Write-Output $_.Exception)
}

### Extra Directories
try {
    Write-Host "Creating ExtraFiles Directories..." -ForegroundColor Green 
    New-Item -Path ($Paths.OSDBPath + "\Content\ExtraFiles\CMTrace\Windows\System32") -ItemType Directory -Force | Out-Null
    $SuccessArray += (Write-Output "Created Path..." | Write-SuccessArray)
    New-Item -Path ($Paths.OSDBPath + "\Content\ExtraFiles\scripts\Windows\Installer") -ItemType Directory -Force | Out-Null
    $SuccessArray += (Write-Output "Created Path..." | Write-SuccessArray)
}
catch {
    $ErrorArray += (Write-Output $_.Exception)
}

try { 
    Write-Host "Populating ExtraFiles Directories and Unattend.xml..." -ForegroundColor Green
    Copy-Item -Path $CMTrace -Destination ($Paths.OSDBPath + "\Content\ExtraFiles\CMTrace\Windows\System32") -Force -ErrorAction Stop | Out-Null
    $SuccessArray += (Write-Output "Copied file to path..." | Write-SuccessArray)
    Copy-Item -Path $ExtrasContent -Destination ($Paths.OSDBPath + "\Content\ExtraFiles\scripts\Windows\Installer") -Recurse -Force -ErrorAction Stop | Out-Null
    $SuccessArray += (Write-Output "Copied file to path..." | Write-SuccessArray)
    Copy-Item -Path ($Paths.ISOPath + "\" + "Unattend.xml") -Destination ($Paths.OSDBPath + "\Content\Unattend") -Force -ErrorAction Stop | Out-Null
}
catch {
    $ErrorArray += (Write-Output $_.Exception)
}

### Update OS Media
try {
    $StartDTM = (Get-Date)
    $OSMediaSource = Get-ChildItem -Path ($Paths.OSDBPath + "\OSImport") | Sort-Object LastAccessTime -Descending | Select-Object -First 1
    Write-Host "Updating OS Media : $($OSMediaSource.Name), starting at $StartDTM..." -ForegroundColor Green 
    Update-OSMedia -Name $($OSMediaSource.Name) -Download -Execute -SkipComponentCleanup -ErrorAction Stop | Out-Null
    $EndDTM = (Get-Date)
    Write-Host "Updated OS Media : $($OSMediaSource.Name), ending at $EndDTM.  Elapsed Time: $(($EndDTM-$StartDTM).TotalMinutes) Minutes" -ForegroundColor Green 
    $SuccessArray += (Write-Output "Update-OSMedia completed succesfully, Elapsed Time: $(($EndDTM-$StartDTM).TotalMinutes) Minutes" | Write-SuccessArray)
}  
catch {
    $ErrorArray += (Write-Output $_.Exception)
}

### Task for OS Media
$Date = Get-Date -Format MMddyy  
$TaskName = "Build-$Date"

try {
    $Pull = (Get-OSMedia)[-1]
    Write-Host "Creating JSON Taskfile for $Pull..." -ForegroundColor Green 
    New-OSBuildTask -TaskName $TaskName <#-EnableNetFX3#> <#-ContentExtraFiles#> <#-ContentUnattend#> -OSMedia $Pull -ErrorAction Stop | Out-Null
    $SuccessArray += (Write-Output "Created JSON Taskfile for $Pull" | Write-SuccessArray)
}  
catch {
    $ErrorArray += (Write-Output $_.Exception)
}

### Inject ExtraFiles Data
$Pattern = @"
    "EnableNetFX3":  "False",
"@

$Inject = @"
    "EnableNetFX3":  "True",
"@

$Pattern1 = @"
    "ExtraFiles":  null,
"@

$Inject1 = @"
    "ExtraFiles": [
      "ExtraFiles\\CMTrace",
      "ExtraFiles\\scripts"
    ],
"@

$Pattern2 = @"
    "UnattendXML":  "",
"@
$Inject2 = @"
    "UnattendXML":  "Unattend\\Unattend.xml",
"@

$JSONPath = $Paths.OSDBPath + "\Tasks\OSBuild " + $TaskName + ".json"
$TaskJSON = Get-Content $JSONPath
$TaskJSON -Replace $Pattern,$Inject | Set-Content -Path $JSONPath
$TaskJSON = Get-Content $JSONPath
$TaskJSON -Replace $Pattern1,$Inject1 | Set-Content -Path $JSONPath
$TaskJSON = Get-Content $JSONPath
$TaskJSON -Replace $Pattern2,$Inject2 | Set-Content -Path $JSONPath
Write-Host "Injected ExtraFiles and Unattend pattern into JSON Taskfile." -ForegroundColor Green 
### Create New OS Build

try {
    $StartDTM = (Get-Date)  
    Write-Host "Creating OS Build : $TaskName, starting at $StartDTM..." -ForegroundColor Green 
    New-OSBuild -ByTaskName $TaskName -Download -Execute | Out-Null
    $EndDTM = (Get-Date)
    Write-Host "Created OS Build : $TaskName, ending at $EndDTM.  Elapsed Time: $(($EndDTM-$StartDTM).TotalMinutes) Minutes" -ForegroundColor Green  
    $SuccessArray += (Write-Output "OS-Media Creation for Task $TaskName completed succesfully, Elapsed time: $(($EndDTM-$StartDTM).TotalMinutes) Minutes" | Write-SuccessArray)
}  
catch {
    $ErrorArray += (Write-Output $_.Exception)
    $ErrorCounter++
}

$LatestBuild = ((Get-ChildItem ($Paths.OSDBPath + "\OSBuilds") | Sort-Object -Descending)[0])
[string]$LatestBuildFN = ((Get-ChildItem ($Paths.OSDBPath + "\OSBuilds") | Sort-Object -Descending)[0])
$WIMSource = $LatestBuild.FullName + "\OS\sources" #\install.wim"
$OSDBCheck = Test-Path $Paths.OSDBWIM
if (!($OSDBCheck)) {
    New-Item -ItemType Directory -Path $Paths.OSDBWIM
}
Write-Host "Copying $WIMSource to $($Paths.OSDBWIM) ..." -ForegroundColor Green
#Copy-Item -Path $WIMSource -Destination $WIMDest -Recurse -ErrorAction Stop | Out-Null
robocopy.exe $WIMSource $Paths.OSDBWIM /zb *install.wim | Out-Null
if (Get-Item -Path ($Paths.OSDBWIM + "\" + $LatestBuildFN + ".wim") -ErrorAction SilentlyContinue) {
    Remove-Item -Path ($Paths.OSDBWIM + "\" + $LatestBuildFN + ".wim")
}
Rename-Item -Path ($Paths.OSDBWIM + "\install.wim") -NewName ($LatestBuildFN + ".wim")
### Clear Stale Mounts
$Mounts = Get-WindowsImage -Mounted -ErrorAction SilentlyContinue

if ($Mounts) {
    try {
        Write-Host "Clearing stuck/unused DISM mounts..." -ForegroundColor DarkMagenta
        Get-WindowsImage -Mounted | Dismount-WindowsImage -Discard #| Out-Null
        $SuccessArray += (Write-Output "Stale mounts cleared" | Write-SuccessArray)
    }
    catch {
        $ErrorArray += ($_.Exception)        
        Clear-WindowsCorruptMountPoint
    }
}

#### Convert to VHD, Create Hyper-V VM with new VHD ####
#$WIM2VHD = $Paths.WIMServicing + "\WIM2VHD"
#Import-Module ($WIM2VHD + "\module\WindowsImageTools\1.9.30\WindowsImageTools.psd1") 

$GUID = (New-GUID).Guid
$date = Get-Date -Format yyyyMMdd
$vhd = $GUID
$WIM = (Get-ChildItem -Path ($Paths.OSDBWim) -Filter *.wim | Sort -Descending | Select -First 1).VersionInfo.FileName

Convert-Wim2VHD -Path "$vhdPath\$vhd.vhdx" -SourcePath $WIM -Index 1 -Size 40GB -DiskLayout UEFI -Dynamic -ErrorAction Stop
Remove-Item $WIM #Clean item from Temp after conversion
New-VM -Name $vhd -MemoryStartupBytes 8GB -VHDPath "$vhdPath\$vhd.vhdx" -Generation 2 -SwitchName 'Default Switch' -Path "$vmPath"
#Add-VMDvdDrive -VMName $vhd -Path "$WIM2VHD\images\WinPE_amd64.iso"
Set-VM -Name $vhd -CheckpointType Disabled

Start-VM -Name $vhd
Start-Process -FilePath "C:\Windows\System32\vmconnect.exe" -ArgumentList "localhost $vhd"
Write-Host -ForegroundColor Green "Waiting for PowerShell Direct session..."

Function Get-BuildSession {
    Get-PSSession -Name "Build" -ErrorAction SilentlyContinue | ? {$_.State -eq "Opened"}
}

$FileSB = {
    Test-Path C:\Windows\Temp\TokenFile.txt
}

Get-BuildSession | Remove-PSSession

do {
    Start-Sleep -Seconds 15
    $Result = $Null
    $VM = Get-VM -Name $vhd
    New-PSSession -VMName $VM.Name -Name "Build" -Credential $Credential -ErrorAction SilentlyContinue | Out-Null
    if (Get-PSSession -Name "Build" -ErrorAction SilentlyContinue | ? {$_.State -eq "Opened"} ) {
        $Result = Invoke-Command -Session (Get-PSSession -Name "Build" -ErrorAction SilentlyContinue | ? {$_.State -eq "Opened"} ) -ScriptBlock $FileSB
        if ($Result -eq $false) {
            Get-PSSession -Name "Build" | Remove-PSSession
        }
    }

} until (
    ( [bool](Get-PSSession -Name "Build" -ErrorAction SilentlyContinue | ? {$_.State -eq "Opened"} ) -and ($Result -eq $true) ) -eq $true
)

$SB = {
    $UpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
    $SearchResult = New-Object -ComObject 'Microsoft.Update.UpdateColl'
    $UpdateSession.ClientApplicationID = 'Build Windows Update Installer'
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    $SearchResult = $UpdateSearcher.Search("IsInstalled=1 and Type='Software' and IsHidden=0")
    $UpdateResults = $SearchResult.Updates | Select Title, SupportUrl
    $Version = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
    $EdgeVersion = (Get-Item -Path ${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe).VersionInfo.ProductVersion

    $OutputObj = [PSCustomObject]@{
        #ReleaseID = $Version.ReleaseId
        Build = $Version.CurrentBuildNumber + "." + $Version.UBR
        MSEdge = $EdgeVersion
        #UBR = $Version.UBR
        Updates = $UpdateResults #| ConvertTo-Json
    }
    $OutputObj
}

#Copy-Item -ToSession (Get-PSSession -Name "Build" | ? {$_.State -eq "Opened"} ) -Path C:\Windows\Temp\Finalize.ps1 -Destination C:\Windows\Temp\Finalize.ps1
$Report = Invoke-Command -ScriptBlock $SB -Session (Get-PSSession -Name "Build"| ? {$_.State -eq "Opened"} ) #| Select Title, SupportURL
Import-Module PSWriteHTML
$BuildVer = $Report.Build
$Updates = $Report.Updates
$MSEdge = $Report.MSEdge
$NewestMSEdge = Get-EdgeEnterpriseMSI -VersionCheck -Channel Stable

#### Build Report ####
New-HTML {
    New-HTMLList {
        New-HTMLListItem -Text "Build Version: $BuildVer" -BackGroundColor SkyBlue -Color White
        New-HTMLListItem -Text "MS Edge Version: $MSEdge - Newest Reported Version: $NewestMSEdge"
    }
    New-HTMLSection -HeaderText 'Updates' -BackgroundColor SkyBlue {
        New-HTMLTable -Title Updates -DataTable $Updates
    }
} -ShowHTML -TitleText "Build Report"

Start-Sleep -s 10
Get-BuildSession | Remove-PSSession

Write-Host -ForegroundColor Green "Waiting for VM to be turned off..."
do {
    Start-Sleep -s 60
} 
until ((Get-VM -Name $vhd).State -eq "Off")

#### ISO Capture ####
Write-Host -ForegroundColor Green "Beginning Capture..."

# Script Log Path
$scriptlog = "$PSScriptRoot\capture.log"

# Start Logging
Start-Transcript $scriptlog -Append

# Define Image File for Capture
$Image = $vhdPath + "\" + $vhd + ".vhdx"

# Mount Image
Write-Host -ForegroundColor Green "Mount Image for Capture..."
Mount-WindowsImage -ImagePath $Image -Index 1 -Path $VHDMount

# Capture Image
Write-Host -ForegroundColor Green "Capture new image..."
New-WindowsImage -CapturePath $VHDMount -Name "Windows 10 Enterprise" -ImagePath "$($CapturePath)\$($vhd).wim" -Description "Windows 10 Enterprise" -Verify -Verbose
Start-Sleep -s 5

# Dismount Image
Write-Host -ForegroundColor Green "Dismount image."
Dismount-WindowsImage -Path $VHDMount -Discard
Stop-Transcript
Write-Host -ForegroundColor Green "Capture completed."