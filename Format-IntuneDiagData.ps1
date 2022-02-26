<#

Format-IntuneDiagData.ps1

Format-IntuneDiagData.ps1 (FIDD) is a utility script to extract and organize zip archive created using the 'Collect diagnostics' feature in Microsoft Endpoint Mananger Intune (MEM).

Author:       Mark Stanfill
Email:        markstan@microsoft.com
Date created: 10/27/2021
Last update:  2/26/2022
Version:      2022.2.26
  

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.
#>

[CmdletBinding()]
Param ( 
    # location of extracted data.  Source and destination to current folder if not specified
    [Alias("Folder")]
    $SourcePath = $PWD,           # location of zip file  
    [Alias("zip", "ZipFile")]
    $ArchiveName,                 # name of zip file
    [Alias("Out")]
    $OutFolder  = $PWD,           # location to create output folder
 
    [switch]$LeaveCABs            # retain folder structure for extracted MMDDiagnostics and other cab-based collectors 
)
 

$FIDDversion = "2021.12.1" 
$ErrorActionPreference = "Stop" 
$FIDDlog = Join-Path $PWD "FIDD_debug.txt"
Try{Start-transcript $FIDDlog -ErrorAction Stop}catch{Start-Transcript $FIDDlog}

function Get-NewFileNameIfExists
{
    [CmdletBinding()]
    PARAM
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({-not([string]::IsNullOrEmpty($_)) -or ($_.Trim().Length -le 0)})]
        [string] $FileName
    )
    PROCESS 
    {
        if(Test-Path($FileName))
        {
            $FileNameBackup = $FileName
            
            [int] $duplicateFilenameCounter = 0;
            while(Test-Path($FileName))
            {
                $duplicateFilenameCounter += 1
                $FileName = $FileNameBackup
                            
                if($FileName.LastIndexOf('.') -ne -1) #Files
                {
                    $FileName = $FileName.Insert($FileName.LastIndexOf('.'), (" ({0})" -f $duplicateFilenameCounter))
                }
                else #Directory/File without extension
                {
                    $FileName = "$FileName ({0})" -f $duplicateFilenameCounter
                }
            }
        }
        else
        {
            New-Item -ItemType Directory -Force -Path (Split-Path $FileName) | Out-Null
        }

        return $FileName
    }
}

function Get-RegPath {
    param (
            $RegFilePath 
        )
         

    $regFile = Join-Path $RegFilePath "export.reg"

    # get the first line that start with [HKEY...    

    foreach($line in [System.IO.File]::ReadLines($regFile) ) {
            if ($line -match "^\[HKEY_" ) { 
                $parsedLine = ""
                # remove square brackets
                $parsedLine = $line -replace "[\[\]]", ""
                $parsedLine = $parsedLine -replace "\\", "_"
                $parsedLine = $parsedLine -replace " ", "_"
                $parsedLine += ".txt"
                $parsedLine
                break
                }
        }
    
     
}


function Parse_Outputlog {
    param (
        $outputlogPath
    )

    $ParsedFilename = "unknown_Output.log"

    $fileContents = Get-Content $outputlogPath

    if ($fileContents -match "AzureAdPrt :") {
        $ParsedFilename = "dsregcmd_status.txt"
    }
    elseif ($fileContents -match   "================ Certificate") {
        $ParsedFilename = "certificates_machine.txt"
    }
    # TODO - validate this.  Blank in sample data
    elseif ($fileContents -match   "my `"Personal`"") {
        $ParsedFilename = "certificates_user.txt"
    }

    elseif ($fileContents -match   "Pinging .*with 32 bytes of data:") {
        $ParsedFilename = "ping_test.txt"
    }
    elseif ($fileContents -match   "Current WinHTTP proxy settings:") {
        $ParsedFilename = "proxy_settings.txt"
    }
    elseif ($fileContents -match   "Windows IP Configuration") {
        $ParsedFilename = "ipconfig.txt"
    }

    elseif ($fileContents -match   "AuthzComputerGrpTransport") {
        $ParsedFilename = "Firewall_Global_settings.txt"
    }
    # TODO - verify netsh commands - 
    # failure 
    elseif ($fileContents -match   "The Wired AutoConfig Service \(dot3svc\) is not running.") {
        $ParsedFilename = "netsh_wlan_show_profiles.txt"
    }
    # success
    elseif ($fileContents -match   "Profiles on interface Wi-Fi:" ) {
        $ParsedFilename = "netsh_wlan_show_profiles.txt"
    }
    # firewall  settings
    elseif ($fileContents -match "LocalFirewallRules"){
        $ParsedFilename = "firewall_profiles.txt"
    }                     

    # skip utility output
    elseif ( ($fileContents -match "Battery life report saved ")    -or  `
        ($fileContents -match "Generating report ... ")             -or
        ($fileContents -match "Enabling tracing for 60 seconds...") -or
        ($fileContents -match "MpCmdRun.exe`" -GetFiles")           -or
        ($fileContents -match "Succeeded to CollectLog")            -or 
        ($fileContents -match "Collecting licensing information.")  # license diag        
       
    ) { 
        $ParsedFilename = "metadata_" + $(Get-Random -Maximum 10000000 -Minimum 1000000) + ".txt"
        
        }
    
    else {
        $ParsedFilename = "Unknown_Command_Result_" + $(Get-Random -Maximum 10000000 -Minimum 1000000) + ".txt"
    }


    


    $ParsedFilename
    
}

function New-DiagFolderStructure {
    [CmdletBinding(SupportsShouldProcess)]
    param( 
        $tempfolder
    )
    
    # Cleanup if results left from previous run
    if (test-path $tempfolder ) { $null = Remove-Item $tempfolder -Recurse -Force }
    $null = mkdir $tempfolder -Force

    $null = mkdir $tempfolder\Registry  -Force
    $null = mkdir $tempfolder\EventLogs -Force
    $null = mkdir $tempfolder\z_MetaData  -Force

}

# test to see if script is being ran from already expanded folder structure
function Test-IsExpandedFolderStructure {
    [bool]$isExpandedDiagFolder = $false
    
    $folderStructure  = Get-ChildItem $PWD
    # assume we are in diagfolder expanded if more than 40 numerical folders 
    if ( ($folderStructure.Name -match "^\d+$").count -gt 40){
        $isExpandedDiagFolder = $true
    }

    return $isExpandedDiagFolder
    
}


function Test-AndExpandArchive {
    [string]$folderName = ""

    if  ($null -eq $ArchiveName) {

        if (Test-Path .\DiagLogs*.zip) {
            $ArchiveName = Get-Item ".\DiagLogs*.zip"
    
            if ($ArchiveName.count -gt 1) {
                Write-Error "More than 1 Diaglogs*.zip file found.  Please specify file name with  -ArchiveName command line parameter."   
                Exit
            }
            else {
                Expand-Archive $ArchiveName -Force # overwrite files if they exist
            }
            $folderName = [System.IO.Path]::GetFileNameWithoutExtension($ArchiveName)
        }
        elseif (Test-IsExpandedFolderStructure) {
            Write-Output "Expanded zip structure detected"
            $folderName = $PWD
        }
        else {
            
            Write-Error "Unable to locate zip file.  Please check that the file exists in the current directory or specify the -ArchiveName command line parameter."   
            Exit -1
        }
    }
 
    else {
        Expand-Archive $ArchiveName -Force
        $folderName = [System.IO.Path]::GetFileNameWithoutExtension($ArchiveName)
    }
    # return folder name
    $folderName
}

function Move-EventLogData {
    param (
        $evtx
    )
    # 2 = open saved evtx file mode
    $LogInfo= $session.GetLogInformation($evtx, 2)
    if ( $LogInfo.RecordCount -eq 0) {
        Write-Output "Skipping empty event log $evtx"
        }
    else {
         $logName = (Get-WinEvent -Path $evtx -Oldest -MaxEvents 1).LogName
         $logName = $logName -replace "\/", "-"              
         $destination = (Join-Path "$tempfolder\EventLogs" "$logName"  ) + ".evtx"
         
         Copy-Item $evtx $destination
    }
}

# REGION Main
Write-Output "Starting Format-IntuneDiagData version $FIDDversion."

$tempfolder =  Join-Path $OutFolder "IntuneDeviceData"
$null = New-DiagFolderStructure -tempfolder $tempfolder 
$session  = New-Object -TypeName System.Diagnostics.Eventing.Reader.EventLogSession   # For event log commands

 
$SourcePath = Test-AndExpandArchive


$diagfolders = @()
$diagfolders = Get-ChildItem $SourcePath -Directory
 
# TODO - move logic to functions

foreach ( $diagfolder  in $diagfolders) {
    
    # ### Registry keys
    $fullDiagPath = $diagfolder.FullName

    if (Test-Path "$fullDiagPath\export.reg") {
        $ParsedFileName = Get-RegPath -RegFilePath $fullDiagPath
        $destinationFile = Join-Path "$tempfolder\Registry" $ParsedFileName

        Copy-Item "$fullDiagPath\export.reg" $destinationFile -Force
    }

    # ### Event Logs

    elseif (Test-Path "$fullDiagPath\Events.evtx") {
        $evtx = join-path $fullDiagPath "Events.evtx"
 
        Move-EventLogData -evtx $evtx
        
    }

    # move contents of $windir event logs
    elseif (Test-Path "$fullDiagPath\*.evtx") {
        Copy-Item "$fullDiagPath\*.evtx" "$tempfolder\EventLogs" -Force
    }

    # ### Windows Update

    elseif (Test-Path "$fullDiagPath\windowsupdate.*.etl") {
         $null =  Get-WindowsUpdateLog -ETLPath $fullDiagPath -LogPath $tempfolder\WindowsUpdate.log | Out-Null 
    }

    # ### ConfigMgr client logs
    elseif (Test-Path "$fullDiagPath\ccmexec.log") {
        $ccmClientFolder = Join-Path $tempfolder ConfigMgr_client_logs
        $null = mkdir $ccmClientFolder
        Copy-Item $fullDiagPath\* $ccmClientFolder
    }

    # ### ConfigMgr setup

    elseif (Test-Path "$fullDiagPath\ccmsetup*.log") {
        $ccmClientSetupFolder = Join-Path $tempfolder ConfigMgr_client_setup_logs
        $null = mkdir $ccmClientSetupFolder
        Copy-Item $fullDiagPath\* $ccmClientSetupFolder
    }

    # ### measuredboot logs

    elseif (Test-Path "$fullDiagPath\00000*-00000*.log") {
        $MeasuredBoot = Join-Path $tempfolder MeasuredBoot_Logs
        $null = New-Item $MeasuredBoot -ItemType Directory -Force
        Copy-Item $fullDiagPath\* $MeasuredBoot
    }

    # ### IME (SideCar) logs

    elseif (Test-Path "$fullDiagPath\intunemanagementextension.log") {
        $SideCar = Join-Path $tempfolder Intune_Management_Extension_Logs
        $null = New-Item $SideCar -ItemType Directory -Force
        Copy-Item $fullDiagPath\*intunemanagementextension*.log $SideCar
        Copy-Item $fullDiagPath\*agentexecutor*.log $SideCar
        Copy-Item $fullDiagPath\*sensor*.log $SideCar
    }

    # ### Autopilot ETLs

    elseif (Test-Path "$fullDiagPath\diagnosticlogcsp_collector_autopilot*.etl") {
        $ApETLs = Join-Path $tempfolder z_ETL_Logs
        $null = New-Item $ApETLs  -ItemType Directory -Force
        Copy-Item $fullDiagPath\* $ApETLs
    }

    # ### Miscellaneous files

    elseif ( (Test-Path "$fullDiagPath\*.html") -or (Test-Path "$fullDiagPath\msinfo32.log") -or (Test-Path "$fullDiagPath\cbs.log") 
             ) {
         
        Copy-Item $fullDiagPath\*   $tempfolder -Force -ErrorAction SilentlyContinue
    }

    # ### Cab files.  Automatically extract
    elseif (Test-Path "$fullDiagPath\*.cab") {
        $cabFolder = ""
        $cabName = ""
        $extractedFolderName = ""

        $cabName = (Get-ChildItem "$fullDiagPath\*.cab").Name
        "##### $cabname"
        $extractedFolderName = "z_" + $($cabname -replace ".cab", "_extracted")
        $cabFolder = Join-Path $tempfolder  $extractedFolderName
        $null = mkdir $cabFolder     
         
        $null = expand $fullDiagPath\$cabName -I -F:* $cabFolder 
        

        # mdmlogs has embedded CAB
        if (Test-Path $cabFolder\*.cab) {
            $null = expand $cabFolder\*.cab   -F:* $cabFolder 
        } 

        if (-not ($LeaveCABs)) {          
            # Organize extracted files
            Move-Item $cabFolder\*.evtx "$tempfolder\EventLogs"  -Force
            # TODO - make this more generic
            if (Test-Path $cabFolder\CLIP) {
                Move-Item $cabFolder\CLIP\*.evtx "$tempfolder\EventLogs"  -Force
                Move-Item $cabFolder\CLIP\dsregcmd.txt "$tempfolder"  -Force
            }
            if (Test-Path $cabFolder\SPP) {
                Move-Item $cabFolder\SPP\*.evtx "$tempfolder\EventLogs"  -Force
                Move-Item $cabFolder\SPP\WPAKeys* "$tempfolder\Registry"  -Force
            }
          
            $regFileNames = Get-Item  "$cabFolder\*registry*"
            if ($regFileNames ) {
                
                foreach ($regFileName in $regFileNames) {
                    $regFileNameTxt = $regFileName.Name -replace "\.reg", ".txt"
                    Write-Output "*** $($regFileName.FullName )"
                    Write-Output "--- $tempfolder\Registry\$regFileNameTxt"
                
                    if (test-path "$tempfolder\Registry\$regFileNameTxt"){
                        $regFileNameTxt = $regFileNameTxt | Get-NewFileNameIfExists
                        Write-Output "____ $regFileNameTxt"
                        }
                    Move-Item $regFileName.FullName "$tempfolder\Registry\$regFileNameTxt"
                    }
                }
            Move-Item "$cabFolder\DeviceHash*"   "$tempfolder" -Force
            Move-Item "$cabFolder\MDMDiag*"      "$tempfolder" -Force
            Move-Item "$cabFolder\systeminfo*"   "$tempfolder" -Force


            $SideCar = Join-Path $tempfolder Intune_Management_Extension_Logs
            if (-not (Test-Path $SideCar) ) {
                $null = New-Item $SideCar -ItemType Directory -Force
                 }
            Move-Item $cabFolder\*intunemanagementextension*.log $SideCar  -Force
            Move-Item $cabFolder\*agentexecutor*.log $SideCar  -Force
            Move-Item $cabFolder\*sensor*.log $SideCar  -Force
            Move-Item $cabFolder\*clienthealth*.log $SideCar  -Force

            $etlPath = Join-Path $tempfolder "z_ETL_Logs"
            if (Test-Path "$cabFolder\*.etl") {
                if (-not (Test-Path $etlPath) ) {
                    $null = New-Item $etlPath -ItemType Directory -Force
                 }
                Move-Item "$cabFolder\*.etl" $etlPath  -Force
            }

        }


    }


    # ### Command output

    elseif (Test-Path "$fullDiagPath\output.log") {
     
       $newFileName = ""
       $newFileName = Parse_Outputlog -outputlogPath "$fullDiagPath\output.log"

       if ( ($newFileName -match "metadata_") -or ($newFileName -match "Unknown_Command_Result") ){
            Copy-Item "$fullDiagPath\output.log" "$tempfolder\z_MetaData\$newFileName"  
            }
       else {
            Copy-Item "$fullDiagPath\output.log" "$tempfolder\$newFileName"
            }
    }

}
# cleanup 
try {
    if ($SourcePath -ne $PWD) {
        $null = Remove-Item $SourcePath -Recurse -Force
    }
}
catch [System.IO.IOException] {
    # something grabbed a file handle.  Usually AV.  Wait and retry
    for ($i = 1; $i -le 5; $i++){
        "waiting for handle to close... $i"
        Start-Sleep 3
        $null = Remove-Item $SourcePath -Recurse -Force   -ErrorAction SilentlyContinue
    }
    if ( Test-Path $SourcePath ) {
        Write-Output "*** Warning: Format-IntuneDiagData.ps1 was unable to remove all or part of $PWD\$SourcePath.  Please remove this folder manually." 
    }
}
catch {
    Write-Output "Unexpected error: $($Error[0].Exception.GetType().fullname)"
    Write-Output $Error[0]

}
# FIDD debug log
Stop-Transcript
Move-Item $FIDDlog $tempfolder\z_MetaData

# show output folder
Start-Process $tempfolder