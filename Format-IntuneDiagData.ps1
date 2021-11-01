<#

Format-IntuneDiagData.ps1

Format-IntuneDiagData.ps1 (FIDD) is a utility script to extract and organize zip archive created using the 'Collect diagnostics' feature in Microsoft Endpoint Mananger Intune (MEM).

Author:  Mark Stanfill
Email: markstan@microsoft.com
Date created: 10/27/2021

  

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
    [switch]$NoUnzip              # do not extract zip file if present.  Use if zip file exists and has aleady been extracted
)
 
$RIDDversion = "2021.10.2" 
$ErrorActionPreference = "Stop" 

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
                $parsedLine += ".reg"
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
    param( 
        $tempfolder
    )
    
    # Cleanup if results left from previous run
    if (test-path $tempfolder ) { $null = Remove-Item $tempfolder -Recurse -Force }
    $null = mkdir $tempfolder -Force

    $null = mkdir $tempfolder\Registry  -Force
    $null = mkdir $tempfolder\EventLogs -Force
    $null = mkdir $tempfolder\MetaData  -Force

}

function Test-AndExpandArchive {

    if  ($null -eq $ArchiveName) {

        if (Test-Path .\DiagLogs*.zip) {
            $ArchiveName = Get-Item ".\DiagLogs*.zip"
    
            if ($ArchiveName.count -gt 1) {
                Write-Host "More than 1 Diaglogs*.zip file found.  Please specify file name with  -ArchiveName command line parameter."  -ForegroundColor Red
                Exit
            }
            else {
                Expand-Archive $ArchiveName -Force # overwrite files if they exist
            }
        }
        else {
            Write-Host "Unable to locate zip file.  Please check that the file exists in the current directory or specify the -ArchiveName command line parameter."  -ForegroundColor Red
    
        }
    }
    else {
        Expand-Archive $ArchiveName -Force
    }
    # return folder name
    [System.IO.Path]::GetFileNameWithoutExtension($ArchiveName)
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
Write-Output "Starting Format-IntuneDiagData version $RIDDversion."

$tempfolder =  Join-Path $OutFolder "IntuneDeviceData"
$null = New-DiagFolderStructure -tempfolder $tempfolder 
$session  = New-Object -TypeName System.Diagnostics.Eventing.Reader.EventLogSession   # For event log commands

$SourcePath = Test-AndExpandArchive

$diagfolders = @()
$diagfolders = Get-ChildItem $SourcePath -Directory
 


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

    # ### Windows Update

    elseif (Test-Path "$fullDiagPath\windowsupdate.*.etl") {
        ### *** UNCOMMENT

      #$null =  Get-WindowsUpdateLog -ETLPath $fullDiagPath -LogPath $tempfolder\WindowsUpdate.log
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
        $null = mkdir $MeasuredBoot
        Copy-Item $fullDiagPath\* $MeasuredBoot
    }

    # ### IME (SideCar) logs

    elseif (Test-Path "$fullDiagPath\intunemanagementextension.log") {
        $SideCar = Join-Path $tempfolder Intune_Management_Extension_Logs
        $null = mkdir $SideCar
        Copy-Item $fullDiagPath\* $SideCar
    }

    # ### Autopilot ETLs

    elseif (Test-Path "$fullDiagPath\diagnosticlogcsp_collector_autopilot*.etl") {
        $ApETLs = Join-Path $tempfolder Autopilot_ETL_Logs
        $null = mkdir $ApETLs
        Copy-Item $fullDiagPath\* $ApETLs
    }

    # ### Miscellaneous files

    elseif ( (Test-Path "$fullDiagPath\*.html") -or (Test-Path "$fullDiagPath\msinfo32.log") -or (Test-Path "$fullDiagPath\cbs.log") 
             ) {
         
        Copy-Item $fullDiagPath\*   $tempfolder
    }

    # ### Cab files.  Automatically extract
    elseif (Test-Path "$fullDiagPath\*.cab") {
        $cabFolder = ""
        $cabName = ""
        $baseName = ""

        $cabName = (Get-ChildItem "$fullDiagPath\*.cab").Name
        $baseName =  $cabName -replace ".cab", ""

        $cabFolder = Join-Path $tempfolder $( $basename + "_extracted")
        $null = mkdir $cabFolder     
         
        $null = expand $fullDiagPath\$cabName -I -F:* $cabFolder 
        

        # mdmlogs has embedded CAB

        if (Test-Path $cabFolder\*.cab) {
            $null = expand $cabFolder\*.cab   -F:* $cabFolder 
        } 
    }


    # ### Command output

    elseif (Test-Path "$fullDiagPath\output.log") {
       # type $fullDiagPath\output.log
       $newFileName = ""
       $newFileName = Parse_Outputlog -outputlogPath "$fullDiagPath\output.log"

       if ( ($newFileName -match "metadata_") -or ($newFileName -match "Unknow_Command_Result") ){
            Copy-Item "$fullDiagPath\output.log" "$tempfolder\MetaData\$newFileName"  
            }
       else {
            Copy-Item "$fullDiagPath\output.log" "$tempfolder\$newFileName"
            }
    }

}
# cleanup 
try {
    $null = Remove-Item $SourcePath -Recurse -Force
}
catch [System.IO.IOException] {
    # something grabbed a file handle.  Usually AV.  Wait and retry
    for ($i = 1; $i -le 5; $i++){
        "waiting for handle to close... $i"
        Start-Sleep 3
        $null = Remove-Item $SourcePath -Recurse -Force   -ErrorAction SilentlyContinue
    }
    if ( Test-Path $SourcePath ) {
        Write-Host "Warning: Format-IntuneDiagData.ps1 was unable to remove all or part of $PWD\$SourcePath.  Please remove this folder manually." `
            -ForegroundColor Yellow
    }
}
catch {
    Write-Output "Unexpected error: $($Error[0].Exception.GetType().fullname)"
    Write-Output $Error[0]

}

# show output folder
Start-Process $tempfolder