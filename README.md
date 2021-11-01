# Format-IntuneDiagData.ps1

Format-IntuneDiagData.ps1 (FIDD) is a stand-alone script to organize data collected by the [Intune collect diagnostics](https://docs.microsoft.com/en-us/mem/intune/remote-actions/collect-diagnostics) device action.

This script will organize the [collected data](https://docs.microsoft.com/en-us/mem/intune/remote-actions/collect-diagnostics#data-collected) in to a logical folder structure and renames the files to reflect their contents.

![FIDD output](https://github.com/markstan/Format-IntuneDiagData/blob/main/FIDD.png)

## Usage

Use these steps to run this utility:

1. Create a temporary folder, download [Format-IntuneDiagData.ps1](https://raw.githubusercontent.com/markstan/Format-IntuneDiagData/master/Format-IntuneDiagData.ps1) from this repo and save the file to this folder.
1. Download the device diagnostics data from the [MEM portal](https://endpoint.microsoft.com/#blade/Microsoft_Intune_DeviceSettings/DevicesMenu/mDMDevicesPreview) (Home &gt; Devices &gt; All devices &gt; &lt;DeviceName&gt; &gt; Device diagnostics &gt; Download).  Place the file in the same folder as Format-IntuneDiagData.ps1.
1. Open a PowerShell window and run **.\Format-IntuneDiagData.ps1**.  If you launch the script from the folder where the zip file is located, no additional parameters are required.  Otherwise, specify the location of the zip file using the **-ArchiveName**  command-line switch.  
**Example:**
    ```powershell-interactive
     .\Format-IntuneDiagData.ps1 -ArchiveName c:\temp\DiagLogs-Computer01-20210029T175224Z.zip
    ```
1. The script will copy data and rename files as appropriate.  Embedded CAB files (mpsupportfiles.cab and mdmlogs*.cab) will be extracted to a subfolder.  When the script completes, it will launch Windows Explorer in the folder where the  extracted data has been copied.



## Known issues and planned improvements
 
* Multiple copies of files may exist (for example, Event Viewer logs and registry keys).  A future improvement will consolidate the files to a single location.
* Some third-party file archiving tools may report "Headers Error:" and the name of the file when extracting data from Diaglogs*.zip.  To work around this limitation, open the zip using Windows Explorer or use the Expand-Archive cmdlet.

   
## FAQ


Q: What is the aim of this tool?

A: The Intune collect diagnostics feature provides admins a simple way to collect data without having to log on to managed Windows devices.  This tool aims to allow admins to quickly locate the data they are looking for.

Q: Where is the data stored?

A: Files are extracted to the current folder by default in a subfolder named **IntuneDeviceData**.

Q:  I'd like to add addtional files to the collected data.  Where can I suggest changes to this feature?

A:  The best way to make this kind of request is through your Microsoft account team.  They can assist you with filing a design change request.

Q: When should I use 'collect diagnostics' and when should I use Intune One Data Collector (ODC)?

A: 'Collect diagnostics' is a great tool for gathering data from a remote computer without needing to either log on to a Windows device interactively or to interrupt your users.  As such, this tool has many advantages for admins in their daily work.

[ODC](https://github.com/markstan/IntuneOneDataCollector) collects data for more specialized troubleshooting.  A lot of data gathered by this tool is aimed at very specific scenarios that require deep knowledge of the various OS components that Intune manages.  ODC is XML-driven, which also allows us to very quickly add new data collection rules.  As such, this tool is most useful to Microsoft Support engineers (but anyone who finds it useful is more than welcome to it :) ).

Q: How can I tell the difference between a zip file generated by 'collect diagnostics' and a zip file created by running ODC?

A: ODC log archives will be named in the format &lt;DeviceName&gt;_CollecteData.zip and 'collect diagnostics' archives will be named DiagLogs-&lt;DeviceName&gt;-&lt;TimeStamp&gt;.zip by default.

## Copyright
Copyright (c) 2017 Microsoft. All rights reserved.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
