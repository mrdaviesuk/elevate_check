This tool automates the discovery of UAC Elevation behaviors defined within Windows Executable (.exe) file manifests. 
It is forked from the original elevate_check.py to broaden the scope of it's capability and associated utility. 

It may be used in UAC privilege escalation scenarios to identify where "allowElevate"==True, as was the original purpose of the script
For more detailed info read:  [Bypassing Windows User Account Control (UAC) and ways of mitigation](https://www.greyhathacker.net/?p=796) 

It may also be used to describe or search for the requestedExecution (asInvoker,highestAvailable,requireAdministrator) of an executable, which informs the behavior of elevation and UAC for Windows Administrators and Standard Users. Whether uiaccess is enabled can also be returned and filtered for. 

All results can be exported to CSV for later review, in addition to the console output.
    
### Requirements
-----------------------------
* python 2.7.x
* pefile
* tabulate 
* BeautifulSoup4
    
### Compatibility
-----------------------------
* MS Windows
	
	
### Usage
-----------------------------
usage: elevate_check.py [-h] [-d DIRECTORY] [-r] [-i] [-la] [-le] [-el] [-ua] [-su] [-e]

optional arguments:
  -h, show this help message and exit
  
  -d DIRECTORY      Target directory.
  
  -r&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Scan subfolders as fell.
  
  -i&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Ignore files manufactured by Microsoft.

  -la&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Identify files with the allowElevate parameter set.

  -le&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;List files with the executionLevel setting and the value configured. Can be combined with the -el parameter to limit the scope to a specific executionLevel value or values.

  -el&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Specify a filter for the executionLevel(s) as a comma separated list.
  
  -ua&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Shows the uiacess setting in the executionLevel output table.

  -su&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Specify the uiaccess value to filter for (true/false).

  -e&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Triggers CSV export, by specifying the Folder Path to export results into CSV file(s).

### Output
----------------------------
![Expected output](allowElevate.png?raw=true "Expected output")
