<#
        .Synopsis
			This script will collect Sysmon events from various sources and create a html report.
        .DESCRIPTION
            This script searches for relevant sysmon events and optionally sends out a mail report.
            Requires powershell > v5 for module imports and needs to be run with admin privileges to be able to read the eventlog.
		   
        .EXAMPLE
            .\Publish-Sysmonevents.ps1            
        
        .LINK
            https://technet.microsoft.com/en-us/sysinternals/sysmon
            https://www.netlogix.at/
            
           
        .NOTES
           Author: Stefan Winkler 2018, Antares-Netlogix
           Version: Publish-SysmonEvents.ps1 v2.0 
#>

Param (
    #Name of log source - sysmon is default 
    [string]$LogSource = "Microsoft-Windows-Sysmon/Operational", 
    #Where to store the reports   
    [string]$ReportFolder = "$env:ProgramData\sysmon",
    #report period - look for events within this number of days
    [int]$ReportPeriod = 7,
    #delete old report files
    [bool]$DeleteOldReports = $true,
    #delete all reports from the filesystem which are older than this number of days
    [int]$deleteReportsOlderThan = 90,
    #Send Emails
    [bool]$SendMail = $true,
    #Mail to
    [string]$MailReceipient = 'admin@example.local',
    #Mail from
    [string]$MailSender = 'SysmonStatus <sysmon@example.local>',
    #Mail Subject
    [string]$MailSubject = "Sysmon Report for $(hostname)",
    #SMTP Server
    [string]$SmtpServer = 'mail.example.local'
)


#Check if Powershell runs with Admin Privileges for event log access and PSHTMLTable module install
#If you run this script with an account with event log readers permissions and already have the PSHTMLTable Module installed disable this check.
#The script account needs write access in $Reportfolder
Function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$isadmin = Test-Administrator

if (!($isadmin)) {
    Write-Host 'Run Powershell with administrative permissions to use this script'
    pause
    exit
}
#End check for admin permissions

#Create report folder if it isn't existing
If (!(test-path $reportfolder)) {
    New-Item -ItemType Directory -Force -Path $reportfolder
}


[dateTime]$ReportStartDate = (get-date).addDays( - $ReportPeriod)
[dateTime]$ReportDeleteDate = (get-date).addDays( - $deleteReportsOlderThan)

$filename = "$reportfolder\sysmon-report_$(hostname)_$(get-date -f yyyy-MM-dd).html"

#If there was already another report run today -> delete it
If (test-path $filename) {
    remove-item $filename -Force
}

    
#Install PSHTMLTable Module - install manually if on older version
If (!(Get-Module -Listavailable -Name PSHTMLTable)) {
    Install-Module PSHTMLTable
}
#Load PSHTMLTable Module 
If (!(Get-Module -Name PSHTMLTable)) {
    Import-Module PSHTMLTable
}
	
Function Get-WinEventData {
    <#
		.SYNOPSIS
			Get custom event data from an event log record

		.DESCRIPTION
			Get custom event data from an event log record

			Takes in Event Log entries from Get-WinEvent, converts each to XML, extracts all properties from Event.EventData.Data

			Notes:
				To avoid overwriting existing properties or skipping event data properties, we append 'EventData' to these extracted properties
				Some events store custom data in other XML nodes.  For example, AppLocker uses Event.UserData.RuleAndFileData

		.PARAMETER Event
			One or more event.
			
			Accepts data from Get-WinEvent or any System.Diagnostics.Eventing.Reader.EventLogRecord object

		.INPUTS
			System.Diagnostics.Eventing.Reader.EventLogRecord

		.OUTPUTS
			System.Diagnostics.Eventing.Reader.EventLogRecord

		.EXAMPLE
			Get-WinEvent -LogName system -max 1 | Get-WinEventData | Select -Property MachineName, TimeCreated, EventData*

			#  Simple example showing the computer an event was generated on, the time, and any custom event data

		.EXAMPLE
			Get-WinEvent -ComputerName DomainController1 -FilterHashtable @{Logname='security';id=4740} -MaxEvents 10 | Get-WinEventData | Select TimeCreated, EventDataTargetUserName, EventDataTargetDomainName

			#  Find lockout events on a domain controller
			#    ideally you have log forwarding, audit collection services, or a product from a t-shirt company for this...

		.NOTES
			Concept and most code borrowed from Ashley McGlone
				http://blogs.technet.com/b/ashleymcglone/archive/2013/08/28/powershell-get-winevent-xml-madness-getting-details-from-event-logs.aspx

		.FUNCTIONALITY
			Computers
		#>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true, 
            ValueFromRemainingArguments = $false, 
            Position = 0 )]
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]
        $event
    )

    Process {
        #Loop through provided events
        foreach ($entry in $event) {
            #Get the XML...
            $XML = [xml]$entry.ToXml()
        
            #Some events use other nodes, like 'UserData' on Applocker events...
            $XMLData = $null
            if ( $XMLData = @( $XML.Event.EventData.Data ) ) {
                For ( $i = 0; $i -lt $XMLData.count; $i++ ) {
                    #We don't want to overwrite properties that might be on the original object, or in another event node.
                    Add-Member -InputObject $entry -MemberType NoteProperty -name "EventData$($XMLData[$i].name)" -Value $XMLData[$i].'#text' -Force
                }
            }

            $entry
        }
    }
}
Function Send-Reportmail {
    #send mail
    $body = Get-Content $filename -Raw
    Send-MailMessage -To $MailReceipient -From $MailSender -Subject $MailSubject -SmtpServer $SmtpServer -Body $body -BodyAsHtml -UseSsl
}

Function Remove-OldReportfiles {
    #Delete old Report Files from $reportfolder
    Get-ChildItem -Path $reportfolder -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $ReportDeleteDate -and $_.Name -like "sysmon-report_*.html" }  | Remove-Item -force
}

$HTML = New-HTMLHead
$HTML += "<h1>Sysmon report $(hostname) - from $($ReportStartDate.ToString("yyyy-MM-dd")) to $(get-date -f yyyy-MM-dd)</h1>"
$global:title = "title variable could not be set - maybe powershell bug with global scope variables ?!?"

###########################
## EVENTLOG Queries - START
###########################

$commands = @()

$commands += {
    $global:title = 'ID 1: Process Create Events'
    Get-WinEvent -FilterHashtable @{logname = $LogSource; id = 1} | Where-Object {$_.TimeCreated -ge $ReportStartDate} | 
        Get-WinEventData |  Group-Object -Property EventDataImage, EventDataHashes  | Select-Object @{N = 'Image , Hash'; E = {$_.Name}}, Count | Sort-Object -Property Count -Descending
}

$commands += {
    $global:title = 'ID 3: Network Connections'
    Get-WinEvent -FilterHashtable @{logname = $LogSource; id = 3} -MaxEvents 1000| Where-Object {$_.TimeCreated -ge $ReportStartDate} |
        Get-WinEventData | Where-Object {$_.EventDataDestinationIp -notlike "127.0.0.1" -and $_.EventDataDestinationIp -notlike "0:0:0:0:0:0:0:1"} | #remove localhost connections
        Select-Object EventDataImage, EventDataDestinationPort, EventDataDestinationPortName, EventDataDestinationIP , EventDataDestinationHostname | Sort-Object -Property EventDataImage, EventDataDestinationIP -Unique
}

$commands += {
    $global:title = 'ID 6: Driver Loads'
    Get-WinEvent -FilterHashtable @{logname = $LogSource; id = 6} | Where-Object {$_.TimeCreated -ge $ReportStartDate}|
        Get-WinEventData| Group-Object -Property EventDataImageLoaded, EventDataSignature, EventDataSignatureStatus | Select-Object @{N = 'Image Loaded , Signature , Signature Status'; E = {$_.Name}}, Count | Sort-Object -Property Count -Descending

    #Get-WinEvent -FilterHashtable @{logname=$LogSource;id=6} | Where-Object {$_.TimeCreated -ge $ReportStartDate}|
    #Get-WinEventData | Where-Object {$_.EventDataSignature -like "Insecure*"} | Format-List -Property EventData* 
}

$commands += {
    $global:title = 'ID 8 - RemoteThreadCreated'
    Get-WinEvent -FilterHashtable @{logname = $LogSource; id = 8} | Where-Object {$_.TimeCreated -ge $ReportStartDate}| 
        Get-WinEventData | Select-Object  EventData*
}

$commands += {
    $global:title = 'ID 11 - FileCreate'
    Get-WinEvent -FilterHashtable @{logname = $LogSource; id = 11} | Where-Object {$_.TimeCreated -ge $ReportStartDate} | 
        Get-WinEventData | Group-Object -Property  EventDataImage, EventDataTargetFilename | Select-Object -Property @{N = 'Image , Targetfilename'; E = {$_.Name}}, Count | Sort-Object -Property Count -Descending
}

$commands += {
    $global:title = 'ID 12 - RegistryObjCreateDelete'
    Get-WinEvent -FilterHashtable @{logname = $LogSource; id = 12} | Where-Object {$_.TimeCreated -ge $ReportStartDate}|
        Get-WinEventData |  Group-Object -Property EventDataImage | Select-Object Name, Count | Sort-Object -Property Count -Descending
}

$commands += {
    $global:title = 'ID 13 - RegistryValueCreate'
    Get-WinEvent -FilterHashtable @{logname = $LogSource; id = 13} | Where-Object {$_.TimeCreated -ge $ReportStartDate}| 
        Get-WinEventData | Group-Object -Property EventDataImage | Select-Object Name, Count | Sort-Object -Property Count -Descending
}

$commands += {
    $global:title = 'ID 15 - FileCreateStreamHash'
    Get-WinEvent -FilterHashtable @{logname = $LogSource; id = 15} | Where-Object {$_.TimeCreated -ge $ReportStartDate}| 
        Get-WinEventData | Group-Object -Property EventDataImage, EventDataTargetFilename | Select-Object @{N = 'Image , Targetfilename'; E = {$_.Name}}, Count | Sort-Object -Property Count -Descending
}

#########################
## EVENTLOG Queries - END
#########################

foreach ($command in $commands) { 
    $events = Invoke-Command -ScriptBlock $command
    $HTML += "<h3>$($global:title)</h3>"
    $HTML += $events | New-HTMLTable    
}

$HTML = $HTML | Close-HTML
set-content $filename $HTML

#Send Reportmail
if ($SendMail) {
    Send-Reportmail
}

#Delete old Reports
if ($DeleteOldReports) {
    Remove-OldReportfiles
}