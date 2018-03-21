<#
        .Synopsis
			Install and configure Sysmon on new system
        .DESCRIPTION
			Uses chocolatey to install sysmon and downloads sysmon sample config from github
		            
        .LINK
            https://chocolatey.org/
            https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon 
            https://github.com/SwiftOnSecurity/sysmon-config/
            https://www.netlogix.at/

        .NOTES
           Author: Stefan Winkler 2018, Antares-Netlogix
           Version: install-sysmon.ps1 v1.0 
#>

function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$isadmin = Test-Administrator

if (!($isadmin)) {
    Write-Host 'Run Powershell with administrative permissions to use this script'
    pause
    Exit
}

#check if choco is installed
$ChocoInstalled = $false
if (Get-Command choco.exe -ErrorAction SilentlyContinue) {
    $ChocoInstalled = $true
}

#Install choco if necessairy
if (!($ChocoInstalled)) {
    Write-Host 'Chocolatey was not found - trying to install it'
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    refreshenv
}



#install sysmon via choco
choco.exe install -y sysmon

#get sysmon config
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  #needed to allow powershell to use tls 1.2 - please fix this microsoft ...
Invoke-WebRequest -uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile "$env:ProgramData\sysmon-config.xml"
sysmon64.exe –accepteula –i "$env:ProgramData\sysmon-config.xml"

#just to be sure ...
sc.exe failure Sysmon actions= restart/10000/restart/10000// reset= 120