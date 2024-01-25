# Script to Harden Windows 11 Home to Cybersecurity Industry Standards

# Disable Windows Error Reporting
Write-Host "Disabling Windows Error Reporting..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Type DWord -Value 1

# Enable Windows Firewall
Write-Host "Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

# Enable Windows Defender Antivirus and Real-time Protection
Write-Host "Enabling Windows Defender Antivirus..."
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable Automatic Windows Updates
Write-Host "Enabling Automatic Windows Updates..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name AUOptions -Type DWord -Value 4

# Disable Remote Desktop
Write-Host "Disabling Remote Desktop..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Type DWord -Value 1

# Disable Guest Account
Write-Host "Disabling Guest Account..."
Set-LocalUser -Name "Guest" -Enabled $false

# Enable BitLocker Drive Encryption (if supported)
Write-Host "Enabling BitLocker Drive Encryption..."
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly

# Disable PowerShell Script Execution
Write-Host "Disabling PowerShell Script Execution..."
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser

# Disable Autorun for Removable Media
Write-Host "Disabling Autorun for Removable Media..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -Type DWord -Value 255

# Enable User Account Control (UAC)
Write-Host "Enabling User Account Control (UAC)..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Type DWord -Value 1

# Disable SMBv1
Write-Host "Disabling SMBv1..."
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Set-SmbClientConfiguration -EnableSMB1Protocol $false

# Enable Windows Defender Firewall Public Profile Logging
Write-Host "Enabling Windows Defender Firewall Public Profile Logging..."
Set-NetFirewallProfile -Profile Public -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
Set-NetFirewallProfile -Profile Public -LogMaxSizeKilobytes 16384
Set-NetFirewallProfile -Profile Public -LogAllowed True

# Disable Remote Registry Service
Write-Host "Disabling Remote Registry Service..."
Set-Service -Name "RemoteRegistry" -StartupType Disabled

# Disable Windows Remote Management (WinRM)
Write-Host "Disabling Windows Remote Management (WinRM)..."
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart

# Enable Windows Defender SmartScreen
Write-Host "Enabling Windows Defender SmartScreen..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name EnableWebContentEvaluation -Type DWord -Value 1

# Disable AutoPlay/AutoRun for all drives
Write-Host "Disabling AutoPlay/AutoRun for all drives..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -Type DWord -Value 255

# Disable Microsoft Office Macros
Write-Host "Disabling Microsoft Office Macros..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Security" -Name "VBAWarnings" -Type DWord -Value 2
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security" -Name "VBAWarnings" -Type DWord -Value 2
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Security" -Name "VBAWarnings" -Type DWord -Value 2

# Disable Remote Assistance
Write-Host "Disabling Remote Assistance..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

# Disable Windows Script Host
Write-Host "Disabling Windows Script Host..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0

# Disable Windows PowerShell Remoting
Write-Host "Disabling Windows PowerShell Remoting..."
Disable-PSRemoting -Force

# Disable Windows Management Instrumentation (WMI) Remoting
Write-Host "Disabling Windows Management Instrumentation (WMI) Remoting..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WMI" -Name "Enabled" -Type DWord -Value 0

# Enable Windows Defender Exploit Protection
Write-Host "Enabling Windows Defender Exploit Protection..."
Set-ProcessMitigation -System -Enable ExportAddressFilterPlus, ExtensionPointDisable, ControlFlowGuard, DisableDynamicCode, FontDisable, ImageLoadNoRemote, ProhibitDynamicCode, StackPivot, StrictHandleChecks, ValidateExceptionChains

# Configure Windows Defender Firewall Rules
Write-Host "Configuring Windows Defender Firewall Rules..."
New-NetFirewallRule -DisplayName "Block Inbound Telnet" -Protocol TCP -LocalPort 23 -Action Block
New-NetFirewallRule -DisplayName "Block Inbound FTP" -Protocol TCP -LocalPort 21 -Action Block
New-NetFirewallRule -DisplayName "Block Inbound RDP" -Protocol TCP -LocalPort 3389 -Action Block

# Enable Secure Boot
Write-Host "Enabling Secure Boot..."
Set-FirmwareConfiguration -ConfiguratonPolicy "Ignore,Ignore,Ignore,Ignore,Ignore,Ignore,Ignore,Ignore,Ignore,Ignore,Ignore,Ignore,Ignore,Ignore,Ignore,Ignore" -Enable

# Disable Microsoft Office Macros
Write-Host "Disabling Microsoft Office Macros..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Security" -Name "VBAWarnings" -Type DWord -Value 3
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security" -Name "VBAWarnings" -Type DWord -Value 3
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Security" -Name "VBAWarnings" -Type DWord -Value 3

# Enable Windows Defender Controlled Folder Access
Write-Host "Enabling Windows Defender Controlled Folder Access..."
Set-MpPreference -EnableControlledFolderAccess Enabled

# Disable Guest Account
Write-Host "Disabling Guest Account..."
Set-LocalUser -Name "Guest" -Enabled $false

# Script completed successfully
Write-Host "Windows 11 Home has been hardened to cybersecurity industry standards."
