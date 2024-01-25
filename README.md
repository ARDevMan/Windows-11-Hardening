# Windows-11-Hardening
2024 Baseline Industry Standards Powershell Hardening Script

This script is designed to enhance the security of a Windows system by disabling Windows Error Reporting, enabling Windows Firewall, and enabling Windows Defender Antivirus. It automates the process of applying these security measures to ensure a more secure environment.

## Usage

1. Download the `Hardening2024.ps1` script to your local machine.

2. Open PowerShell with administrative privileges.

3. Navigate to the directory where the script is saved.

4. Run the script by executing the following command:

.\Hardening2024.ps1

applescript
Copy

## Features

1. Disabling Windows Error Reporting: This script disables the Windows Error Reporting feature, which helps to prevent the automatic sending of error reports to Microsoft. Disabling this feature can enhance privacy and reduce network traffic.

2. Enabling Windows Firewall: The script enables the built-in Windows Firewall, which provides a barrier against unauthorized access to your computer from external networks. Enabling the firewall helps protect your system from various network-based attacks.

3. Enabling Windows Defender Antivirus: Windows Defender Antivirus is a built-in security solution that helps protect your system against malware and other malicious threats. This script ensures that Windows Defender is enabled and real-time monitoring is active, providing continuous protection for your system.

## Troubleshooting

If you encounter any issues while running the script, such as the error mentioned below:

Set-MpPreference : Operation failed with the following error: 0x800106ba. Operation: Set-MpPreference. Target: DisableRealtimeMonitoring.

applescript
Copy

You can try the following steps to resolve the issue:

1. Restart your computer.

2. Check if the "Windows Defender Antivirus Service" is running. Start it if it's not.

3. Run the Windows Defender Antivirus troubleshooter.

4. Repair the Windows Defender Antivirus installation.

5. Perform a system file check using the `sfc /scannow` command in an elevated Command Prompt.

If the issue persists, consider seeking assistance from Microsoft support.

## Disclaimer

Please note that this script is provided as-is and without any warranty. It is recommended to review and understand the script's contents before running it on your system. Use it at your own risk.

Always ensure that you have a backup of your important data before making any system changes.

## Contributing

Contributions to this script are welcome. If you have any suggestions, improvements, or bug fixes, feel free to contribute by creating a pull request.
