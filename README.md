# SOC-MOCK Project
🛠️ Working on Full-Detailed documentation... 🛠️
<br>
## Description
### Hardened Windows VM to reduce attack surface: 
- Implemented security best practices on the Windows VM, such as disabling unnecessary services, configuring firewall rules, and strengthening user account controls. This minimized potential entry points for attackers.
### Deployed security tools (Sysmon, LimaCharlie EDR) for threat detection: 
- Installed and configured Sysmon for advanced system activity monitoring, capturing detailed logs of process creation, network connections, and file system modifications. Additionally, deployed LimaCharlie EDR to collect and analyze these logs in real-time, providing a comprehensive view of system activity for threat detection.

### Analyzed EDR telemetry to identify adversary techniques (credential dumping): 
- Monitored system activity through LimaCharlie EDR: Utilized LimaCharlie's dashboards and timeline features to track system events, focusing on suspicious activities like process creation, network connections, and file access attempts.
- Analyzed events related to access of the "lsass.exe" process, a known target for credential theft tools. This analysis involved examining details like user accounts involved, access times, and potentially suspicious command-line arguments used.
### Created D&R rules for automated threat response and reporting:
- Utilized LimaCharlie's built-in capabilities to create customized detection rules based on observed suspicious activity.
- Defined a rule that triggers upon access attempts to "lsass.exe" by unauthorized users or with suspicious patterns. This rule could generate reports for further investigation or even take automated actions like terminating the offending process.
- Configured reporting and response actions: Defined the desired response within the rule, such as generating detailed reports or potentially terminating the process to prevent further damage.

### Implemented YARA rules for signature-based malware detection:
- Leveraged YARA, a tool for identifying malware based on textual or binary patterns. This allowed for targeted detection of specific malware families or malicious behaviors.
- Developed a YARA rule specifically designed to identify the Sliver C2 framework, a common tool used by adversaries for remote control. This custom rule enhanced detection capabilities beyond pre-built signatures provided by EDR vendors.
- Integrated YARA scanning into LimaCharlie's D&R framework. This enabled automated scans of downloaded files and running processes against the custom YARA rule, identifying potential malware infections.
