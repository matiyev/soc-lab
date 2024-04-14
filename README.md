# SOC-MOCK
## Objective
This project aimed to build a realistic Security Operations Center (SOC) training environment focusing on practical skills for detecting and responding to cyber threats.
Objectives were enhancing network security by implementing best practices such as disabling unnecessary services, configuring firewalls, and strengthening user account controls. Advanced threat detection tools like Sysmon and LimaCharlie EDR were deployed for real-time analysis. Adversary techniques were simulated, and threat responses were automated to stay ahead of potential risks. Additionally, YARA rules were integrated to enhance malware detection capabilities.
<br><br>

## Components

- **VirtualBox**: Used for creating and managing virtual machines.
- **Ubuntu Server VM**: Used to deploy the Sliver C2 framework, which acts as a simulated attacker tool.
- **Windows VM**: Used as victim endpoint device.
- **LimaCharlie EDR**: An EDR platform used to collect, analyze logs and investigate telemetry from the Windows VM.
- **Sliver C2**: A simulated attacker tool used to create a Command & Control (C2) server on the Ubuntu VM.
- **YARA Rules**: Specific sets of instructions used to identify malware based on patterns.
- **Sysmon**: Windows system service used to monitor and log system activity to the event log.
- **VirusTotal**: A service for analyzing suspicious files and URLs for malware.
- **NAT Network**: Configured in VirtualBox for network simulation.

<details>
  <summary><h2><b>Section 1: Setting up the Virtual Environment</b></h2></summary>
  This section will guide through the setup of virtual environment using VirtualBox (If you want you, can use VMware as well). Configure a NAT network and install two virtual machines – one for Ubuntu Server and another for a Windows 10. <br><br>

  - **Step 1: Download and setup Virtualbox**:  
    You can download Virtualbox from here. Setup is pretty straightforward
    <br><br>
  - **Step 2: Create a New VM for Windows 10**:  
   Next, set up a new virtual machine in VirtualBox for Windows 10.
    - Create it with following minimum specs:
      - RAM: Approx 2 GB
      - Processors: 2 CPU cores
      - Hard Disk Storage: 50 GB
    <br><br>
    
  - **Step 3: Create a New VM for Ubuntu Server**:  
    Now, set up a new virtual machine in VirtualBox for Ubuntu Server.
    - Create it with following minimum specs:
      - RAM: Approx 2 GB
      - Processors: 2 CPU cores
      - Hard Disk Storage: 20 GB
    - During OS install, leave defaults as is
  ![Image](https://imgur.com/GDfOZmg.png)
    <br><br>
    - After installation it should look like this:
  ![Image](https://imgur.com/9VNGxVp.png)
    <br><br>
       
  - **Step 4: Configure Windows VM**:  
    Permanently disable Microsoft Defender so it doesn’t interfere with the fun stuff we’re planning. This is pretty tricky (especially in Windows 11) as Defender will turn itself back on.
I. Disable Tamper Protection
  - Go to "Windows Security"
  - Click “Virus & threat protection”
  - Under “Virus & threat protection settings” click “Manage settings”
  - Toggle OFF the “Tamper Protection” switch. When prompted, click “Yes”
![Image](https://imgur.com/iTuPTwi.png)
  - Toggle every other option OFF as well
II. Permanently Disable Defender via Group Policy Editor
  - Click the “Start” menu icon
  - Type “cmd” into the search bar within the Start Menu
  - Right+Click “Command Prompt” and click “Run as administrator”
  - Run the following command
''' gpedit.msc '''
  - Inside the Local Group Policy Editor
  - Click Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus
  - Double-click “Turn off Microsoft Defender Antivirus”
  - Select “Enabled” (If you enable this policy setting, Defender doesn't run, and will not scan for malware or other potentially unwanted software)
  - Click "Apply"
![Image](https://imgur.com/9bsP5Lf.png)
III. Permanently Disable Defender via Registry
  - From the same administrative cmd, copy/paste this command and press Enter

  <br>
'''REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
</br>

IV. Prepare to boot into Safe Mode to disable all Defender services
  - Click the “Start” menu icon
  - Type “msconfig” into the search bar
  - Go to “Boot” tab and select “Boot Options”
  - Check the box for “Safe boot” and “Minimal”
![Image](https://imgur.com/0K1OBWq.png)
  - Click Apply and OK
  - System will restart into Safe Mode

V. Now, in Safe Mode, we’ll disable some services via the Registry
  - Click the “Win + R"
  - Type “regedit” into the search bar and hit Enter
  - For each of the following registry locations, browse to the key, find the “Start” value, and change it to "4"
![Image](https://imgur.com/IWskQZt.png)
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter

VI. Leave Safe Mode the same way we got into it
  - Uncheck the box for “Safe boot”
  - System will restart into normal desktop environment, hopefully Defender-free
    <br><br>
</details>

<details>
  <summary><h2><b>Section 2: Security Onion Initial Setup</b></h2></summary>
  Lets setup up and configure our Security Onion (NSM) Network Security Monitoring solution<br><br>
<<<<<<< HEAD
</details>