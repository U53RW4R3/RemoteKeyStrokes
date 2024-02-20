#!/bin/bash

function check_dependencies() {
    if ! which xdotool &>/dev/null
    then
        echo "[!] Installing missing dependency..."
        if [[ ! $(which sudo 2>/dev/null) || $UID -ne 0 ]]
        then
            apt install -y xdotool
        else
            sudo apt install -y xdotool
        fi
        exit 1
    fi
}

function print_status {
    local status=$1
    local message=$2
    # TODO: Add colors
    # [*] for blue PROGRESS:
    # [+] for green DONE:
    # [!] for yellow WARN:
    # [-] for red ERROR:
    # white to reset colors
    echo ""
}

function CmdFile {
    local file=$1

    echo "[*] Executing commands..."
    while read -r line
    do
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$line"
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return
    done < $file
    echo "[+] Task completed!"
}

function Execute {
    local commands=$1
    local method=$2

    case $method in
        none)
            echo "[*] Executing commands..."
            xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$commands"
            xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return
            echo "[+] Task completed!"
            ;;
        dialogbox)
            DialogBox "$commands"
            ;;
        runspace)
            MSBuild "$commands"
        *)
            echo "Invalid Execution Type!" >&2
            exit 1
            ;;
    esac
}

function DialogBox {
    local commands=$1

    echo "[*] Checking one of the lines reaches 260 character limit"
    length=$(echo -n "$commands" | wc -c)
    if [ "$length" -ge 260 ]
    then
        echo "[-] Character Limit reached! Terminating program."
        exit 1
    fi

    echo "[*] Executing commands..."
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Super+r
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$commands"
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return
    echo "[+] Task completed!"
}

function MSBuild {
    # TODO: Add two methods one for adding shellcode and the other for powershell runspace
    # Add a flag C# implant

    # Add a flag if an input is passed as powershell runspace
    echo "msbuild"
}

function Base64 {
    local input_file=(base64 -w 0 $1)
    local output_file=$2
    local platform=$3
    
    # TODO: Finish the implementation
    echo "[*] Transferring file..."
    if [ $platform = "windows" ]
    then
        echo "Windows OS"
    elif [ $platform = "linux" ]
    then
        echo "Linux OS"
    fi

    echo "[+] File transferred!"
}

function CopyCon {
    local file_content=$1
    local output_file=$2

    if [ $platform != "windows" ]
    then
        echo "[-] copycon only exists on Windows operating system user! Try 'base64' method instead."
        exit 1
    fi
    
    echo "[*] Checking one of the lines reaches 255 character limit"
    while read -r line
    do
        length=$(echo -n "$line" | wc -c)
        if [ "$length" -ge 255 ]
        then
            echo "[-] Character Limit reached! Terminating program."
            exit 1
        fi
    done < $file_content

    echo "[*] Transferring file..."
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "copy con $output_file"
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return

    while read -r line
    do
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$line"
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return
    done < $file_content

    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Ctrl+Z Return
    echo "[+] File transferred!"
}

function OutputRemoteFile {
    local local_file=$1
    local remote_file=$2
    local platform=$3
    local method=$4

    # TODO: Implement bin2hex method
    case $method in
        "" | base64)
            Base64 $local_file $remote_file $platform
            ;;
        copycon)
            CopyCon $local_file $remote_file $platform
            ;;
        *)
            echo "Invalid File Transfer Technique!" >&2
            exit 1
            ;;
    esac
}

function CreateUser {
    local select=$1
    local platform=$2
    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ $platform = "windows" ]
    then
        echo "Windows"
    elif [ $platform = "linux" ]
    then
        echo "Linux"
    fi
}

function StickyKey {
    local select=$1
    local platform=$2
    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ $platform != "windows" ]
    then
        echo "[-] Registry keys only exists on Windows operating system user!"
        exit 1
    fi

    echo "[*] Activating sethc.exe (sticky keys) backdoor..."
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key shift shift shift shift shift
    echo "[+] Backdoor Activated!"
}

function UtilityManager {
    local select=$1
    local platform=$2
    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ $platform != "windows" ]
    then
        echo "[-] Registry keys only exists on Windows operating system user!"
        exit 1
    fi

    echo "[*] Activating utilman.exe (utility manager) backdoor..."
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Super+u
    echo "[+] Backdoor Activated!"
}

function Magnifier {
    local select=$1
    local platform=$2
    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ $platform != "windows" ]
    then
        echo "[-] Registry keys only exists on Windows operating system user!"
        exit 1
    fi

    echo "[*] Activating magnifier.exe backdoor..."
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Super+equal
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Super+minus
    echo "[+] Backdoor Activated!"
}

function Narrator {
    local select=$1
    local platform=$2
    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ $platform != "windows" ]
    then
        echo "[-] Registry keys only exists on Windows operating system user!"
        exit 1
    fi

    echo "[*] Activating narrator.exe backdoor..."
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Super+Return
    echo "[+] Backdoor Activated!"
}

function DisplaySwitch {
    local select=$1
    local platform=$2
    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ $platform != "windows" ]
    then
        echo "[-] Registry keys only exists on Windows operating system user!"
        exit 1
    fi

    echo "[*] Activating displayswitch.exe backdoor..."
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Super+p
    echo "[+] Backdoor Activated!"
}

function Persistence {
    local select=$1
    local platform=$2
    local persistence_method=$3

    # -s, --select flag "info,backdoor". For info contains the execution commands
    # for both command prompt and powershell. To enumerate, persistence and cleanup
    # TODO: Fill in the rest of the persistence methods
    case $persistence_method in
        createuser)
            CreateUser $select $platform
            ;;
        sethc)
            StickyKey $select $platform
            ;;
        utilman)
            UtilityManager $select $platform
            ;;
        magnifier)
            Magnifier $select $platform
            ;;
        narrator)
            Narrator $select $platform
            ;;
        displayswitch)
            DisplaySwitch $select $platform
            ;;
        *)
            echo "Invalid Persistence Technique!" >&2
            exit 1
            ;;
    esac
}

function PrivEsc {
    local elevate_mode=$1
    local platform=$2
    local elevate_method=$3
    # TODO: add -e, --elevated flag
    # -e info -p <windows | linux> -m bypassuac
    echo "Not implemented"
}

function EventViewer {
    local mode=$1

    if [[ $mode = "" || $mode = "manual" ]]
    then
        DialogBox "eventvwr.msc"
    else
        echo "[-] Invalid mode!"
    fi
}

function AntiForensics {
    local antiforensics_mode=$1
    local platform=$2
    local antiforensics_method=$3
    # TODO: Include features for anti-forensics also include eventvwr.msc with a dialog box
    # add flag -a, --antiforensics

    # -a <info (display info) | execute (to execute the commands | script (to transfer script) | manual (display the commands)>
    # -p <windows | linux> -m <wevutil | winevent>
    
    # Batch script
    # Powershell script
    # Bash script
    case $persistence_method in
        wevutil)
            WevUtil $antiforensics_mode $platform
            ;;
        winevent)
            WinEvent $antiforensics_mode $platform
            ;;
        eventvwr)
            EventViewer $antiforensics_mode $platform
            ;;
        *)
            echo "Invalid Antiforensic Technique!" >&2
            exit 1
            ;;
    esac
}

function usage() {
    cat << EOF
Usage: $0 (RemoteKeyStrokes)
Options:
    -c, --command <command | cmdfile>       Specify a command or a file containing to execute
    -i, --input <input_file>                Specify the local input file to transfer
    -o, --output <output_file>              Specify the remote output file to transfer

    -p, --platform <operating_system>       Specify the operating system (windows is set by
                                            default if not specified)

    -m, --method <method>                   Specify the file transfer or execution method
                                            (For file transfer "base64" is set by default if
                                            not specified. For command execution method
                                            "none" is set by default if not specified)

    -w, --windowname <name>	                Specify the window name for graphical remote
                                            program (freerdp is set by default if not
                                            specified)

    -h, --help                              Display this help message
EOF
    exit 1
}

long_opts="command:,input:,output:,platform:,method:,windowname:,help"

OPTS=$(getopt -o "c:i:o:p:m:w:h" --long "$long_opts" -n "$(basename "$0")" -- "$@")
if [ $? != 0 ]
then
    echo "Failed to parse options... Exiting." >&2
    exit 1
fi

eval set -- "${OPTS}"

while true
do
    case "$1" in
        -c | --command)
            COMMAND=$2
            shift 2
            ;;
        -i | --input)
            INPUT=$2
            shift 2
            ;;
        -o | --output)
            OUTPUT=$2
            shift 2
            ;;
        -p | --platform)
            PLATFORM=$2
            shift 2
            ;;
        -m | --method)
            METHOD=$2
            shift 2
            ;;
        -w | --windowname)
            WINDOWNAME=$2
            shift 2
            ;;
        -h | --help)
            usage
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Invalid option: $1" >&2
            exit 1
            ;;
    esac
done

function main() {
    check_dependencies

    if [ -z "$WINDOWNAME" ]
    then
        WINDOWNAME="FreeRDP"
    elif [[ "$WINDOWNAME" != "freerdp" && "$WINDOWNAME" != "rdesktop" && "$WINDOWNAME" != "tightvnc" ]]
    then
        echo "[-] Invalid window name specified. Allowed values: 'freerdp', 'rdesktop', or 'tightvnc'."
        exit 1
    fi

    # Select Remote Desktop Program to match the window name
    if [ "$WINDOWNAME" = "freerdp" ]
    then
        WINDOWNAME="FreeRDP"
    elif [ "$WINDOWNAME" = "rdesktop" ]
    then
        continue
    elif [ "$WINDOWNAME" = "tightvnc" ]
    then
        WINDOWNAME="TightVNC"
    fi

    # Operating System
    if [ -z "$PLATFORM" ]
    then
        PLATFORM="windows"
    elif [[ "$PLATFORM" != "windows" && "$PLATFORM" != "linux" ]]
    then
        echo "[-] Invalid or operating system not supported. Allowed values: 'windows' or 'linux'."
        exit 1
    fi

    # Executing commands
    if [ -f "$COMMAND" ]
    then
        # Check if a file is passed as input
        CmdFile "$COMMAND"
    fi
    
    if [[ ! -f "$COMMAND" && -n "$COMMAND" ]]
    then
		# When input is string and not a file. It executes command
		if [ -z "$METHOD" ]
		then
		    METHOD="none"
		fi
		Execute "$COMMAND" "$METHOD"
	fi
    
    # File transfer
    if [[ -f "$INPUT" && -n "$OUTPUT" ]]
    then
        OutputRemoteFile "$INPUT" "$OUTPUT" "$PLATFORM" "$METHOD"
    fi
    
    # Persistence method
    if [[ -n "$SELECT" && -n "$METHOD" ]]
    then
        # -s <info | backdoor | cleanup> -p <windows | linux> -m <persistence_method>
        Persistence "$SELECT" "$PLATFORM" "$METHOD"
    fi
}

main
