#!/bin/bash

function check_dependencies() {
    if ! which xdotool &>/dev/null
    then
        echo "[!] Installing missing dependency..."
        sudo apt install -y xdotool
        exit 1
    fi
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
            echo "[*] Executing commands..."
            DialogBox $commands
            echo "[+] Task completed!"
            ;;
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
        echo "[!] Character Limit reached! Terminating program."
        exit 1
    fi

    echo "[*] Executing commands..."
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Super_L+R
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$commands"
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return
    echo "[+] Task completed!"
}

function MSBuild {
    # TODO: Add two methods one for adding shellcode and the other for powershell runspace
    # Add a flag C# implant
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
    elif [ $file_type == "linux" ]
    then
        echo "Linux OS"
    fi

    echo "[*] File transferred!"
}

function CopyCon {
    local file_content=$1
    local output_file=$2

    if [ $platform != "windows" ]
    then
        echo "[!] copycon only exists on Windows operating system user! Try 'base64' method instead."
        exit 1
    fi
    
    echo "[*] Checking one of the lines reaches 255 character limit"
    while read -r line
    do
        line_length=$(wc -c < "$line")
        if [ "$line_length" -ge 255 ]
        then
            echo "[!] Character Limit reached! Terminating program."
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
    echo "[*] File transferred!"
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

function usage() {
    cat << EOF
Usage: $0 [-c <command | cmdfile> | -i <input_file> -o <output_file> -p <platform>] [-m <method>] [-w <windowname>] [-h]
Options:
    -c, --command <command | cmdfile>       Specify a command or a file containing to execute
    -i, --input <input_file>                Specify the local input file to transfer
    -o, --output <output_file>              Specify the remote output file to transfer
    -m, --method <method>                   Specify the file transfer or execution method
                                            (For file transfer "base64" is set by default if
                                            not specified. For execution method "none" is set
                                            by default if not specified)

    -p, --platform <operating_system>       Specify the operating system (windows is set by default
                                            if not specified)

    -w, --windowname <name>	                Specify the window name for graphical remote program (freerdp is set
                                            by default if not specified)

    -h, --help                              Display this help message
EOF
    exit 1
}

long_opts="command:,input:,output:,method:,platform:,windowname:,help"

OPTS=$(getopt -o "c:i:o:m:p:w:h" --long "$long_opts" -n "$(basename "$0")" -- "$@")
if [ $? != 0 ]
then
    echo "Failed to parse options... Exiting." >&2
    exit 1
fi

eval set -- "${OPTS}"

while true; do
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
        -m | --method)
            METHOD=$2
            shift 2
            ;;
        -p | --platform)
            PLATFORM=$2
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
        echo "Invalid window name specified. Allowed values: 'freerdp', 'rdesktop', or 'tightvnc'."
        exit 1
    fi

    # Matches the window name
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

    # Selecting operating system
    if [ -z "$PLATFORM" ]
    then
        PLATFORM="windows"
    elif [[ "$PLATFORM" != "windows" && "$PLATFORM" != "linux" ]]
    then
        echo "Invalid or operating system not supported. Allowed values: 'windows' or 'linux'."
        exit 1
    fi

    # Check if a file is provided
    if [ -f "$COMMAND" ]
    then
        CmdFile "$COMMAND"
    elif [[ -n "$COMMAND" && -n "$METHOD" ]]
    then
        # When input is string it executes command
        if [ -z "$METHOD" ]
        then
            METHOD="none"
        fi

        Execute "$COMMAND" "$METHOD"
    elif [ -f "$INPUT" ] && [ -n "$OUTPUT" ]
    then
        OutputRemoteFile "$INPUT" "$OUTPUT" "$PLATFORM" "$METHOD"
    fi
}

main
