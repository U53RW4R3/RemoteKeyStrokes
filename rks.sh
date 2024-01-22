#!/bin/bash

function check_dependencies() {
    if ! which xdotool &>/dev/null
    then
        echo "[!] xdotool is missing! Installing dependency."
        sudo apt install -y xdotool
        exit 1
    fi
}

function InputFile {
    local local_file=$1

    while read -r line
    do
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$line"
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return
    done < $local_file
}

function OutputRemoteFile {
    local file_content=$1
    local remote_file=$2

    xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "copy con $remote_file"
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return

    while read -r line
    do
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$line"
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return
    done < $file_content

    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Ctrl+Z Return
}

function usage() {
    cat << EOF
Usage: $0 [-c <cmdfile> | -i <input> -o <tofile>] [-w <windowname>] [-h]
Options:
    -c, --cmdfile <cmdfile>     Specify the file containing commands to execute
    -i, --input <input>         Specify the input file to transfer
    -o, --tofile <tofile>       Specify the output file to transfer
    -w, --windowname <name>     Specify the window name for RDP (FreeRDP is set
                                by default if not specified)

    -h, --help                  Display this help message
EOF
    exit 1
}

long_opts="cmdfile:,input:,tofile:,windowname:,help"

OPTS=$(getopt -o "c:i:o:w:h" --long "$long_opts" -n "$(basename "$0")" -- "$@")
if [ $? != 0 ]
then
    echo "Failed to parse options... Exiting." >&2
    exit 1
fi

eval set -- "${OPTS}"

while true; do
    case "$1" in
        -c | --cmdfile)
            CMDFILE=$2
            shift 2
            ;;
        -i | --input)
            INPUT=$2
            shift 2
            ;;
        -o | --tofile)
            OUTPUT=$2
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
    elif [[ "$WINDOWNAME" != "FreeRDP" && "$WINDOWNAME" != "rdesktop" ]]
    then
        echo "Invalid window name specified. Allowed values: 'FreeRDP' or 'rdesktop'."
        exit 1
    fi

    if [ -n "$CMDFILE" ]
    then
        InputFile "$CMDFILE"
    elif [ -n "$INPUT" ] && [ -n "$OUTPUT" ]
    then
        OutputRemoteFile "$INPUT" "$OUTPUT"
    fi
}

main
