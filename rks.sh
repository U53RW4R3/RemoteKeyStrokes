#!/bin/bash

function check_dependencies() {
    if ! which xdotool &>/dev/null
    then
        echo "[!] Installing missing dependency..."
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

function Base64 {
    local file_content=$1
    local output_file=$2
    
    # TODO: Finish the implementation
}

function CopyCon {
    local file_content=$1
    local output_file=$2

    xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "copy con $output_file"
    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return

    while read -r line
    do
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$line"
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return
    done < $file_content

    xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Ctrl+Z Return
}

function OutputRemoteFile {
    local local_file=$1
    local remote_file=$2
    local transfer_type=$3

    # TODO: Fill in the rest of the transfer methods
    case $transfer_type in
    	"" | base64)
    	   Base64 $local_file $remote_file
    	   ;;
    	copycon)
    	   CopyCon $local_file $remote_file
    	   ;;
    	*)
    	   echo -n "Invalid Type Transfer!"
    	   ;;
    esac
}

function usage() {
    cat << EOF
Usage: $0 [-c <cmdfile> | -i <input> -o <tofile>] [-w <windowname>] [-h]
Options:
    -c, --cmdfile <cmdfile>     Specify the file containing commands to execute
    -i, --input <input>         Specify the input file to transfer
    -o, --tofile <tofile>       Specify the output file to transfer
    -t, --type <transfer_type>  Specify the transfer type (base64 is set by
    				default if not specified)

    -w, --windowname <name>     Specify the window name for RDP (FreeRDP is set
                                by default if not specified)

    -h, --help                  Display this help message
EOF
    exit 1
}

long_opts="cmdfile:,input:,tofile:,type:,windowname:,help"

OPTS=$(getopt -o "c:i:o:t:w:h" --long "$long_opts" -n "$(basename "$0")" -- "$@")
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
	-t | --type)
            TYPE=$2
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
    elif [[ "$WINDOWNAME" != "FreeRDP" && "$WINDOWNAME" != "rdesktop"  != "TightVNC" ]]
    then
        echo "Invalid window name specified. Allowed values: 'FreeRDP', 'rdesktop', or 'TightVNC'."
        exit 1
    fi

    if [ -n "$CMDFILE" ]
    then
        InputFile "$CMDFILE"
    elif [ -n "$INPUT" ] && [ -n "$OUTPUT" ] && [ -n "$TYPE" ]
    then
        OutputRemoteFile "$INPUT" "$OUTPUT" "$TYPE"
    fi
}

main
