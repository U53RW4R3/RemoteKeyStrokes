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
    local local_file=$1

    while read -r line
    do
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$line"
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return
    done < $local_file
}

function Execute {
    local commands=$1
    local method=$2

    # TODO: Fill in the rest of the execution types
    case $method in
    	dialogbox)
    	   DialogBox
    	   ;;
    	msbuild)
    	   MSBuild
    	   ;;
    	*)
    	   echo "Invalid Execution Type!" >&2
    	   exit 1
    	   ;;
    esac
}

function DialogBox {
    # TODO: Calculate the character limit if it's greater or equal to 260 before execute the command
    echo "dialog"
}

function MSBuild {
    # TODO: Add two methods one for adding shellcode and the other for powershell runspace
    echo "msbuild"
}

function Base64 {
    local local_file=$1
    local output_file=$2
    local file_type=$(file "$local_file")
    
    # TODO: Finish the implementation
    if [[ $file_type == *"ASCII text"* ]]
    then
        echo "The file is ASCII text"
    elif [[ $file_type == *"ELF"*"LSB pie executable"* ]]
    then
        echo "The file is an ELF binary"
    elif [[ $file_type == *"PE32+ executable (DLL)"* ]]
    then
        echo "The file is a DLL binary"
    elif [[ $file_type == *"PE32+ executable"* ]]
    then
        echo "The file is an EXE binary"
    else
        echo "The file type is unknown"
    fi

}

function CopyCon {
    local file_content=$1
    local output_file=$2
    
    # Check one of the lines reached the 255 character limit
    while read -r line
    do
    	line_length=$(wc -c < "$line")
    	if [ "$line_length" -ge 255 ]
    	then
    	    echo "[!] Character Limit reached! Terminating program."
    	    exit 1
    	fi
    done < $file_content

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
    local method=$3

    # TODO: Fill in the rest of the transfer methods
    case $method in
    	"" | base64)
    	   Base64 $local_file $remote_file
    	   ;;
    	copycon)
    	   CopyCon $local_file $remote_file
    	   ;;
    	*)
    	   echo "Invalid Type Transfer!" >&2
    	   exit 1
    	   ;;
    esac
}

function usage() {
    cat << EOF
Usage: $0 [-c <command | cmdfile> | -i <input_file> -o <output_file>] [-w <windowname>] [-h]
Options:
    -c, --command <command | cmdfile>		Specify the file containing commands to execute
    -i, --input <input_file>         		Specify the local input file to transfer
    -o, --output <output_file>			Specify the remote output file to transfer
    -m, --method <method>			Specify the file transfer or execution method
						(For file transfer "base64" is set by default if
						not specified. For execution method "none" is set
						by default if not specified)

    -w, --windowname <name>			Specify the window name for RDP (freerdp is set
 						by default if not specified)

    -h, --help					Display this help message
EOF
    exit 1
}

long_opts="cmdfile:,input:,output:,method:,windowname:,help"

OPTS=$(getopt -o "c:i:o:m:w:h" --long "$long_opts" -n "$(basename "$0")" -- "$@")
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
    	if [ "$WINDOWNAME" = "freerdp" ]
    	then
    	    WINDOWNAME="FreeRDP"
    	elif [ "$WINDOWNAME" = "rdesktop" ]
    	then
    	    continue
    	elif [ "$WINDOWNAME" = "tightvnc" ]
    	then
    	    WINDOWNAME="TightVNC"
    	else
            echo "Invalid window name specified. Allowed values: 'freerdp', 'rdesktop', or 'tightvnc'."
            exit 1
        fi
    fi

    # TODO: Make an if statement when passed input as a string.
    # It executes a single line otherwise read the contents of the file.
    
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
        OutputRemoteFile "$INPUT" "$OUTPUT" "$METHOD"
    fi
}

main
