#!/bin/bash
# """
# Script Name: deploy_application.py
# Description: Deploy any Django and React Web Application

# Owner: Kandukuri Kamal Hanesha
# Contributors:
#     - Alan PG
#     - Khavij V B
# """

# Create and update File
check_create_update_file(){
	file_path="$1"
	if [ -f $file_path ]; then
		echo  " $file_path - exists"
		echo  "────────────────────────────────────────────────────────────"
		cat $file_path
		echo  "────────────────────────────────────────────────────────────"
		read -p "Do you want to append to $file_path - Yes/No : " update_yes_no
		if [ "$update_yes_no" = "Yes" ]; then
			read -p "Enter the content to append : " update_file
			echo $update_file  >> $file_path
			echo  " updated $file_path"
			echo  "────────────────────────────────────────────────────────────"
			cat $file_path
			echo  "────────────────────────────────────────────────────────────"
		fi
	else
		read -p " $file_path does not exists - Do you want to create one  Yes/No: " create_file
		if [ "$create_file" = "Yes" ]; then
			read -p " Enter the content to add in the file : " file_content
			echo $file_content >> $file_path
			echo  "────────────────────────────────────────────────────────────"
			cat $file_path
			echo  "────────────────────────────────────────────────────────────"
		fi
	fi
	unset update_yes_no  update_file  create_file  file_content
}
#────────────────────────────────────────────────────────────
# Check a package is installed or not 
check_package_installed_or_not(){
	package="$1"
	echo  "────────────────────────────────────────────────────────────"
	if dpkg -l $package | grep -q "ii";then
		echo  " $package exists"
	else
		echo  " Installing $package"
		apt install $package
		apt update
		if dpkg -l $package | grep -q "ii";then
			echo  " $package installed successfully"
		fi
	fi
	if [ "$package" != "git" ]; then
		systemctl start $package
		systemctl enable $package
		systemctl is-active --quiet $package && systemctl is-enabled --quiet $package && echo  " Running & Enabled" || echo  "Not OK"
	fi 
	echo  "────────────────────────────────────────────────────────────"
	unset package
}
# ────────────────────────────────────────────────────────────
# check and install a package 
check_install_package(){
	package="$1"
	if dpkg -l $package | grep -q "ii";then
		echo  " $package exists"
	else
		echo " Installing $package"
		apt install $package
		apt update
		if dpkg -l $package | grep -q "ii";then
			echo  " $package installed successfully"
		fi
	fi
}
# ────────────────────────────────────────────────────────────
# Check Internet is connected or not 
check_internet(){
	if [ "$(nmcli -t -f CONNECTIVITY g)" = "full" ]; then
		echo  " Internet Connected"
	else
		echo  " Please connect to Internet"
		check_internet
	fi
}
# ────────────────────────────────────────────────────────────
# Check if a directory exists or not
check_directory_exists() {
    base_dir="$1"
    dir_name1="$2"
    # Find manage.py directory
    manage_dir=$(find "$project_root/" -type f -name "manage.py" -exec dirname {} \; )

    if [ -z "$manage_dir" ]; then
        echo  " manage.py not found under $project_root"
        return 1
    fi

    dir_name="$manage_dir/$dir_name1"

    if [ -d "$dir_name" ]; then
        # echo  " $dir_name folder exists: $dir_name"
		:
    else
        # echo  " Creating $dir_name folder: $dir_name"
        mkdir -p "$dir_name"
    fi
	echo "$dir_name"
}
# ────────────────────────────────────────────────────────────
# Function to add port inside an IfModule block
add_port_to_block() {
    MODULE=$1
    BLOCK_START=$(grep -n "<IfModule $MODULE>" "$PORTS_CONF" | cut -d: -f1)

    if [ -z "$BLOCK_START" ]; then
        echo "Warning: $MODULE block not found. Creating one."
        echo -e "\n<IfModule $MODULE>\n    Listen $PORT\n</IfModule>" | sudo tee -a "$PORTS_CONF" > /dev/null
    else
        # Find the end of the block
        BLOCK_END=$(tail -n +$BLOCK_START "$PORTS_CONF" | grep -n "</IfModule>" | head -n1 | cut -d: -f1)
        BLOCK_END_LINE=$((BLOCK_START + BLOCK_END - 1))
        # Insert the new Listen line before </IfModule>
        sudo sed -i "${BLOCK_END_LINE}i \    Listen $PORT" "$PORTS_CONF"
    fi
}
# ---------------------------------------------------------------
ssl_self_signed(){
    project_base_dir=$1
	echo  "────────────────────────────────────────────────────────────"
	echo "Installing OpenSSL"
	echo  "────────────────────────────────────────────────────────────"
	apt update
	apt install openssl
	apt install libssl-dev
	echo  "────────────────────────────────────────────────────────────"
	echo "Generating Private key"
	echo  "────────────────────────────────────────────────────────────"
	openssl genpkey -algorithm RSA -out /etc/ssl/certs/${project_base_dir}.key -aes256
	echo "private Key Path :  /etc/ssl/certs/${project_base_dir}.key"
	export private_key_path="/etc/ssl/certs/${project_base_dir}.key"
	echo  "────────────────────────────────────────────────────────────"
	echo  "────────────────────────────────────────────────────────────"
	echo "Generating CSR"
	echo  "────────────────────────────────────────────────────────────"
	openssl req -new -key ${private_key_path} -out /etc/ssl/certs/${project_base_dir}.csr
	export csr_path="/etc/ssl/certs/${project_base_dir}.csr"
	echo  "────────────────────────────────────────────────────────────"
	echo "Generating Certificate "
	echo  "────────────────────────────────────────────────────────────"

	openssl x509 -req -in ${csr_path} -signkey ${private_key_path} -out /etc/ssl/certs/${project_base_dir}.crt -days 365
	export certs_path="/etc/ssl/certs/${project_base_dir}.crt"
	echo  "────────────────────────────────────────────────────────────"
}
ca_certificate(){
	read -p "Are your SSL files in /etc/ssl/certs/? (yes/no): " conf_ssl_path
	if [[ "$conf_ssl_path" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]; then
		ssl_dir="/etc/ssl/certs"
	else
		read -p "Please enter the directory where your SSL files are located: " ssl_dir
	fi

	echo "Enter the file names (only names, not full paths):"

	read -p "Enter End Entity Certificate file name (e.g., endentity.cer): " end_entity
	read -p "Enter Chain Certificate file name (e.g., chain.cer): " chain_cert
	read -p "Enter Private Key file name (e.g., domain.key): " private_key

	# Build full paths
	export ca_end_entity_path="$ssl_dir/$end_entity"
	export ca_chain_cert_path="$ssl_dir/$chain_cert"
	export ca_private_key_path="$ssl_dir/$private_key"

	echo "Checking SSL files..."
	echo  "────────────────────────────────────────────────────────────"

	missing_files=()

	[[ ! -f "$ca_end_entity_path" ]] && missing_files+=("$end_entity")
	[[ ! -f "$ca_chain_cert_path" ]] && missing_files+=("$chain_cert")
	[[ ! -f "$ca_private_key_path" ]] && missing_files+=("$private_key")

	if (( ${#missing_files[@]} > 0 )); then
		echo "The following file(s) are missing in $ssl_dir:"
		for file in "${missing_files[@]}"; do
			echo "  - $file"
		done

		echo
		echo "Please move the missing file(s) to: $ssl_dir"
		echo "After moving, run the script again."
	else
		echo "All SSL files found successfully."
	fi

}
echo  "────────────────────────────────────────────────────────────"
echo "Script Information"
echo  "────────────────────────────────────────────────────────────"
echo "Owner       : K.Kamal Hanesha"
echo "Contributors: Alan P G, Khavij VB"
echo  "────────────────────────────────────────────────────────────"
echo "Before proceeding Please make sure you have the following :"
echo  "────────────────────────────────────────────────────────────"
echo "1.Please make sure you have Internet connected"
echo "2.URL to clone your Backend Django Project."
echo "3.Filename where all your python requirements specified."
echo "4.Folder name of Templates , Media"
echo "5.PostgresSQL Database details - database name ,username , password"
echo "6.Log Path and logfile to create"
echo "7.Django Super user details"
echo "8.Port in which you wish to host the server"
echo "9.SSL details - Self signed / CA / No SSL - Recommended SSL"
echo "10.Apache access log path and error log path"
echo "11.Server Alias and Redirect path for apache configuration"
echo "12.Select the static folder path - select from choices / Manually enter the path"
echo "13.Enter the path where Frontend react project exists"
echo "14.Confirm Build Updation"
echo "15.Confirm the index.html file"
echo  "────────────────────────────────────────────────────────────"

read -p "Press Enter to continue..."


echo  "────────────────────────────────────────────────────────────"

echo  " Script Execution started"
echo  "────────────────────────────────────────────────────────────"


echo  " Checking Internet"
check_internet
echo  "────────────────────────────────────────────────────────────"

echo  " checking sources.list exists"
check_create_update_file "/etc/apt/sources.list"
echo  "────────────────────────────────────────────────────────────"

echo  " checking /etc/hosts"
check_create_update_file "/etc/hosts"
echo  "────────────────────────────────────────────────────────────"

echo  " Installation and verification of apache2"
check_package_installed_or_not "apache2"


echo  " Installation and verification of postgresql"
check_package_installed_or_not "postgresql"


echo  " Installation and verification of git"
check_package_installed_or_not "git"




read -p "Enter the Directory name to be used in /opt/ : " project_base_dir
export project_base_dir
echo  "────────────────────────────────────────────────────────────"
echo " Creating Base Directory"
cd /opt/ ; mkdir $project_base_dir
echo "Created $project_base_dir in /opt/"
echo  "────────────────────────────────────────────────────────────"

echo " Listing files and folders in opt folder"
echo  "────────────────────────────────────────────────────────────"
ls /opt/
echo  "────────────────────────────────────────────────────────────"

echo  " Cloning Project"
echo  "────────────────────────────────────────────────────────────"
read -p "Enter the git clone url  to Clone the project into /opt/$project_base_dir : " git_url
cd /opt/$project_base_dir/
# set -e
git clone $git_url
echo  "────────────────────────────────────────────────────────────"

echo  " Checking Python version"
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo  " $python_version"
echo  "────────────────────────────────────────────────────────────"

echo  " Installing Virtual Environment"
apt install python$python_version-venv
check_install_package "python${python_version}-venv"
echo  "────────────────────────────────────────────────────────────"

echo  " Creating Virtual Environment"
cd /opt/$project_base_dir/
python$python_version -m venv "${project_base_dir}_env"

source /opt/$project_base_dir/"${project_base_dir}_env"/bin/activate
echo  " Path of virtual environment /opt/${project_base_dir}/${project_base_dir}_env"
echo  "────────────────────────────────────────────────────────────"

echo  " listing all folder hierarchy : "
echo  "────────────────────────────────────────────────────────────"
# ls -R /opt/${project_base_dir}/
echo  "────────────────────────────────────────────────────────────"
echo  "────────────────────────────────────────────────────────────"
# tree /opt/${project_base_dir}/
echo  "────────────────────────────────────────────────────────────"

echo  " Setting up backend server"
echo  "────────────────────────────────────────────────────────────"

echo  " Installing Requirements"
echo  "────────────────────────────────────────────────────────────"
read -p "Enter the file name where requirements for Backend Server is listed : " requirements_filename
requirements_path=$(find /opt/$project_base_dir/ -iname $requirements_filename)
pip install -r $requirements_path
echo  " Requirements installed successfully"
echo  "────────────────────────────────────────────────────────────"

# echo  " Create and Verify - Logs "
# echo  "────────────────────────────────────────────────────────────"
# read -p "Enter the folder name of logs  : " logs_filename
# echo  "────────────────────────────────────────────────────────────"

echo  " Create and Verify - Media "
read -p "Enter the folder name of  media : " media_filename
echo  "────────────────────────────────────────────────────────────"

echo  " Create and Verify - Templates "
read -p "Enter the folder name of  templates : " template_filename
echo  "────────────────────────────────────────────────────────────"

project_root="/opt/$project_base_dir"
templates_path=$(check_directory_exists "$project_root" "$template_filename")
media_path=$(check_directory_exists "$project_root" "$media_filename")
echo "Template path : $templates_path"
echo  "────────────────────────────────────────────────────────────"
# echo "Logs path : $logs_path"
# echo  "────────────────────────────────────────────────────────────"
echo "Media path : $media_path"
echo  "────────────────────────────────────────────────────────────"


echo  "Setting up database"
echo  "────────────────────────────────────────────────────────────"
read -p "Enter the Database name : " db_name
read -p "Enter the Database user : " db_user
read -p "Enter the password for the $db_user : " db_password
echo  "────────────────────────────────────────────────────────────"
echo  "Creating  database"
sudo -u postgres psql -c "create database $db_name;" 
echo  "Creating Database user with password"
sudo -u postgres psql -c "create user $db_user with password '$db_password';" 
echo  "Granting previleges on $db_name to $db_user"
sudo -u postgres psql -c "grant all privileges on database $db_name to $db_user ;"
echo "Alerting Ownership of database"
sudo -u postgres psql -c "ALTER DATABASE $db_name OWNER TO $db_user;"
echo "Database setup completed"
echo  "────────────────────────────────────────────────────────────"
cd /opt/$project_base_dir/
export document_root=$(find "/opt/$project_base_dir" -type d -name ".git" | sed 's|/.git$||')
echo "$document_root"

export git_folder=$(find "/opt/$project_base_dir/" -type d -name ".git" -print -quit | sed 's|/.git$||; s|.*/||' )


export project_root=$(find . -name manage.py -exec dirname {} \;)
cd $project_root


echo  "────────────────────────────────────────────────────────────"

echo "Changing owner to  www-data:www-data for $document_root"
echo  "────────────────────────────────────────────────────────────"
chown -R www-data:www-data $document_root
echo "Changed owner to  www-data:www-data for $project_base_dir"
echo  "────────────────────────────────────────────────────────────"

echo "Activating Virtual Environment"
source /opt/$project_base_dir/"${project_base_dir}_env"/bin/activate
echo  "────────────────────────────────────────────────────────────"
# echo $document_root/
# echo  "────────────────────────────────────────────────────────────"

read -p "Enter the path where logs file to be created: " logs_path
# Create folder if missing
if [ ! -d "$logs_path" ]; then
    echo "Path does not exist. Creating directory..."
    sudo mkdir -p -- "$logs_path"
fi

# Confirm folder exists
if [ ! -d "$logs_path" ]; then
    echo "ERROR: Directory could not be created: $logs_path"
fi
read -p "Do you want to create log file in $logs_path Yes / No: " logfile
echo  "────────────────────────────────────────────────────────────"
if [ "$logfile" = "Yes" ]; then
			read -p "Enter File name:" filename
			cd $logs_path
			touch $filename
			ls $logs_path
			echo "Granting permission to Log file"
			chmod a+rwx "$logs_path/$filename"
			echo  "────────────────────────────────────────────────────────────"
			echo "Log File created successfully"
			echo  "────────────────────────────────────────────────────────────"
			cd -
			
fi

echo "Running Make migrations command"
echo  "────────────────────────────────────────────────────────────"

echo  "────────────────────────────────────────────────────────────"

python manage.py makemigrations
echo  "────────────────────────────────────────────────────────────"



echo "Running  migrate command"
echo  "────────────────────────────────────────────────────────────"
python manage.py migrate
echo  "────────────────────────────────────────────────────────────"

echo "Creating super user"
echo  "────────────────────────────────────────────────────────────"
python manage.py createsuperuser
echo  "────────────────────────────────────────────────────────────"

echo "Testing Backend"
echo  "────────────────────────────────────────────────────────────"
python manage.py runserver
echo  "────────────────────────────────────────────────────────────"


apt update
echo "Hosting the application in apache2"
echo  "────────────────────────────────────────────────────────────"

echo "Installing libapache2-mod-wsgi-py3"
echo  "────────────────────────────────────────────────────────────"
apt install libapache2-mod-wsgi-py3
echo  "────────────────────────────────────────────────────────────"

echo "Enabling libapache2-mod-wsgi-py3"
echo  "────────────────────────────────────────────────────────────"
a2enmod wsgi 
echo  "────────────────────────────────────────────────────────────"

echo "Creating the configuration file"
echo  "────────────────────────────────────────────────────────────"
cd /etc/apache2/sites-available/
touch $project_base_dir.conf
export apache_conf_file=$"/etc/apache2/sites-available/$project_base_dir.conf"
ls /etc/apache2/sites-available/

echo  "────────────────────────────────────────────────────────────"

export SERVER_IP=$(ip addr show | awk '/inet / && !/127.0.0.1/ {print $2}' | cut -d/ -f1)

# If no IP detected, ask the user
if [ -z "$SERVER_IP" ]; then
    echo "No IP address detected automatically."
    read -p "Please enter the IP address manually: " SERVER_IP
fi
echo "Using IP address: $SERVER_IP"
echo  "────────────────────────────────────────────────────────────"
echo "Ports available in Apache2 "
grep -Ri "Listen" /etc/httpd/conf /etc/apache2/ 2>/dev/null | grep -vE '^#' | grep -oP '(\d+)$' | sort -nu | paste -sd "," -
echo  "────────────────────────────────────────────────────────────"

#!/bin/bash

# Apache ports configuration file
echo  "────────────────────────────────────────────────────────────"

PORTS_CONF="/etc/apache2/ports.conf"
echo  "────────────────────────────────────────────────────────────"
# Ask user for the port
read -p "Enter the SSL port to add: " PORT

# Validate numeric port
if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
    echo "Invalid port number."
	PORT = 443
fi

# Check if port already exists
if grep -Riq "Listen.*\b$PORT\b" "$PORTS_CONF"; then
    echo "Port $PORT already exists. OK."
fi
export PORT
echo  "────────────────────────────────────────────────────────────"

# Function to check and add port only if missing
add_port_to_block() {
    module="$1"
    conf_file="$PORTS_CONF"

    # Check if the port already exists inside this IfModule block
    if grep -A2 -E "<IfModule ${module}>" "$conf_file" | grep -q "Listen ${PORT}"; then
        echo "Port $PORT already exists in <$module> block. Skipping..."
        return
    fi

    # Add the port if not found
    sed -i "/<IfModule ${module}>/a\    Listen ${PORT}" "$conf_file"
    echo "Port $PORT added inside <$module> block."
}

# Add to SSL blocks
add_port_to_block "ssl_module"
add_port_to_block "mod_gnutls.c"

echo "────────────────────────────────────────────────────────────"
echo "Port addition process completed."
echo "────────────────────────────────────────────────────────────"
cat /etc/apache2/ports.conf
echo "────────────────────────────────────────────────────────────"

# Optional: reload Apache
systemctl reload apache2   
echo  "────────────────────────────────────────────────────────────"
read -p "SSL - Do you want to add SSL? Yes/No : " ssl_choice
if [[ "$ssl_choice" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]; then
    echo "SSL selected."
    # Ask for SSL type
    echo "Do you want to use a self-signed certificate or a CA certificate? (self/ca)"
    read ssl_type
	echo  "────────────────────────────────────────────────────────────"

    if [[ "$ssl_type" =~ ^([Ss][Ee][Ll][Ff]|self)$ ]]; then
        echo "Self-signed certificate selected."
		ssl_self_signed ${project_base_dir}
    elif [[ "$ssl_type" =~ ^([Cc][Aa]|ca)$ ]]; then
        echo "CA certificate selected."
		ca_certificate ${project_base_dir}

    else
        echo "Invalid SSL type. Please enter 'self' or 'ca'."
    fi
	echo  "────────────────────────────────────────────────────────────"

else
    echo "SSL not selected. Continuing without SSL..."
fi
echo  "────────────────────────────────────────────────────────────"
read -p "Enter error log path: " error_log
read -p "Enter access log path: " access_log
echo  "────────────────────────────────────────────────────────────"

error_dir=$(dirname "$error_log")
access_dir=$(dirname "$access_log")
echo  "────────────────────────────────────────────────────────────"

if [ ! -d "$error_dir" ]; then
    echo "Directory $error_dir does not exist. Creating..."
    mkdir -p "$error_dir"
fi
if [ ! -d "$access_dir" ]; then
    echo "Directory $access_dir does not exist. Creating..."
    mkdir -p "$access_dir"
fi

echo "Directories ready."
echo "ErrorLog $error_log"
echo "CustomLog $access_log combined"
echo  "────────────────────────────────────────────────────────────"

read -p "Do you want to add a ServerAlias? yes/no: " add_alias
echo  "────────────────────────────────────────────────────────────"

server_alias=""

if [[ "$add_alias" =~ ^(yes|y)$ ]]; then
    read -p "Enter ServerAlias: " server_alias
    echo "ServerAlias added: $server_alias"
else
    echo "No ServerAlias will be added."
fi
echo  "────────────────────────────────────────────────────────────"
read -p "Do you want to add a Redirect permanent rule? yes/no: " add_redirect
echo  "────────────────────────────────────────────────────────────"

redirect_url=""

if [[ "$add_redirect" =~ ^(yes|y)$ ]]; then
    read -p "Enter the URL/path to redirect Url : " redirect_url

    echo "Redirect will be added: Redirect permanent  $redirect_url"
else
    echo "No redirect rule will be added."
fi

echo  "────────────────────────────────────────────────────────────"

echo "Searching for 'static' folders inside $document_root ..."
mapfile -t static_paths < <(find "$document_root" -type d -name "static")
echo  "────────────────────────────────────────────────────────────"

# If static folders found
if (( ${#static_paths[@]} > 0 )); then
    echo "Found the following 'static' directories:"
    i=1
    for path in "${static_paths[@]}"; do
        echo "  $i) $path"
        ((i++))
    done

    echo "  0 Enter a custom path"
    
    # Ask user to choose
    read -p "Select a number: " choice

    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#static_paths[@]} )); then
        selected_path="${static_paths[$((choice-1))]}"
        echo "You selected: $selected_path"
    else
        read -p "Enter custom static folder path: " selected_path
    fi

else
    echo "No 'static' directory found. Please enter one manually."
    read -p "Enter static folder path: " selected_path
fi
export selected_path
echo "Final static folder path: $selected_path"
echo  "────────────────────────────────────────────────────────────"
export wsgi_dir=$(find "$document_root" -type f -name "wsgi.py" -exec dirname {} \; )
config=""
if [[ "$ssl_choice" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]; then
	config+="<IfModule mod_ssl.c>"
fi
config+="
<VirtualHost *:$PORT>
    ServerName $SERVER_IP
"

# ------------------------------
# ServerAlias
# ------------------------------
if [[ "$add_alias" =~ ^(yes|y)$ ]]; then
    config+="    ServerAlias $server_alias
"
fi

# ------------------------------
# SSL SECTION
# ------------------------------
if [[ "$ssl_choice" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]; then

    if [[ "$ssl_type" =~ ^([Ss][Ee][Ll][Ff]|self)$ ]]; then
        config+="    SSLEngine on
    SSLCertificateFile    $certs_path
    SSLCertificateKeyFile $private_key_path
"
    elif [[ "$ssl_type" =~ ^([Cc][Aa]|ca)$ ]]; then
        config+="    SSLEngine on
    SSLCertificateFile    $ca_end_entity_path
    SSLCertificateChainFile $ca_chain_cert_path
    SSLCertificateKeyFile $ca_private_key_path
"
    fi

fi


# ------------------------------
# MAIN BLOCK
# ------------------------------
config+="    DocumentRoot $document_root/
    <Directory \"$document_root/\">
            Require all granted

        <FilesMatch \"^\\.\">
            Require all denied
        </FilesMatch>
    </Directory>

    <IfModule mod_rewrite.c>
        RewriteEngine on
        RewriteRule ^.* - [F,L]
        RewriteCond %{HTTP_USER_AGENT} !12d41f4a6b7a12c6481e9145ceac9f8f
        RewriteCond %{HTTP_USER_AGENT} !^.*Chrome.*$
        RewriteCond %{HTTP_USER_AGENT} !^.*Mozilla.*$
        RewriteCond %{HTTP_USER_AGENT} !^.*AppleWebKit.*$
        RewriteCond %{HTTP_USER_AGENT} !^.*Safari.*$
        RewriteRule ^.* - [F,L]
    </IfModule>

    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security \"max-age=63072000; includeSubdomains; preload\"
        Header set X-XSS-Protection \"1; mode=block\"
        Header always set X-Content-Type-Options nosniff
        Header always set X-Download-Options noopen
        Header always append X-Frame-Options DENY
        Header edit Set-Cookie ^(.*)$ \"\\1;HttpOnly;Secure\"
        Header set Server \"$project_base_dir\"
        Header unset X-Forwarded-Host
    </IfModule>

    WSGIDaemonProcess $git_folder python-home=/opt/$project_base_dir/${project_base_dir}_env/ python-path="/opt/test/$project_root/"
    WSGIProcessGroup $git_folder

    WSGIScriptAlias / $wsgi_dir/wsgi.py
    WSGIApplicationGroup %{GLOBAL}
    WSGIPassAuthorization On


    ErrorLog $error_log
    CustomLog $access_log combined
    UseCanonicalName On

    <Directory $wsgi_dir/>
        <Files wsgi.py>
            Require all granted
        </Files>
    </Directory>

    Alias /static $selected_path
    <Directory $selected_path>
        Require all granted
        FileETag None
    </Directory>

"
# # ------------------------------
# # Proxy Section (SSL / NON-SSL)
# # ------------------------------
# if [[ "$ssl_choice" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]; then
#     config+="ProxyPass /api/ https://$SERVER_IP/
#     ProxyPassReverse /api/ https://$SERVER_IP/
#     ProxyPreserveHost On
# "
# else
#     config+="ProxyPass /api/ http://$SERVER_IP/
#     ProxyPassReverse /api/ http://$SERVER_IP/
#     ProxyPreserveHost On
# "
# fi
config+="</VirtualHost>"

if [[ "$ssl_choice" =~ ^([Yy][Ee][Ss]|[Yy])$ ]]; then
	config+="
	</IfModule>"
fi
config+="
<VirtualHost *:80>
    ServerName $SERVER_IP
"

# ------------------------------
# ServerAlias in port 80 block
# ------------------------------
if [[ "$add_alias" =~ ^(yes|y)$ ]]; then
    config+="    ServerAlias $server_alias
"
fi

# ------------------------------
# Redirect block
# ------------------------------
if [[ "$add_redirect" =~ ^(yes|y)$ ]]; then
    config+="    Redirect permanent / $redirect_url
"
fi

# ------------------------------
# MAIN HTTP BLOCK
# ------------------------------
config+="    <Directory $document_root/>
                Require all granted

    </Directory>

    <IfModule mod_rewrite.c>
        RewriteEngine on
        RewriteCond %{HTTP_USER_AGENT} !12d41f4a6b7a12c6481e9145ceac9f8f
        RewriteCond %{HTTP_USER_AGENT} !^.*Chrome.*$
        RewriteCond %{HTTP_USER_AGENT} !^.*Mozilla.*$
        RewriteCond %{HTTP_USER_AGENT} !^.*AppleWebKit.*$
        RewriteCond %{HTTP_USER_AGENT} !^.*Safari.*$
        RewriteRule ^.* - [F,L]
    </IfModule>

    DocumentRoot $document_root/
    UseCanonicalName On

    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security \"max-age=63072000; includeSubdomains; preload\"
        Header set X-XSS-Protection \"1; mode=block\"
        Header always set X-Content-Type-Options nosniff
        Header always set X-Download-Options noopen
        Header always append X-Frame-Options DENY
        Header edit Set-Cookie ^(.*)$ \"\\1;HttpOnly;Secure\"
        Header set Server \"$project_base_dir\"
        Header unset X-Forwarded-Host
    </IfModule>
</VirtualHost>
"


# ------------------------------
# Write config to file
# ------------------------------
echo "$config" > "$apache_conf_file"
echo  "────────────────────────────────────────────────────────────"
echo "Apache configuration generated and updated in $apache_conf_file"
echo  "────────────────────────────────────────────────────────────"
echo "Enabling ssl"
echo  "────────────────────────────────────────────────────────────"

sudo a2enmod ssl
echo  "────────────────────────────────────────────────────────────"
echo "Restarting Apache2"
echo  "────────────────────────────────────────────────────────────"

sudo systemctl restart apache2
echo  "────────────────────────────────────────────────────────────"

# Disable all enabled sites
# Disable only the default site
echo  "────────────────────────────────────────────────────────────"
echo "Disabling default configuration"
echo  "────────────────────────────────────────────────────────────"

sudo a2dissite 000-default.conf 2>/dev/null
echo  "────────────────────────────────────────────────────────────"
echo "reloading Apache2"

echo  "────────────────────────────────────────────────────────────"

# Reload apache to apply change
sudo systemctl reload apache2
echo  "────────────────────────────────────────────────────────────"

# Show remaining active sites
echo "Remaining enabled Apache sites:"
ls -1 /etc/apache2/sites-enabled/
echo  "────────────────────────────────────────────────────────────"

systemctl reload apache2
echo  "────────────────────────────────────────────────────────────"
echo "Enabling configuration"
cd /etc/apache2/sites-enabled/
a2ensite "$project_base_dir.conf"
echo "────────────────────────────────────────────────────────────"
systemctl reload apache2
echo  "────────────────────────────────────────────────────────────"
echo "testing configuration"
# Debian/Ubuntu
apache2ctl configtest
echo  "────────────────────────────────────────────────────────────"
echo "Restarting Apache2"

echo  "────────────────────────────────────────────────────────────"

systemctl restart apache2
echo  "────────────────────────────────────────────────────────────"
echo "Fetching Frontend directory"
echo  "────────────────────────────────────────────────────────────"
find_build() {
    while true; do
        read -p "Enter the base directory to search for frontend build folder without / at end: " frontend_dir

        # Validate directory
        if [ ! -d "$frontend_dir" ]; then
            echo "Directory does not exist. Please enter a valid path."
            continue
        fi

        # Search for build folder
        build_dir=$(find "$frontend_dir" -type d -name build -print -quit)

        if [ -n "$build_dir" ]; then
            echo "Build folder found at: $build_dir"
            export build_dir
            break
        else
            echo "No build folder found under '$frontend_dir'. Try again."
        fi
    done
}

find_build


build_static="$build_dir/static/"
backend_static="$selected_path"

# If empty, use default
templates_folder=${template_filename:-templates}

# Build the full path
echo $document_root
manage_dir=$(find "$document_root" -type f -name "manage.py" -exec dirname {} \; | head -n 1)

TEMPLATES_DEST="${manage_dir}/${templates_folder}/"

# Print the result
echo "Templates directory resolved to: $TEMPLATES_DEST"
echo  "────────────────────────────────────────────────────────────"

mkdir -p "$backend_static"
mkdir -p "$TEMPLATES_DEST"
echo  "────────────────────────────────────────────────────────────"
echo "Cleaning existing static files..."
echo  "────────────────────────────────────────────────────────────"

# Delete all files and directories in the static destination
if [ -d "$backend_static" ]; then
    rm -rf "$backend_static"/* 
fi
echo  "────────────────────────────────────────────────────────────"
echo "Copying static files..."
echo  "────────────────────────────────────────────────────────────"

# Copy all files and directories from source to destination
cp -r "$build_static"* "$backend_static"

echo "Static files copied successfully!"
echo  "────────────────────────────────────────────────────────────"

# Update index.html
if [ -f "$build_dir/index.html" ]; then
    echo "Updating index.html..."
    rm -f "$TEMPLATES_DEST/index.html"   # Delete old index.html
    cp "$build_dir/index.html" "$TEMPLATES_DEST"   # Copy new file
    echo "Copied: $build_dir/index.html -> $TEMPLATES_DEST"
else
    echo "File index.html not found in source directory."
fi

nano "$TEMPLATES_DEST/index.html"

echo "────────────────────────────────────────────────────────────"

# Update manifest.json
if [ -f "$build_dir/manifest.json" ]; then
    echo "Updating manifest.json..."
    rm -f "$backend_static/manifest.json"   # Delete old manifest.json
    cp "$build_dir/manifest.json" "$backend_static"   # Copy new file
    echo "Copied: $build_dir/manifest.json -> $backend_static"
else
    echo "File manifest.json not found in source directory."
fi

echo "────────────────────────────────────────────────────────────"
echo "Restarting apache2"
systemctl restart apache2
echo  "────────────────────────────────────────────────────────────"
echo "Build Updated successfully!"
echo "────────────────────────────────────────────────────────────"
echo "Script executed successfully."
echo "────────────────────────────────────────────────────────────"
