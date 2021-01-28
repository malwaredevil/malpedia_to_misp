#!/bin/bash
set -e

if [[ "$(whoami)" != root ]]; then
  echo "Only user root can run this script."
  exit 1
fi
_RANDOM_PASSWORD=$(date +%s | sha256sum | base64 | head -c 32)
_EMPTY_STRING=0


_MISP_KEY_INPUT="${_EMPTY_STRING}"
_MISP_URL_INPUT="${_EMPTY_STRING}"
_MALPEDIA_KEY_INPUT="${3:-$_EMPTY_STRING}"
_POSTGRES_HOST_INPUT="${6:-localhost}"
_POSTGRES_PORT_INPUT="${7:-5432}"
_POSTGRES_USER_INPUT="${8:-mptomisp}"
_POSTGRES_PASSWORD_INPUT="${9:-$_RANDOM_PASSWORD}"


# SEE IF ANY PARAMETERIZED ARGS ARE THERE
while [[ $# -gt 0 ]]; do
    opt="$1"
    shift;
    current_arg="$1"
    if [[ "$current_arg" =~ ^-{1,2}.* ]]; then
        echo "WARNING: You may have left an argument blank. Double check your command." 
    fi
    case $opt in
        "-h" ) # process option h 
            echo "Usage:"
            echo "  ./bootstrap.sh -m MISPKEY -u MISPURL -k MALPEDIAKEY -p POSTGRESSERVER -o POSTGRESPORT -u POSTGRESUSER -x PASSWORD"
            echo "    -m or --misp-key:            Must be a valid MISP key."
            echo "    -k or --misp-url:            Must be the url of a valid MISP instance in the form of https://misp.local/."
            echo "    -u or --malpedia-key:        Must be a valid Malpedia key."
            echo "    -l or --postgres-server:     IP or fqdn of PostgreSQL server (e.g. 10.10.10.10, localhost, postgres.local, etc.)"
            echo "    -t or --postgres-port:       PostgreSQL server port."
            echo "    -r or --postgres-user:       PostgreSQL server username."
            echo "    -a or --postgres-password:   PostgreSQL server password."
            exit
            ;;
        "-m"| "--misp-key" ) 
            _MISP_KEY_INPUT="$1";  shift;;
        "-k"| "--misp-url" ) 
            _MISP_URL_INPUT="$1";  shift;;
        "-u"| "--malpedia-key" ) 
            _MALPEDIA_KEY_INPUT=$1;  shift;;
        "-l"| "--postgres-server" ) 
            _POSTGRES_HOST_INPUT="$1";  shift;;
        "-t"| "--postgres-port" ) 
            _POSTGRES_PORT_INPUT="$1";  shift;;
        "-r"| "--postgres-user" ) 
            _POSTGRES_USER_INPUT="$1";  shift;;
        "-a"| "--postgres-password") 
            _POSTGRES_PASSWORD_INPUT="$1";  shift;;
        * ) 
            echo "Type \"./bootstrap.sh -h\" for help."
            exit
        ;;
    esac
done
YELLOW="\033[1;33m"
BOLD="\e[1m"
NC="\033[0m" # No Color
if [ "$_MISP_KEY_INPUT" = "$_EMPTY_STRING" ] || [ "$_MISP_URL_INPUT" = "$_EMPTY_STRING" ] || [ "$_MALPEDIA_KEY_INPUT" = "$_EMPTY_STRING" ]
then
    echo -e " ${YELLOW}${BOLD}"
    echo "***********************************************************************************"
    echo "***********************************************************************************"
    echo "**        This script must be run using root permissions.                        **"
    echo "**        Before running, make sure that the root user has an                    **"
    echo "**        SSH key registered with Malpedia so you can download                   **"
    echo "**        from the git repo. For instructions see:                               **"
    echo "**        'Adding a Deploy Key (SSH) for repository access'                      **" 
    echo "**        https://malpedia.caad.fkie.fraunhofer.de/usage/website                 **"
    echo "**        Additionally the ssh-agent must be started and the key                 **"
    echo "**        must be registered/added to the ssh-agent (ssh-add -k ~/.ssh/id_rsa)   **"
    echo "**        for both root and the sudo user that will be executing                 **"
    echo "**        the malpedia to misp ingestor tool.                                    **"
    echo "***********************************************************************************"
    echo "***********************************************************************************"
    echo -e  " ${NC}"
    echo -e "${YELLOW}${BOLD}"
    while true; do
        read -p "[?] Are you ready to proceed? " yn
        case $yn in
            [Yy]* ) break;;
            [Nn]* ) exit;;
            * ) echo "[?] Please answer yes or no.";;
        esac
    done

    mkdir -p /opt/m2m/dependencies
    while true; do
        echo " "
        echo " "
        # echo $_MISP_KEY_INPUT
        echo "[?] Please enter your MISP key: "
        read _MISP_KEY_INPUT
        echo " "
        echo " "
        # echo $_MISP_URL_INPUT
        echo "[?] Please enter your MISP url (e.g. https://misp.local/): "
        read _MISP_URL_INPUT
        echo " "
        echo " "
        # echo $_MALPEDIA_KEY_INPUT
        echo "[?] Please enter your Malpedia key: "
        read _MALPEDIA_KEY_INPUT
        echo " "
        echo " "
        # echo $_POSTGRES_HOST_INPUT
        echo "[?] Please enter your PostgreSQL server (e.g. 10.10.10.10, localhost, 127.0.0.1, server.local, etc.). Default is localhost if left blank: "
        read _POSTGRES_HOST_INPUT
        _POSTGRES_HOST_INPUT="${_POSTGRES_HOST_INPUT:-localhost}"
        echo " "
        echo " "
        # echo $_POSTGRES_PORT_INPUT
        echo "[?] Please enter your PostgreSQL server's port(default is 5432). Default is 5432 if left blank: "
        read _POSTGRES_PORT_INPUT
        _POSTGRES_PORT_INPUT="${_POSTGRES_PORT_INPUT:-5432}"
        echo " "
        echo " "
        # echo $_POSTGRES_USER_INPUT
        echo "[?] Please enter your PostgreSQL username. Default is mptomisp if left blank: "
        read _POSTGRES_USER_INPUT
        _POSTGRES_USER_INPUT="${_POSTGRES_USER_INPUT:-mptomisp}"
        echo " "
        echo " "
        # echo $_POSTGRES_PASSWORD_INPUT
        
        while true; do
            read -p "Type a password for PostgreSQL. Default is a randomly generated password if left blank: " _POSTGRES_PASSWORD_INPUT
            echo
            read -p "Retype Password. Default is a randomly generated password if left blank: " _POSTGRES_PASSWORD_INPUT2
            echo
            [ "$_POSTGRES_PASSWORD_INPUT" = "$_POSTGRES_PASSWORD_INPUT2" ] && break
            echo "Passwords do not match. Please try again."
        done
        _POSTGRES_PASSWORD_INPUT="${_POSTGRES_PASSWORD_INPUT:-$_RANDOM_PASSWORD}"

        echo " "
        echo -e "${YELLOW}${BOLD}"
        echo "[!] The values you entered are: "
        echo "MISP KEY: $_MISP_KEY_INPUT"
        echo "MISP URL: $_MISP_URL_INPUT"
        echo "MALPEDIA KEY: $_MALPEDIA_KEY_INPUT"
        echo "POSTGRESQL SERVER: $_POSTGRES_HOST_INPUT"
        echo "POSTGRESQL PORT: $_POSTGRES_PORT_INPUT"
        echo "POSTGRESQL USER: $_POSTGRES_USER_INPUT"
        echo "POSTGRESQL PASSWORD: $_POSTGRES_PASSWORD_INPUT"

        echo " "
        echo " "
        read -p "[?] Are these the correct values? " yn
        case $yn in
            [Yy]* ) break;;
            [Nn]* ) continue;;
            * ) echo "Please answer yes or no.";;
        esac
    done
# else
#     _POSTGRES_HOST_INPUT="${4:-localhost}"
#     _POSTGRES_PORT_INPUT="${5:-5432}"
#     _POSTGRES_USER_INPUT="${6:-mptomisp}"
#     _POSTGRES_PASSWORD_INPUT="${7:-$_RANDOM_PASSWORD}"
fi
echo -e "${YELLOW}${BOLD}"
echo "[!] Proceeding installation with the following values."
echo "    MISP KEY: $_MISP_KEY_INPUT"
echo "    MISP URL: $_MISP_URL_INPUT"
echo "    MALPEDIA KEY: $_MALPEDIA_KEY_INPUT"
echo "    POSTGRESQL SERVER: $_POSTGRES_HOST_INPUT"
echo "    POSTGRESQL PORT: $_POSTGRES_PORT_INPUT"
echo "    POSTGRESQL USER: $_POSTGRES_USER_INPUT"
echo "    POSTGRESQL PASSWORD: $_POSTGRES_PASSWORD_INPUT"

# SET SYSTEM WIDE
echo "export MISP_KEY=$_MISP_KEY_INPUT" >> /etc/bash.bashrc
echo "export MISP_URL=$_MISP_URL_INPUT" >> /etc/bash.bashrc
echo "export MALPEDIA_KEY=$_MALPEDIA_KEY_INPUT" >> /etc/bash.bashrc
echo "export POSTGRES_HOST=$_POSTGRES_HOST_INPUT" >> /etc/bash.bashrc
echo "export POSTGRES_PORT=$_POSTGRES_PORT_INPUT" >> /etc/bash.bashrc
echo "export POSTGRES_DB=mp_to_misp_db" >> /etc/bash.bashrc
echo "export POSTGRES_USER=$_POSTGRES_USER_INPUT" >> /etc/bash.bashrc
echo "export POSTGRES_PASSWORD=$_POSTGRES_PASSWORD_INPUT" >> /etc/bash.bashrc

#SET FOR CURRENT SHELL
export MISP_KEY=$_MISP_KEY_INPUT
export MISP_URL=$_MISP_URL_INPUT
export MALPEDIA_KEY=$_MALPEDIA_KEY_INPUT
export POSTGRES_HOST=$_POSTGRES_HOST_INPUT
export POSTGRES_PORT=$_POSTGRES_PORT_INPUT
export POSTGRES_DB=mp_to_misp_db
export POSTGRES_USER=$_POSTGRES_USER_INPUT
export POSTGRES_PASSWORD=$_POSTGRES_PASSWORD_INPUT

echo " "
echo -e "${YELLOW}${BOLD}"
source ~/.bashrc
echo "[+] The following environment variables have been set. If you need to change them in the future edit the /etc/bash.bashrc file. Please copy them for your records:"
echo "    MISP_KEY=$MISP_KEY"
echo "    MISP_URL=$MISP_URL"
echo "    MALPEDIA_KEY=$MALPEDIA_KEY"
echo "    POSTGRES_HOST=$POSTGRES_HOST"
echo "    POSTGRES_PORT=$POSTGRES_PORT"
echo "    POSTGRES_DB=$POSTGRES_DB"
echo "    POSTGRES_USER=$POSTGRES_USER"
echo "    POSTGRES_PASSWORD=$POSTGRES_PASSWORD"
echo -e  " ${NC}"

sleep  30s
echo " "
echo -e "${YELLOW}${BOLD}"
echo "[+] Installing requirements." 
echo -e  " ${NC}"
_BUILD_DEPS="build-essential"
_APP_DEPS="python3 python3-dev python3-venv python3-pip curl git ssh gcc openssh-client supervisor wget python3-setuptools python3-pip libfuzzy-dev ssdeep libpq-dev postgresql-client supervisor"

apt-get update && apt-get install -y $_BUILD_DEPS $_APP_DEPS && \
apt-get clean -y && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* && apt-get purge -y --auto-remove $_BUILD_DEPS && \
rm -rf /usr/share/doc && rm -rf /usr/share/man
echo  "SERVER $POSTGRES_HOST"
if [ "$POSTGRES_HOST" = "localhost" ]
then
    sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
    apt-get update
    apt-get -y install postgresql
fi

echo " "
echo -e "${YELLOW}${BOLD}"
echo "[+] Installing Python requirements."
echo -e  " ${NC}"
pip3 install --no-cache-dir -r requirements.txt

echo " "
echo -e "${YELLOW}${BOLD}"
echo "[+] Configuring git and ssh."
echo -e  " ${NC}"
eval `ssh-agent -s`
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
service ssh restart
ssh-add -k /root/.ssh/id_rsa
ssh -o StrictHostKeyChecking=no git@malpedia.caad.fkie.fraunhofer.de
service ssh restart


echo " "
echo -e "${YELLOW}${BOLD}"
echo "[+] Cloning and Installing Malpedia Client. Do not close even if you see \"fatal: destination path 'malpedia' already exists and is not an empty directory.\". This is normal."
echo -e  " ${NC}"
cd /opt/m2m/dependencies
git clone https://github.com/malpedia/malpediaclient.git || (cd /opt/m2m/dependencies/malpediaclient ; git pull) || true
cd /opt/m2m/dependencies/malpediaclient
python3 setup.py install

echo " "
echo " "
cd /opt/m2m/dependencies
echo -e "${YELLOW}${BOLD}"
echo "[+] Cloning/Updating Malpedia To MISP Core. Do not close even if you see \"fatal: destination path 'malpedia' already exists and is not an empty directory.\". This is normal."
echo -e  " ${NC}"
git clone https://github.com/malwaredevil/malpedia_to_misp.git || (cd /opt/m2m/dependencies/malpedia_to_misp ; git pull) || true

if [ "$POSTGRES_HOST" = "localhost" ]
then
    echo " "
    echo -e "${YELLOW}${BOLD}"
    echo "[+] Configuring PostgreSQL."
    echo -e  " ${NC}"
    pg_ctlcluster 13 main start
    sudo -u postgres createdb mp_to_misp_db || echo -e "${YELLOW}${BOLD}"; echo "[!] mp_to_misp_db database found. Re-initializing.";echo -e  " ${NC}"
    sudo -u postgres psql -U postgres -d postgres -c "CREATE USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';" || sudo -u postgres psql -U postgres -d postgres -c "alter user $POSTGRES_USER with password '$POSTGRES_PASSWORD';"
    systemctl restart postgresql
fi
while ! pg_isready --dbname="postgresql://$POSTGRES_USER:$POSTGRES_PASSWORD@$POSTGRES_HOST:$POSTGRES_PORT/mp_to_misp_db"; do
    sleep 5
    echo -e "${YELLOW}${BOLD}"
    echo "Waiting for database to initialize..."
    echo -e  " ${NC}"
done
echo "MP_TO_MISP_DB='postgresql://$POSTGRES_USER:$POSTGRES_USER@$POSTGRES_HOST:$POSTGRES_PORT/mp_to_misp_db'" > /opt/m2m/dependencies/malpedia_to_misp/.env
cd /opt/m2m/dependencies/malpedia_to_misp
alembic upgrade head

echo " "
echo " "
cd /opt/m2m/dependencies
echo -e "${YELLOW}${BOLD}"
echo "[+] Cloning/Updating MITRE CTI. Do not close even if you see \"fatal: destination path 'malpedia' already exists and is not an empty directory.\". This is normal."
echo -e  " ${NC}"
git clone https://github.com/mitre/cti.git || (cd /opt/m2m/dependencies/cti ; git pull) || true

echo " "
echo " "
cd /opt/m2m/dependencies
echo -e "${YELLOW}${BOLD}"
echo "[+] Cloning/Updating misp-galaxy. Do not close even if you see \"fatal: destination path 'malpedia' already exists and is not an empty directory.\". This is normal."
echo -e  " ${NC}"
git clone https://github.com/MISP/misp-galaxy.git  || (cd /opt/m2m/dependencies/misp-galaxy ; git pull) || true

echo " "
echo " "
cd /opt/m2m/dependencies
echo -e "${YELLOW}${BOLD}"
echo "[+] Cloning/Updating Malpedia. The first time the container is started/built this is a long running process that must download 8GB +/- data. Please do not close or cancel. Do not close even if you see \"fatal: destination path 'malpedia' already exists and is not an empty directory.\". This is normal."
echo -e  " ${NC}"
git clone git@malpedia.caad.fkie.fraunhofer.de:malpedia/malpedia.git || (cd /opt/m2m/dependencies/malpedia ; git pull) || true

echo " "
echo " "
echo -e "${YELLOW}${BOLD}"
echo "[+] Starting Malpedia to MISP ingestion routine. The first time the container is started/built this is a long running process that will categorize and enter data into the MISP instance you specified. Please do not close or cancel."
echo -e  " ${NC}"
cd /opt/m2m/dependencies/malpedia_to_misp
python3 ./initialize.py

echo " "
echo -e "${YELLOW}${BOLD}"
echo "***********************************************************************************"
echo "**                MALPEDIA TO MISP INGESTOR SETUP                                **"
echo "***********************************************************************************"
echo "***********************************************************************************"
echo "**        Setup complete. You can delete this directory. The                     **"
echo "**        malpedia to misp project has been created in the                       **"
echo "**        /opt/m2m/dependencies/malpedia_to_misp directory.                      **"
echo "**        You can run it by executing either the initialize.py                   **"
echo "**        or update.py files. Please read the documentation for more.            **" 
echo "***********************************************************************************"
echo "***********************************************************************************"
echo -e " ${NC}"
# exec "$@"