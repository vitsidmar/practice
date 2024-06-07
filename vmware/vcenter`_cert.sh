#!/bin/bash
#------------------------------
# Script to manage vCenter SSL certificates.
#
# Author: Vincent Santa Maria [vsantamaria@vmware.com]
#------------------------------

#------------------------------
# for debugging purposes only, uncomment the following line:
# export PS4='+[${SECONDS}s][${BASH_SOURCE}:${LINENO}]: ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'; set -x;
# to debug run: ./vCert 2>vCert-debug.txt
#------------------------------

VERSION="4.13.0"
VCERT_PID="$$"
trap "exit 1" 10

#------------------------------
# Prints help information
#------------------------------
function printHelp() {
   cat << EOF
vCert: vCenter Certificate Management Utility
Usage: $0 [options]
Options:
   -h | --help          Prints this help menu
   -d | --debug         Enables debug-level logging
   -j | --just-do-it    JUST DO IT! Script operations will continue if backup tasks fail
   -u | --user          Specify an SSO administrator account
   -v | --version       Prints script version
   -w | --password      Password for the specified SSO administrator account

EOF
}

#------------------------------
# Parses arguments passed to the script
#------------------------------
function parseArguments() {
   logInfo 'Entering the parseArguments function'
   logDetails "Arguments: $#"
   if [ "$#" -ge 1 ]; then
      logInfo 'There are arguments passed'
      while [ "$#" -ge 1 ]; do
	      logInfo "Parsing argument '$1'"
	      case "$1" in
		      -h|--help)
               logInfo 'Printing help menu'
			      stopLoading
			      printHelp
			      exit
			      ;;
            -d|--debug)
               logInfo 'Enabling debug-level logging'
               DEBUG=1
               shift 1
               ;;
            -j|--just-do-it)
               logInfo 'Disabling exit on backup task failure'
               EXIT_ON_BACKUP_FAILURE=0
               shift 1
               ;;
			   -u|--user)
               logInfo "Specified SSO Administrator account: $2"
			      VMDIR_USER_UPN="$2"
			      VMDIR_USER=$(echo $VMDIR_USER_UPN | awk -F'@' '{print $1}')
			      shift 2
			      ;;
			   -v|--version)
               logInfo 'Printing script version'
			      stopLoading			   
			      echo "vCert: version $VERSION"
			      exit
			      ;;
			   -w|--password)
               logInfo "Specified SSO Administrator password: $(echo $2 | tr '[:print:]' '*')"
			      echo -n "$2" > $STAGE_DIR/.vmdir-user-password
               chmod 640 $STAGE_DIR/.vmdir-user-password
			      VMDIR_USER_PASSWORD="$2"
			      shift 2
			      ;;
			   *)
               logInfo "Invalid argument $1"
			      echo $'\n'"${YELLOW}Invalid argument '$1'"
			      stopLoading
			      printHelp
			      exit
			      ;;
		   esac
	   done	  
   fi
   if [ -n "$VMDIR_USER_UPN" ] && [ -f $STAGE_DIR/.vmdir-user-password ]; then VERIFY_PASSED_CREDENTIALS=1; fi   
}

#------------------------------
# Print loading message
#------------------------------
function loading() {
   i=2
   e[0]='.'
   e[1]='..'
   e[2]='...'
   while [ $i -lt 3 ]; do
      echo -ne "\r\033[KLoading${e[$i]}"
      if [ $i -eq 2 ]; then
         i=0
      else
         ((++i))
      fi
      sleep 1
   done
}

loading &
LOADING_PID=$!

#------------------------------
# Stop loading message
#------------------------------
function stopLoading() {
   kill $LOADING_PID 
   wait $LOADING_PID > /dev/null 2>&1
   echo -ne "\r\033[K"
}

#------------------------------
# Print section header
#------------------------------
function header() {
   printf "\n${CYAN}$1\n"
   printf "%65s${NORMAL}\n" | tr " " "-"
   logInfo "Operation: $1"
}

#------------------------------
# Print task description
#------------------------------
function task() {
   printf "%-52s" "$1"
   logInfo "Task: $1"
}

#------------------------------
# Print formatted status message with colored text
#------------------------------
function statusMessage() {
   printf "%13s\n" "${1}" | sed "s/${1}/${!2}&${NORMAL}/"
   logInfo "Task Status: $1"
}

#------------------------------
# Print formatted 'errror' message
#------------------------------
function errorMessage() {
   if [ -z $3 ]; then printf "%13s\n\n" "FAILED" | sed "s/FAILED/${RED}&${NORMAL}/"; else printf "\n\n"; fi
   logError "Task Error: $1"
   
   if [ -z $2 ]; then
      printf "${YELLOW}${1}. Exiting...${NORMAL}\n\n"
      kill -10 $VCERT_PID
   else
      case $2 in
         'backup')
            if [ $EXIT_ON_BACKUP_FAILURE == 1 ]; then 
               printf "${YELLOW}${1}. Exiting...${NORMAL}\n\n"
               kill -10 $VCERT_PID
            fi
            ;;
         *)
            printf "${YELLOW}${1}. Exiting...${NORMAL}\n\n"
            kill -10 $VCERT_PID
            ;;
      esac
   fi
}

#------------------------------
# Main logging function
#------------------------------
function logEntry() {
   if [ -n "$1" ]; then
      IN="$1"
      LOG_LEVEL="$2"
   else
      read IN
      LOG_LEVEL='INFO'
   fi
   LOG_TIMESTAMP=$(date "+%Y-%m-%dT%H:%M:%S %Z %:z")
   echo "$LOG_TIMESTAMP $LOG_LEVEL $IN" >> $LOG 2>/dev/null
}

#------------------------------
# Logging function for log details
#------------------------------
function logDetails() {
   if [ -n "$1" ]; then
      IN="$1"
   else
      read IN
   fi
   echo "$IN" | sed -e 's/^[.]*/--> &/g' >> $LOG 2>/dev/null
}

#------------------------------
# Logging function for info-level logging
#------------------------------
function logInfo() {
   if [ -n "$1" ]; then
      IN="$1"
   else
      read IN
   fi
   logEntry "$IN" 'INFO'
}

#------------------------------
# Logging function for error-level logging
#------------------------------
function logError() {
   if [ -n "$1" ]; then
      IN="$1"
   else
      read IN
   fi
   logEntry "$IN" 'ERROR'
}

#------------------------------
# Logging function for debug-level logging
#------------------------------
function logDebug() {
   if [ "$DEBUG" -gt 0 ]; then
      if [ -n "$1" ]; then
         IN="$1"
      else
         read IN
      fi
      logEntry "$IN" 'DEBUG'
   fi
}

#------------------------------
# Logging function for debug-level logging
#------------------------------
function logDebugDetails() {
   if [ "$DEBUG" -gt 0 ]; then
      if [ -n "$1" ]; then
         IN="$1"
      else
         read IN
      fi
      echo "$IN" | sed -e 's/^[.]*/--> &/g' >> $LOG 2>/dev/null
   fi
}

#------------------------------
# Set color variables
#------------------------------
function enableColor() {
   RED=$(tput setaf 1)
   GREEN=$(tput setaf 2)
   YELLOW=$(tput setaf 3)
   CYAN=$(tput setaf 6)
   NORMAL=$(tput sgr0)
}

#------------------------------
# Clear color variables for reports
#------------------------------
function disableColor() {
   RED=''
   GREEN=''
   YELLOW=''
   CYAN=''
   NORMAL=''
}

#------------------------------
# Pre-start operations
#------------------------------
function preStartOperations() {
   if [ ! -d $LOG_DIR ]; then mkdir $LOG_DIR; fi
   if [ ! -d $STAGE_DIR ]; then mkdir -p $STAGE_DIR; fi
   if [ ! -d $REQUEST_DIR ]; then mkdir -p $REQUEST_DIR; fi
   if [ ! -d $BACKUP_DIR ]; then mkdir -p $BACKUP_DIR; fi
   if [ ! -f $LOG ]; then touch $LOG; fi
   logInfo "Starting vCert version $VERSION"
      
   echo -n "$VMDIR_MACHINE_PASSWORD" > $STAGE_DIR/.machine-account-password
   chmod 640 $STAGE_DIR/.machine-account-password     
   
   updateVcSupport
   
   setTimestamp
   
   parseArguments "$@"
   
   enableColor
   
   checkServices
   
   checkVmdirMachineCredentials
   
   checkCAPermissions   
   
   setSolutionUsers
   
   setVECSStores
   
   clearCSRInfo
   
   checkForVCF
   
   stopLoading
}

#------------------------------
# make sure vCert.log is included in a support bundle
#------------------------------
function updateVcSupport() {
   if [ ! -f /etc/vmware/vm-support/vcert.mfx ]; then
      logInfo 'Creating vc-support manifest for vCert'
      cat << EOF > /etc/vmware/vm-support/vcert.mfx
% Manifest name: vcert
% Manifest group: VirtualAppliance
% Manifest default: Enabled
# action Options file/command
copy IGNORE_MISSING $LOG_DIR/*	  
EOF
   fi
}

#------------------------------
# set the TIMESTAMP variable
#------------------------------
function setTimestamp() {
   TIMESTAMP=$(date +%Y%m%d%H%M%S)
}

#------------------------------
# Cleanup operations
#------------------------------
function cleanup() {
   if [ $CLEANUP -eq 1 ]; then
      rm -Rf $STAGE_DIR
   fi
}

#------------------------------
# Validate an IP address
#------------------------------
function validateIp() {
   logInfo 'Attempting to validate $1 as an IP address'
   RETURN=1
   if [[ $1 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      OIFS=$IFS
      IFS='.'
      ip=($1)
      IFS=$OIFS
      [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
      RETURN=$?
   fi
   if [ $RETURN ]; then
      logInfo '$1 is a valid IP address'
   else
      logInfo '$1 is not a valid IP address'
   fi
   return $RETURN
}

#------------------------------
# Authenticate if needed
#------------------------------
function authenticateIfNeeded() {
   if [ -z "$VMDIR_USER_UPN" ] || [ ! -f $STAGE_DIR/.vmdir-user-password ]; then
      getSSOCredentials
      verifySSOCredentials
   fi
   if [ $VERIFY_PASSED_CREDENTIALS == 1 ]; then verifySSOCredentials; fi
}

#------------------------------
# Get SSO administrator credentials
#------------------------------
function getSSOCredentials() {
   unset VMDIR_USER_UPN_INPUT
   read -p $'\n'"Please enter a Single Sign-On administrator account [${VMDIR_USER_UPN_DEFAULT}]: " VMDIR_USER_UPN_INPUT
   
   if [ -z "$VMDIR_USER_UPN_INPUT" ]; then 
      VMDIR_USER_UPN=$VMDIR_USER_UPN_DEFAULT
   else
      VMDIR_USER_UPN=$VMDIR_USER_UPN_INPUT
   fi

   logInfo "User has chosen the following Single Sign-On account: $VMDIR_USER_UPN"

   VMDIR_USER=$(echo $VMDIR_USER_UPN | awk -F'@' '{print $1}')
   USER_PROVIDED_SSO_DOMAIN=$(echo $VMDIR_USER_UPN | awk -F'@' '{print $2}')

   if [ "$USER_PROVIDED_SSO_DOMAIN" != "$SSO_DOMAIN" ]; then
      echo ''
      while [ "$USER_PROVIDED_SSO_DOMAIN" != "$SSO_DOMAIN" ]; do         
         read -p "${YELLOW}Invalid domain, please provide an account in the SSO domain ($SSO_DOMAIN):${NORMAL} " VMDIR_USER_UPN_INPUT
         VMDIR_USER_UPN=$VMDIR_USER_UPN_INPUT
         VMDIR_USER=$(echo $VMDIR_USER_UPN | awk -F'@' '{print $1}')
         USER_PROVIDED_SSO_DOMAIN=$(echo $VMDIR_USER_UPN | awk -F'@' '{print $2}')
      done
      echo ''
   fi

   read -r -s -p "Please provide the password for $VMDIR_USER_UPN: " VMDIR_USER_PASSWORD
   echo -n "$VMDIR_USER_PASSWORD" > $STAGE_DIR/.vmdir-user-password
   chmod 640 $STAGE_DIR/.vmdir-user-password
   echo ''
}

#------------------------------
# Verify SSO credentials
#------------------------------
function verifySSOCredentials() {
   VERIFIED=0
   ATTEMPT=1

   logInfo "Validating credentials for ${VMDIR_USER_UPN}"

   while [ $ATTEMPT -le 3 ]; do
      if ! $LDAP_SEARCH -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=Servers,cn=$SSO_SITE,cn=Sites,cn=Configuration,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password "(objectclass=vmwDirServer)" cn 2>/dev/null 1>/dev/null; then
         logInfo "Invalid credentials for $VMDIR_USER_UPN (attempt $ATTEMPT)"
		   if [ $VERIFY_PASSED_CREDENTIALS == 1 ] && [ $ATTEMPT == 1 ]; then
            echo "${YELLOW}Unable to validate the provided credentials for $VMDIR_USER_UPN${NORMAL}"
		      getSSOCredentials
		   else
            read -r -s -p $'\n'"${YELLOW}Invalid credentials, please enter the password for $VMDIR_USER_UPN:${NORMAL} " VMDIR_USER_PASSWORD
            echo -n "$VMDIR_USER_PASSWORD" > $STAGE_DIR/.vmdir-user-password
            chmod 640 $STAGE_DIR/.vmdir-user-password
		   fi
         ((++ATTEMPT))
      else
         VERIFIED=1
         logInfo "Credentials verified for $VMDIR_USER_UPN"
         if [ $ATTEMPT -gt 1 ]; then echo ''; fi
         break
      fi
   done

   if [ $VERIFIED == 0 ]; then
      errorMessage "Unable to verify credentials for $VMDIR_USER_UPN"
   fi
}

#------------------------------
# Check if vmafdd, vmdird, and reverse proxy are running
#------------------------------
function checkServices() {
   if [[ "$VC_VERSION" =~ ^[78] ]]; then
      logInfo 'Checking state of the vmware-envoy service'
      if ! checkService 'vmware-envoy'; then
         logError 'The Envoy service is not running'
         echo $'\n'"${YELLOW}The Envoy Service is not running!"
         echo "The script cannot continue. Exiting...${NORMAL}"
         stopLoading
         exit
      fi
      logInfo 'The vmware-envoy service is running'
   fi
   logInfo 'Checking state of the vmware-rhttpproxy service'
   if ! checkService 'vmware-rhttpproxy'; then
      logError 'The reverse proxy service is not running'
      echo $'\n'"${YELLOW}The Reverse Proxy Service is not running!}"
      echo "The script cannot continue. Exiting...${NORMAL}"
      stopLoading
      exit
   fi
   logInfo 'The vmware-rhttpproxy service is running'
   logInfo 'Checking state of the vmafdd service'
   if ! checkService 'vmafdd'; then
      logError 'The vmafdd service is not running'
      echo $'\n'"${YELLOW}The VMware Authentication Framework Service is not running!"
      echo "The script cannot continue. Exiting...${NORMAL}"
      stopLoading
      exit
   fi
   logInfo 'The vmafdd service is running'
   if [ $NODE_TYPE != 'management' ]; then
      logInfo 'Checking state of the vmdird service'
      if ! checkService 'vmdird'; then
         logError 'The vmdird service is not running'
         echo $'\n'"${YELLOW}The VMware Directory Service is not running!"
         echo "The script cannot continue. Exiting...${NORMAL}"
         stopLoading
         exit
      else
         VMDIR_STATE=$(echo 6 | /usr/lib/vmware-vmdir/bin/vdcadmintool 2>/dev/null | awk '{print $NF}' | tr -d '\n')
      fi
      logInfo "The vmdird service is running and in the following state: $VMDIR_STATE"
   fi
}

#------------------------------
# Check if PSC is configured to be behind a load balancer
#------------------------------
function checkPSCHA() {
   if [ $NODE_TYPE = 'infrastructure' ]; then
      PSC_LB=$(grep proxyName /usr/lib/vmware-sso/vmware-sts/conf/server.xml | sed 's/ /\n/g' | grep proxyName | awk -F'=' '{print $NF}' | tr -d '"')
   fi
}

#------------------------------
# Notice for additional steps with PSC HA
#------------------------------
function noticePSCHA() {
   if [ $NODE_TYPE = 'infrastructure' ] && [ -n "$PSC_LB" ]; then
      cat << EOF
${YELLOW}-------------------------!!! WARNING !!!-------------------------
This PSC has been detected to be in an HA configuration.
 - The new certificate and private key should be installed on all other
   PSCs configured behind the load balancer.
 - If the load balancer is configured for SSL termination, it will need
   the new Machine SSL certificate and private key.
 - If the load balancer is configured for SSL passthrough, no additional
   configuration should be necessary.${NORMAL}
EOF
   fi
}

#------------------------------
# Check if service is running
#------------------------------
function checkService() {
   if service-control --status $1 | grep -i stopped >/dev/null 2>&1; then
      return 1
   else
      return 0
   fi
}

#------------------------------
# Check if machine account can connect to VMware Directory
#------------------------------
function checkVmdirMachineCredentials() {
   logInfo "Checking credentials for machine account $VMDIR_MACHINE_ACCOUNT_DN"
   if ! $LDAP_SEARCH -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "ou=Domain Controllers,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password dn > /dev/null 2>&1; then
      LDAP_ERROR=$?
      echo $'\n'"${YELLOW}The machine account $VMDIR_MACHINE_ACCOUNT_DN"
      echo "was unable to authenticate to the VMware Directory instance at $PSC_LOCATION:$VMDIR_PORT"
      echo "LDAP error: $LDAP_ERROR"
      echo "The script cannot continue. Exiting...${NORMAL}"
      logError "Credentials for machine account $VMDIR_MACHINE_ACCOUNT_DN could not be verified (LDAP error: $LDAP_ERROR)"
      stopLoading
      exit
   fi
   logInfo "Credentials for machine account $VMDIR_MACHINE_ACCOUNT_DN verified"
}

#------------------------------
# Check if machine account has proper CA permissions
#------------------------------
function checkCAPermissions() {
   logInfo "Machine account DN: $VMDIR_MACHINE_ACCOUNT_DN"
   logInfo "PSC location: $PSC_LOCATION"
   if [ $NODE_TYPE != 'management' ]; then 
      DCADMINS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=DCAdmins,cn=BuiltIn,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password member | sed -e 's/^ //g' | tr -d '\n' | sed -e 's/member:/\n&/g')
      logInfo 'Checking DCAdmins membership:'
      logDetails "$DCADMINS"
      if echo "$DCADMINS" | grep -i "$VMDIR_MACHINE_ACCOUNT_DN" 2>/dev/null > /dev/null; then
         CAADMINS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=CAAdmins,cn=BuiltIn,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password member | sed -e 's/^ //g' | tr -d '\n' | sed -e 's/member:/\n&/g')
         if echo "$CAADMINS" | grep -i "cn=DCAdmins,cn=BuiltIn,$VMDIR_DOMAIN_DN" 2>/dev/null > /dev/null; then
            return 0
         else
            echo $'\n'"${YELLOW}The DCAdmins SSO group is not a member of the CAAdmins SSO group!"
            echo "The script cannot continue. Exiting...${NORMAL}"
            logError 'The DCAdmins SSO group is not a member of the CAAdmins SSO group'
            stopLoading
            exit
         fi
      else
         echo $'\n'"${YELLOW}The machine account is not a member of the DCAdmins SSO group!"
         echo "The script cannot continue. Exiting...${NORMAL}"
         logError 'The machine account is not a member of the DCAdmins SSO group'
         stopLoading
         exit
      fi
   else
      DCCLIENTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=DCClients,cn=BuiltIn,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password member | sed -e 's/^ //g' | tr -d '\n' | sed -e 's/member:/\n&/g')
      logInfo 'Checking DCClients membership:'
	   logDetails "$DCCLIENTS"
	   if echo "$DCCLIENTS" | grep -i "$VMDIR_MACHINE_ACCOUNT_DN" 2>/dev/null > /dev/null; then
         CAADMINS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=CAAdmins,cn=BuiltIn,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password member | sed -e 's/^ //g' | tr -d '\n' | sed -e 's/member:/\n&/g')
         if echo "$CAADMINS" | grep -i "cn=DCClients,cn=BuiltIn,$VMDIR_DOMAIN_DN" 2>/dev/null > /dev/null; then
            return 0
         else
            echo $'\n'"${YELLOW}The DCAdmins SSO group is not a member of the CAAdmins SSO group!"
            echo "The script cannot continue. Exiting...${NORMAL}"
            logError 'The DCAdmins SSO group is not a member of the CAAdmins SSO group'
            stopLoading
            exit
         fi
      else
         echo $'\n'"${YELLOW}The machine account is not a member of the DCClients SSO group!"
         echo "The script cannot continue. Exiting...${NORMAL}"
         logError 'The machine account is not a member of the DCAdmins SSO group'
         stopLoading
         exit
      fi
   fi
}

#------------------------------
# Set the Solution Users for this node
#------------------------------
function setSolutionUsers() {
   SOLUTION_USERS=('machine' 'vsphere-webclient')
   if [ $NODE_TYPE != 'infrastructure' ]; then
      SOLUTION_USERS+=('vpxd' 'vpxd-extension')
      if [[ "$VC_VERSION" =~ ^[78] ]]; then
         SOLUTION_USERS+=('hvc' 'wcp')
      fi
   fi
   logInfo "Setting Solution Users: ${SOLUTION_USERS[*]}"
}

#------------------------------
# Set the VECS Stores and default permissions for this node
#------------------------------
function setVECSStores() {
   VECS_STORES='MACHINE_SSL_CERT TRUSTED_ROOTS TRUSTED_ROOT_CRLS machine vsphere-webclient'
   declare -gA VECS_STORE_READ_PERMISSIONS=()
   declare -gA VECS_STORE_WRITE_PERMISSIONS=()
   if [ $NODE_TYPE == 'infrastructure' ]; then
      VECS_STORE_READ_PERMISSIONS[MACHINE_SSL_CERT]=''
	   VECS_STORE_READ_PERMISSIONS[TRUSTED_ROOTS]='EVERYONE'
	   VECS_STORE_READ_PERMISSIONS[TRUSTED_ROOT_CRLS]='EVERYONE'
	   VECS_STORE_READ_PERMISSIONS[machine]='cm'
      VECS_STORE_READ_PERMISSIONS[vsphere-webclient]='vapiEndpoint'
   else
      VECS_STORES+=' vpxd vpxd-extension SMS'
      VECS_STORE_READ_PERMISSIONS[MACHINE_SSL_CERT]='updatemgr vsphere-ui vpxd vpostgres vsphere-client vsm'
      VECS_STORE_READ_PERMISSIONS[TRUSTED_ROOTS]='EVERYONE vpxd'
      VECS_STORE_READ_PERMISSIONS[TRUSTED_ROOT_CRLS]='EVERYONE vpxd'
      VECS_STORE_READ_PERMISSIONS[machine]='vpxd cm'
      VECS_STORE_READ_PERMISSIONS[vsphere-webclient]='vsphere-ui vpxd perfcharts vapiEndpoint'
      VECS_STORE_READ_PERMISSIONS[vpxd]='vpxd'
      VECS_STORE_READ_PERMISSIONS[vpxd-extension]='deploy updatemgr vsphere-ui vpxd vsm imagebuilder content-library eam mbcs'
      VECS_STORE_READ_PERMISSIONS[SMS]='deploy vpxd'
   fi
   
   case $VC_VERSION in
      '6.5')
	      if [ $NODE_TYPE != 'infrastructure' ]; then
	         VECS_STORE_READ_PERMISSIONS[SMS]='vpxd'
			   VECS_STORE_READ_PERMISSIONS[vpxd-extension]+=' vsphere-client'
		   fi
	      ;;
      '6.7')
	      if [ $NODE_TYPE == 'infrastructure' ]; then
		      VECS_STORES+=' APPLMGMT_PASSWORD'
		      VECS_STORE_READ_PERMISSIONS[APPLMGMT_PASSWORD]=''
	      else 
		     VECS_STORES+=' APPLMGMT_PASSWORD'
		     VECS_STORE_READ_PERMISSIONS[APPLMGMT_PASSWORD]='vpxd'
		     VECS_STORE_READ_PERMISSIONS[data-encipherment]='vpxd'
			  VECS_STORE_READ_PERMISSIONS[vpxd-extension]+=' vsphere-client'
		   fi
	      ;;
	  '7.0')
	      VECS_STORES+=' APPLMGMT_PASSWORD data-encipherment hvc wcp'
		   VECS_STORE_READ_PERMISSIONS[MACHINE_SSL_CERT]='updatemgr vsphere-ui vpxd vpostgres vsm'
		   VECS_STORE_READ_PERMISSIONS[machine]='vpxd vsan-health'
		   VECS_STORE_READ_PERMISSIONS[hvc]='vpxd'
		   if [ $VC_BUILD -ge 19480866 ]; then
		      VECS_STORE_READ_PERMISSIONS[vpxd-extension]='vlcm wcp deploy updatemgr vsphere-ui vpxd vsm vsan-health imagebuilder content-library eam vstatsuser'
		      VECS_STORE_READ_PERMISSIONS[wcp]='wcp vpxd content-library'
		   else
		      VECS_STORE_READ_PERMISSIONS[vpxd-extension]='vlcm deploy updatemgr vsphere-ui vpxd vsm imagebuilder content-library eam vstatsuser'
		      VECS_STORE_READ_PERMISSIONS[wcp]='vpxd content-library'
		   fi
		   if [ $VC_BUILD -ge 20051473 ]; then
		      VECS_STORE_WRITE_PERMISSIONS[TRUSTED_ROOTS]='sps'
			   VECS_STORE_READ_PERMISSIONS[machine]+=' observability'
			   VECS_STORE_WRITE_PERMISSIONS[machine]='infraprofile certauth certmgr'
			   VECS_STORE_READ_PERMISSIONS[vsphere-webclient]+=' analytics'
			   VECS_STORE_WRITE_PERMISSIONS[vsphere-webclient]='infraprofile'
			   VECS_STORE_WRITE_PERMISSIONS[vpxd-extension]='infraprofile sps'
			   VECS_STORE_READ_PERMISSIONS[vpxd-extension]+=' analytics'
			   VECS_STORE_WRITE_PERMISSIONS[SMS]='sps'
		   fi
		   VECS_STORE_READ_PERMISSIONS[APPLMGMT_PASSWORD]='vpxd'
		   VECS_STORE_READ_PERMISSIONS[data-encipherment]='vpxd'
	      ;;
      '8.0')
         VECS_STORE_READ_PERMISSIONS[MACHINE_SSL_CERT]='vlcm updatemgr vsphere-ui vpxd vpostgres vsm vsan-health lighttpd'
         VECS_STORE_WRITE_PERMISSIONS[MACHINE_SSL_CERT]='rhttpproxy'
         VECS_STORE_WRITE_PERMISSIONS[TRUSTED_ROOTS]='rhttpproxy sps'
         if [ $VC_BUILD -lt 22385739 ]; then
            VECS_STORE_READ_PERMISSIONS[machine]='statsmon vsan-health sca vpxd observability'
         else
            VECS_STORE_READ_PERMISSIONS[machine]='vsan-health sca vpxd observability'
         fi
         VECS_STORE_WRITE_PERMISSIONS[machine]='certauth certmgr infraprofile sts'
         VECS_STORE_READ_PERMISSIONS[vsphere-webclient]+=' analytics'
         VECS_STORE_WRITE_PERMISSIONS[vsphere-webclient]='infraprofile'
         VECS_STORE_READ_PERMISSIONS[vpxd]+=' vsan-health'
         if [ $VC_BUILD -lt 22385739 ]; then
            VECS_STORE_READ_PERMISSIONS[vpxd-extension]='analytics content-library deploy eam imagebuilder updatemgr vlcm vpxd vsan-health vsm vsphere-ui vstatsuser wcp'
         else
            VECS_STORE_READ_PERMISSIONS[vpxd-extension]='analytics content-library eam imagebuilder updatemgr vlcm vpxd vsan-health vsm vsphere-ui vstatsuser wcp'
         fi
         VECS_STORE_WRITE_PERMISSIONS[vpxd-extension]='infraprofile sps'
         VECS_STORE_READ_PERMISSIONS[hvc]='vpxd'
         VECS_STORE_READ_PERMISSIONS[wcp]='wcp content-library'
         VECS_STORE_READ_PERMISSIONS[SMS]='deploy'
         VECS_STORE_WRITE_PERMISSIONS[SMS]='vpxd'
         if [ $VC_BUILD -ge 20920323 ]; then
            VECS_STORE_WRITE_PERMISSIONS[SMS]=''
            if [ $VC_BUILD -lt 21560480 ]; then
               VECS_STORE_WRITE_PERMISSIONS[TRUSTED_ROOTS]+=' hvc infraprofile'
               VECS_STORE_WRITE_PERMISSIONS[machine]+=' sts hvc'
               VECS_STORE_WRITE_PERMISSIONS[vsphere-webclient]+=' hvc'
               VECS_STORE_WRITE_PERMISSIONS[vpxd]='hvc'
               VECS_STORE_WRITE_PERMISSIONS[vpxd-extension]+=' hvc'
               VECS_STORE_WRITE_PERMISSIONS[hvc]='hvc'
               VECS_STORE_READ_PERMISSIONS[wcp]+=' vpxd'
               VECS_STORE_READ_PERMISSIONS[SMS]+=' vpxd'
            else
               VECS_STORE_WRITE_PERMISSIONS[TRUSTED_ROOTS]=''
               VECS_STORE_WRITE_PERMISSIONS[machine]='certauth certmgr infraprofile'
            fi
            
         fi
         
         ;;
   esac
}

#------------------------------
# Check if vCenter is managed by SDDC Manager
#------------------------------
function checkForVCF() {
   SDDC_MANAGER=$($LDAP_SEARCH -LLL -h $PSC_LOCATION -b "cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password '(objectclass=vmwSTSTenant)' vmwSTSLogonBanner | tr -d '\n' | awk -F'::' '{print $NF}' | tr -d ' ' | base64 -d 2>/dev/null | grep 'SDDC Manager' | awk -F '[()]' '{print $2}' | grep -v '^$')
}

#------------------------------
# Print warning about VCHA on the main operation menu
#------------------------------
function operationMenuSDDCWarning() {
   cat << EOF
${YELLOW}-------------------------!!! WARNING !!!-------------------------
This vCenter is managed by the following SDDC Manager:
   $SDDC_MANAGER

Updating certificates may require adding new
CA certificates to the SDDC Manager keystore.

See https://kb.vmware.com/s/article/78607 for details.$NORMAL

EOF
}

#------------------------------
# Get access token for running API calls to SDDC Manager
#------------------------------
function getSDDCAccessToken() {
   authenticateIfNeeded
   
   task 'Get API access token'
   SDDC_API_ACCESS_TOKEN_RESPONSE=$(curl -i -k -X POST https://$SDDC_MANAGER/v1/tokens -H 'Content-Type: application/json' -H 'Accept: application/json' -d "{'username' : '$VMDIR_USER_UPN', 'password' : '$(cat $STAGE_DIR/.vmdir-user-password)'}" 2>&1 | logDebug)
   if echo "$SDDC_API_ACCESS_TOKEN_RESPONSE" | grep '^HTTP' | grep '200' > /dev/null; then
      SDDC_API_ACCESS_TOKEN=$(echo "$SDDC_API_ACCESS_TOKEN_RESPONSE" | grep '^{' | jq . | grep accessToken | awk '{print $NF}' | tr -d '",')
	   statusMessage 'OK' 'GREEN'
   else
      errorMessage 'Unable to get access token from the SDDC Manager'
   fi   
}

#------------------------------
# Add new CA certificates to SDDC Manager via API
#------------------------------
function publishCACertsSDDCManager() {
   CA_CERT_STRING=$(cat $1 | awk '{printf "%s\\n", $0}' | sed -e 's/[\\n]*$//g')
   
   task 'Publish CA cert for outbound connections'
   logDebug "CA JSON string: $CA_CERT_STRING"
   if [ -n "$SDDC_API_ACCESS_TOKEN" ]; then
      SDDC_API_PUBLISH_CA_OUTBOUND_RESPONSE=$(curl -i -k -X POST https://$SDDC_MANAGER/v1/sddc-manager/trusted-certificates -H "Authorization: Bearer $SDDC_API_ACCESS_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json' -d "{'certificate':'$CA_CERT_STRING','certificateUsageType':'TRUSTED_FOR_OUTBOUND'}" 2>&1 | logDebug)
      if echo "$SDDC_API_PUBLISH_CA_OUTBOUND_RESPONSE" | grep '^HTTP' | grep '200' > /dev/null; then
         statusMessage 'OK' 'GREEN'
      else
         logInfo "Publish CA to SDDC Manager response code (outbound trust): $SDDC_API_PUBLISH_CA_INBOUND_RESPONSE"
         errorMessage 'Unable to publish CA certificate to SDDC Manager'		 
      fi
      if [[ "$VC_VERSION" =~ ^[78] ]] && [ $VC_BUILD -ge 17327517 ]; then
         task 'Publish CA cert for inbound connections'
         SDDC_API_PUBLISH_CA_INBOUND_RESPONSE=$(curl -i -k -X POST https://$SDDC_MANAGER/v1/sddc-manager/trusted-certificates -H "Authorization: Bearer $SDDC_API_ACCESS_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json' -d "{'certificate':'$CA_CERT_STRING','certificateUsageType':'TRUSTED_FOR_INBOUND'}" 2>&1 | logDebug)
         if echo "$SDDC_API_PUBLISH_CA_INBOUND_RESPONSE" | grep '^HTTP' | grep '200' > /dev/null; then
            statusMessage 'OK' 'GREEN'
         else
            logInfo "Publish CA to SDDC Manager response code (inbound trust): $SDDC_API_PUBLISH_CA_INBOUND_RESPONSE"
            errorMessage 'Unable to publish CA certificate to SDDC Manager'		
         fi
      fi
   else
      errorMessage 'No API access token found'
   fi
}

#------------------------------
# Print the operation menu
#------------------------------
function operationMenu() {
   UPDATED_MACHINE_SSL=0
   UPDATED_TRUST_ANCHORS=0

   header "vCenter $VC_VERSION Certificate Management Utility ($VERSION)"
   logInfo 'Printing Main Menu'
   cat << EOF
 1. Check current certificates status
 2. View certificate info
 3. Manage certificates
 4. Manage SSL trust anchors
 5. Check configurations
 6. Reset all certificates with VMCA-signed certificates
 7. ESXi certificate operations
 8. Restart services
 9. Generate certificate report
EOF

   if isVCHAConfigured; then echo ' I. vCenter High Availability information'; fi
   
   echo ' E. Exit'
   echo ''
   
   if isVCHAConfigured; then
      operationMenuVCHAWarning
   fi
   
   if [ -n "$SDDC_MANAGER" ]; then
      operationMenuSDDCWarning
   fi

   if [ $NODE_TYPE != 'management' ] && [ "$VMDIR_STATE" != 'Normal' ] && [ "$VMDIR_STATE" != 'Standalone' ]; then
      echo "${YELLOW}The VMware Directory service is not in NORMAL mode ($VMDIR_STATE)!"
	   echo 'Certificate operations should not be actioned until this service'
	   echo "is running correctly in a NORMAL state.${NORMAL}"
	   exit      
   else
      if [ "$NODE_TYPE" != 'infrastructure' ] && ! checkService 'vmware-vpostgres'; then
         echo "${YELLOW}The vPostgres service is stopped!"
         echo "Many certificate operations require changes to the vCenter database."
         echo "Please ensure this service is running before replacing any certificates."
         echo "Hint: Check the number of CRL entries in VECS${NORMAL}"
         echo ''
      fi
      read -p 'Select an option [1]: ' OPERATION

      if [ -z $OPERATION ]; then OPERATION=1; fi

      logInfo "User selected option '$OPERATION'"
   fi
}

#------------------------------
# Check if VCHA is configured
#------------------------------
function isVCHAConfigured() {
   if cat /storage/vmware-vmon/defaultStartProfile | grep 'HACore' > /dev/null; then
      VMON_SERVICE_PROFILE='--vmon-profile HAActive'
      return 0
   else
      VMON_SERVICE_PROFILE='--all'
      return 1
   fi
}

#------------------------------
# Get current VCHA mode
#------------------------------
function getVCHAMode() {
   authenticateIfNeeded
   VCHA_MODE='UNKNOWN'
   SESSION_HEADER=$(curl -k -i -u "$VMDIR_USER_UPN:$(cat $STAGE_DIR/.vmdir-user-password)" -X POST -c $STAGE_DIR/session-info.txt https://localhost/rest/com/vmware/cis/session 2>/dev/null)
   if echo "$SESSION_HEADER" | grep '^HTTP' | grep '200' > /dev/null; then
      if [[ "$VC_VERSION" =~ ^6 ]]; then
	     VCHA_MODE_INFO=$(curl -k -b $STAGE_DIR/session-info.txt https://localhost/rest/vcenter/vcha/cluster/mode 2>/dev/null | python -m json.tool --sort-keys)		 
	  else
	     VCHA_MODE_INFO=$(curl -k -b $STAGE_DIR/session-info.txt https://localhost/rest/vcenter/vcha/cluster/mode 2>/dev/null | jq .)
	  fi
	  logDebug "VCHA Mode API call: $VCHA_MODE_INFO"
      VCHA_MODE=$(echo "$VCHA_MODE_INFO" | grep 'mode' | awk '{print $NF}' | tr -d '"')     
   fi
   logInfo "VCHA Mode: $VCHA_MODE"
}

#------------------------------
# Print warning about VCHA on the main operation menu
#------------------------------
function operationMenuVCHAWarning() {
   echo "${YELLOW}-------------------------!!! WARNING !!!-------------------------"
   printf 'vCenter High Availability has been configured,'
   if service-control --status vmware-vcha | grep -i stopped; then
      printf " but the\nservice is currently stopped. "
   else
      printf " and the\nservice is currently running. "
   fi
   printf "\n\nRestarting services may trigger a failover.\nFor more information, select option 'I' from the menu.\n\n${NORMAL}"
}

#------------------------------
# Print VCHA information
#------------------------------
function VCHAInfo() {
   if [ $NODE_TYPE != 'infrastructure' ]; then
   getVCHAMode
   cat << EOF

${YELLOW}The supported methods of replacing SSL certificates with 
vCenter High Availability configured are:

   1. Place VCHA into Maintenance Mode so restarting 
      services does not trigger an automatic failover, or
	  
   2. Destroy the VCHA cluster, replace the SSL certificate(s), 
      and re-create the VCHA cluster   
EOF
      case $VCHA_MODE in
	      'MAINTENANCE')
		      cat << EOF

The VCHA cluster is in Maintenance Mode, so you should be able 
to proceed with the certificate replacement.${NORMAL}
			
EOF
            if checkService 'vmware-vpxd'; then
               read -p 'Place VCHA cluster into Enabled Mode? [n]: ' VCHA_SET_MM_INPUT

               if [[ "$VCHA_SET_MM_INPUT" =~ ^[Yy] ]]; then
			         header 'vCenter High Availability Mode'
			         task 'Put VCHA cluster into Enabled Mode'
			         VCHA_MM_API=$(curl -k -i -b $STAGE_DIR/session-info.txt -H 'Content-Type: application/json' -X PUT https://localhost/rest/vcenter/vcha/cluster/mode?vmw-task=true -d '{"mode":"ENABLED"}' 2>/dev/null)
			         logDebug "$VCHA_MM_API"
			         if echo "$VCHA_MM_API" | grep '^HTTP' | grep '200' > /dev/null; then
			            statusMessage 'OK' 'GREEN'
			         else
			            errorMessage 'Unable to place VCHA cluster into Enabled Mode'
			         fi
			      fi
			   fi
		      ;;
		 
		   'ENABLED')
		      cat << EOF

The VCHA cluster is in Enabled Mode, so restarting 
services will trigger a failover to the Passive Node. 
It is recommended to place the VCHA cluster into 
Maintenance Mode before performing operations on any 
SSL certificates.${NORMAL}
			
EOF
            if checkService 'vmware-vpxd'; then
               read -p 'Place VCHA cluster into Maintenance Mode? [n]: ' VCHA_SET_MM_INPUT

               if [[ "$VCHA_SET_MM_INPUT" =~ ^[Yy] ]]; then
			         header 'vCenter High Availability Mode'
			         task 'Put VCHA cluster into Maintenance Mode'
			         VCHA_MM_API=$(curl -k -i -b $STAGE_DIR/session-info.txt -H 'Content-Type: application/json' -X PUT https://localhost/rest/vcenter/vcha/cluster/mode?vmw-task=true -d '{"mode":"MAINTENANCE"}' 2>/dev/null)
			         logDebug "$VCHA_MM_API"
			         if echo "$VCHA_MM_API" | grep '^HTTP' | grep '200' > /dev/null; then
			            statusMessage 'OK' 'GREEN'
			         else
			            errorMessage 'Unable to place VCHA cluster into Maintenance Mode'
			         fi
			      fi
			   fi
		      ;;
		 
		   'UNKNOWN')
		      cat << EOF
			
The state of the VCHA cluster cannot be determined 
via the REST API. It is recommended to destroy the 
VCHA cluster before performing operations on any 
SSL certificates.${NORMAL}
EOF
			
		      ;;
	   esac
   else
      printf "\n${YELLOW}Invalid operation${NORMAL}\n\n"
   fi
}

#------------------------------
# Process the operation selected by user
#------------------------------
function processOperationMenu() {
   setTimestamp
   
   if [[ $OPERATION =~ ^[Ee] ]]; then 
      cleanup
      exit
   fi
   
   if [[ $OPERATION =~ ^[Ii] ]]; then
      VCHAInfo
   elif [[ "$OPERATION" =~ ^[0-9]+$ ]]; then
      echo ''

      case $OPERATION in
         1)
            checkCerts
            ;;
         2)
            viewCertificateMenu
            ;;      
         3)
            manageCertificateMenu
            ;;         
         4)
            manageSSLTrustAnchors
            ;;         
         5)
            checkConfigurationMenu
            ;;         
         6)
            resetAllCertificates            
            ;;         
		   7)
		      manageESXiCertificates
		      ;;		 
         8)
            restartServicesMenu
            ;;		 
		   9)
		      #viewCertificateReportMenu
			   generatevCenterCertificateReport
		      ;;         
         *)
            echo $'\n'"${YELLOW}Invalid operation${NORMAL}"
            ;;
      esac      
   else
      echo $'\n'"${YELLOW}Invalid operation${NORMAL}"
   fi
   operationMenu
   processOperationMenu
}

#------------------------------
# Perform quick check of certificates
#------------------------------
function checkCerts() {
   authenticateIfNeeded
      
   resetCertStatusChecks
   
   header 'Checking Certifcate Status'
   
   task 'Checking Machine SSL certificate'
   checkVECSCert 'MACHINE_SSL_CERT' '__MACHINE_CERT'
   
   if checkMachineSSLCSR; then
      task 'Checking Machine SSL CSR'
	  checkVECSCert 'MACHINE_SSL_CERT' '__MACHINE_CSR'
   fi

   echo 'Checking Solution User certificates:'
   for soluser in "${SOLUTION_USERS[@]}"; do
      task "   $soluser"
      checkVECSCert "$soluser" "$soluser"
   done   
  
   if [ $NODE_TYPE != 'infrastructure' ]; then   
      task 'Checking SMS self-signed certificate'
      checkVECSCert 'SMS' 'sms_self_signed'

      if [[ "$VC_VERSION" =~ ^8 ]]; then
         task 'Checking SMS VMCA-signed certificate'
         checkVECSCert 'SMS' 'sps-extension'
      fi
	  
      if [ "$VC_VERSION" != '6.5' ]; then
         task 'Checking data-encipherment certificate'
         checkVECSCert 'data-encipherment' 'data-encipherment'
      fi
      
      task 'Checking Authentication Proxy certificate'
      checkFilesystemCert '/var/lib/vmware/vmcam/ssl/vmcamcert.pem'
      
      task 'Checking Auto Deploy CA certificate'
      checkFilesystemCert '/etc/vmware-rbd/ssl/rbd-ca.crt'
   fi
   
   if checkVECSStore 'BACKUP_STORE'; then
      echo 'Checking BACKUP_STORE entries:'
      for alias in $($VECS_CLI entry list --store BACKUP_STORE | grep Alias | awk '{print $NF}'); do
         task "   $alias"
         checkVECSCert 'BACKUP_STORE' $alias
      done
   fi
   if checkVECSStore 'BACKUP_STORE_H5C'; then
      echo 'Checking BACKUP_STORE_H5C entries:'
	  for alias in $($VECS_CLI entry list --store BACKUP_STORE_H5C | grep Alias | awk '{print $NF}'); do
         task "   $alias"
         checkVECSCert 'BACKUP_STORE_H5C' $alias
      done
	  
   fi
   if checkVECSStore 'STS_INTERNAL_SSL_CERT'; then
      task 'Checking legacy Lookup Service certificate'
      checkVECSCert 'STS_INTERNAL_SSL_CERT' '__MACHINE_CERT'
   fi
   
   if [ $NODE_TYPE != 'management' ]; then
      if [ -f '/usr/lib/vmware-vmdir/share/config/vmdircert.pem' ]; then
         task 'Checking VMDir certificate'
         checkFilesystemCert '/usr/lib/vmware-vmdir/share/config/vmdircert.pem'
	  fi
      
      task 'Checking VMCA certificate'
      checkFilesystemCert '/var/lib/vmware/vmca/root.cer'
      header 'Checking STS Signing Certs & Signing Chains'
      manageSTSTenantCerts 'Check'
   fi
   
   checkCACertificates
   
   checkSMSVASACerts
   
   quickCheckVECSStores
   
   quickCheckServicePrincipals
   
   checkCRLs
   
   manageCACCerts 'Check'
   
   manageLDAPSCerts 'Check'
   
   manageTanzuSupervisorClusterCerts 'Check'
   
   quickCheckSSLTrustAnchors
   
   if [ $NODE_TYPE != 'infrastructure' ]; then 
      manageVCExtensionThumbprints 'Checking'
	   checkAutoDeployDB
	   checkVMCADatabaseConfig
   fi

   if [ $NODE_TYPE != 'management' ]; then
      quickCheckSTSConfig
   fi
   
   buildCertificateStatusMessage
   
   if [ -n "$CERT_STATUS_MESSAGE" ]; then
      echo $'\n'"${YELLOW}------------------------!!! Attention !!!------------------------ "
      echo "$CERT_STATUS_MESSAGE${NORMAL}"    
   fi
}

#------------------------------
# Resets the certificate status flags
#------------------------------
function resetCertStatusChecks() {
   CERT_STATUS_MESSAGE=''
   CERT_STATUS_EXPIRES_SOON=0
   CERT_STATUS_MISSING_PNID=0
   CERT_STATUS_MISSING_SAN=0
   CERT_STATUS_KEY_USAGE=0
   CERT_STATUS_EXPIRED=0
   CERT_STATUS_NON_CA=0
   CERT_STATUS_BAD_ALIAS=0
   CERT_STATUS_SHA1_SIGNING=0
   CERT_STATUS_MISSING=0
   CERT_STATUS_MISSING_VMDIR=0
   CERT_STATUS_MISMATCH_SERVICE_PRINCIPAL=0
   CERT_STATUS_TOO_MANY_CRLS=0
   CERT_STATUS_MISSING_CA=0
   CERT_STATUS_EXPIRED_EMBEDDED_CA=0
   CERT_STATUS_STORE_MISSING=0
   CERT_STATUS_STORE_PERMISSIONS=0
   CERT_STATUS_SERVICE_PRINCIPAL_MISSING=0
   CERT_STATUS_VMCA_EMPTY_CONFIG=0
   CERT_STATUS_VMCA_MODE=0 
   CERT_STATUS_CLIENT_CA_LIST_FILE_LOCATION=0
   CERT_STATUS_CLIENT_CA_LIST_FILE_MISSING=0
   CERT_STATUS_STS_VECS_CONFIG=0
   CERT_STATUS_STS_CONNECTION_STRINGS=0
   CERT_STATUS_UNSUPPORTED_SIGNATURE_ALGORITHM=0
   CERT_STATUS_CA_MISSING_SKID=0
}

#------------------------------
# Checks on certificates in VECS
#------------------------------
function checkVECSCert() {
   KU_LIST='Digital Signature Key Encipherment Key Agreement Data Encipherment Non Repudiation'
   case $1 in
      'MACHINE_SSL_CERT')
         CHECK_PNID=1
         CHECK_KU=1
		   CHECK_SAN=1
         CHECK_SHA1=1
         CHECK_SERVICE_PRINCIPAL=0
		   CHECK_CA_CHAIN=1
		   CHECK_EMBEDDED_CHAIN=1
         ;;     

      SMS)
         CHECK_PNID=0
         CHECK_KU=0
         CHECK_SAN=0
         CHECK_SHA1=0
         CHECK_SERVICE_PRINCIPAL=0
		   CHECK_CA_CHAIN=0
		   CHECK_EMBEDDED_CHAIN=0
         ;;
      
      *)
         CHECK_PNID=0
         CHECK_KU=1
		   CHECK_SAN=1
         CHECK_SHA1=1
		   CHECK_CA_CHAIN=1
		   CHECK_EMBEDDED_CHAIN=1
         CHECK_SERVICE_PRINCIPAL=0
         if [[ " ${SOLUTION_USERS[*]} " =~ " $1 " ]]; then CHECK_SERVICE_PRINCIPAL=1; fi
		   if [ "$1" == 'wcp' ]; then CHECK_SAN=0; fi
         ;;
   esac
   logInfo "Checking VECS for store '$2'"
   if ! $VECS_CLI entry list --store $1 | grep Alias | grep $2 > /dev/null 2>&1; then
      CERT_STATUS_MISSING=1
	   statusMessage 'NOT FOUND' 'RED'
      logError "Store '$2' not found"
	   return 1
   else 
      logInfo "Found Store '$2'"
   fi
   
   TEMP_CERT=$($VECS_CLI entry getcert --store $1 --alias $2 2>/dev/null)
   
   if [ -z "$TEMP_CERT" ]; then 
      statusMessage 'PROBLEM' 'RED'
      logError "No certificate found for alias '$2' in store '$1'"
      return 1
   fi

   if ! isExpired "$TEMP_CERT" 'hash'; then
      DAYS_LEFT=$(checkCertExpireSoon "$TEMP_CERT")
      if [[ $DAYS_LEFT -ge 0 ]]; then
         CERT_STATUS_EXPIRES_SOON=1   
         statusMessage "$DAYS_LEFT DAYS" 'YELLOW'
         logInfo "Certificate for alias '$2' in store '$1' expires in $DAYS_LEFT days"
         return 0
      else
         if [ $CHECK_PNID = 1 ]; then
            if ! echo "$TEMP_CERT" | openssl x509 -noout -text 2>&1 | grep -A1 'Subject Alternative Name' | grep -i "$PNID" > /dev/null; then
               CERT_STATUS_MISSING_PNID=1
               statusMessage 'NO PNID' 'YELLOW' 
               logInfo "Certificate for alias '$2' in store '$1' does not have the PNID ($PNID) in the Subject Alternative Name field"
               return 0
            fi
         fi
         if [ $CHECK_KU = 1 ]; then
            if ! checkCertKeyUsage "$TEMP_CERT" "$1:$2" "$KU_LIST"; then
               CERT_STATUS_KEY_USAGE=1
               statusMessage 'KEY USAGE' 'YELLOW'
               logInfo "Certificate for alias '$2' in store '$1' does not have the expected Key Usage Values"           
               return 0
            fi             
         fi
         if [ $CHECK_SAN = 1 ]; then
            if ! echo "$TEMP_CERT" | openssl x509 -noout -text 2>&1 | grep 'Subject Alternative Name' > /dev/null; then
               CERT_STATUS_MISSING_SAN=1
               statusMessage 'NO SAN' 'YELLOW'
               logInfo "Certificate for alias '$2' in store '$1' has no values in the Subject Alternative Name field"
               return 0
            fi
         fi
         if [ $CHECK_SERVICE_PRINCIPAL = 1 ]; then
            if ! checkServicePrincipalCert "$1"; then                          
               CERT_STATUS_MISMATCH_SERVICE_PRINCIPAL=1
               statusMessage 'MISMATCH' 'YELLOW'
               logError "The certificate in the VECS store '$1' does not match the certificate for the corresponding Service Principal in VMware Directory"
               return 0
            fi
         fi
		   if [ $CHECK_CA_CHAIN = 1 ]; then
		      if ! checkCACertsPresent "$TEMP_CERT"; then
			      CERT_STATUS_MISSING_CA=1
			      statusMessage 'MISSING CA' 'YELLOW'
               logError "One of the CA certificates in the signing chain for the certificate for alias '$2' in store '$1' is missing"
			      return 0
			   fi
		   fi
		   if [ $CHECK_EMBEDDED_CHAIN = 1 ]; then
		      if ! checkEmbeddedChain "$TEMP_CERT"; then
			      CERT_STATUS_EXPIRED_EMBEDDED_CA=1
			      statusMessage 'EMBEDDED CA' 'YELLOW'
			      return 0
			   fi
		   fi
         if ! checkCertSignatureAlgorithm "$TEMP_CERT"; then
            CERT_STATUS_UNSUPPORTED_SIGNATURE_ALGORITHM=1
            statusMessage 'ALGORITHM' 'YELLOW'
            logInfo "Certificate for alias '$2' in store '$1' is signed with an unsupported Signature Algorithm" 
            return 0
         fi
         statusMessage 'VALID' 'GREEN'      
         return 0
      fi
   else
      CERT_STATUS_EXPIRED=1
      statusMessage 'EXPIRED' 'YELLOW'
      logError "Certificate for alias '$2' in store '$1' is expired"     
      return 1
   fi   
}

#------------------------------
# Check for the existence of the __MACHINE_CSR alias in VECS
#------------------------------
function checkMachineSSLCSR() {
   if $VECS_CLI entry list --store 'MACHINE_SSL_CERT' | grep Alias | grep '__MACHINE_CSR' > /dev/null 2>&1; then
      return 0
   else
      return 1
   fi
}

#------------------------------
# Check Solution User cert in VECS matches Service Principal
#------------------------------
function checkServicePrincipalCert() {
   VECS_THUMBPRINT=$($VECS_CLI entry getcert --store $1 --alias $1 2>&1 | openssl x509 -noout -fingerprint -sha1 2>&1)
   SERVICE_PRINCIPAL_HASH=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$1-$MACHINE_ID,cn=ServicePrincipals,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password userCertificate 2>&1 | grep '^userCertificate' | awk '{print $NF}')
   SERVICE_PRINCIPAL_CERT=$(buildCertFromHash "$SERVICE_PRINCIPAL_HASH")
   SERVICE_PRINCIPAL_THUMBPRINT=$(echo "$SERVICE_PRINCIPAL_CERT" | openssl x509 -noout -fingerprint -sha1 2>&1)
   logInfo "Checking Service Principal: VECS Thumbprint: $VECS_THUMBPRINT"
   logInfo "Checking Service Principal: Service Principal Thumbprint: $SERVICE_PRINCIPAL_THUMBPRINT"
   
   if [ "$VECS_THUMBPRINT" = "$SERVICE_PRINCIPAL_THUMBPRINT" ]; then
      return 0
   else
      return 1
   fi  
}

#------------------------------
# Check if certificate on the file system has expired
#------------------------------
function checkFilesystemCert() {
   if [ ! -f $1 ]; then
      CERT_STATUS_MISSING=1
      statusMessage 'NOT FOUND' 'RED'
      logError "Certificate at $1 could not be found"
      return 1
   fi
   logInfo "Checking certificate at $1"
   FS_CERT=$(cat $1)
   checkCert "$FS_CERT"
}

#------------------------------
# Check if certificate has expired
#------------------------------
function checkCert() {
   logInfo 'Checking the following certificate'
   logDetails "$1"
   logDebugDetails "'$(echo $1 | openssl x509 -noout -text 2>/dev/null)'"
   if ! isExpired "$1" 'hash'; then
      DAYS_LEFT=$(checkCertExpireSoon "$1")
      if [[ $DAYS_LEFT -gt 0 ]]; then
         CERT_STATUS_EXPIRES_SOON=1   
         statusMessage "$DAYS_LEFT DAYS" 'YELLOW'
         logInfo "Certificate expires in $DAYS_LEFT days"
         return 0
      else
         if ! checkCertSignatureAlgorithm "$1"; then
            CERT_STATUS_UNSUPPORTED_SIGNATURE_ALGORITHM=1
            statusMessage 'ALGORITHM' 'YELLOW'
            return 1
         fi
         statusMessage 'VALID' 'GREEN'
         logInfo 'Certificate is valid'
         return 0
      fi
   else
      CERT_STATUS_EXPIRED=1
      statusMessage 'EXPIRED' 'YELLOW'
      logError 'Certificate is expired'   
      return 1
   fi
}

#------------------------------
# Check if a certificate is expired
#------------------------------
function isExpired() {
   if [ "$2" == 'file' ]; then
      HASH=$(cat "$1")
   else
      HASH="$1"
   fi
   logInfo 'Checking expiration of the following certificate'
   logDetails "$HASH"
   if echo "$HASH" | openssl x509 -noout -checkend 0 > /dev/null 2>&1; then
      return 1
   else
      return 0
   fi
}

#------------------------------
# Backup certificate and key from filesystem
#------------------------------
function backupFilesystemCertKey() {
   task 'Backing up certificate and private key'
   
   if [ -f $1 ]; then
     cp $1 $BACKUP_DIR/$3-$TIMESTAMP.crt 2>&1 | logDebug || errorMessage "Unable to backup $3 certificate"
   else
      statusMessage 'NOT FOUND' 'YELLOW'
      logError "Certificate not found at $1"
   fi
   
   if [ -f $2 ]; then
      cp $2 $BACKUP_DIR/$3-$TIMESTAMP.key 2>&1 | logDebug || errorMessage "Unable to backup $3 key"
   else
      statusMessage 'NOT FOUND' 'YELLOW'
      logError "Private key not found at $2"
   fi
   statusMessage 'OK' 'GREEN'
   logInfo "Certificate and key backed up to $BACKUP_DIR/$3-$TIMESTAMP.crt and $BACKUP_DIR/$3-$TIMESTAMP.key"
}

#------------------------------
# Check if cert has unsupported signature algorithms
#------------------------------
function checkCertSignatureAlgorithm() {
   CERT_HASH=$1
   CERT_SIGNATURE_ALGORITHM=$(echo "$CERT_HASH" | openssl x509 -noout -text | grep 'Signature Algorithm' | head -n1 | awk '{print $NF}')
   logInfo "Checking certificate signature algorithm '$CERT_SIGNATURE_ALGORITHM' against unsupported signature algorithms ($UNSUPPORTED_SIGNATURE_ALGORITHMS)"
   if echo "$CERT_SIGNATURE_ALGORITHM" | grep -iE "$UNSUPPORTED_SIGNATURE_ALGORITHMS" > /dev/null; then
      return 1
   else
      return 0
   fi
}

#------------------------------
# Check if cert has recommended Key Usage
#------------------------------
function checkCertKeyUsage() {
   CERT_HASH=$1
   CERT_DESCRIPTION=$2
   KU_LIST=$3
   UNSUPPORTED_KEY_USAGE=0
   
   if ! echo "$CERT_HASH" | openssl x509 -text -noout 2>/dev/null | grep 'X509v3 Key Usage' > /dev/null; then
      return 0
   fi

   logInfo "Checking Key Usage for cert $CERT_DESCRIPTION among supported values of: $KU_LIST"
   
   KEY_USAGE_SEARCH=$(echo "$CERT_HASH" | openssl x509 -text -noout 2>/dev/null | grep -A1 'X509v3 Key Usage' | tail -n1 | sed -e 's/^[[:space:]]*//' -e 's/, /\n/g')
   
   IFS=$'\n'
   for key_usage in $KEY_USAGE_SEARCH; do
      KEY_USAGE_SEARCH_RESULT=$(echo "$KU_LIST" | grep "$key_usage")
      if [ -z "$KEY_USAGE_SEARCH_RESULT" ]; then
	     logInfo "Found unsupported Key Usage value: $key_usage"
	     UNSUPPORTED_KEY_USAGE=1
	  else
	     logInfo "Found supported Key Usage value: $key_usage"
	  fi
   done
   IFS=$' \t\n'
   if [ "$UNSUPPORTED_KEY_USAGE" == 1 ]; then
      return 1
   else
      return 0
   fi
}

#------------------------------
# Check if cert is expiring within 30 days
#------------------------------
function checkCertExpireSoon() {
   if ! echo "$1" | openssl x509 -noout -checkend 2592000 > /dev/null 2>&1; then
      CERT_END_DATE=$(echo "$1" | openssl x509 -noout -enddate 2>/dev/null | sed "s/.*=\(.*\)/\1/")
      CERT_END_EPOCH=$(date -d "$CERT_END_DATE" +%s)
      NOW_EPOCH=$(date -d now +%s)
      DAYS_LEFT=$(( (CERT_END_EPOCH - NOW_EPOCH) / 86400))
      
      echo "$DAYS_LEFT"
   else
      echo '-1'
   fi
}

#------------------------------
# Check VASA Provider certs in SMS store
#------------------------------
function checkSMSVASACerts() {
   if [ $NODE_TYPE != 'infrastructure' ]; then
      SMS_VASA_ENTRIES=$($VECS_CLI entry list --store SMS | grep Alias | sed -e 's/Alias ://g' -e 's/^[[:space:]]*//g' | grep -vE '^sms_self_signed$|^sps-extension$')
      if [ -n "$SMS_VASA_ENTRIES" ]; then
         header 'Checking Additional Entries in SMS Store'
	  
         for alias in $SMS_VASA_ENTRIES; do
            task "$alias"
            checkVECSCert 'SMS' "$alias"
         done
      fi
   fi
}

#------------------------------
# Quick check of VECS store status and permissions
#------------------------------
function quickCheckVECSStores() {
   header 'Checking VECS Stores'
   echo 'Checking status and permissions for VECS stores:'
   logInfo 'Checking status and permissions for VECS stores'
   MISSING_STORES=''
   declare -gA MISSING_STORE_READ_PERMISSIONS=()
   declare -gA MISSING_STORE_WRITE_PERMISSIONS=()
   
   for store in $VECS_STORES; do
      task "   $store"
	   if ! checkVECSStore $store; then
	      CERT_STATUS_STORE_MISSING=1
		   if [ -z "$MISSING_STORES" ]; then MISSING_STORES+="$store"; else MISSING_STORES+=" $store"; fi
		   statusMessage 'MISSING' 'YELLOW'
         logError "Could not find store '$store' in VECS"
	   else
	      PERMISSIONS_OK=1
	      STORE_PERMISSIONS=$($VECS_CLI store get-permissions --name $store)
		   STORE_PERMISSIONS_FORMATTED=$'\n'$(echo "$STORE_PERMISSIONS" | head -n2)
		   STORE_PERMISSIONS_FORMATTED+=$'\n'$(echo "$STORE_PERMISSIONS" | tail -n+3 | column -t)
         logInfo "Permissions for VECS store $store:"
		   logDetails "$STORE_PERMISSIONS_FORMATTED"
		   logInfo "Users with expected read permissions: ${VECS_STORE_READ_PERMISSIONS[$store]}"
		   logInfo "Users with expected write permissions: ${VECS_STORE_WRITE_PERMISSIONS[$store]}"
		   for user in ${VECS_STORE_READ_PERMISSIONS[$store]}; do
		      if ! echo "$STORE_PERMISSIONS" | grep $user | grep 'read' > /dev/null; then
			      logInfo "Could not find read permission for user $user in VECS store $store"
			      if [ -z ${MISSING_STORE_READ_PERMISSIONS[$store]} ]; then MISSING_STORE_READ_PERMISSIONS[$store]="$user"; else MISSING_STORE_READ_PERMISSIONS[$store]=" $user"; fi
			      PERMISSIONS_OK=0
			   else
			      logInfo "Found read permission for user $user in VECS store $store"
			   fi			
		   done
		   if [[ "$VC_VERSION" =~ ^[78] ]] && [ $VC_BUILD -ge 20051473 ]; then
		      for user in ${VECS_STORE_WRITE_PERMISSIONS[$store]}; do
			      if ! echo "$STORE_PERMISSIONS" | grep $user | grep -E 'OWNER|write' > /dev/null; then                  
			         logInfo "Could not find write permission for user $user in VECS store $store"
				      if [ -z ${MISSING_STORE_WRITE_PERMISSIONS[$store]} ]; then MISSING_STORE_WRITE_PERMISSIONS[$store]="$user"; else MISSING_STORE_WRITE_PERMISSIONS[$store]=" $user"; fi
				      PERMISSIONS_OK=0
			      else
			         logInfo "Found write permission for user $user in VECS store $store"
			      fi
			   done
		   fi
		   if [ $PERMISSIONS_OK == 1 ]; then
		      statusMessage 'OK' 'GREEN'
		   else
		      CERT_STATUS_STORE_PERMISSIONS=1
			   statusMessage 'PERMISSIONS' 'YELLOW'
		   fi
	   fi
   done
}

#------------------------------
# Check and remediation of VECS store status and permissions
#------------------------------
function checkVECSStores() {
   quickCheckVECSStores
   unset RECREATE_VECS_STORES_INPUT
   unset FIX_VECS_STORES_PERMISSIONS
   
   if [ -n "$MISSING_STORES" ]; then
      read -p $'\n'"Some VECS stores are missing, recreate them? [n]: " RECREATE_VECS_STORES_INPUT
	  if [[ $RECREATE_VECS_STORES_INPUT =~ ^[Yy] ]]; then recreateMissingVECSStores; fi
   fi
   
   if [[ ${MISSING_STORE_READ_PERMISSIONS[*]} ]] || [[ ${MISSING_STORE_WRITE_PERMISSIONS[*]} ]]; then
      read -p $'\n'"Some VECS stores are missing expected permissions, reassign them? [n]: " FIX_VECS_STORES_PERMISSIONS
      if [[ $FIX_VECS_STORES_PERMISSIONS =~ ^[Yy] ]]; then  fixVECSStorePermissions; fi
   fi   
}

#------------------------------
# Recreate missing VECS store
#------------------------------
function recreateMissingVECSStores() {
   header 'Recreate missing VECS stores'
   for store in $MISSING_STORES; do
      task "Recreate store $store"
	   if [ "$store" == "SMS" ]; then
	      vmon-cli -r sps > /dev/null 2>&1 || errorMessage "Unable to create the VECS store SMS by restarting the sps service"
	   else
	      $VECS_CLI store create --name $store > /dev/null 2>&1 || errorMessage "Unable to create VECS store $store"
	   fi
	   statusMessage 'OK' 'GREEN'
	   echo 'Assigning permissions:'
	   for user in ${VECS_STORE_READ_PERMISSIONS[$store]}; do
	      task "   Read permmisson for user $user"
		   $VECS_CLI store permission --name $store --user $user --grant read > /dev/null 2>&1 || errorMessage "Unable to assign read permission to user $user on store $store"
		   statusMessage 'OK' 'GREEN'
	   done
	   if [[ "$VC_VERSION" =~ ^[78] ]] && [ $VC_BUILD -ge 20051473 ]; then
	      for user in ${VECS_STORE_WRITE_PERMISSIONS[$store]}; do
		      task "   Write permmisson for user $user"
		      $VECS_CLI store permission --name $store --user $user --grant write > /dev/null 2>&1 || errorMessage "Unable to assign write permission to user $user on store $store"
		      statusMessage 'OK' 'GREEN'
		   done
	   fi
   done
}

#------------------------------
# Recreate missing VECS store permissions
#------------------------------
function fixVECSStorePermissions() {
   header 'Fix VECS store permissions'
   logInfo "Stores missing read permissions: ${!MISSING_STORE_READ_PERMISSIONS[*]}"
   for store in "${!MISSING_STORE_READ_PERMISSIONS[@]}"; do
      echo "Assign read permissions on store $store:"
	  for user in ${MISSING_STORE_READ_PERMISSIONS[$store]}; do
	     task "   Read permission for user $user"
		 $VECS_CLI store permission --name $store --user $user --grant read > /dev/null 2>&1 || errorMessage "Unable to assign read permission to user $user on store $store"
		 statusMessage 'OK' 'GREEN'
	  done
   done
   if [[ "$VC_VERSION" =~ ^[78] ]] && [ $VC_BUILD -ge 20051473 ]; then
      logInfo "Stores missing write permissions: ${!MISSING_STORE_WRITE_PERMISSIONS[*]}"
      for store in "${!MISSING_STORE_WRITE_PERMISSIONS[@]}"; do
	      echo "Assign write permissions on store $store:"
	      for user in ${MISSING_STORE_WRITE_PERMISSIONS[$store]}; do
		      task "   Write permission for user $user"
			   $VECS_CLI store permission --name $store --user $user --grant write > /dev/null 2>&1 || errorMessage "Unable to assign write permission to user $user on store $store"
		      statusMessage 'OK' 'GREEN'
		   done
	   done
   fi
}

#------------------------------
# Check if a particular VECS store is present
#------------------------------
function checkVECSStore() {
   if $VECS_CLI store list | grep "^$1\$" > /dev/null; then
      return 0
   else
      return 1
   fi
}

#------------------------------
# Check if a particular entry exists in a VECS store
#------------------------------
function checkVECSEntry() {
   if $VECS_CLI entry list --store "$1" | grep "$2\$" > /dev/null; then
      return 0
   else
      return 1
   fi
}

#------------------------------
# Manage STS Signing certificates
#------------------------------
function manageSTSTenantCerts() {
   case $1 in
      'Check')      
         checkSTSTenantCerts
         checkSTSTrustedCertChains
      ;;
      
      'View')
         viewSTSTenantCerts
      ;;
      
      'Replace')
         authenticateIfNeeded
         viewSTSTenantCerts
         if promptReplaceSTS; then
            if replaceSSOSTSCert; then promptRestartVMwareServices; fi
         fi
      ;;
   esac
}

#------------------------------
# Manage Smart Card (CAC) certificates
#------------------------------
function manageCACCerts() {
   case $1 in
      'Check')
         if configuredForCAC; then
            checkRhttpproxyCACCerts
            checkVMDirCACCerts
         fi
         ;;   
      'View')
         if configuredForCAC; then
            viewRhttpproxyCACCerts
            viewVMDirCACCerts
         else
            echo $'\n'"${YELLOW}This vCenter Server is not configured for Smart Card authentication${NORMAL}"
         fi
         ;;      
      'Manage')
         if configuredForCAC; then
            viewRhttpproxyCACCerts
            viewVMDirCACCerts
            header 'Manage Smart Card Issuing CA Certificates'
            cat << EOF
1. Add Smart Card issuing CA certificate(s)
   to Reverse Proxy filter file
2. Remove Smart Card issuing CA certificate(s)
   from Reverse Proxy filter file
3. Add Smart Card issuing CA certificate(s)
   to VMware Directory
4. Remove Smart Card issuing CA certificate(s)
   from VMware Directory   
EOF
            read -p $'\n'"Enter selection [Return to Main Menu]: " MANAGE_CAC_INPUT
            
            case $MANAGE_CAC_INPUT in
               1)
                  addCACCertsFilterFile
                  ;;               
               2)
                  removeCACCertsFilterFile
                  ;;			   
               3)
                  updateSSOCACConfig 'add'
                  ;;               
               4)
                  updateSSOCACConfig 'remove'
                  ;;
            esac
         else
            echo $'\n'"This vCenter Server is not configured for Smart Card authentication"
            read -t $READ_TIMEOUTS -p $'\nConfigure vCenter Server for Smart Card authentication? [n]: ' CONFIGURE_CAC_INPUT
            
            if [ $? -lt 128 ]; then
               if [[ "$CONFIGURE_CAC_INPUT" =~ ^[Yy] ]]; then configureCACAuthentication; fi
            else
               echo ''
            fi
         fi
         ;;
   esac
}

#------------------------------
# Check Reverse Proxy Smart Card signing CA certificates
#------------------------------
function checkRhttpproxyCACCerts() {
   CAC_FILTER_FILE=$(grep clientCAListFile /etc/vmware-rhttpproxy/config.xml | sed -e 's|<clientCAListFile>||g' -e 's|</clientCAListFile>||g' | tr -d ' ' | grep -v '^<!--')
   if [ -n "$CAC_FILTER_FILE" ]; then
      header 'Check Reverse Proxy Smart Card signing CA certificates'
      task 'Check CA Filter File'
      if [[ "$VC_VERSION" =~ ^7 ]] && [[ $VC_BUILD -ge 20845200 ]]; then
         if [ "$CAC_FILTER_FILE" == '/usr/lib/vmware-sso/vmware-sts/conf/clienttrustCA.pem' ]; then
            if [ -s $CAC_FILTER_FILE ]; then
               statusMessage 'OK' 'GREEN'
            else
               statusMessage 'MISSING' 'YELLOW'
               CERT_STATUS_CLIENT_CA_LIST_FILE_MISSING=1
            fi
         else
            statusMessage 'PROBLEM' 'YELLOW'
            CERT_STATUS_CLIENT_CA_LIST_FILE_LOCATION=1
         fi
      else
         if [ -s $CAC_FILTER_FILE ]; then
            statusMessage 'OK' 'GREEN'
         else
            statusMessage 'MISSING' 'YELLOW'
            CERT_STATUS_CLIENT_CA_LIST_FILE_MISSING=1
         fi
      fi
      if [ -s $CAC_FILTER_FILE ]; then
         rm $STAGE_DIR/rhttpproxy-ca-* 2>&1 | logDebug
         csplit -s -z -f $STAGE_DIR/rhttpproxy-ca- -b %02d.crt $CAC_FILTER_FILE '/-----BEGIN CERTIFICATE-----/' '{*}'
	      i=1
         #for cert in $(ls $STAGE_DIR/rhttpproxy-ca-*); do
	      #   task "Certificate $i"
		   #   checkFilesystemCert "$cert"
		   #   ((++i))
	      #done
         for cert in $STAGE_DIR/rhttpproxy-ca-*; do
            [[ -e "$cert" ]] || break
            task "Certificate $i"
            checkFilesystemCert "$cert"
            ((++i))
         done
	      rm $STAGE_DIR/rhttpproxy-ca-* 2>&1 | logDebug
      fi
   fi
}

#------------------------------
# View Reverse Proxy Smart Card signing CA certificates
#------------------------------
function viewRhttpproxyCACCerts() {
   REVERSE_PROXY_CAC_CERT_THUMBPRINTS=()
   CAC_FILTER_FILE=$(grep clientCAListFile /etc/vmware-rhttpproxy/config.xml | sed -e 's|<clientCAListFile>||g' -e 's|</clientCAListFile>||g' | tr -d ' ' | grep -v '^<!--')
   if [ -z $CAC_FILTER_FILE ] && [ -f /usr/lib/vmware-sso/vmware-sts/conf/clienttrustCA.pem ] && [ ! -z "$(cat /usr/lib/vmware-sso/vmware-sts/conf/clienttrustCA.pem)" ]; then
      CAC_FILTER_FILE='/usr/lib/vmware-sso/vmware-sts/conf/clienttrustCA.pem'
   fi
   header 'Reverse Proxy CA Certificate Filter File'
   logInfo "Smart Card filter file: $CAC_FILTER_FILE"
   if [ -n "$CAC_FILTER_FILE" ] && [ -s "$CAC_FILTER_FILE" ]; then
      rm $STAGE_DIR/rhttpproxy-ca-* 2>&1 | logDebug
      csplit -s -z -f $STAGE_DIR/rhttpproxy-ca- -b %02d.crt $CAC_FILTER_FILE '/-----BEGIN CERTIFICATE-----/' '{*}'
      i=1
      for cert in $STAGE_DIR/rhttpproxy-ca-*; do
         [[ -e "$cert" ]] || break
         TEMP_CERT=$(cat "$cert")         
         CERT_OUTPUT=$(viewBriefCertificateInfo "$TEMP_CERT")
         REVERSE_PROXY_CAC_CERT_THUMBPRINTS+=($(openssl x509 -noout -fingerprint -sha1 -in $cert 2>>/dev/null | awk -F'=' '{print $NF}'))
         printf "%2s. %s\n\n" $i "$CERT_OUTPUT"
         ((++i))
      done
      rm $STAGE_DIR/rhttpproxy-ca-* 2>&1 | logDebug
   else
      echo "${YELLOW}No Smart Card CA filter file found or it is empty.$NORMAL"
   fi
}

#------------------------------
# Check VMware Directory Smart Card signing CA certificates
#------------------------------
function checkVMDirCACCerts() {
   CAC_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=ClientCertAuthnTrustedCAs,cn=Default,cn=ClientCertificatePolicies,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,${VMDIR_DOMAIN_DN}" -D "cn=${VMDIR_USER},cn=users,${VMDIR_DOMAIN_DN}" -y $STAGE_DIR/.vmdir-user-password '(objectclass=*)' userCertificate 2>/dev/null | grep -v '^dn:' | sed -e 's/userCertificate:: //g')
   if [ -n "$CAC_CERTS" ]; then
      header 'Check VMDir Smart Card signing CA certificates'
      i=1
	  for hash in $CAC_CERTS; do
	     TEMP_CERT=$(buildCertFromHash "$hash")
		 task "Certificate $i"
		 checkCert "$TEMP_CERT"
		 ((++i))
	  done
   fi
}

#------------------------------
# View VMware Directory Smart Card signing CA certificates
#------------------------------
function viewVMDirCACCerts() {
   CAC_CERT_LIST=()
   header 'Smart Card Issuing CA Certificates'
   CAC_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=ClientCertAuthnTrustedCAs,cn=Default,cn=ClientCertificatePolicies,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,${VMDIR_DOMAIN_DN}" -D "cn=${VMDIR_USER},cn=users,${VMDIR_DOMAIN_DN}" -y $STAGE_DIR/.vmdir-user-password '(objectclass=*)' userCertificate 2>/dev/null | grep -v '^dn:' | sed -e 's/userCertificate:: //g')
   i=1
   if [ -n "$CAC_CERTS" ]; then
      for hash in $CAC_CERTS; do
         TEMP_CERT=$(buildCertFromHash "$hash")
         CAC_CERT_LIST+=("$TEMP_CERT")
         CERT_OUTPUT=$(viewBriefCertificateInfo "$TEMP_CERT")
      
         printf "%2s. %s\n\n" $i "$CERT_OUTPUT"
         ((++i))
      done
   else
      echo "${YELLOW}No Smart Card issuing CA certificates found in VMware Directory.$NORMAL"
   fi
}

#------------------------------
# Add Smart Card (CAC) issuing certificates to reverse proxy filter file
#------------------------------
function addCACCertsFilterFile() {
   read -e -p $'\nEnter path to new Smart Card issuing certifcate(s): ' NEW_CAC_CERTS_INPUT
   while [ ! -f $NEW_CAC_CERTS_INPUT ]; do read -s -p $'\n'"${YELLOW}File not found, enter path to new Smart Card issuing certifcate(s):${NORMAL} " NEW_CAC_CERTS_INPUT; done
   
   rm $STAGE_DIR/new-cac-cert-* 2>&1 | logDebug
   csplit -s -z -f $STAGE_DIR/new-cac-cert- -b %02d.crt $NEW_CAC_CERTS_INPUT '/-----BEGIN CERTIFICATE-----/' '{*}'
   
   header 'Adding New Smart Card Issuing Certificates'
   CAC_FILTER_FILE=$(grep '<clientCAListFile>' /etc/vmware-rhttpproxy/config.xml | awk -F'>' '{print $2}' | awk -F'<' '{print $1}')
   if ! echo $CAC_FILTER_FILE | grep '^/' > /dev/null 2>&1; then CAC_FILTER_FILE="/etc/vmware/rhttpproxy/$CAC_FILTER_FILE"; fi
   
   for cert in $(ls $STAGE_DIR/new-cac-cert-*); do
      if ! isExpired "$cert" 'file'; then
         task "Adding cert $(openssl x509 -noout -hash -in $cert 2>&1 | logDebug) to reverse proxy file"
         cat $cert >> $CAC_FILTER_FILE
         statusMessage 'OK' 'GREEN'                  
      fi
   done
   sed -i '/^$/d' $CAC_FILTER_FILE
}

#------------------------------
# Remove Smart Card (CAC) issuing certificates from reverse proxy filter file
#------------------------------
function removeCACCertsFilterFile() {
   read -p $'\nEnter number of Smart Card issuing certificate(s) to remove (comma-separated list): ' CAC_CERT_REMOVE_INPUT
   
   if [ -n "$CAC_CERT_REMOVE_INPUT" ]; then
      header 'Removing Smart Card Issuing Certificates'
      HASHES_TO_REMOVE=()
      for index in $(echo $CAC_CERT_REMOVE_INPUT | tr -d ' ' | sed 's/,/ /g'); do
         HASHES_TO_REMOVE+=(" ${REVERSE_PROXY_CAC_CERT_THUMBPRINTS[$((index - 1))]}")
      done
	  
	  CAC_FILTER_FILE=$(grep clientCAListFile /etc/vmware-rhttpproxy/config.xml | sed -e 's|<clientCAListFile>||g' -e 's|</clientCAListFile>||g' | tr -d ' ')
      if ! echo "$CAC_FILTER_FILE" | grep '^/' > /dev/null 2>&1; then CAC_FILTER_FILE="/etc/vmware/rhttpproxy/$CAC_FILTER_FILE"; fi
      
	  logInfo "Hashes to remove from $CAC_FILTER_FILE: ${HASHES_TO_REMOVE[@]}"
            
	  if [ -f $CAC_FILTER_FILE ]; then
         if [ -f $STAGE_DIR/new-cac-certs.pem ]; then rm $STAGE_DIR/new-cac-certs.pem; fi
         csplit -s -z -f $STAGE_DIR/rhttpproxy-ca- -b %02d.crt $CAC_FILTER_FILE '/-----BEGIN CERTIFICATE-----/' '{*}'
         for cert in $(ls $STAGE_DIR/rhttpproxy-ca-*); do
            CERT_THUMBPRINT=$(openssl x509 -noout -fingerprint -sha1 -in $cert 2>/dev/null | awk -F'=' '{print $NF}')
            if [[ ! " ${HASHES_TO_REMOVE[@]} " =~ " $CERT_THUMBPRINT" ]]; then
               cat $cert >> $STAGE_DIR/new-cac-certs.pem
            fi
         done
         task 'Updating reverse proxy filter file'
         cp $STAGE_DIR/new-cac-certs.pem $CAC_FILTER_FILE > /dev/null 2>&1 || errorMessage 'Unable to update reverse proxy filter file'
         statusMessage 'OK' 'GREEN'
      else
         errorMessage 'Unable to determine reverse proxy filter file'
      fi
   fi
   rm $STAGE_DIR/rhttpproxy-ca-* 2>&1 | logDebug        
}

#------------------------------
# Configure Smart Card (CAC) authentication
#------------------------------
function configureCACAuthentication() {
   read -e -p $'\nEnter path to Smart Card issuing CA certificate(s): ' CAC_CA_FILE_INPUT
   while [ ! -f "$CAC_CA_FILE_INPUT" ]; do read -e -p 'File not found, please provide path to the Smart Card issuing CA certificate(s) certificate: ' CAC_CA_FILE_INPUT; done
   
   header 'Configure Smart Card authentication'
   task 'Verify CA certificates'
   csplit -s -z -f $STAGE_DIR/cac-ca- -b %02d.crt "$CAC_CA_FILE_INPUT" '/-----BEGIN CERTIFICATE-----/' '{*}'
   
   for cert in $(ls $STAGE_DIR/cac-ca-*); do
      if isCertCA "$(cat $cert)"; then
         if ! isExpired "$cert" 'file'; then
            cat "$cert" >> $STAGE_DIR/cac-certs.pem
         fi
      fi
   done
   statusMessage 'OK' 'GREEN'
   
   if [ ! -s $STAGE_DIR/cac-certs.pem ]; then
      errorMessage "No valid CA certificates found in $CAC_CA_FILE_INPUT"
   else
      task 'Backup reverse proxy config'
      cp /etc/vmware-rhttpproxy/config.xml /etc/vmware-rhttpproxy/config.xml.backup 2>/dev/null || errorMessage 'Unable to backup /etc/vmware-rhttpproxy/config.xml'
      statusMessage 'OK' 'GREEN'
      
      cp $STAGE_DIR/cac-certs.pem /usr/lib/vmware-sso/vmware-sts/conf/clienttrustCA.pem
      
      task 'Configure reverse proxy'
      CAC_FILTER_FILE=$(grep '<clientCAListFile>' /etc/vmware-rhttpproxy/config.xml | awk -F'>' '{print $2}' | awk -F'<' '{print $1}')
      sed -i -e "s|$CAC_FILTER_FILE|/usr/lib/vmware-sso/vmware-sts/conf/clienttrustCA.pem|" -e 's|<!-- <clientCAListFile>|<clientCAListFile>|' -e 's|</clientCAListFile> -->|</clientCAListFile>|' -e 's|<!-- <clientCertificateMaxSize>|<clientCertificateMaxSize>|' -e 's|</clientCertificateMaxSize> -->|</clientCertificateMaxSize>|' -e '/<clientCAListFile>/i <requestClientCertificate>true</requestClientCertificate>' /etc/vmware-rhttpproxy/config.xml > /dev/null 2>&1 || errorMessage 'Unable to update reverse proxy configuration'
      statusMessage 'OK' 'GREEN'
      
      updateSSOCACConfig 'add' '/usr/lib/vmware-sso/vmware-sts/conf/clienttrustCA.pem'
   fi  
}

#------------------------------
# Export SSO Smart Card CA certificates
#------------------------------
function exportSSOCACCerts() {
   SSO_CAC_CA_CERTS=$(ldapsearch -LLL -h localhost -b "cn=DefaultClientCertCAStore,cn=ClientCertAuthnTrustedCAs,cn=Default,cn=ClientCertificatePolicies,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password userCertificate 2>/dev/null | sed -e 's/^ //g' | tr -d '\n' | sed -e 's/dn:/\n&/g' -e 's/userCertificate:/\n&/g' | grep '^userCertificate' | awk '{print $NF}')
   logInfo 'Exporting Smart Card CA certificates from VMware Directory'
   SSO_CAC_CA_CERT_FILES=()
   if [ -n "$SSO_CAC_CA_CERTS" ]; then
      i=$1
	   for hash in $SSO_CAC_CA_CERTS; do
	      CERT_PRESENT=0
	      TEMP_CERT=$(buildCertFromHash "$hash")
		   TEMP_CERT_THUMBPRINT=$(echo "$TEMP_CERT" | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
		   logInfo "Checking SSO Smart Card CA certificate with thumbprint $TEMP_CERT_THUMBPRINT"
         for cert in $(ls $STAGE_DIR/sso-cac-ca-cert-*.crt); do
		      CURRENT_CERT_THUMBPRINT=$(openssl x509 -noout -fingerprint -sha1 -in $cert 2>/dev/null | awk -F'=' '{print $NF}')
            logDebug "Checking SSO Smart Card CA certificate thumbprint ($TEMP_CERT_THUMBPRINT) against new certificate thumbprint ($CURRENT_CERT_THUMBPRINT)"
			   if [ "$CURRENT_CERT_THUMBPRINT" = "$TEMP_CERT_THUMBPRINT" ]; then CERT_PRESENT=1; fi
		   done
		 
		   if [ $CERT_PRESENT -eq 0 ]; then
		      echo "$TEMP_CERT" > $STAGE_DIR/sso-cac-ca-cert-$i.crt
		      SSO_CAC_CA_CERT_FILES+=("$STAGE_DIR/sso-cac-ca-cert-$i.crt")
            logInfo "Saving SSO Smart Card CA certificate to $STAGE_DIR/sso-cac-ca-cert-$i.crt"
		   fi
		   ((++i))
	  done
   fi
}

#------------------------------
# Export SSO LDAPS CA certificates
#------------------------------
function exportSSOLDAPSCerts() {
   logInfo "Exporting LDAPS certificates with Identity Source type: $1"
   case $1 in
      'Microsoft ADFS')
	      LDAPS_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=VCIdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' userCertificate 2>/dev/null | sed -e 's/^ //g' | grep '^userCertificate:' | awk '{print $NF}')         
	      ;;
      *)
	      LDAPS_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$2,cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(|(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP))' userCertificate 2>/dev/null | sed -e 's/^ //g' | grep '^userCertificate:' | awk '{print $NF}')		 
	      ;;
   esac   
   
   for hash in $LDAPS_CERTS; do
      TEMP_CERT=$(buildCertFromHash "$hash")
      TEMP_CERT_SUBJECT_HASH=$(echo "$TEMP_CERT" | openssl x509 -noout -hash)
      echo "$TEMP_CERT" > $STAGE_DIR/${3}$TEMP_CERT_SUBJECT_HASH.crt
   done
} 

#------------------------------
# Update SSO with Smart Card configuration
#------------------------------
function updateSSOCACConfig() {
   rm $STAGE_DIR/sso-cac-ca-cert-* > /dev/null 2>&1
   CAC_CA_CERTS=()     
   case $1 in 
      'add')
         if [ -n "$2" ]; then
            CA_FILE=$2
         else
            read -e -p $'\nEnter path to smart card CA certificate file: ' CA_FILE
            while [ ! -f $CA_FILE ]; do read -e -p "${YELLOW}File not found, enter path to smart card CA certificate file:${NORMAL} " CA_FILE; done
         fi
         header 'Adding Smart Card CA certificates to VMware Directory'
         csplit -z -s -f $STAGE_DIR/sso-cac-ca-cert- -b %01d.crt $CA_FILE '/-----BEGIN CERTIFICATE-----/' '{*}'
		 
         CAC_CA_CERT_COUNT=$(ls $STAGE_DIR/sso-cac-ca-cert-* | wc -l)
		 
         exportSSOCACCerts "$CAC_CA_CERT_COUNT"
		 
         for cert in $(ls $STAGE_DIR/sso-cac-ca-cert-*); do
            CERT_HASH=$(openssl x509 -noout -hash -in $cert 2>&1 | logDebug)
            task "Adding certificate $CERT_HASH"
            CAC_CA_CERTS+=("$cert")
            statusMessage 'OK' 'GREEN'
         done
         ;;
	  
      'remove')
         exportSSOCACCerts '0'
		 
         read -p $'\nEnter the number(s) of the certificate(s) to delete (multiple entries separated by a comma): ' CAC_CAS_TO_REMOVE
		 
         if [ -n "$CAC_CAS_TO_REMOVE" ]; then
            header 'Removing Smart Card CA certificates from VMware Directory'
            for index in $(echo $CAC_CAS_TO_REMOVE | tr -d ' ' | sed 's/,/ /g'); do
               CERT_TO_REMOVE=${CAC_CERT_LIST[$((index - 1))]}
               THUMBPRINT_TO_REMOVE=$(echo "$CERT_TO_REMOVE" | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
               SUBJECT_HASH_TO_REMOVE=$(echo "$CERT_TO_REMOVE" | openssl x509 -noout -hash)
               for cert in $(ls $STAGE_DIR/sso-cac-ca-cert-*); do
                  CURRENT_CERT_THUMBPRINT=$(openssl x509 -noout -fingerprint -sha1 -in $cert 2>/dev/null | awk -F'=' '{print $NF}')
				  
                  if [ "$THUMBPRINT_TO_REMOVE" = "$CURRENT_CERT_THUMBPRINT" ]; then
                     task "Removing certificate $SUBJECT_HASH_TO_REMOVE"
                     rm $cert > /dev/null 2>&1 || errorMessage "Unable to remove certificate $SUBJECT_HASH_TO_REMOVE"
                     statusMessage 'OK' 'GREEN'
                  fi
               done
            done
         fi
		 
         for cert in $(ls $STAGE_DIR/sso-cac-ca-cert-*); do
            CAC_CA_CERTS+=("$cert")
         done
         ;;
   esac
   
   SSO_CAC_CERTS=$(printf -v joined '%s,' "${CAC_CA_CERTS[@]}"; echo "${joined%,}")
   logInfo "Updating SSO configuration with '$SSO_CAC_CERTS'"
   task 'Update SSO configuration'
   sso-config.sh -set_authn_policy -certAuthn true -cacerts "$SSO_CAC_CERTS" -t "$SSO_DOMAIN" > /dev/null 2>&1 || errorMessage "Unable to configure SSO for Smart Card authentication"
   
   statusMessage 'OK' 'GREEN'   
}

#------------------------------
# Manage AD over LDAP certificates
#------------------------------
function manageLDAPSCerts() {
   if configuredForADoverLDAPS; then
      case $1 in
         'Check')
            checkLDAPSCerts			
            ;;		 
         'View')
            viewLDAPSCerts
            read -p $'\nSelect certificate [Return to Main Menu]: ' VIEW_LDAPS_CERT_INPUT
            if [ -n "$VIEW_LDAPS_CERT_INPUT" ] && [[ $VIEW_LDAPS_CERT_INPUT -le $LDAPS_CERT_COUNTER ]]; then
               LDAP_CERT_HASH=${LDAPS_CERT_HASHES[$((VIEW_LDAPS_CERT_INPUT - 1))]}
               TEMP_CERT=$(buildCertFromHash "$LDAP_CERT_HASH")
               viewCertificateInfo "$TEMP_CERT" 'view-path'
            fi
            ;;      
         'Manage')
            selectLDAPSDomain
            viewIdentitySourceLDAPSCerts                   
            ;;
      esac
   fi
}

#------------------------------
# List LDAPS domains
#------------------------------
function selectLDAPSDomain() {
   LDAPS_DOMAINS=()
   SELECTED_LDAPS_DOMAIN=''
   AD_OVER_LDAPS_DOMAINS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' -s one cn 2>/dev/null | sed -e 's/^ //g' | grep '^cn:' | awk '{print $NF}')
   OPENLDAP_DOMAINS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP)' -s one cn 2>/dev/null | sed -e 's/^ //g' | grep '^cn:' | awk '{print $NF}')
   ADFS_ISSUER=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=VCIdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwSTSExternalIdp)' -s one vmwSTSIssuerName 2>/dev/null | grep '^vmwSTSIssuerName:' | awk '{print $NF}')
   
   for domain in $OPENLDAP_DOMAINS; do
      LDAPS_DOMAINS+=("$domain|OpenLDAP")
   done

   for domain in $AD_OVER_LDAPS_DOMAINS; do
      LDAPS_DOMAINS+=("$domain|AD over LDAPS")
   done

   if [[ "$VC_VERSION" =~ ^[78] ]]; then
      if [ ! -z $ADFS_ISSUER ]; then
         LDAPS_DOMAINS+=("$ADFS_ISSUER|Microsoft ADFS")
      fi
   fi

   if [ ${#LDAPS_DOMAINS[@]} -eq 0 ]; then 
      echo "${YELLOW}There are no Identity Sources configured that can utilize an LDAPS connection.${NORMAL}"
   else
      header 'Select Domain to Manage LDAPS Certificates'
	   i=1
	   for entry in "${LDAPS_DOMAINS[@]}"; do
         domain=$(echo "$entry" | awk -F '|' '{print $1}')
         source_type=$(echo "$entry" | awk -F '|' '{print $2}')
	      printf "%2s. %s (%s)\n" $i $domain "$source_type"  
		   ((++i))
	   done
	  
	   read -p $'\nSelect domain [1]: ' SELECTED_LDAPS_DOMAIN_INPUT
	  
	   if [ -z $SELECTED_LDAPS_DOMAIN_INPUT ]; then SELECTED_LDAPS_DOMAIN_INPUT=1; fi

	   SELECTED_LDAPS_DOMAIN=${LDAPS_DOMAINS[(($SELECTED_LDAPS_DOMAIN_INPUT - 1))]}
   fi
}

#------------------------------
# Check LDAPS certificates
#------------------------------
function checkLDAPSCerts() {
   AD_OVER_LDAPS_DOMAINS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' -s one cn 2>/dev/null | sed -e 's/^ //g' | grep '^cn:' | awk '{print $NF}')   
   OPENLDAP_DOMAINS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP)' -s one cn 2>/dev/null | sed -e 's/^ //g' | grep '^cn:' | awk '{print $NF}')
   
   if [ -n "$OPENLDAP_DOMAINS" ]; then
      header 'Check OpenLDAP LDAPS certificates'
      for domain in $OPENLDAP_DOMAINS; do
         echo "Domain: $domain"
         LDAP_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$domain,cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP)' userCertificate 2>/dev/null | sed -e 's/^ //g' | grep '^userCertificate:' | awk '{print $NF}')
         i=1
		   for hash in $LDAP_CERTS; do
		      TEMP_CERT=$(buildCertFromHash "$hash")
			   task "   Certificate $i"
			   checkCert "$TEMP_CERT"
			   ((++i))
		   done	
      done
   fi
   if [ -n "$AD_OVER_LDAPS_DOMAINS" ]; then
      header 'Check AD over LDAPS certificates'
	   for domain in $AD_OVER_LDAPS_DOMAINS; do
	      echo "Domain: $domain"
		   LDAP_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$domain,cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' userCertificate 2>/dev/null | sed -e 's/^ //g' | grep '^userCertificate:' | awk '{print $NF}')
		   i=1
		   for hash in $LDAP_CERTS; do
		      TEMP_CERT=$(buildCertFromHash "$hash")
			   task "   Certificate $i"
			   checkCert "$TEMP_CERT"
			   ((++i))
		   done		 
	   done
   fi
   if [[ "$VC_VERSION" =~ ^[78] ]]; then
      ADFS_LDAPS_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=VCIdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' userCertificate 2>/dev/null | grep '^userCertificate' | awk '{print $NF}')
      if [ -n "$ADFS_LDAPS_CERTS" ]; then
	      header 'Check ADFS LDAPS certificates'
		   i=1
		   for hash in $ADFS_LDAPS_CERTS; do
		      TEMP_CERT=$(buildCertFromHash "$hash")
			   task "Certificate $i"
			   checkCert "$TEMP_CERT"
			   ((++i))
		   done
      fi
   fi
}

#------------------------------
# View Identity Source LDAPS certificates
#------------------------------
function viewIdentitySourceLDAPSCerts() {
   if [ ! -z "$SELECTED_LDAPS_DOMAIN" ]; then
      LDAPS_CERT_THUMBPRINT_LIST=()
      LDAPS_CERT_HASHES=()
      LDAPS_CERT_COUNTER=1
      
      domain=$(echo "$SELECTED_LDAPS_DOMAIN" | awk -F '|' '{print $1}')
      source_type=$(echo "$SELECTED_LDAPS_DOMAIN" | awk -F '|' '{print $2}')

      case $source_type in
         'Microsoft ADFS')
            LDAP_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=VCIdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' userCertificate 2>/dev/null | grep '^userCertificate' | awk -F':' '{print $NF}')
            header='Manage Certificates for External Provider: Microsoft ADFS'
            ;;
         *)
            LDAP_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$domain,cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' userCertificate 2>/dev/null | sed -e 's/^ //g' | grep '^userCertificate:' | awk '{print $NF}')
            header="Manage Certificates for Identity Provider: Domain $domain"
		      ;;
      esac
      header 'Currently Configured Certificatse for LDAPS Connection'
      viewLDAPSCertInfo "$LDAP_CERTS" "$domain" "$source_type"

      header "$header"
      cat << EOF
 1. Add LDAP server certificate(s)
 2. Remove LDAP server certificate(s)
EOF
      read -p $'\nEnter selection [Return to Main Menu]: ' MANAGE_LDAPS_INPUT

      case $MANAGE_LDAPS_INPUT in
         1)
            addLDAPSCerts
            ;;               
         2)
            removeLDAPSCerts
            ;;
      esac
   fi
}

#------------------------------
# View LDAPS certificates
#------------------------------
function viewLDAPSCerts() {
   LDAPS_CERT_THUMBPRINT_LIST=()
   LDAPS_DOMAINS=()
   LDAPS_CERT_HASHES=()
   LDAPS_CERT_COUNTER=1
   LDAPS_CERT_DNS=()
   AD_OVER_LDAPS_DOMAINS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' -s one cn 2>/dev/null | sed -e 's/^ //g' | grep '^cn:' | awk '{print $NF}')
   OPENLDAP_DOMAINS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP)' -s one cn 2>/dev/null | sed -e 's/^ //g' | grep '^cn:' | awk '{print $NF}')
   ADFS_ISSUER=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=VCIdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwSTSExternalIdp)' -s one vmwSTSIssuerName 2>/dev/null | grep '^vmwSTSIssuerName:' | awk '{print $NF}')
   header 'LDAPS Certificates'
   if [ -n "$OPENLDAP_DOMAINS" ]; then
      for domain in $OPENLDAP_DOMAINS; do
         LDAPS_DOMAINS+=("$domain|OpenLDAP")
         LDAP_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$domain,cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP)' userCertificate 2>/dev/null | sed -e 's/^ //g' | grep '^userCertificate:' | awk '{print $NF}')
		   viewLDAPSCertInfo "$LDAP_CERTS" "$domain" 'OpenLDAP'
      done
   fi
   if [ -n "$AD_OVER_LDAPS_DOMAINS" ]; then
      for domain in $AD_OVER_LDAPS_DOMAINS; do
         LDAPS_DOMAINS+=("$domain|AD over LDAPS")
         LDAP_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$domain,cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' userCertificate 2>/dev/null | sed -e 's/^ //g' | grep '^userCertificate:' | awk '{print $NF}')
		   viewLDAPSCertInfo "$LDAP_CERTS" "$domain" 'AD over LDAPS'
	  done
   fi
   if [[ "$VC_VERSION" =~ ^[78] ]]; then
      ADFS_LDAPS_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=VCIdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' userCertificate 2>/dev/null | grep '^userCertificate' | awk -F':' '{print $NF}')
      if [ -n "$ADFS_LDAPS_CERTS" ]; then
	      LDAP_CERTS=$ADFS_LDAPS_CERTS
         LDAPS_DOMAINS+=("$ADFS_ISSUER|Microsoft ADFS")
		   viewLDAPSCertInfo "$LDAP_CERTS" "$ADFS_ISSUER" 'Microsoft ADFS'
      fi
   fi
}

#------------------------------
# View AD over LDAPS certificate info
#------------------------------
function viewLDAPSCertInfo() {
   for hash in $1; do
      TEMP_CERT=$(buildCertFromHash "$hash")
      LDAPS_CERT_THUMBPRINT_LIST+=($(echo "$TEMP_CERT" | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}'))
	   LDAPS_CERT_HASHES+=($hash)
      CERT_OUTPUT=$(viewBriefCertificateInfo "$TEMP_CERT")
      if [[ "$2" =~ ^http ]]; then
	      CERT_OUTPUT+=$'\n'"    External Issuer: $2"
      else 
         CERT_OUTPUT+=$'\n'"    Domain: $2"
      fi
      CERT_OUTPUT+=$'\n'"    Identity Source Type: $3"
      
      printf "%2s. %s\n\n" $LDAPS_CERT_COUNTER "$CERT_OUTPUT"
      case $3 in
         'AD over LDAPS')
            LDAPS_CERT_DNS+=("cn=$2,cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN")
            ;;
         *)
            ADFS_LDAP_PROVIDER_DN=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=VCIdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwSTSIdentityStore)' dn 2>>$LOG | awk '{print $NF}')
            LDAPS_CERT_DNS+=("$ADFS_LDAP_PROVIDER_DN")
            ;;
      esac
      ((++LDAPS_CERT_COUNTER))
   done
}

#------------------------------
# Add LDAPS certificates
#------------------------------
function addLDAPSCerts() {  
   domain=$(echo "$SELECTED_LDAPS_DOMAIN" | awk -F '|' '{print $1}')
   source_type=$(echo "$SELECTED_LDAPS_DOMAIN" | awk -F '|' '{print $2}')
   
   case $source_type in
      'Microsoft ADFS')
         file_prefix='ldaps-adfs-cert-'
         ;;
      *)
         file_prefix="ldaps-$domain-cer-"
         ;;
   esac

   read -e -p $'\nEnter path to new LDAP server certificate(s): ' NEW_LDAPS_CERTS_INPUT

   while [ ! -f "$NEW_LDAPS_CERTS_INPUT" ]; do read -e -p $'\n'"${YELLOW}File not found, enter path to new LDAP server certificate(s):${NORMAL} " NEW_LDAPS_CERTS_INPUT; done
   if [ -f "$NEW_LDAPS_CERTS_INPUT" ]; then
      csplit -s -z -f $STAGE_DIR/$file_prefix -b %02d.crt "$NEW_LDAPS_CERTS_INPUT" '/-----BEGIN CERTIFICATE-----/' '{*}'
   
      exportSSOLDAPSCerts "$source_type" "$domain" "$file_prefix"
   
      header 'Publish new LDAP server ceritifcates'   
      updateLDAPSCerts "$file_prefix"
   fi
}

#------------------------------
# Remove LDAPS certificates
#------------------------------
function removeLDAPSCerts() {
   domain=$(echo "$SELECTED_LDAPS_DOMAIN" | awk -F '|' '{print $1}')
   source_type=$(echo "$SELECTED_LDAPS_DOMAIN" | awk -F '|' '{print $2}')
   
   case $source_type in
      'Microsoft ADFS')
         file_prefix='ldaps-adfs-cert-'
         ;;
      *)
         file_prefix="ldaps-$domain-cer-"
         ;;
   esac
   
   read -p $'\nEnter the number(s) of the LDAP server certificate(s) to remove (comma-separated list): ' REMOVE_LDAP_CERTS_INPUT
   
   exportSSOLDAPSCerts "$source_type" "$domain" "$file_prefix"
   
   for index in $(echo "$REMOVE_LDAP_CERTS_INPUT" | tr -d ' ' | sed 's/,/ /g'); do
      to_delete_thumbprint=${LDAPS_CERT_THUMBPRINT_LIST[$((index - 1))]}
      logInfo "Removing LDAPS certificate with thumbprint $to_delete_thumbprint"
	   for cert in $(ls $STAGE_DIR/$file_prefix*); do
         current_thumbprint=$(openssl x509 -noout -fingerprint -sha1 -in $cert 2>/dev/null | awk -F'=' '{print $NF}')
	      if [ "$current_thumbprint" = "$to_delete_thumbprint" ]; then
		      logInfo "Removing $cert"
			   rm $cert 2>&1 | logDebug
		   fi		 
	   done
   done
   
   header 'Publish new LDAP server ceritifcates'
   updateLDAPSCerts "$file_prefix"
}

#------------------------------
# Remove LDAP certificates
#------------------------------
function updateLDAPSCerts() {
   domain=$(echo "$SELECTED_LDAPS_DOMAIN" | awk -F '|' '{print $1}')
   source_type=$(echo "$SELECTED_LDAPS_DOMAIN" | awk -F '|' '{print $2}')

   case $source_type in
      'Microsoft ADFS')
         LDAPS_UPDATE_DN=$($LDAP_SEARCH -LLL -o ldif-wrap=no -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=VCIdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwSTSIdentityStore)' dn | awk '{print $NF}')
         ;;
      *)
         LDAPS_UPDATE_DN="cn=$domain,cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN"
         ;;
   esac

   echo "dn: $LDAPS_UPDATE_DN" > $STAGE_DIR/$1.ldif
   echo 'changetype: modify' >> $STAGE_DIR/$1.ldif
   echo 'replace: userCertificate' >> $STAGE_DIR/$1.ldif
   
   for cert in $(ls $STAGE_DIR/$1*.crt); do
      task "Staging certificate $(openssl x509 -noout -hash -in $cert 2>&1 | logDebug)"
	   CERT_BINARY_FILE=$(echo "$cert" | sed -e 's/.crt/.der/')
      if openssl x509 -inform pem -outform der -in $cert -out $CERT_BINARY_FILE > /dev/null 2>&1; then
	      echo "userCertificate:< file://$CERT_BINARY_FILE" >> $STAGE_DIR/$1.ldif
		   statusMessage 'OK' 'GREEN'
      else
	      statusMessage 'ERROR' 'YELLOW'
	  fi
   done
   
   task 'Update LDAPS certificates'
   $LDAP_MODIFY -x -h $PSC_LOCATION -p $VMDIR_PORT -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password -f $STAGE_DIR/$1.ldif > /dev/null 2>&1 || errorMessage 'Unable to update LDAPS server certificates'
   statusMessage 'OK' 'GREEN'
   rm $STAGE_DIR/ldaps-$1-cert* 2>&1 | logDebug
}

#------------------------------
# Manage Tanzu Supervisor Cluster certificates
#------------------------------
function manageTanzuSupervisorClusterCerts() {
   if tanzuSupervisorClustersPresent; then
      case $1 in 
	     'Check')
		    checkTanzuSupervisorCluseterCerts
		    ;;
		 
		 'View')
		    viewTanzuSupervisorCluseterCerts
		    ;;
			
		 'Manage')
		    ;;
	  esac
   fi   
}

#------------------------------
# Check certificates in the Tanzu Supervisor Clusters
#------------------------------
function checkTanzuSupervisorCluseterCerts() {
   header 'Checking Tanzu Supervisor Cluster Certificates'
   
   IFS=$'\n'
   for line in $(/usr/lib/vmware-wcp/decryptK8Pwd.py | grep -E '^Cluster: |^IP: |^PWD: '); do
      if [[ "$line" =~ ^Cluster ]]; then
         TANZU_CLUSTER_ID=$(echo "$line" | awk '{print $NF}' | awk -F':' '{print $1}' | sed -e 's/domain-c//')
	      TANZU_CLUSTER=$(/opt/vmware/vpostgres/current/bin/psql -d VCDB -U postgres -c "SELECT e.name FROM vpx_entity AS e LEFT JOIN vpx_object_type AS ot ON e.type_id = ot.id WHERE ot.name='CLUSTER_COMPUTE_RESOURCE' AND e.id=$TANZU_CLUSTER_ID" -t | sed -e 's/^[[:space:]]*//g' | grep -v '^$')   
      fi
      if [[ "$line" =~ ^IP ]]; then
         TANZU_CLUSTER_IP=$(echo "$line" | awk '{print $NF}')
      fi
      if [[ "$line" =~ ^PWD ]]; then
         TANZU_CLUSTER_PASSWD=$(echo "$line" | awk '{print $NF}')
         echo "Cluster: $TANZU_CLUSTER"
         logInfo "Checking cluster: $TANZU_CLUSTER"
         ssh-keygen -R $TANZU_CLUSTER_IP 2>&1 | logDebug
         sshpass -p "$TANZU_CLUSTER_PASSWD" ssh -q -o StrictHostKeyChecking=no -t -t root@$TANZU_CLUSTER_IP 'for cert in $(find / -type f \( -name "*.cert" -o -name "*.crt" \)  -print 2>/dev/null | egrep -v "ca.crt$|ca-bundle.crt$|kubelet\/pods|var\/lib\/containerd|run\/containerd|bootstrapper"); do printf "%-52s" "   $cert"; if openssl x509 -noout -in $cert -checkend 0 > /dev/null 2>&1; then printf "%13s\n" "VALID"; else printf "%13s\n" "EXPIRED"; fi; done'	| sed -e "s/VALID/${GREEN}&${NORMAL}/g" -e "s/EXPIRED/${YELLOW}&${NORMAL}/g"
      fi
   done
   IFS=$' \t\n'
}

#------------------------------
# View info on Tanzu Supervisor Cluster certificates
#------------------------------
function viewTanzuSupervisorCluseterCerts() {
   header 'View Tanzu Supervisor Cluster Certificates'
   TANZU_CLUSTERS=()
   TANZU_CLUSTER_IDS=()
   i=1
   echo ''
   for tanzu_cluster_id in $(/usr/lib/vmware-wcp/decryptK8Pwd.py | grep '^Cluster: ' | awk '{print $NF}' | awk -F':' '{print $1}' | sed -e 's/domain-c//'); do
      TANZU_CLUSTER=$(/opt/vmware/vpostgres/current/bin/psql -d VCDB -U postgres -c "SELECT e.name FROM vpx_entity AS e LEFT JOIN vpx_object_type AS ot ON e.type_id = ot.id WHERE ot.name='CLUSTER_COMPUTE_RESOURCE' AND e.id=$tanzu_cluster_id" -t | sed -e 's/^[[:space:]]*//g' | grep -v '^$')
      if [ -n "$TANZU_CLUSTER" ]; then
         TANZU_CLUSTERS+=("$TANZU_CLUSTER")
         TANZU_CLUSTER_IDS+=("$tanzu_cluster_id")
         printf "%2s. %s\n" $i "$TANZU_CLUSTER"
      fi
   done
   
   if [ -n "$TANZU_CLUSTERS" ]; then
      read -p $'\nSelect Supervisor Cluster [Return to Main Menu]: ' TANZU_CLUSTER_INPUT
	  
      if [ -n "$TANZU_CLUSTER_INPUT" ]; then
         TANZU_CLUSTER_NAME=${TANZU_CLUSTERS[$((TANZU_CLUSTER_INPUT - 1))]}
         TANZU_CLUSTER_ID=${TANZU_CLUSTER_IDS[$((TANZU_CLUSTER_INPUT - 1))]}
         TANZU_CLUSTER_INFO=$(/usr/lib/vmware-wcp/decryptK8Pwd.py | grep -A2 "domain-c$TANZU_CLUSTER_ID")
         TANZU_CLUSTER_IP=$(echo "$TANZU_CLUSTER_INFO" | awk '/^IP: /{print $NF}')
         TANZU_CLUSTER_PASSWD=$(echo "$TANZU_CLUSTER_INFO" | awk '/^PWD: /{print $NF}')
		 
         header "'$TANZU_CLUSTER_NAME' Certificates"
         ssh-keygen -R $TANZU_CLUSTER_IP 2>&1 | logDebug
         sshpass -p "$TANZU_CLUSTER_PASSWD" ssh -q -o StrictHostKeyChecking=no -t -t root@$TANZU_CLUSTER_IP 'for cert in $(find / -type f \( -name "*.cert" -o -name "*.crt" \)  -print 2>/dev/null | egrep -v "ca.crt$|ca-bundle.crt$|kubelet\/pods|var\/lib\/containerd|run\/containerd|bootstrapper"); do echo "Cert: $cert"; openssl x509 -noout -in $cert -text; echo ''; done'
	  fi
   fi
}

#------------------------------
# Check if STS Tenant Credential certificates have expired
#------------------------------
function checkSTSTenantCerts() {
   CA_SKIDS=$($DIR_CLI trustedcert list --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" | grep '^CN' | awk '{print $NF}')
   TENANT_CREDENTIAL_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password '(objectclass=vmwSTSTenantCredential)' userCertificate)
   
   IFS=$'\n'
   for line in $TENANT_CREDENTIAL_CERTS; do
	  if [[ "$line" =~ ^dn: ]]; then
	     TENANT_CN=$(echo "$line" | awk '{print $NF}' | awk -F',' '{print $1}' | awk -F'=' '{print $NF}')
	     echo "Checking $TENANT_CN:"
	  else
	     hash=$(echo "$line" | awk '{print $NF}')
		 TEMP_CERT=$(buildCertFromHash "$hash")
		 if echo "$TEMP_CERT" | openssl x509 -text -noout 2>/dev/null | grep 'CA:TRUE' > /dev/null 2>&1; then
            checkSTSTenantCert "$TEMP_CERT" $TENANT_CN 'CA' "$CA_SKIDS"
         else
            checkSTSTenantCert "$TEMP_CERT" $TENANT_CN 'signing'
         fi
	  fi
   done
   IFS=$' \t\n'
}

#------------------------------
# Check if STS Tenant Credential certificates have expired
#------------------------------
function checkSTSTrustedCertChains() {
   CA_SKIDS=$($DIR_CLI trustedcert list --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" | grep '^CN' | awk '{print $NF}')
   TENANT_TRUSTED_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password '(&(objectclass=vmwSTSTenantTrustedCertificateChain)(cn=TrustedCertChain*))' userCertificate)
   
   IFS=$'\n'
   for line in $TENANT_TRUSTED_CERTS; do
      if [[ "$line" =~ ^dn: ]]; then
         CHAIN_CN=$(echo "$line" | awk '{print $NF}' | awk -F',' '{print $1}' | awk -F'=' '{print $NF}')
         echo "Checking $CHAIN_CN:"
      else
         hash=$(echo "$line" | awk '{print $NF}')
         TEMP_CERT=$(buildCertFromHash "$hash")
         if echo "$TEMP_CERT" | openssl x509 -text -noout 2>/dev/null | grep 'CA:TRUE' > /dev/null 2>&1; then
            checkSTSTenantCert "$TEMP_CERT" $CHAIN_CN 'CA' "$CA_SKIDS"
         else
            checkSTSTenantCert "$TEMP_CERT" $CHAIN_CN 'signing'
         fi
      fi
   done
   IFS=$' \t\n'
}

#------------------------------
# Check if individual STS Signing certificate has expired
#------------------------------
function checkSTSTenantCert() {
   task "   $2 $3 certificate"

   if ! isExpired "$1" 'hash'; then
      CERT_SKID=$(echo "$1" | openssl x509 -noout -text | grep -A1 'Subject Key Id' | tail -n1 | tr -d ': ')
      if ! echo "$4" | grep "$CERT_SKID" > /dev/null && [ "$3" == 'CA' ]; then
	     CERT_STATUS_MISSING_VMDIR=1
		 statusMessage 'MISSING' 'YELLOW'
		 return 0
	  else	  
	     DAYS_LEFT=$(checkCertExpireSoon "$1")
         if [[ $DAYS_LEFT -gt 0 ]]; then
            CERT_STATUS_EXPIRES_SOON=1
            statusMessage "$DAYS_LEFT DAYS" 'YELLOW'
            return 0
         else
            HAS_KEY_USAGE=$(checkCertKeyUsage "$1" "STS Tenant $2 $3")
            if [[ $3 == 'signing' && $HAS_KEY_USAGE -gt 0 ]]; then
               CERT_STATUS_KEY_USAGE=1      
               statusMessage 'KEY USAGE' 'YELLOW'          
               return 0
            fi
            statusMessage 'VALID' 'GREEN'      
            return 0
         fi
	  fi
   else
      CERT_STATUS_EXPIRED=1
      statusMessage 'EXPIRED' 'YELLOW'      
      return 1
   fi 
}

#------------------------------
# View STS Signing certificates
#------------------------------
function viewSTSTenantCerts() {
   header 'View STS signing certificates'   
   LDAP_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password '(objectclass=vmwSTSTenantCredential)' userCertificate | grep '^userCertificate' | awk '{print $NF}')
   TENANT_COUNT=1

   for hash in $LDAP_CERTS; do
      TEMP_CERT=$(buildCertFromHash "$hash")
      CERT_INFO=$(viewBriefCertificateInfo "$TEMP_CERT")
      
      if echo "$TEMP_CERT" | openssl x509 -noout -text 2>/dev/null | grep 'CA:TRUE' > /dev/null; then
         CERT_OUTPUT="   Certificate Type: CA Certificate"$'\n    '
      else
         CERT_OUTPUT="   Certificate Type: Signing Certificate"$'\n    '
      fi
      
      CERT_OUTPUT+=$CERT_INFO

      if echo "$TEMP_CERT" | openssl x509 -text -noout 2>/dev/null | grep 'CA:TRUE' > /dev/null 2>&1; then
         echo $'\n'"$CERT_OUTPUT"$'\n'
         ((++TENANT_COUNT))         
      else
         echo "Tenant Credential $TENANT_COUNT"
         echo "$CERT_OUTPUT"
      fi
   done
}

#------------------------------
# Check CA certificates in VMDir and VECS
#------------------------------
function checkCACertificates() {
   VMDIR_CERTS=()
   VMDIR_CERT_SKIDS=()
   VECS_CERTS=()
   VECS_CERT_ALIASES=()
   header 'Checking CA certificates in VMDir [by CN(id)]'
   for skid in $($DIR_CLI trustedcert list --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" | grep '^CN' | awk '{print $NF}'); do
      logInfo "Retrieving certificate with Subject Key ID $skid from VMDir"
      $DIR_CLI trustedcert get --id $skid --outcert $STAGE_DIR/$skid.crt --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" 2>&1 | logInfo
        
      task "${skid}"
      CA_CERT=$(cat $STAGE_DIR/$skid.crt)
      if isExpired "$STAGE_DIR/$skid.crt" 'file'; then
         CERT_STATUS_EXPIRED=1
         statusMessage 'EXPIRED' 'YELLOW'
      elif ! isCertCA "$(cat $STAGE_DIR/$skid.crt)"; then
         CERT_STATUS_NON_CA=1
         statusMessage 'NON-CA' 'YELLOW'
      else         
         DAYS_LEFT=$(checkCertExpireSoon "$CA_CERT")
         if ! openssl x509 -noout -text -in $STAGE_DIR/$skid.crt 2>/dev/null | grep 'Subject Key Identifier:' > /dev/null; then
            CERT_STATUS_CA_MISSING_SKID=1
            statusMessage 'NO SKID' 'YELLOW'
         elif [[ $DAYS_LEFT -gt 0 ]]; then
            CERT_STATUS_EXPIRES_SOON=1       
            statusMessage "$DAYS_LEFT DAYS" 'YELLOW'
         else     
            statusMessage 'VALID' 'GREEN'
         fi
      fi
   done
   
   header 'Checking CA certificates in VECS [by Alias]'
   
   IFS=$'\n'
   for alias in $($VECS_CLI entry list --store TRUSTED_ROOTS 2>>$LOG | grep '^Alias' | awk '{print $NF}'); do
      logInfo "Checking certificate with alias '$alias'"
      TEMP_VECS_CERT=$($VECS_CLI entry getcert --store TRUSTED_ROOTS --alias "$alias" 2>>$LOG)
      
      task $alias
      
      if isExpired "$TEMP_VECS_CERT" 'hash'; then
         CERT_STATUS_EXPIRED=1
         statusMessage 'EXPIRED' 'YELLOW'
      elif ! echo "$TEMP_VECS_CERT" | openssl x509 -text -noout 2>/dev/null | grep 'CA:TRUE' > /dev/null; then
         CERT_STATUS_NON_CA=1
         statusMessage 'NON-CA' 'YELLOW'
      elif [ $(echo "$TEMP_VECS_CERT" | openssl x509 -fingerprint -sha1 -noout 2>/dev/null | cut -d '=' -f 2 | tr -d ':' | awk '{print tolower($0)}') != "$alias" ]; then
         CERT_STATUS_BAD_ALIAS=1
         statusMessage 'BAD ALIAS' 'YELLOW'
      else
         DAYS_LEFT=$(checkCertExpireSoon "$TEMP_VECS_CERT")
         if [[ $DAYS_LEFT -gt 0 ]]; then
            CERT_STATUS_EXPIRES_SOON=1       
            statusMessage "$DAYS_LEFT DAYS" 'YELLOW'
         else
            statusMessage 'VALID' 'GREEN'
         fi
      fi
   done
   IFS=$' \t\n'
}

#------------------------------
# Publish new signing chain to VMDir
#------------------------------
function publishCASigningCertificates() {
   csplit -s -z -f $STAGE_DIR/signing-ca-new- -b %02d.crt $1 '/-----BEGIN CERTIFICATE-----/' '{*}'
   
   VMDIR_CA_SKIDS=$($DIR_CLI trustedcert list --login $VMDIR_USER --password "$(cat $STAGE_DIR/.vmdir-user-password)" | grep '^CN' | tr -d '\t' | awk -F':' '{print $2}')
   
   for cert in $(ls $STAGE_DIR/signing-ca-new-*.crt); do
      CURRENT_SKID=$(openssl x509 -noout -text -in $cert 2>/dev/null | grep -A1 'Subject Key Id' | tail -n1 | tr -d ' ' | sed 's/keyid://' | tr -d ':')
      if echo "$VMDIR_CA_SKIDS" | grep "$CURRENT_SKID" > /dev/null; then
         $DIR_CLI trustedcert get --id $CURRENT_SKID --login $VMDIR_USER --password "$(cat $STAGE_DIR/.vmdir-user-password)" --outcert $STAGE_DIR/signing-ca-old-$CURRENT_SKID.crt 2>&1 | logInfo 
         $DIR_CLI trustedcert unpublish --login $VMDIR_USER --password "$(cat $STAGE_DIR/.vmdir-user-password)" --cert $STAGE_DIR/signing-ca-old-$CURRENT_SKID.crt 2>&1 | logInfo
      fi
   done
   
   $DIR_CLI trustedcert publish --chain --cert $TRUSTED_ROOT_CHAIN --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" 2>&1 | logInfo || errorMessage 'Unable to publish trusted root chain to VMDir'
   statusMessage 'OK' 'GREEN'
   
   rm $STAGE_DIR/signing-ca-new-*.crt $STAGE_DIR/signing-ca-old-*.crt 2>&1 | logDebug
}

#------------------------------
# Check if certificate is a CA cert
#------------------------------
function isCertCA() {
   if echo "$1" | openssl x509 -noout -text 2>/dev/null | grep 'CA:TRUE' > /dev/null; then
      return 0
   else
      return 1
   fi
}

#------------------------------
# Quick check if Service Principal entries exist in VMware Directory
#------------------------------
function quickCheckServicePrincipals() {
   header 'Checking Service Principals'
   EXISTING_SERVICE_PRINCIPALS=$($DIR_CLI service list --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" 2>/dev/null)
   if [ -n "$EXISTING_SERVICE_PRINCIPALS" ]; then
      echo "Node $MACHINE_ID:"
      for soluser in "${SOLUTION_USERS[@]}"; do
         task "   $soluser"
		 if echo "$EXISTING_SERVICE_PRINCIPALS" | grep "$soluser-$MACHINE_ID" > /dev/null 2>&1; then
		    statusMessage 'PRESENT' 'GREEN'
		 else
		    CERT_STATUS_SERVICE_PRINCIPAL_MISSING=1
		    statusMessage 'MISSING' 'YELLOW'
		 fi
      done
   else
      task 'Listing SSO Service Principals'
      errorMessage 'Could not get list of Service Principal entries from VMware Directory'
   fi
}

#------------------------------
# Check if Service Principal entries exist in VMware Directory
#------------------------------
function checkServicePrincipals() {
   task 'Verifying Service Principal entries exist'
   MISSING_SERVICE_PRINCIPALS=''
   EXISTING_SERVICE_PRINCIPALS=$($DIR_CLI service list --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" 2>&1)
   if [ -n "$EXISTING_SERVICE_PRINCIPALS" ]; then
      for soluser in "${SOLUTION_USERS[@]}"; do
         if ! echo "$EXISTING_SERVICE_PRINCIPALS" | grep "$soluser-$MACHINE_ID" > /dev/null 2>&1; then
	         if [ -z "$MISSING_SERVICE_PRINCIPALS" ]; then MISSING_SERVICE_PRINCIPALS+="$soluser-$MACHINE_ID"; else MISSING_SERVICE_PRINCIPALS+=" $soluser-$MACHINE_ID"; fi
	      fi
      done
   
      if [ -n "$MISSING_SERVICE_PRINCIPALS" ]; then
         statusMessage 'ERROR' 'RED'
         echo $'\n'"${YELLOW}------------------------!!! Attention !!!------------------------ "
         echo 'The following Service Principal entries are missing:'
         for sp in $MISSING_SERVICE_PRINCIPALS; do
            echo " - $sp"
         done
	  
         echo $'\nPlease refer to KB https://kb.vmware.com/s/article/80469'
         echo 'on using the lsdoctor utility to recreate the missing'
         echo "Solution User/Service Principal entries.${NORMAL}"
	  
         if [[ "$VC_VERSION" =~ ^[78] ]] && (echo "$MISSING_SERVICE_PRINCIPALS" | grep "wcp-$MACHINE_ID" > /dev/null || echo "$MISSING_SERVICE_PRINCIPALS" | grep "hvc-$MACHINE_ID" > /dev/null); then
            echo $'\n'"${YELLOW}Note: The hvc and/or wcp Service Principal entries are"
            echo 'missing, and currently lsdoctor will NOT recreate these'
            echo 'Service Principal entries. These will need to be created'
            echo "and assigned to the proper groups manually.${NORMAL}"		
         fi
         exit
      else
         statusMessage 'OK' 'GREEN'
      fi
   else
      errorMessage 'Could not get list of Service Principal entries from VMware Directory'
   fi
}

#------------------------------
# Builds the expanded message detailng issues with certificates
#------------------------------
function buildCertificateStatusMessage() {
   if [ $CERT_STATUS_EXPIRES_SOON == 1 ]; then CERT_STATUS_MESSAGE+=$' - One or more certificates are expiring within 30 days\n'; fi
   
   if [ $CERT_STATUS_MISSING_PNID == 1 ]; then CERT_STATUS_MESSAGE+=" - One or more certificates are missing the PNID ($PNID) from the SAN entry"$'\n'; fi
   
   if [ $CERT_STATUS_KEY_USAGE == 1 ]; then 
      CERT_STATUS_MESSAGE+=$' - One or more certificates do not have the recommended\n'
      CERT_STATUS_MESSAGE+=$'   Key Usage values\n'; fi
   
   if [ $CERT_STATUS_EXPIRED == 1 ]; then CERT_STATUS_MESSAGE+=$' - One or more certificates are expired\n'; fi
   
   if [ $CERT_STATUS_NON_CA == 1 ]; then CERT_STATUS_MESSAGE+=$' - One or more certificates are not CA certificates\n'; fi
   
   if [ $CERT_STATUS_BAD_ALIAS == 1 ]; then CERT_STATUS_MESSAGE+=$' - One or more entries in the TRUSTED_ROOTS store have an alias that is not the SHA1 thumbprint\n'; fi
   
   if [ $CERT_STATUS_MISSING_SAN == 1 ]; then CERT_STATUS_MESSAGE+=$' - One or more certificates do not have any Subject Alternative Name values\n'; fi
   
   if [ $CERT_STATUS_SHA1_SIGNING == 1 ]; then CERT_STATUS_MESSAGE+=$' - One or more certificates are signed using the SHA-1 algorithm\n'; fi
   
   if [ $CERT_STATUS_MISSING == 1 ]; then CERT_STATUS_MESSAGE+=$' - One or more certificates are missing\n'; fi
   
   if [ $CERT_STATUS_MISSING_VMDIR == 1 ]; then 
      CERT_STATUS_MESSAGE+=$' - One or more CA certificates are missing from\n'
      CERT_STATUS_MESSAGE+=$'   VMware Directory\n'
   fi
   
   if [ $CERT_STATUS_MISMATCH_SERVICE_PRINCIPAL == 1 ]; then 
      CERT_STATUS_MESSAGE+=$' - One or more Solution User certificates does not match\n'
      CERT_STATUS_MESSAGE+=$'   the Service Principal certificate in VMware Directory\n'
   fi
   
   if [ $CERT_STATUS_MISSING_CA == 1 ]; then 
      CERT_STATUS_MESSAGE+=$' - One or more certificates do not have all of the CA\n'
      CERT_STATUS_MESSAGE+=$'   certificates in its signing chain in VMware Directory\n'
   fi
   
   if [ $CERT_STATUS_EXPIRED_EMBEDDED_CA == 1 ]; then
      CERT_STATUS_MESSAGE+=$' - One or more certificates has a CA certificate embedded\n'
      CERT_STATUS_MESSAGE+=$'   in its chain that is expired\n'
   fi

   if [ $CERT_STATUS_UNSUPPORTED_SIGNATURE_ALGORITHM == 1 ]; then
      CERT_STATUS_MESSAGE+=$' - One or more certificates is using an unsupported\n'
      CERT_STATUS_MESSAGE+=$'   signature algorithm'
   fi
   
   if [ $CERT_STATUS_STORE_MISSING == 1 ]; then CERT_STATUS_MESSAGE+=$' - One or more VECS stores are missing\n'; fi
   
   if [ $CERT_STATUS_STORE_PERMISSIONS == 1 ]; then CERT_STATUS_MESSAGE+=$' - One or more VECS stores are missing permissions\n'; fi
   
   if [ $CERT_STATUS_SERVICE_PRINCIPAL_MISSING == 1 ]; then 
      CERT_STATUS_MESSAGE+=$' - One or more Service Principal entries are missing\n'
      CERT_STATUS_MESSAGE+=$'   from VMware Directory\n'; fi
   
   if [ $TRUST_ANCHORS_MISMATCH == 1 ]; then
      CERT_STATUS_MESSAGE+=$' - One or more vCenter/PSC nodes have mismatched SSL trust anchors\n'
   fi

   if [ $TRUST_ANCHORS_UNKNOWN == 1 ]; then 
      CERT_STATUS_MESSAGE+=$' - The Machine SSL certificate could not be obtained from\n'
      CERT_STATUS_MESSAGE+=$'   the following nodes to check SSL trust anchors:\n'
      for unknown_node in "${TRUST_ANCHORS_UNKNOWN_NODES[@]}"; do
         CERT_STATUS_MESSAGE+="     $unknown_node"$'\n'
      done
   fi  

   if [ $TRUST_ANCHORS_CHECK_URI == 1 ]; then
      if [ $TRUST_ANCHORS_CHECK_URI_MISMATCH == 1 ]; then
         CERT_STATUS_MESSAGE+=$' - One or more vCenter/PSC nodes have mismatched SSL trust anchors and\n'
         CERT_STATUS_MESSAGE+=$'   have Lookup Service registrations using the IP address instead\n'
         CERT_STATUS_MESSAGE+=$'   of the PNID in the endpoint URIs. These can be fixed with the\n'
         CERT_STATUS_MESSAGE+=$'   lsdoctor utility: https://kb.vmware.com/s/article/80469\n'
      else
         CERT_STATUS_MESSAGE+=$' - One or more vCenter/PSC nodes have Lookup Service registrations\n'
         CERT_STATUS_MESSAGE+=$'   using the IP address instead of the PNID in the endpoint URIs.\n'
         CERT_STATUS_MESSAGE+=$'   These can be fixed with the lsdoctor utility:\n'
         CERT_STATUS_MESSAGE+=$'   https://kb.vmware.com/s/article/80469\n'
      fi
   fi 
   
   if [ $CERT_STATUS_TOO_MANY_CRLS == 1 ]; then CERT_STATUS_MESSAGE+=' - The number of CRLs in VECS may be preventing some services from starting'; fi
   
   if [ $CERT_STATUS_VMCA_EMPTY_CONFIG == 1 ]; then
      CERT_STATUS_MESSAGE+=$' - Some are one or more vpxd.certmgmt.certs.cn.* settings with empty values\n'
      CERT_STATUS_MESSAGE+=$'   This can cause issues pushing VMCA-signed certificates to ESXi hosts\n'
   fi
   
   if [ $CERT_STATUS_VMCA_MODE == 1 ]; then
      CERT_STATUS_MESSAGE+=" - The certificate management mode is set to 'thumbprint'"$'\n'
      CERT_STATUS_MESSAGE+="   This is not recommended, and should be set to 'vmca' or 'custom'"$'\n'
   fi

   if [ $CERT_STATUS_CLIENT_CA_LIST_FILE_LOCATION == 1 ]; then
      CERT_STATUS_MESSAGE+=" - The <clientCAListFile> value must reference the following file:"$'\n'
      CERT_STATUS_MESSAGE+="   /usr/lib/vmware-sso/vmware-sts/conf/clienttrustCA.pem"
   fi

   if [ $CERT_STATUS_CLIENT_CA_LIST_FILE_MISSING == 1 ]; then
      CERT_STATUS_MESSAGE+=" - The <clientCAListFile> file at /usr/lib/vmware-sso/vmware-sts/conf/clienttrustCA.pem does not exist"$'\n'
   fi

   if [ $CERT_STATUS_STS_VECS_CONFIG == 1 ]; then
      CERT_STATUS_MESSAGE+=$' - The STS server is configured to use a VECS store other than\n'
      CERT_STATUS_MESSAGE+=$'   the MACHINE_SSL_CERT store\n'
   fi

   if [ $CERT_STATUS_STS_CONNECTION_STRINGS == 1 ]; then
      CERT_STATUS_MESSAGE+=$' - The STS ConnectionStrings value is not set properly for an SSO\n'
      CERT_STATUS_MESSAGE+=$'   domain with multiple Domain Controllers\n'
   fi

   if [ $CERT_STATUS_CA_MISSING_SKID == 1 ]; then
      CERT_STATUS_MESSAGE+=$' - One or more CA certificates is missing the Subject Key ID extension'
   fi 
}

#------------------------------
# Check the number of CRLs in VECS
#------------------------------
function checkCRLs() {
   CERT_STATUS_TOO_MANY_CRLS=0
   NUM_CRLS=$($VECS_CLI entry list --store TRUSTED_ROOT_CRLS | head -n1 | awk '{print $NF}')
   header 'Checking Certificate Revocation Lists'
   task 'Number of CRLs in VECS'
   
   if [ $NUM_CRLS -le 30 ]; then
      statusMessage "$NUM_CRLS" 'GREEN'
   elif [ $NUM_CRLS -le 100 ]; then
      statusMessage "$NUM_CRLS" 'YELLOW'
   else
      statusMessage "$NUM_CRLS" 'RED'
      CERT_STATUS_TOO_MANY_CRLS=1
   fi
}

#------------------------------
# Clear CRLs in VECS
#------------------------------
function clearCRLs() {
   header 'Clear Certificate Revocation Lists in VECS'
   task 'Backup CRLs'
   
   if [ ! -d $BACKUP_DIR/old-CRLs ]; then mkdir $BACKUP_DIR/old-CRLs 2>/dev/null || errorMessage 'Unable to create backup CRL directory'; fi
   
   find /etc/ssl/certs -type f -iname '*.r[0-9]' -exec mv {} $BACKUP_DIR/old-CRLs \; || errorMessage "Unable to move CRL files to $BACKUP_DIR/old-CRLs"
   
   statusMessage 'OK' 'GREEN'
   
   task 'Delete CRLs from VECS (this may take some time)'
   for alias in $($VECS_CLI entry list --store TRUSTED_ROOT_CRLS | grep Alias | awk '{print $NF}'); do
      logInfo "Removing CRL $alias from VECS"
      $VECS_CLI entry delete --store TRUSTED_ROOT_CRLS --alias $alias -y > /dev/null 2>&1
   done
   
   statusMessage 'OK' 'GREEN'
   
   if [ $NODE_TYPE != 'management' ]; then
      restartVMwareServices 'vmafdd' 'vmdird' 'vmcad'
   else
      restartVMwareServices 'vmafdd'
   fi
}

#------------------------------
# Clear BACKUP_STORE in VECS
#------------------------------
function clearBackupStore() {
   header 'Clear BACKUP_STORE'
   
   for alias in $($VECS_CLI entry list --store BACKUP_STORE | grep Alias | awk '{print $NF}'); do
      task "Removing $alias"
      $VECS_CLI entry delete --store BACKUP_STORE --alias $alias -y > /dev/null 2>&1 || errorMessage "Unable to remove $alias entry from BACKUP_STORE"
      statusMessage 'OK' 'GREEN'
   done
   
   if checkVECSStore 'BACKUP_STORE_H5C'; then
      header 'Clear BACKUP_STORE_H5C'
      for alias in $($VECS_CLI entry list --store BACKUP_STORE_H5C | grep Alias | awk '{print $NF}'); do
         task "Removing $alias"
         $VECS_CLI entry delete --store BACKUP_STORE_H5C --alias $alias -y > /dev/null 2>&1 || errorMessage "Unable to remove $alias entry from BACKUP_STORE_H5C"
	     statusMessage 'OK' 'GREEN'
      done
   fi
}

#------------------------------
# Clear BACKUP_STORE in VECS
#------------------------------
function clearMachineSSLCSR() {
   unset DELETE_MACHINE_CSR_INPUT
   echo $'\n'"${YELLOW}-------------------------!!! WARNING !!!-------------------------"
   echo "This entry was created using the 'Generate Certificate"
   echo "Signing Request (CSR)' option from the vSphere Client."
   echo 'It contains the corresponding private key associated'
   echo 'with this CSR. DO NOT DELETE if you are still waiting'
   echo "for this request to be signed by your Certificate Authority!${NORMAL}"
   
   read -p $'\nDelete the __MACHINE_CSR entry from VECS? [n]: ' DELETE_MACHINE_CSR_INPUT
   
   if [ -z $DELETE_MACHINE_CSR_INPUT ]; then DELETE_MACHINE_CSR_INPUT='n'; fi
   
   if [[ $DELETE_MACHINE_CSR_INPUT =~ ^[Yy] ]]; then
      header 'Delete Machine SSL CSR entry in VECS'
      task 'Backup private key'
      $VECS_CLI entry getkey --store MACHINE_SSL_CERT --alias __MACHINE_CSR > $BACKUP_DIR/__MACHINE_CSR.key 2>&1 || errorMessage 'Unable to backup private key in __MACHINE_CSR entry from VECS'
      statusMessage 'OK' 'GREEN'
      
      task 'Delete entry in MACHINE_SSL_CERT store'
      $VECS_CLI entry delete --store MACHINE_SSL_CERT --alias __MACHINE_CSR -y > /dev/null 2>&1 || errorMessage "Unable to delete entry '__MACHINE_CSR' from VECS"
      statusMessage 'OK' 'GREEN'
   fi   
}

#------------------------------
# Perform quick check of SSL trust anchors
#------------------------------
function quickCheckSSLTrustAnchors() {
   header 'Checking SSL Trust Anchors'
   getSSODomainNodes
   TRUST_ANCHORS_UNKNOWN=0
   TRUST_ANCHORS_MISMATCH=0
   TRUST_ANCHORS_CHECK_URI=0
   TRUST_ANCHORS_CHECK_URI_MISMATCH=0
   TRUST_ANCHORS_UNKNOWN_NODES=()
   
   for node in "${SSO_NODES[@]}"; do
      MISMATCH=0
      task "$node"
      NODE_MACHINE_SSL_THUMBPRINT=$(echo | openssl s_client -connect $node:443 2>/dev/null | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
      if [ -n "$NODE_MACHINE_SSL_THUMBPRINT" ]; then
         TRUST_ANCHOR_SEARCH_FILTER="(&(|(vmwLKUPURI=https://$node:*)(vmwLKUPURI=https://$node/*))(|(objectclass=vmwLKUPServiceEndpoint)(objectclass=vmwLKUPEndpointRegistration)))"
         NODE_TRUST_ANCHORS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=Sites,cn=Configuration,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password "$TRUST_ANCHOR_SEARCH_FILTER" vmwLKUPEndpointSslTrust vmwLKUPSslTrustAnchor 2>>$LOG | grep -v '^dn:' | awk '{print $NF}' | sort | uniq)
         
         if [ -z "$NODE_TRUST_ANCHORS" ]; then
            TRUST_ANCHOR_SEARCH_FILTER="(&(|(vmwLKUPURI=https://$IP:*)(vmwLKUPURI=https://$IP/*))(|(objectclass=vmwLKUPServiceEndpoint)(objectclass=vmwLKUPEndpointRegistration)))"
            NODE_TRUST_ANCHORS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=Sites,cn=Configuration,$VMDIR_DOMAIN_DN" -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password "$TRUST_ANCHOR_SEARCH_FILTER" vmwLKUPEndpointSslTrust vmwLKUPSslTrustAnchor 2>>$LOG | grep -v '^dn:' | awk '{print $NF}' | sort | uniq)
            if [ -z "$NODE_TRUST_ANCHORS" ]; then
               statusMessage 'MISSING' 'YELLOW'
            else
               TRUST_ANCHORS_CHECK_URI=1
               for hash_raw in $NODE_TRUST_ANCHORS; do
                  logInfo "Checking following raw certificate hash"
                  logDetails "$hash_raw"
                  if [[ "$hash_raw" =~ ^TUl ]]; then
                     hash=$(echo $hash_raw | base64 --decode | tr -d '\r\n')
                  else
                     hash=($hash_raw)
                  fi
                  TEMP_CERT=$(buildCertFromHash "$hash")
                  ANCHOR_THUMBPRINT=$(echo "$TEMP_CERT" | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
                  logInfo "Checking node thumbprint $NODE_MACHINE_SSL_THUMBPRINT against unique trust anchor thumbprint $ANCHOR_THUMBPRINT"
                  if [ "$NODE_MACHINE_SSL_THUMBPRINT" != "$ANCHOR_THUMBPRINT" ]; then
                     MISMATCH=1
                  fi
               done
               if [ $MISMATCH -eq 0 ]; then
                  statusMessage 'CHECK URI' 'YELLOW'
               else
                  TRUST_ANCHORS_CHECK_URI_MISMATCH=1
                  statusMessage 'MISMATCH*' 'YELLOW'
               fi
            fi
         else
            for hash_raw in $NODE_TRUST_ANCHORS; do
               logInfo "Checking following raw certificate hash"
               logDetails "$hash_raw"
               if [[ "$hash_raw" =~ ^TUl ]]; then
                  hash=$(echo $hash_raw | base64 --decode | tr -d '\r\n')
               else
                  hash=($hash_raw)
               fi
               TEMP_CERT=$(buildCertFromHash "$hash")
               ANCHOR_THUMBPRINT=$(echo "$TEMP_CERT" | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
               logInfo "Checking node thumbprint $NODE_MACHINE_SSL_THUMBPRINT against unique trust anchor thumbprint $ANCHOR_THUMBPRINT"
               if [ "$NODE_MACHINE_SSL_THUMBPRINT" != "$ANCHOR_THUMBPRINT" ]; then
                  MISMATCH=1
                  TRUST_ANCHORS_MISMATCH=1
               fi
            done
            if [ $MISMATCH -eq 0 ]; then
               statusMessage 'VALID' 'GREEN'
            else
               statusMessage 'MISMATCH' 'YELLOW'
            fi
         fi
      else
         TRUST_ANCHORS_UNKNOWN=1
         TRUST_ANCHORS_UNKNOWN_NODES+=($node)
         statusMessage 'UNKNOWN' 'YELLOW'
      fi
   done
}

#------------------------------
# Get the PSC and vCenter nodes in an SSO Domain
#------------------------------
function getSSODomainNodes() {
   SSO_NODES=()
   PSC_NODES=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "ou=Domain Controllers,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=computer)' cn | grep '^cn:' | awk '{print $NF}')
   PSC_COUNT=$(echo "$PSC_NODES" | wc -l)
   VCENTER_NODES=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "ou=Computers,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=computer)' cn | grep '^cn:' | awk '{print $NF}')
   VCENTER_COUNT=$(echo "$VCENTER_NODES" | wc -l)
   
   for psc_node in "$PSC_NODES"; do
      if [[ ! "${SSO_NODES[@]}" =~ "$psc_node" ]]; then SSO_NODES+=($psc_node); fi
   done

   for vc_node in "$VCENTER_NODES"; do
      if [[ ! "${SSO_NODES[@]}" =~ "$vc_node" ]]; then SSO_NODES+=($vc_node); fi
   done
}

#------------------------------
# Print menu to view or manage certificates
#------------------------------
function printCertificateMenu() {
   authenticateIfNeeded
   header "$1 vCenter Certificates"
   logInfo "Printing the $1 vCenter Certificates Menu"
   echo ' 1. Machine SSL certificate'
   echo ' 2. Solution User certificates'
   echo ' 3. CA certificates in VMware Directory'
   echo ' 4. CA certificates in VECS'
   
   if [ $NODE_TYPE = 'infrastructure' ]; then printf "$YELLOW"; fi
   
   echo ' 5. Authentication Proxy certifcate'
   echo ' 6. Auto Deploy CA certificate'
   echo ' 7. SMS certificates'
   if [ "$VC_VERSION" == '6.5' ]; then printf "$YELLOW"; fi
   echo ' 8. Data Encipherment certificate'
   printf "$NORMAL"
   if [ $NODE_TYPE = 'infrastructure' ]; then printf "$YELLOW"; fi
   echo ' 9. vCenter Extension thumbprints'
   printf "$NORMAL"
   if [ $NODE_TYPE = 'management' ]; then
      printf "$YELLOW"
   else
      printf "$NORMAL"
   fi
   
   echo '10. VMware Directory certificate'
   echo '11. STS signing certificates'
   echo '12. VMCA certificate'
   if ! configuredForCAC; then printf "$YELLOW"; fi   
   echo '13. Smart Card CA certificates'
   printf "$NORMAL"
   if ! configuredForADoverLDAPS; then printf "$YELLOW"; fi
   echo '14. LDAPS Identity Source certificates'
   printf "$NORMAL"
   if ! tanzuSupervisorClustersPresent || [ "$1" == 'Manage' ]; then printf "$YELLOW"; fi
   echo '15. Tanzu Supervisor Cluster certificates'
   printf "$NORMAL"
   if [ "$1" == 'Manage' ]; then
      if ! checkVECSStore 'BACKUP_STORE'; then printf "$YELLOW"; fi
      echo '16. Clear BACKUP_STORE in VECS'
	  printf "$NORMAL"
      echo '17. Clear TRUSTED_ROOT_CRLS store in VECS'
	  if ! checkMachineSSLCSR; then printf "$YELLOW"; fi
	  echo '18. Clear Machine SSL CSR in VECS'
	  printf "$NORMAL"
   fi
   echo ''
}

#------------------------------
# Check if Smart Card authentication is configured
#------------------------------
function configuredForCAC() {
   if $LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password  '(objectclass=vmwSTSTenant)' vmwSTSAuthnTypes | grep 'vmwSTSAuthnTypes: 4' > /dev/null; then
      return 0
   else
      return 1
   fi
}

#------------------------------
# Check the an AD over LDAPS Identity Source is configured
#------------------------------
function configuredForADoverLDAPS() {
   if $LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' cn 2>/dev/null | grep cn > /dev/null 2>&1; then
      logInfo 'vCenter is using AD over LDAPS as an Identity Source'
      return 0
   elif $LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=VCIdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' cn 2>/dev/null | grep cn > /dev/null 2>&1; then
      logInfo 'vCenter is using ADFS as an Identity Source'
      return 0
   elif $LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP)' cn 2>/dev/null | grep cn > /dev/null 2>&1; then
      logInfo 'vCenter is using OpenLDAP as an Identity Source'
      return 0
   else
      logInfo 'vCenter is NOT using AD over LDAPS as an Identity Source'
      return 1
   fi
}

#------------------------------
# Check if there are any Tanzu Supervisor clusters deployed
#------------------------------
function tanzuSupervisorClustersPresent() {
   if [ -f /usr/lib/vmware-wcp/decryptK8Pwd.py ]; then
      if /usr/lib/vmware-wcp/decryptK8Pwd.py | grep -E '^Cluster: |^IP: |^PWD: ' > /dev/null 2>&1; then 
         logInfo 'Tanzu Supervisor Clusters detected'
         return 0
      else 
         logInfo 'No Tanzu Supervisor Clusters detected'
         return 1
      fi
   else
      return 1
   fi
}

#------------------------------
# Display options to view certificate info
#------------------------------
function viewCertificateMenu() {
   printCertificateMenu 'View'
   
   read -p 'Select an option [Return to Main Menu]: ' VIEW_CERT_OPERATION
   
   logInfo "User selected option $VIEW_CERT_OPERATION"
   
   if [[ "$VIEW_CERT_OPERATION" -ge 0 &&  "$VIEW_CERT_OPERATION" -le 15 ]]; then processViewCertificate; fi
}

#------------------------------
# Display options to manage certificates 
#------------------------------
function manageCertificateMenu() {
   printCertificateMenu 'Manage'
   
   read -t $READ_TIMEOUTS -p 'Select an option [Return to Main Menu]: ' MANAGE_CERT_OPERATION
   
   if [ $? -le 128 ]; then   
      logInfo "User selected option '$MANAGE_CERT_OPERATION'"
   
      if [[ "$MANAGE_CERT_OPERATION" -ge 1 &&  "$MANAGE_CERT_OPERATION" -le 18 ]]; then processManageCertificate; fi   
   else
      echo ''
   fi
}

#------------------------------
# Process view certificate selection
#------------------------------
function processViewCertificate() {
   case $VIEW_CERT_OPERATION in
      1)
         viewVECSCertificateInfo 'MACHINE_SSL_CERT' '__MACHINE_CERT'
         ;;
      
      2)
         for soluser in "${SOLUTION_USERS[@]}"; do
            echo $'\n'"Solution User: $soluser"
            viewVECSCertificateInfo "$soluser" "$soluser"
         done
         ;;
      
      3)
         manageVMDirCACertificates 'View'
         ;;
      
      4)
         manageVECSCACertificates 'View'
         ;;
      
      5)
         viewFilesystemCertificateInfo '/var/lib/vmware/vmcam/ssl/vmcamcert.pem'
         ;;
      
      6)
         viewFilesystemCertificateInfo '/etc/vmware-rbd/ssl/rbd-ca.crt'
         ;;
      
      7)
         manageSMSCertificates 'View'
         ;;
      
	  8) 
	     viewVECSCertificateInfo 'data-encipherment' 'data-encipherment'
	     ;;
	  
      9)
         manageVCExtensionThumbprints 'View'
         ;;
      
      10)
         if [[ "$VC_VERSION" =~ ^[78] ]]; then
            viewRemoteCertificateInfo 'localhost' '636'
         else
            viewFilesystemCertificateInfo '/usr/lib/vmware-vmdir/share/config/vmdircert.pem'
         fi
         ;;
         
      11)
         manageSTSTenantCerts 'View'
         ;;
      
      12)
         viewFilesystemCertificateInfo '/var/lib/vmware/vmca/root.cer'
         ;;
         
      13)
         manageCACCerts 'View'
         ;;
      
      14)
         manageLDAPSCerts 'View'
         ;;
	  
	  15)
	     manageTanzuSupervisorClusterCerts 'View'
		 ;;
   esac
}

#------------------------------
# Process manage certificate selection
#------------------------------
function processManageCertificate() {
   setTimestamp
   
   case $MANAGE_CERT_OPERATION in
      1)
         if promptReplaceMachineSSL; then
            if replaceMachineSSLCert && [[ $UPDATED_MACHINE_SSL -eq 1 ]]; then
               if [ $NODE_TYPE != 'infrastructure' ]; then           
                  SSLTrustAnchorSelf
                  updateSSLTrustAnchors
                  manageVCExtensionThumbprints 'Update'
                  updateAutoDeployDB
               fi
               if [ $NODE_TYPE = 'infrastructure' ]; then
                  if [ -n "$PSC_LB" ]; then
			            NODE_FQDN="$PSC_LB"
                  else
                     SSLTrustAnchorSelf
                  fi
			         updateSSLTrustAnchors
               fi
			      noticePSCHA
               promptRestartVMwareServices
            fi
            clearCSRInfo
         fi
         ;;
      
      2)
         if promptReplaceSolutionUsers; then       
            if replaceSolutionUserCerts && [ $NODE_TYPE != 'infrastructure' ]; then 
               manageVCExtensionThumbprints 'Update'
               promptRestartVMwareServices
            fi
            clearCSRInfo
         fi
         ;;
      
      3)
	      manageVMDirCACertificates 'Manage'
         ;;
      
      4)
         manageVECSCACertificates 'Manage'
         ;;
      
      5)
         if [ $NODE_TYPE != 'infrastructure' ]; then
            if promptReplaceAuthProxy; then
               if replaceAuthProxyCert; then
                  manageVCExtensionThumbprints 'Update' 
                  promptRestartVMwareServices 'vmcam'               
               fi
               clearCSRInfo
            fi
         else
            printf "\n${YELLOW}This operation must be done on the vCenter Server.${NORMAL}\n\n"
         fi
         ;;
      
      6)
         if [ $NODE_TYPE != 'infrastructure' ]; then
            if promptReplaceAutoDeployCA; then
               if replaceAutoDeployCACert; then promptRestartVMwareServices 'vmware-rbd-watchdog'; fi
               clearCSRInfo
            fi
         else
            printf "\n${YELLOW}This operation must be done on the vCenter Server.${NORMAL}\n\n"
         fi
         ;;
      
      7)
         manageSMSCertificates 'Manage'
         ;;
      
      8) 
	     replaceDataEnciphermentCertificate
	     ;;
	    
      9)
         if [ $NODE_TYPE != 'infrastructure' ]; then
            manageVCExtensionThumbprints 'Check'
         else
            printf "\n${YELLOW}This operation must be done on the vCenter Server.${NORMAL}\n\n"
         fi
         ;;
      
      10)
         if [[ "$VC_VERSION" =~ ^[78] ]]; then
            if [ -f /usr/lib/vmware-vmdir/share/config/vmdircert.pem ]; then
               removeVMDirCert
            else
               printf "\n${YELLOW}This operation is not available for vCenter 7.x or later${NORMAL}\n\n"
            fi
         elif [ $NODE_TYPE != 'management' ]; then
            if promptReplaceVMDir; then replaceVMDirCert; fi
         else
            printf "\n${YELLOW}This operation must be done on the Platform Services Controller${NORMAL}\n\n"
         fi
         ;;
      
      11)
         if [ $NODE_TYPE != 'management' ]; then
            manageSTSTenantCerts 'Replace'
         else
            printf "\n${YELLOW}This operation must be done on the Platform Services Controller${NORMAL}\n\n"
         fi
         ;;
      
      12)
         if [ $NODE_TYPE != 'management' ]; then
            if promptReplaceVMCA; then
               if replaceVMCACert && [ "$VMCA_REGENERATE_CERTIFICATES" == '1' ]; then resetAllCertificates; fi
            fi
         else
            printf "\n${YELLOW}This operation must be done on the Platform Services Controller${NORMAL}\n\n"
         fi
         ;;
      
      13)
         manageCACCerts 'Manage'
         ;;
      
      14)
         manageLDAPSCerts 'Manage'
         ;;
	  
	  15) 
	     #manageTanzuSupervisorClusterCerts 'Manage'
		 ;;
		 
	  16)
	     if checkVECSStore 'BACKUP_STORE'; then
	        clearBackupStore
		 else
		    echo $'\n'"${YELLOW}The BACKUP_STORE does not exist in VECS, nothing to do.$NORMAL"
		 fi
	     ;;
	  
	  17)
	     clearCRLs
	     ;;
	  
	  18)
	     clearMachineSSLCSR
	     ;;
   esac
}

#------------------------------
# Menu for options generating the certificate report
#------------------------------
function viewCertificateReportMenu() {
   unset CERTIFICATE_REPORT_INPUT
   header 'Certificate Report Options'
   cat << EOF
 1. Generate vCenter certificate report"
 2. Generate ESXi certificate report"
 3. Generate vCenter and ESXi certifiate report   
EOF
   
   read -p $'\nEnter report selection [Return to Main Menu]: ' CERTIFICATE_REPORT_INPUT
   
   if [ -z $CERTIFICATE_REPORT_INPUT ]; then return 1; fi
   
   if [ -f $VC_REPORT ]; then echo '' > $VC_REPORT; fi
   printf "\n"
   case $CERTIFICATE_REPORT_INPUT in
      1)
         generatevCenterCertificateReport
         ;;
      
      2)
         generateESXiCertificateReport
         ;;
      
      3)
         generatevCenterCertificateReport
         generateESXiCertificateReport
         ;;
   esac
}

#------------------------------
# Generate vCenter certificate report
#------------------------------
function generatevCenterCertificateReport() {
   if [ "$NODE_TYPE" != 'infrastructure' ] && ! checkService 'vmware-vpostgres'; then
      echo "${YELLOW}The vPostgres service is stopped!"
      echo "Please ensure this service is running before generating a certificate report."
      echo "Hint: Check the number of CRL entries in VECS${NORMAL}"
      return 1 
   fi

   authenticateIfNeeded
   disableColor

   printf '%0.1s' "="{1..130} | tee $VC_REPORT
   printf '\n' | tee -a $VC_REPORT
   echo 'SSL Certificate Report' | tee -a $VC_REPORT
   echo "vCert $VERSION" | tee -a $VC_REPORT
   echo "Host: $HOSTNAME" | tee -a $VC_REPORT
   echo "Date: $(date -u)" | tee -a $VC_REPORT
   echo "Node Type: $NODE_TYPE" | tee -a $VC_REPORT
   echo "Build: $VC_BUILD" | tee -a $VC_REPORT
   echo "Machine ID: $MACHINE_ID" | tee -a $VC_REPORT
   echo "PNID: $PNID" | tee -a $VC_REPORT
   if [ $NODE_TYPE != 'infrastructure' ]; then
      CERT_MGMT_MODE=$($PSQL -d VCDB -U postgres -c "SELECT value FROM vpx_parameter WHERE name='vpxd.certmgmt.mode'" -t | grep -v '^$')   
      echo "Certificate Management Mode: $CERT_MGMT_MODE" | tee -a $VC_REPORT
   fi
   printf '%0.1s' "="{1..130} | tee -a $VC_REPORT
   printf '\n' | tee -a $VC_REPORT
   
   VMDIR_CA_SUBJECT_IDS=''
   VECS_CA_SUBJECT_IDS=''
   for CNID in $($DIR_CLI trustedcert list --login "$VMDIR_USER_UPN" --password "$VMDIR_USER_PASSWORD" | grep 'CN(id)' | awk '{print $NF}'); do
      CERT=$($DIR_CLI trustedcert get --id $CNID --login "$VMDIR_USER_UPN" --password "$VMDIR_USER_PASSWORD" --outcert /dev/stdout | grep -v 'Certificate retrieved successfully')
      VMDIR_CERT_INFO=$(viewCertificateInfo "$CERT")
      
      VMDIR_CERT_SERIAL=$(echo "$VMDIR_CERT_INFO" | grep -A1 'Serial Number' | tail -n1 | tr -d ' ' | awk '{print toupper($0)}')
      VMDIR_CERT_SUBJECT=$(echo "$VMDIR_CERT_INFO" | grep 'Subject: ' | sed 's/Subject: //')
      VMDIR_CERT_SUBJECT_KEY=$(echo "$VMDIR_CERT_INFO" | grep -A1 'Subject Key Identifier' | tail -n1 | tr -d ' ')
      VMDIR_CA_SUBJECT_IDS+="serial:$VMDIR_CERT_SERIAL|DirName:$VMDIR_CERT_SUBJECT|keyid:$VMDIR_CERT_SUBJECT_KEY"$'\n'
   done
   
   IFS=$'\n'
   for alias in $($VECS_CLI entry list --store TRUSTED_ROOTS --text | grep 'Alias' | awk -F"[[:space:]]:[[:space:]]" '{print $NF}'); do
      CERT=$($VECS_CLI entry getcert --store TRUSTED_ROOTS --alias "$alias")
      VECS_CERT_INFO=$(viewCertificateInfo "$CERT")
      
      VECS_CERT_SERIAL=$(echo "$VECS_CERT_INFO" | grep -A1 'Serial Number' | tail -n1 | tr -d ' ' | awk '{print toupper($0)}')
      VECS_CERT_SUBJECT=$(echo "$VECS_CERT_INFO" | grep 'Subject: ' | sed 's/Subject: //')
      VECS_CERT_SUBJECT_KEY=$(echo "$VECS_CERT_INFO" | grep -A1 'Subject Key Identifier' | tail -n1 | tr -d ' ')
      VECS_CA_SUBJECT_IDS+="serial:$VECS_CERT_SERIAL|DirName:$VECS_CERT_SUBJECT|keyid:$VECS_CERT_SUBJECT_KEY"$'\n'
   done
   IFS=$' \t\n'
   
   echo 'VECS Certificates' | tee -a $VC_REPORT
   for store in $($VECS_CLI store list | grep -v 'APPLMGMT_PASSWORD'); do
      echo "   Store: $store" | tee -a $VC_REPORT
      
      IFS=$'\n'
      for alias in $($VECS_CLI entry list --store $store --text | grep 'Alias' | tr -d '\t' | awk -F':' '{print $NF}'); do
         echo "      Alias: $alias" | tee -a $VC_REPORT
         VECS_HASH=$($VECS_CLI entry getcert --store $store --alias "$alias" 2>/dev/null)
         if [[ $? -eq 0 ]]; then
            if ! echo "$VECS_HASH" | head -n1 | grep 'BEGIN CERTIFICATE' > /dev/null; then
               reportCRLDetails "$VECS_HASH"
            else
               case $store-$alias in
                  MACHINE_SSL_CERT-__MACHINE_CERT)
                     EXTRA_INFO='checkCurrentMachineSSLUsage'
                     ;;                  
                  vpxd-extension-vpxd-extension)
                     EXTRA_INFO='checkCurrentExtensionThumbprints'
                     ;;                  
                  *)
                     EXTRA_INFO=''
                     ;;
               esac
               
               reportCertDetails "$VECS_HASH" "$EXTRA_INFO"
            fi
         else
            echo "         |_No certificate found in store" | tee -a $VC_REPORT
         fi
      done
      IFS=$' \t\n'
   done

   echo 'VMware Directory Certificates' | tee -a $VC_REPORT
   echo '   CA Certificates' | tee -a $VC_REPORT
   for CNID in $($DIR_CLI trustedcert list --login "$VMDIR_USER_UPN" --password "$VMDIR_USER_PASSWORD" | grep 'CN(id)' | awk '{print $NF}'); do
      echo "      CN(id): $CNID" | tee -a $VC_REPORT
      VMDIR_CA_HASH=$($DIR_CLI trustedcert get --id $CNID --login "$VMDIR_USER_UPN" --password "$VMDIR_USER_PASSWORD" --outcert /dev/stdout | grep -v 'Certificate retrieved successfully')
      reportCertDetails "$VMDIR_CA_HASH"
   done
   
   echo '   Service Principal (Solution User) Certificates' | tee -a $VC_REPORT
   
   IFS=$'\n'
   for line in $($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=ServicePrincipals,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwServicePrincipal)' userCertificate); do
      if [[ "$line" =~ ^dn: ]]; then
         SERVICE_PRINCIPAL=$(echo "$line" | awk -F':' '{print $NF}' | awk -F',' '{print $1}' | awk -F'=' '{print $NF}')
         echo "      Service Principal: $SERVICE_PRINCIPAL" | tee -a $VC_REPORT
      else
         SERVICE_PRINCIPAL_CERT_HASH=$(echo "$line" | awk '{print $NF}')
         TEMP_CERT=$(buildCertFromHash "$SERVICE_PRINCIPAL_CERT_HASH")
         reportCertDetails "$TEMP_CERT"
      fi           
   done
   IFS=$' \t\n'
   echo '   Single Sign-On Secure Token Service Certificates' | tee -a $VC_REPORT
   TENANT_COUNT=0
   for hash in $($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwSTSTenantCredential)' userCertificate | grep '^userCertificate' | awk '{print $NF}'); do
      TEMP_CERT=$(buildCertFromHash "$hash")
      
      if isCertCA "$TEMP_CERT"; then
         echo "      TenantCredential-$TENANT_COUNT CA Certificate" | tee -a $VC_REPORT
      else
         ((++TENANT_COUNT))
         echo "      TenantCredential-$TENANT_COUNT Signing Certificate" | tee -a $VC_REPORT  
      fi
      reportCertDetails "$TEMP_CERT"
   done
   
   CHAIN_COUNT=0  
   for hash in $($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=TrustedCertificateChains,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwSTSTenantTrustedCertificateChain)' userCertificate | grep '^userCertificate' | awk '{print $NF}'); do
      TEMP_CERT=$(buildCertFromHash "$hash")
      
      if isCertCA "$TEMP_CERT"; then
         echo "      TrustedCertChain-$CHAIN_COUNT CA Certificate" | tee -a $VC_REPORT
      else
         ((++CHAIN_COUNT))
         echo "      TrustedCertChain-$CHAIN_COUNT Signing Certificate" | tee -a $VC_REPORT  
      fi
      reportCertDetails "$TEMP_CERT"
   done
   
   
   CAC_CAS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=DefaultClientCertCAStore,cn=ClientCertAuthnTrustedCAs,cn=Default,cn=ClientCertificatePolicies,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwSTSTenantTrustedCertificateChain)' userCertificate 2>/dev/null | grep '^userCertificate' | awk '{print $NF}')
   
   if [ -n "$CAC_CAS" ]; then
      CAC_ISSUING_CA_COUNT=1
      echo '   Smart Card Issuing CA Certificates' | tee -a $VC_REPORT
      for hash in $CAC_CAS; do
         TEMP_CERT=$(buildCertFromHash "$hash")      
         echo "      Smart Card Issuing CA $CAC_ISSUING_CA_COUNT" | tee -a $VC_REPORT
         reportCertDetails "$TEMP_CERT"
         ((++CAC_ISSUING_CA_COUNT))
      done
   fi
   
   AD_LDAPS_CERTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(vmwSTSProviderType=IDENTITY_STORE_TYPE_LDAP_WITH_AD_MAPPING)' userCertificate 2>/dev/null | grep '^userCertificate::' | awk '{print $NF}')
   
   if [ -n "$AD_LDAPS_CERTS" ]; then
      echo '   AD Over LDAPS Domain Controller Certificates' | tee -a $VC_REPORT
      LDAPS_DC_CERT_COUNT=1
      for hash in $AD_LDAPS_CERTS; do
         echo "      Certificate $LDAPS_DC_CERT_COUNT" | tee -a $VC_REPORT
         reportCertDetails "$(buildCertFromHash $hash)"
         ((++LDAPS_DC_CERT_COUNT))
      done
   fi
   
   echo 'Filesystem Certificates' | tee -a $VC_REPORT
   if [ "$NODE_TYPE" != 'management' ]; then
      if [[ "$VC_VERSION" =~ ^6 ]]; then
        echo '   VMware Directory Certificate' | tee -a $VC_REPORT
        echo '      Certificate: /usr/lib/vmware-vmdir/share/config/vmdircert.pem' | tee -a $VC_REPORT
        reportCertDetails "$(cat /usr/lib/vmware-vmdir/share/config/vmdircert.pem)"
      fi
      echo '   VMCA Certificate' | tee -a $VC_REPORT
      echo '      Certificate: /var/lib/vmware/vmca/root.cer' | tee -a $VC_REPORT
      reportCertDetails "$(cat /var/lib/vmware/vmca/root.cer)"
   fi
   if [ "$NODE_TYPE" != 'infrastructure' ]; then
      echo '   Authentication Proxy Certificate' | tee -a $VC_REPORT
      echo '      Certificate: /var/lib/vmware/vmcam/ssl/vmcamcert.pem' | tee -a $VC_REPORT
      reportCertDetails "$(cat /var/lib/vmware/vmcam/ssl/vmcamcert.pem)"
	  
      echo '   Auto Deploy CA Certificate' | tee -a $VC_REPORT
      echo '      Certificate: /etc/vmware-rbd/ssl/rbd-ca.crt' | tee -a $VC_REPORT
      reportCertDetails "$(cat /etc/vmware-rbd/ssl/rbd-ca.crt)"
   fi
   
   if grep '<clientCAListFile>' /etc/vmware-rhttpproxy/config.xml | grep -v '<!--' > /dev/null; then
      echo '   Smart Card Whitelist Certificates' | tee -a $VC_REPORT
      CAC_FILTER_FILE=$(grep '<clientCAListFile>' /etc/vmware-rhttpproxy/config.xml | grep -v '<!--' | awk -F'>' '{print $2}' | awk -F'<' '{print $1}')
      csplit -s -z -f $STAGE_DIR/cac_whitelist_ca- -b %02d.crt $CAC_FILTER_FILE '/-----BEGIN CERTIFICATE-----/' '{*}'
      WHITELIST_CERT_COUNT=1
      for cert in $(ls $STAGE_DIR/cac_whitelist_ca-*); do
         echo "      Certificate $WHITELIST_CERT_COUNT: $CAC_FILTER_FILE" | tee -a $VC_REPORT 
         reportCertDetails "$(cat $cert)"
         ((++WHITELIST_CERT_COUNT))
      done
   fi
   
   if tanzuSupervisorClustersPresent; then
      echo 'Tanzu Supervisor Cluster Certificates' | tee -a $VC_REPORT
      
      IFS=$'\n'
      for line in $(/usr/lib/vmware-wcp/decryptK8Pwd.py | grep -E '^Cluster: |^IP: |^PWD: '); do
         if [[ "$line" =~ ^Cluster ]]; then
            TANZU_CLUSTER_ID=$(echo "$line" | awk '{print $NF}' | awk -F':' '{print $1}' | sed -e 's/domain-c//')
	        TANZU_CLUSTER=$(/opt/vmware/vpostgres/current/bin/psql -d VCDB -U postgres -c "SELECT e.name FROM vpx_entity AS e LEFT JOIN vpx_object_type AS ot ON e.type_id = ot.id WHERE ot.name='CLUSTER_COMPUTE_RESOURCE' AND e.id=$TANZU_CLUSTER_ID" -t | sed -e 's/^[[:space:]]*//g' | grep -v '^$')   
         fi
         if [[ "$line" =~ ^IP ]]; then
            TANZU_CLUSTER_IP=$(echo "$line" | awk '{print $NF}')
         fi
         if [[ "$line" =~ ^PWD ]]; then
            TANZU_CLUSTER_PASSWD=$(echo "$line" | awk '{print $NF}')
            echo "   Cluster: $TANZU_CLUSTER" | tee -a $VC_REPORT
            ssh-keygen -R $TANZU_CLUSTER_IP 2>&1 | logDebug
            TANZU_CLUSTER_CERTIFICATES=$(sshpass -p "$TANZU_CLUSTER_PASSWD" ssh -q -o StrictHostKeyChecking=no -t -t root@$TANZU_CLUSTER_IP 'for cert in $(find / -type f \( -name "*.cert" -o -name "*.crt" \)  -print 2>/dev/null | egrep -v "ca.crt$|ca-bundle.crt$|kubelet\/pods|var\/lib\/containerd|run\/containerd|bootstrapper"); do echo "Certificate: $cert"; hash=$(openssl x509 -in $cert | grep -v '^-----' | tr -d "\n"); echo "Hash: $hash"; done')
			for line2 in $TANZU_CLUSTER_CERTIFICATES; do
			   if [[ "$line2" =~ ^Certificate ]]; then
			      echo "      $line2"
			   else
			      TANZU_CERT_HASH=$(echo "$line2" | awk '{print $NF}')
               TEMP_CERT=$(buildCertFromHash "$TANZU_CERT_HASH")
               reportCertDetails "$TEMP_CERT"
			   fi
			done
         fi
      done
      IFS=$' \t\n'
   fi
   
   echo 'Lookup Service Registration Trust Anchors' | tee -a $VC_REPORT
   
   getSSLTrustAnchorHashes

   for hash in "${CERT_HASHES[@]}"; do
      echo "      Endpoint Certificate $CERT_COUNT" | tee -a $VC_REPORT
      TEMP_CERT=$(buildCertFromHash "$hash")
      
      double_encoded_hash=$(echo "$hash" | tr -d '\n' | sed -e 's/.\{76\}/&\r\n/g' | xargs -0 printf "%s\r\n" | base64 -w 0)     
      
      USED_BY_SERVICE_IDS=$(getSSLTrustAnchorServiceIds "$hash" "$double_encoded_hash")
      NUM_USED_BY_SERVICE_IDS=$(echo "$USED_BY_SERVICE_IDS" | grep -v '^$' | wc -l)

      USED_BY_ENDPOINTS=$(getSSLTrustAnchorEndpoints "$hash" "$double_encoded_hash")   
      NUM_USED_BY_ENDPOINTS=$(echo "$USED_BY_ENDPOINTS" | grep -v '^$' | wc -l)

      ((++CERT_COUNT))
      
      reportTrustAnchorDetails "$TEMP_CERT" "$USED_BY_SERVICE_IDS" "$USED_BY_ENDPOINTS"
   done
   
   enableColor
   
   echo $'\n'"${YELLOW}Certificate report is available at ${VC_REPORT}${NORMAL}"$'\n'
}

#------------------------------
# Generate ESXi certificate report
#------------------------------
#function generateESXiCertificateReport() {
#
#}

#------------------------------
# CRL information for report
#------------------------------
function reportCRLDetails() {
   REPORT_CRL=$1
   REPORT_CRL_INFO=$(viewCRLInfo "$REPORT_CRL")
   REPORT_CRL_ISSUER=$(echo "$REPORT_CRL_INFO" | grep 'Issuer:' | awk -F'Issuer: ' '{print $NF}')
   REPORT_CRL_LAST_UPDATE=$(echo "$REPORT_CRL" | openssl crl -noout -lastupdate 2>/dev/null | sed 's/lastUpdate=//')
   REPORT_CRL_NEXT_UPDATE=$(echo "$REPORT_CRL" | openssl crl -noout -nextupdate 2>/dev/null | sed 's/nextUpdate=//')
   REPORT_CRL_SIGNATURE_ALGORITHM=$(echo "$REPORT_CRL_INFO" | grep 'Signature Algorithm' | head -n1 | awk '{print $NF}')
   REPORT_CRL_AUTH_KEYS=$(echo "$REPORT_CRL_INFO" | grep 'Authority Key Identifier' -A3 | grep -E 'keyid:|DirName:|issuer:' | tr -d ' ')
   
   echo "         Issuer: $REPORT_CRL_ISSUER" | tee -a $VC_REPORT
   echo "            Last Update: $REPORT_CRL_LAST_UPDATE" | tee -a $VC_REPORT
   echo "            Next Update: $REPORT_CRL_NEXT_UPDATE" | tee -a $VC_REPORT
   echo "            Signature Algorithm: $REPORT_CRL_SIGNATURE_ALGORITHM" | tee -a $VC_REPORT
}

#------------------------------
# Certificate information for report
#------------------------------
function reportCertDetails() {
   ISSUER_FOUND_VMDIR=0
   ISSUER_FOUND_VECS=0
   REPORT_CERT=${1}
   if isCertCA "$REPORT_CERT"; then REPORT_CERT_IS_CA='Yes'; else REPORT_CERT_IS_CA='No'; fi
   REPORT_CERT_INFO=$(viewCertificateInfo "$REPORT_CERT")
   REPORT_CERT_SUBJECT=$(echo "$REPORT_CERT_INFO" | grep 'Subject:' | awk -F'Subject: ' '{print $NF}')
   REPORT_CERT_ISSUER=$(echo "$REPORT_CERT_INFO" | grep 'Issuer:' | awk -F'Issuer: ' '{print $NF}')
   REPORT_CERT_VALID_START=$(echo "$REPORT_CERT" | openssl x509 -noout -startdate 2>/dev/null | sed 's/notBefore=//')
   REPORT_CERT_VALID_END=$(echo "$REPORT_CERT" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
   REPORT_CERT_FINGERPRINT=$(echo "$REPORT_CERT" | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $2}')
   REPORT_CERT_SIGNATURE_ALGORITHM=$(echo "$REPORT_CERT_INFO" | grep 'Signature Algorithm' | head -n1 | awk '{print $NF}')
   REPORT_CERT_SUBJECT_KEY=$(echo "$REPORT_CERT_INFO" | grep 'Subject Key Identifier:' -A1 | tail -n1 | tr -d ' ')
   REPORT_CERT_AUTH_KEYS=$(echo "$REPORT_CERT_INFO" | grep 'Authority Key Identifier' -A3 | grep -E 'keyid:|DirName:|issuer:' | tr -d ' ')
   REPORT_CERT_KEY_USAGE=$(echo "$REPORT_CERT_INFO" | grep 'X509v3 Key Usage' -A1 | tail -n1 | sed -e 's/^ *//g' -e 's/, /\n/g' | grep -v '^$')
   REPORT_CERT_KEY_EXT_USAGE=$(echo "$REPORT_CERT_INFO" | grep 'X509v3 Extended Key Usage' -A1 | tail -n1 | sed -e 's/^ *//g' -e 's/, /\n/g' | grep -v '^$')
   REPORT_CERT_SAN=$(echo "$REPORT_CERT_INFO" | grep 'X509v3 Subject Alternative Name' -A1 | tail -n1 | sed -e 's/^ *//g' -e 's/, /\n/g' | grep -v '^$' | sort)
         
   echo "         Issuer: $REPORT_CERT_ISSUER" | tee -a $VC_REPORT
   echo "         Subject: $REPORT_CERT_SUBJECT" | tee -a $VC_REPORT
   echo "            Not Before: $REPORT_CERT_VALID_START" | tee -a $VC_REPORT
   echo "            Not After : $REPORT_CERT_VALID_END" | tee -a $VC_REPORT
   echo "            SHA1 Fingerprint : $REPORT_CERT_FINGERPRINT" | tee -a $VC_REPORT
   echo "            Signature Algorithm: $REPORT_CERT_SIGNATURE_ALGORITHM" | tee -a $VC_REPORT
   echo "            Subject Key Identifier: $REPORT_CERT_SUBJECT_KEY" | tee -a $VC_REPORT   
   
   if [ -n "$REPORT_CERT_AUTH_KEYS" ]; then
      echo '            Authority Key Identifier:' | tee -a $VC_REPORT
      
	  IFS=$'\n'
      for auth_key in $(echo "$REPORT_CERT_AUTH_KEYS"); do
         echo "               |_$auth_key" | tee -a $VC_REPORT
         if echo "$VMDIR_CA_SUBJECT_IDS" | grep "$auth_key" > /dev/null; then ISSUER_FOUND_VMDIR=1; fi
         if echo "$VECS_CA_SUBJECT_IDS" | grep "$auth_key" > /dev/null; then ISSUER_FOUND_VECS=1; fi 
      done
      IFS=$' \t\n'
   fi
   
   if [[ $ISSUER_FOUND_VMDIR -eq 0 && $ISSUER_FOUND_VECS -eq 0 ]]; then
      if [[ "$REPORT_CERT_SUBJECT" == "$REPORT_CERT_ISSUER" ]]; then
         REPORT_CERT_ISSUER_FOUND='No (Self-Signed)'
      else
         REPORT_CERT_ISSUER_FOUND='No'
      fi
   elif [[ $ISSUER_FOUND_VMDIR -eq 1 && $ISSUER_FOUND_VECS -eq 0 ]]; then
      REPORT_CERT_ISSUER_FOUND='Yes, in VMware Directory'
   elif [[ $ISSUER_FOUND_VMDIR -eq 0 && $ISSUER_FOUND_VECS -eq 1 ]]; then
      REPORT_CERT_ISSUER_FOUND='Yes, in VECS'
   else
      REPORT_CERT_ISSUER_FOUND='Yes, in both'
   fi
   
   echo '            Key Usage:' | tee -a $VC_REPORT
   if [ -n "$REPORT_CERT_KEY_USAGE" ]; then 
      
	  IFS=$'\n'
      for key_usage in $(echo "$REPORT_CERT_KEY_USAGE"); do
         echo "               |_$key_usage" | tee -a $VC_REPORT
      done
      IFS=$' \t\n'
   fi
   echo '            Extended Key Usage:' | tee -a $VC_REPORT
   if [ -n "$REPORT_CERT_KEY_EXT_USAGE" ]; then 
      
	  IFS=$'\n'
      for ext_key_usage in $(echo "$REPORT_CERT_KEY_EXT_USAGE"); do
         echo "               |_$ext_key_usage" | tee -a $VC_REPORT
      done
      IFS=$' \t\n'
   fi
   echo '            Subject Alternative Name entries:' | tee -a $VC_REPORT
   if [ -n "$REPORT_CERT_SAN" ]; then
      
	  IFS=$'\n'
      for san in $(echo "$REPORT_CERT_SAN"); do
         echo "               |_$san" | tee -a $VC_REPORT
      done
      IFS=$' \t\n'
   fi
   
   echo '            Other Information:' | tee -a $VC_REPORT
   echo "               |_Is a Certificate Authority: $REPORT_CERT_IS_CA" | tee -a $VC_REPORT
   echo "               |_Issuing CA in VMware Directory/VECS: $REPORT_CERT_ISSUER_FOUND" | tee -a $VC_REPORT   
   
   if [ -n "$2" ]; then
      CUSTOM_INFO=$(echo "$2" | tr '|' '\n')
      
	  IFS=$'\n'
      for custom_call in $CUSTOM_INFO; do
         FUNCTION_STRING=$(echo "$custom_call" | tr ':' ' ')
         eval $FUNCTION_STRING
      done
      IFS=$' \t\n'
   fi
}

#------------------------------
# Trust Anchor information for report
#------------------------------
function reportTrustAnchorDetails() {
   TRUST_ANCHOR_CERT="$1"
   SERVICE_IDS="$2"
   ENDPOINTS="$3"
   TRUST_ANCHOR_INFO=$(viewCertificateInfo "$TRUST_ANCHOR_CERT")
   TRUST_ANCHOR_SUBJECT=$(echo "$TRUST_ANCHOR_INFO" | grep 'Subject:' | awk -F'Subject: ' '{print $NF}')
   TRUST_ANCHOR_ISSUER=$(echo "$TRUST_ANCHOR_INFO" | grep 'Issuer:' | awk -F'Issuer: ' '{print $NF}')
   TRUST_ANCHOR_VALID_START=$(echo "$TRUST_ANCHOR_CERT" | openssl x509 -noout -startdate 2>/dev/null | sed 's/notBefore=//')
   TRUST_ANCHOR_VALID_END=$(echo "$TRUST_ANCHOR_CERT" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
   TRUST_ANCHOR_FINGERPRINT=$(echo "$TRUST_ANCHOR_CERT" | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $2}')
   
   
   echo "         Issuer: $TRUST_ANCHOR_ISSUER" | tee -a $VC_REPORT
   echo "         Subject: $TRUST_ANCHOR_SUBJECT" | tee -a $VC_REPORT
   echo "            Not Before: $TRUST_ANCHOR_VALID_START" | tee -a $VC_REPORT
   echo "            Not After : $TRUST_ANCHOR_VALID_END" | tee -a $VC_REPORT
   echo "            SHA1 Fingerprint: $TRUST_ANCHOR_FINGERPRINT" | tee -a $VC_REPORT
   echo '            Service IDs:' | tee -a $VC_REPORT
   
   for service in $SERVICE_IDS; do
      echo "               |_$service" | tee -a $VC_REPORT
   done
   
   echo '            Endpoints:' | tee -a $VC_REPORT
   
   for endpoint in $ENDPOINTS; do
      echo "               |_$endpoint" | tee -a $VC_REPORT
   done
   
   return 0
}

#------------------------------
# Extra information regarding the Machine SSL certificate
#------------------------------
function checkCurrentMachineSSLUsage() {
   RHTTPPROXY_CERT_FINGERPRINT=$(echo | openssl s_client -connect localhost:443 2>/dev/null | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
   VPXD_CERT_FINGERPRINT=$(echo | openssl s_client -connect localhost:8089 2>/dev/null | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
   echo "               |_Current certificate used by the reverse proxy: $RHTTPPROXY_CERT_FINGERPRINT" | tee -a $VC_REPORT
   echo "               |_Current certificate used by vCenter (vpxd)   : $VPXD_CERT_FINGERPRINT" | tee -a $VC_REPORT
}

#------------------------------
# Extra information regarding the vpxd-extension certificate
#------------------------------
function checkCurrentExtensionThumbprints() {
   EAM_EXT_FINGERPRINT=$($PSQL -d VCDB -U postgres -c "SELECT thumbprint FROM vpx_ext WHERE ext_id = 'com.vmware.vim.eam'" -t | grep -v '^$' | tr -d ' ')
   RBD_EXT_FINGERPRINT=$($PSQL -d VCDB -U postgres -c "SELECT thumbprint FROM vpx_ext WHERE ext_id = 'com.vmware.rbd'" -t | grep -v '^$' | tr -d ' ')
   VUM_EXT_FINGERPRINT=$($PSQL -d VCDB -U postgres -c "SELECT thumbprint FROM vpx_ext WHERE ext_id = 'com.vmware.vcIntegrity'" -t | grep -v '^$' | tr -d ' ')
   VLCM_CLIENT_EXT_FINGERPRINT=$($PSQL -d VCDB -U postgres -c "SELECT thumbprint FROM vpx_ext WHERE ext_id = 'com.vmware.vlcm.client'" -t | grep -v '^$' | tr -d ' ')
   IMAGE_BUILDER_EXT_FINGERPRINT=$($PSQL -d VCDB -U postgres -c "SELECT thumbprint FROM vpx_ext WHERE ext_id = 'com.vmware.imagebuilder'" -t | grep -v '^$' | tr -d ' ')
   echo '               |_Thumbprints in VCDB for extensions that should use the vpxd-extension certificate' | tee -a ${REPORT}
   echo "                  |_com.vmware.vim.eam     : $EAM_EXT_FINGERPRINT" | tee -a $VC_REPORT
   echo "                  |_com.vmware.vcIntegrity : $VUM_EXT_FINGERPRINT" | tee -a $VC_REPORT
   
   if [ -n "$RBD_EXT_FINGERPRINT" ]; then
      echo "                  |_com.vmware.rbd         : $RBD_EXT_FINGERPRINT" | tee -a $VC_REPORT
   fi
   if [ -n "$IMAGE_BUILDER_EXT_FINGERPRINT" ]; then
      echo "                  |_com.vmware.imagebuilder: $IMAGE_BUILDER_EXT_FINGERPRINT" | tee -a $VC_REPORT
   fi
   if [[ "$VC_VERSION" =~ ^8 ]]; then
   echo "                  |_com.vmware.vlcm.client : $VLCM_CLIENT_EXT_FINGERPRINT" | tee -a $VC_REPORT
   fi
}

#------------------------------
# View VECS certificate info
#------------------------------
function viewVECSCertificateInfo() {
   logInfo "Viewing certificate in VECS store $1 with alias $2"
   CERT=$($VECS_CLI entry getcert --store $1 --alias $2 2>/dev/null)
   if [ -n "$CERT" ]; then
      logDetails "$CERT"
      viewCertificateInfo "$CERT" 'view-path'
   else
      logInfo "Unable to view the certificate in VECS store $1 with alias $2"
      echo $'\n'"${YELLOW}Unable to view the $1 certificate.${NORMAL}"
   fi
}

#------------------------------
# View certificate info from a file
#------------------------------
function viewFilesystemCertificateInfo() {
   logInfo "Viewing certificate at $1"
   CERT=$(cat $1 2>/dev/null)
   if [ -n "$CERT" ]; then
      logDetails "$CERT"
      viewCertificateInfo "$CERT" 'view-path'
   else
      logInfo "Unable to view the certificate at $1"
      echo $'\n'"${YELLOW}Unable to view certificate at $1.${NORMAL}"
   fi
}

#------------------------------
# View certificate info from a remote service
#------------------------------
function viewRemoteCertificateInfo() {
   logInfo "Viewing certificate at $1:$2"
   CERT=$(echo | openssl s_client -connect $1:$2 2>/dev/null | openssl x509 2>/dev/null)
   if [ -n "$CERT" ]; then
      logDetails "$CERT"
      viewCertificateInfo "$CERT" 'view-path'
   else
      logInfo "Unable to view certificate at $1:$2"
      echo $'\n'"${YELLOW}Unable to view certificate from $1:$2.${NORMAL}"
   fi
}

#------------------------------
# Manage VMDir CA certificates
#------------------------------
function manageVMDirCACertificates() {
   authenticateIfNeeded
   header 'CA Certificates in VMware Directory'
   listVMDirCACertificates
   
   case $1 in 
      'View')
         read -p $'\nSelect certificate [Return to Main Menu]: ' VIEW_VMDIR_CA_CERT_INPUT
   
         if [ -n "$VIEW_VMDIR_CA_CERT_INPUT" ]; then
            viewVMDirCACertificate "$VIEW_VMDIR_CA_CERT_INPUT"
         fi
      ;;
      
      'Manage')
         header 'Manage Certificates in VMware Directory'
         echo ' 1. Publish CA certificate(s) to VMware Directory'
         echo ' 2. Remove CA certificate(s) from VMware Directory'
         if [ -n "$SDDC_MANAGER" ]; then echo ' 3. Publish CA certificate(s) to SDDC Manager'; fi
   
         read -p $'\nSelect an option [Return to Main Menu]: ' MANAGE_VMDIR_CA_CERT_INPUT
   
         case $MANAGE_VMDIR_CA_CERT_INPUT in
            1)
               publishCACertsVMDir
               ;;
            2)
               removeCACertsVMDir
               ;;
            3)
			      if [ -n "$SDDC_MANAGER" ]; then 
			         publishVMDirCACertSDDCManager
			      else
			         echo $'\n'"${YELLOW}Invalid option.${NORMAL}"
			      fi
			      ;;
         esac
         ;;
   esac  
}

#------------------------------
# Add new STS signing certificate
#------------------------------
function replaceSSOSTSCert() {
   if [ $STS_REPLACE == 'VMCA-SIGNED' ]; then
      STS_CERT=$STAGE_DIR/sso-sts.crt
      STS_PUBKEY=$STAGE_DIR/sso-sts.pub
      STS_KEY=$STAGE_DIR/sso-sts.key

      header 'Replace SSO STS Signing Certificate'      
      generateCertoolConfig 'sts' 'ssoserverSign'
      task 'Regenerate STS signing certificate'
      regenerateVMCASignedCertificate 'sso-sts'
      statusMessage 'OK' 'GREEN'
      TRUSTED_ROOT_CHAIN=$VMCA_CERT
   else
      unset STS_CA_SIGNED_OPTION_INPUT
      echo $'\n1. Generate Certificate Signing Request and Private Key'
      echo '2. Generate Certificate Signing Request and Private Key'
      echo '   from custom OpenSSL configuration file'
      echo '3. Import CA-signed Certificate and Key'
      read -p $'\nSelect an option [Return to Main Menu]: ' STS_CA_SIGNED_OPTION_INPUT
	  
	   if [ -z $STS_CA_SIGNED_OPTION_INPUT ]; then return 1; fi

      if [ "$STS_CA_SIGNED_OPTION_INPUT" == '3' ]; then
         logInfo 'User has chosen to import a CA-signed STS Signing certificate and key'
         read -e -p $'\n'"Provide path to the CA-signed ${CYAN}Machine SSL${NORMAL} certificate: " STS_CERT_INPUT
         while [ ! -f "$STS_CERT_INPUT" ]; do read -e -p "${YELLOW}File not found, please provide path to the STS Signing certificate:${NORMAL} " STS_CERT_INPUT; done
         
         getCorrectCertFormat "$STS_CERT_INPUT" 'STS_CERT'
         STS_CERT_MODULUS_HASH=$(openssl x509 -noout -modulus -in $STS_CERT 2>/dev/null | md5sum | awk '{print $1}')
		 
		   getPrivateKey "$STS_CERT_MODULUS_HASH" "STS" 'STS Signing'     
		   getCAChain "$STS_CERT"

         header 'Certificate Verification'
         task 'Verifying certificate and key'        
        
         logDebug "Using STS Signing cert: $STS_CERT"
         logDebug "Using Private Key: $STS_KEY"
         logDebug "Using trusted root chain: $TRUSTED_ROOT_CHAIN"
        
         verifyCertAndKey "$STS_CERT" "$STS_KEY" 
         statusMessage 'OK' 'GREEN'
        
         task 'Verifying root chain'
         verifyRootChain $STS_CERT $TRUSTED_ROOT_CHAIN || errorMessage 'Certificate Authority chain is not complete'
         statusMessage 'OK' 'GREEN'
                
         header 'Replace SSO STS Signing Certificate'                 
         task 'Publish CA signing certificates'
		   publishCASigningCertificates $TRUSTED_ROOT_CHAIN
      else
         unset STS_CN_INPUT
         STS_CSR=$REQUEST_DIR/sso-sts-$TIMESTAMP.csr
         STS_KEY=$REQUEST_DIR/sso-sts-$TIMESTAMP.key
                  
         if [ "$STS_CA_SIGNED_OPTION_INPUT" == '1' ]; then
            STS_CFG=$REQUEST_DIR/sso-sts.cfg
            logInfo 'User has chosen to generate the STS Signing private key and CSR'
            if [ -z "$CSR_COUNTRY" ]; then getCSRInfo; fi

            read -p "Enter a value for the ${CYAN}CommonName${NORMAL} of the certificate [ssoserver]: " STS_CN_INPUT

            if [ -z "$STS_CN_INPUT" ]; then STS_CN_INPUT='ssoserver'; fi

            checkPSCHA
            defineSANEntries 'sso-sts' 'STS Signing'
            generateOpensslConfig $STS_CN_INPUT $STS_CFG 'sso-sts'
         else
            logInfo 'User has chosen to generate the STS Signing private key and CSR from a custom OpenSSL configuration file'
            read -e -p $'\nEnter path to custom OpenSSL configuration file: ' STS_CFG
            while [ ! -f "$STS_CFG" ]; do read -e -p "${YELLOW}File not found, enter path to custom OpenSSL configuration file:${NORMAL} " STS_CFG; done
         fi
         
         generateCSR $STS_CSR $STS_KEY "$STS_CFG" || errorMessage "Unable to generate Certificate Signing Request and Private Key"
         
         printf "\nCertificate Signing Request generated at ${CYAN}${STS_CSR}${NORMAL}"
         printf "\nPrivate Key generated at ${CYAN}${STS_KEY}${NORMAL}\n"
         
         return 0
      fi
   fi

   task 'Backup and delete tenant credentials'
   TENANT_CREDS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwSTSTenantCredential)' dn | sed 's/^dn: //g')
   i=1
   for credential in $TENANT_CREDS; do
      logInfo "Backing up credential $credential"
      $LDAP_SEARCH -h $PSC_LOCATION -p $VMDIR_PORT -D "cn=${VMDIR_USER},cn=users,${VMDIR_DOMAIN_DN}" -y $STAGE_DIR/.vmdir-user-password -b "$credential" 2>/dev/null > $BACKUP_DIR/TenantCredential-$i.ldif
      logInfo "Deleting credential $credential"
      $LDAP_DELETE -h $PSC_LOCATION -p $VMDIR_PORT -D "cn=${VMDIR_USER},cn=users,${VMDIR_DOMAIN_DN}" -y $STAGE_DIR/.vmdir-user-password "$credential" 2>&1 | logDebug
      ((i++))
   done
   statusMessage 'OK' 'GREEN'
   
   task 'Backup and delete trusted cert chains'
   
   TRUSTED_CHAINS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwSTSTenantTrustedCertificateChain)' dn | sed 's/^dn: //g')
   i=1
   for chain in $TRUSTED_CHAINS; do
      logInfo "Backing up chain $chain"
      $LDAP_SEARCH -h $PSC_LOCATION -p $VMDIR_PORT -D "cn=${VMDIR_USER},cn=users,${VMDIR_DOMAIN_DN}" -y $STAGE_DIR/.vmdir-user-password -b "$chain" 2>/dev/null > $BACKUP_DIR/TrustedCertChain-$i.ldif
      logInfo "Deleting chain $chain"
      $LDAP_DELETE -h $PSC_LOCATION -p $VMDIR_PORT -D "cn=${VMDIR_USER},cn=users,${VMDIR_DOMAIN_DN}" -y $STAGE_DIR/.vmdir-user-password "$chain" 2>&1 | logDebug
      ((i++))
   done
   statusMessage 'OK' 'GREEN'

   task 'Add new STS signing certifcate to VMDir'   

   openssl x509 -outform der -in $STS_CERT -out $STAGE_DIR/sso-sts.der 2>/dev/null || errorMessage 'Unable to create binary SSO STS certificate'
   openssl pkcs8 -topk8 -inform pem -outform der -in $STS_KEY -out $STAGE_DIR/sso-sts.key.der -nocrypt 2>/dev/null || errorMessage 'Unable to create binary SSO STS private key'
   
   STS_CA_CERTS=$(csplit -z -f $STAGE_DIR/sts-ca-cert- -b %02d.crt $TRUSTED_ROOT_CHAIN '/-----BEGIN CERTIFICATE-----/' '{*}' | wc -l)
   i=0
   until [ $i -eq $STS_CA_CERTS ]; do
      openssl x509 -outform der -in $STAGE_DIR/sts-ca-cert-0$i.crt -out $STAGE_DIR/sts-ca-cert-0$i.der 2>&1 | logDebug
      ((i++))
   done
   
   echo "dn: cn=TenantCredential-1,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" > $STAGE_DIR/sso-sts.ldif
   echo 'changetype: add' >> $STAGE_DIR/sso-sts.ldif
   echo 'objectClass: vmwSTSTenantCredential' >> $STAGE_DIR/sso-sts.ldif
   echo 'objectClass: top' >> $STAGE_DIR/sso-sts.ldif
   echo 'cn: TenantCredential-1' >> $STAGE_DIR/sso-sts.ldif
   echo "userCertificate:< file://$STAGE_DIR/sso-sts.der" >> $STAGE_DIR/sso-sts.ldif
   
   i=0
   until [ $i -eq $STS_CA_CERTS ]; do
      echo "userCertificate:< file:$STAGE_DIR/sts-ca-cert-0${i}.der" >> $STAGE_DIR/sso-sts.ldif
      ((i++))
   done
   
   echo "vmwSTSPrivateKey:< file://$STAGE_DIR/sso-sts.key.der" >> $STAGE_DIR/sso-sts.ldif
   echo '' >> $STAGE_DIR/sso-sts.ldif
   echo "dn: cn=TrustedCertChain-1,cn=TrustedCertificateChains,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" >> $STAGE_DIR/sso-sts.ldif
   echo 'changetype: add' >> $STAGE_DIR/sso-sts.ldif
   echo 'objectClass: vmwSTSTenantTrustedCertificateChain' >> $STAGE_DIR/sso-sts.ldif
   echo 'objectClass: top' >> $STAGE_DIR/sso-sts.ldif
   echo 'cn: TrustedCertChain-1' >> $STAGE_DIR/sso-sts.ldif
   echo "userCertificate:< file://$STAGE_DIR/sso-sts.der" >> $STAGE_DIR/sso-sts.ldif
   
   i=0
   until [ $i -eq $STS_CA_CERTS ]; do
      echo "userCertificate:< file:$STAGE_DIR/sts-ca-cert-0$i.der" >> $STAGE_DIR/sso-sts.ldif
      ((i++))
   done

   $LDAP_MODIFY -v -h $PSC_LOCATION -p $VMDIR_PORT -D "$VMDIR_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.machine-account-password -f $STAGE_DIR/sso-sts.ldif 2>&1 | logDebug

   statusMessage 'OK' 'GREEN'
}

#------------------------------
# Remove certificates from VMDir
#------------------------------
function removeCACertsVMDir() {
   read -p $'\nEnter the number(s) of the certificate(s) to delete (multiple entries separated by a comma): ' DELETE_VMDIR_CA_LIST
   
   if [ -n "$DELETE_VMDIR_CA_LIST" ]; then
      header 'Removing CA certificates from VMware Directory'
      for index in $(echo "$DELETE_VMDIR_CA_LIST" | tr -d ' ' | sed 's/,/ /g'); do
         skid=${VMDIR_CA_CERT_SKIDS[$((index - 1))]}
         task "Backup $skid"
         if $DIR_CLI trustedcert get --id $skid --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" --outcert $BACKUP_DIR/$skid.crt 2>&1 | logInfo; then
            statusMessage 'OK' 'GREEN'
         else
            errorMessage "Unable to backup certificate with Subject Key ID $skid" 'backup'
         fi
         
         task "Remove $skid"
         $DIR_CLI trustedcert unpublish --cert $BACKUP_DIR/$skid.crt --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" 2>&1 | logInfo
         if [ $? -eq 0 ]; then
            statusMessage 'OK' 'GREEN'
         else
            statusMessage 'FAILED' 'YELLOW'
            task "Remove $skid directly"
            $LDAP_DELETE -h $PSC_LOCATION -p $VMDIR_PORT -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password "cn=$skid,cn=Certificate-Authorities,cn=Configuration,$VMDIR_DOMAIN_DN" 2>&1 | logDebug || errorMessage "Unable to delete certificate with Subject Key ID $skid from VMware Directory"
            statusMessage 'OK' 'GREEN'
         fi
      done
      task 'Refreshing CA certificates to VECS'
      $VECS_CLI force-refresh 2>/dev/null || errorMessage 'Error refreshing CA certificates to VECS'
      statusMessage 'OK' 'GREEN'
   fi
}

#------------------------------
# Publish CA certificate(s) from VMDir to SDDC Manager
#------------------------------
function publishVMDirCACertSDDCManager() {
   read -p $'\n'"Enter the number(s) of the certificate(s) to publish to $SDDC_MANAGER (multiple entries separated by a comma): " PUBLISH_VMDIR_CA_SDDC_LIST
   
   if [ -n "$PUBLISH_VMDIR_CA_SDDC_LIST" ]; then
      header 'Publishing CA certificates to SDDC Manager'
      getSDDCAccessToken
      for index in $(echo "$PUBLISH_VMDIR_CA_SDDC_LIST" | tr -d ' ' | sed 's/,/ /g'); do
         skid=${VMDIR_CA_CERT_SKIDS[$((index - 1))]}
         task 'Export cert from VMware Directory'
         $DIR_CLI trustedcert get --id $skid --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" --outcert $STAGE_DIR/sddc_$skid.crt 2>&1 | logInfo || errorMessage "Unable to backup certificate with Subject Key ID $skid" 'backup'
         statusMessage 'OK' 'GREEN'
		 
         publishCACertsSDDCManager "$STAGE_DIR/sddc_$skid.crt"
      done
      echo $'\n'"${YELLOW}Services will need to be restarted on the SDDC Manager"
      echo "by running /opt/vmware/vcf/operationsmanager/scripts/cli/sddcmanager_restart_services.sh${NORMAL}"
   fi
}

#------------------------------
# View VECS CA certificates
#----------------------------
function manageVECSCACertificates() {
   header 'CA Certificates in TRUSTED_ROOTS store in VECS'
   listVECSCACertificates
   
   case $1 in
      'View')
         read -p $'\nSelect certificate [Return to Main Menu]: ' VIEW_VECS_CA_CERT_INPUT
   
         if [ -n "$VIEW_VECS_CA_CERT_INPUT" ]; then
            viewVECSCACertificate "$VIEW_VECS_CA_CERT_INPUT"
         fi
         ;;
      
      'Manage')
         header 'Manage Certificates in VECS'
         echo ' 1. Remove CA certificate(s) from VMware Directory'
         if [ -n "$SDDC_MANAGER" ]; then echo ' 2. Publish CA certificate(s) to SDDC Manager'; fi
   
         read -p $'\nSelect an option [Return to Main Menu]: ' MANAGE_VECS_CA_CERT_INPUT
		 
         case $MANAGE_VECS_CA_CERT_INPUT in
		 	   1)	 
               removeCACertsVECS
		         ;;			
			   2)
			      if [ -n "$SDDC_MANAGER" ]; then 
			         publishVECSCACertSDDCManager
			      else
			         echo $'\n'"${YELLOW}Invalid option.${NORMAL}"
			      fi
               ;;			
		   esac
         ;;   
   esac
}

#------------------------------
# Remove CA certificates from VECS
#------------------------------
function removeCACertsVECS() {
   echo $'\n'"${CYAN}To add CA certificates to VECS, publish them to VMware Directory.${NORMAL}"
   read -p $'\nEnter the number(s) of the certificate(s) to delete (multiple entries separated by a comma): ' DELETE_VECS_CA_LIST
   
   if [ -n "$DELETE_VECS_CA_LIST" ]; then
      header 'Removing CA certificates from VECS'
      for index in $(echo "$DELETE_VECS_CA_LIST" | tr -d ' ' | sed 's/,/ /g'); do
         alias=${VECS_CA_CERT_ALIASES[$((index - 1))]}
         task "Backup $alias"
		 BACKUP_ALIAS_FILENAME=$(echo "$alias" | tr '/' '_')
         if $VECS_CLI entry getcert --store TRUSTED_ROOTS --alias $alias > $BACKUP_DIR/$BACKUP_ALIAS_FILENAME.crt 2>/dev/null; then
            statusMessage 'OK' 'GREEN'
         else
            errorMessage "Unable to backup certificate with $alias" 'backup'
         fi
         
         task "Remove $alias"
         $VECS_CLI entry delete --store TRUSTED_ROOTS --alias $alias -y 2>/dev/null|| errorMessage "Unable to delete certificate with Alias $alias"
         statusMessage 'OK' 'GREEN'         
      done      
   fi
}

#------------------------------
# Publish CA certificate(s) from VECS to SDDC Manager
#------------------------------
function publishVECSCACertSDDCManager() {
   read -p $'\n'"Enter the number(s) of the certificate(s) to publish to $SDDC_MANAGER (multiple entries separated by a comma): " PUBLISH_VECS_CA_SDDC_LIST
   
   if [ -n "$PUBLISH_VECS_CA_SDDC_LIST" ]; then
      header 'Publishing CA certificates to SDDC Manager'
	  getSDDCAccessToken
	  for index in $(echo "$PUBLISH_VECS_CA_SDDC_LIST" | tr -d ' ' | sed 's/,/ /g'); do
	     alias=${VECS_CA_CERT_ALIASES[$((index - 1))]}
		 task "Export $alias"
		 $VECS_CLI entry getcert --store TRUSTED_ROOTS --alias $alias > $STAGE_DIR/sddc_$alias.crt 2>/dev/null || errorMessage "Unable to backup certificate with alias $alias" 'backup'
		 statusMessage 'OK' 'GREEN'
		 
		 publishCACertsSDDCManager "$STAGE_DIR/sddc_$alias.crt"
	  done
      echo $'\n'"${YELLOW}Services will need to be restarted on the SDDC Manager"
      echo "by running /opt/vmware/vcf/operationsmanager/scripts/cli/sddcmanager_restart_services.sh${NORMAL}"
   fi
}

#------------------------------
# List CA certificates in VMware Directory
#------------------------------
function listVMDirCACertificates() {
   VMDIR_CERTS=()
   VMDIR_CA_CERT_SKIDS=()
   logInfo 'Listing certificate information for CA certificates in VMware Directory'
   for skid in $($DIR_CLI trustedcert list --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" | grep '^CN' | tr -d '\t' | awk -F':' '{print $2}'); do
      CA_CERT=$($DIR_CLI trustedcert get --id $skid --outcert $STAGE_DIR/$skid.crt --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" --outcert /dev/stdout | grep -v 'Certificate retrieved successfully')      
      VMDIR_CA_CERT_INFO=$(viewBriefCertificateInfo "$CA_CERT" '' "$skid")
      VMDIR_CERTS+=("$VMDIR_CA_CERT_INFO")
      VMDIR_CA_CERT_SKIDS+=($skid)           
   done
   i=0
   while [ $i -lt "${#VMDIR_CERTS[@]}" ]; do
      n=$((i+1))
      printf "%2s. %s\n\n" $n "${VMDIR_CERTS[$i]}"
      logDetails "${VMDIR_CERTS[$i]}"
      logDetails ' '
      ((++i))
   done
}

#------------------------------
# Publish CA certificate(s) to VMware Directory
#------------------------------
function publishCACertsVMDir() {
   read -e -p $'\nEnter path to CA certificate (or chain): ' CA_CERTS_TO_PUBLISH
   i=0
   NON_CA_FOUND=0
   CA_PUBLISHED=0
   UPDATED_EMBEDDED=0
   while [ ! -f $CA_CERTS_TO_PUBLISH ]; do
      if [ $i -lt 3 ]; then
	      read -e -p 'File not found. Enter path to CA certificate (or chain): ' CA_CERTS_TO_PUBLISH
	   else
	      errorMessage "CA Certificate file not found at $CA_CERTS_TO_PUBLISH"
	   fi
   done
   getCorrectCertFormat "$CA_CERTS_TO_PUBLISH" 'CA_CERTS_TO_PUBLISH'
   logInfo "Provided new CA certificates to publish to VMware Directory:"
   logDetails "$(cat $CA_CERTS_TO_PUBLISH)"
   header 'Publish CA Certificate(s)'
   VMDIR_CA_SKIDS=$($DIR_CLI trustedcert list --login $VMDIR_USER --password "$(cat $STAGE_DIR/.vmdir-user-password)" | grep '^CN' | tr -d '\t' | awk -F':' '{print $2}')   
   csplit -s -z -f $STAGE_DIR/ca-to-publish- -b %02d.crt $CA_CERTS_TO_PUBLISH '/-----BEGIN CERTIFICATE-----/' '{*}'
   for cert in $(ls $STAGE_DIR/ca-to-publish-*); do
      if isCertCA "$(cat $cert)"; then
	      CURRENT_SKID=$(openssl x509 -noout -text -in $cert 2>/dev/null | grep -A1 'Subject Key Id' | tail -n1 | tr -d ' ' | sed 's/keyid://' | tr -d ':')
         if echo "$VMDIR_CA_SKIDS" | grep "$CURRENT_SKID" > /dev/null; then
            logInfo "Found CA certificate with Subject Key ID $CURRENT_SKID, unpublishing"
            $DIR_CLI trustedcert get --id $CURRENT_SKID --login $VMDIR_USER --password "$(cat $STAGE_DIR/.vmdir-user-password)" --outcert $STAGE_DIR/signing-ca-old-$CURRENT_SKID.crt 2>&1 | logInfo
            $DIR_CLI trustedcert unpublish --login $VMDIR_USER --password "$(cat $STAGE_DIR/.vmdir-user-password)" --cert $STAGE_DIR/signing-ca-old-$CURRENT_SKID.crt 2>&1 | logInfo
         fi
         logInfo "Publishing CA certificate with Subject Key ID $CURRENT_SKID"
         if $DIR_CLI trustedcert publish --cert $cert --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" 2>&1 | logInfo; then
            checkUpdateEmbeddedCAChain "$cert"
            ((++CA_PUBLISHED))
         fi
      else
         ((++NON_CA_FOUND))
      fi 
	done	
	
   echo "Published ${GREEN}${CA_PUBLISHED}${NORMAL} certificates to VMware Directory"
   statusMessage 'OK' 'GREEN'
	
   if [ $NON_CA_FOUND -gt 0 ]; then
	   echo $'\n'"Found ${YELLOW}${NON_CA_FOUND}${NORMAL} non-CA certificates in the provided file."
		echo 'These certificates were not published to VMware Directory.'
   fi

   if [ $CA_PUBLISHED -gt 0 ]; then
      task 'Refreshing CA certificates to VECS'
      $VECS_CLI force-refresh 2>/dev/null || errorMessage 'Unable to perform a force-refresh of CA certificates to VECS'
      statusMessage 'OK' 'GREEN'
   fi
   
   if [ $UPDATED_EMBEDDED -gt 0 ]; then
      echo $'\n'"${YELLOW}Certificate(s) with an embedded CA chain have been updated.${NORMAL}"
      promptRestartVMwareServices
   fi
   
   rm $STAGE_DIR/ca-to-publish-*
}

#------------------------------
# Check if we need to update CA cert in embedded chain
#------------------------------
function checkUpdateEmbeddedCAChain() {
   CURRENT_SKID=$(cat "$1" | openssl x509 -noout -text 2>/dev/null | grep -A1 'Subject Key Id' | tail -n1)
   
   MACHINE_SSL_CERT=$($VECS_CLI entry getcert --store MACHINE_SSL_CERT --alias __MACHINE_CERT)
   if [ $(echo "$MACHINE_SSL_CERT" | grep 'BEGIN CERTIFICATE' | wc -l) -gt 1 ]; then
      if echo "$MACHINE_SSL_CERT" | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null | openssl pkcs7 -print_certs -noout -text 2>/dev/null | grep "$CURRENT_SKID" > /dev/null; then
         updateEmbeddedCACertVECS "$CURRENT_SKID" "$1" 'MACHINE_SSL_CERT' '__MACHINE_CERT'
      fi
   fi
   
   for soluser in "${SOLUTION_USERS[@]}"; do
      SOLUTION_USER_CERT=$($VECS_CLI entry getcert --store $soluser --alias $soluser)
	  if [ $(echo "$SOLUTION_USER_CERT" | grep 'BEGIN CERTIFICATE' | wc -l) -gt 1 ]; then
	     if echo "$SOLUTION_USER_CERT" | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null | openssl pkcs7 -print_certs -noout -text 2>/dev/null | grep "$CURRENT_SKID" > /dev/null; then
            updateEmbeddedCACertVECS "$CURRENT_SKID" "$1" "$soluser" "$soluser"
         fi
	  fi
   done
   
   AUTH_PROXY_CERT='/var/lib/vmware/vmcam/ssl/rui.crt'
   if [ $(cat "$AUTH_PROXY_CERT" | grep 'BEGIN CERTIFICATE' | wc -l) -gt 1 ]; then
      if cat "$AUTH_PROXY_CERT" | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null | openssl pkcs7 -print_certs -noout -text 2>/dev/null | grep "$CURRENT_SKID" > /dev/null; then
         updateEmbeddedCACertFile "$CURRENT_SKID" "$1" "$AUTH_PROXY_CERT" 'Auth Proxy Cert'
      fi
   fi
   
   AUTO_DEPLOY_CA_CERT='/etc/vmware-rbd/ssl/rbd-ca.crt'
   if [ $(cat "$AUTO_DEPLOY_CA_CERT" | grep 'BEGIN CERTIFICATE' | wc -l) -gt 1 ]; then
      if cat "$AUTH_PROXY_CERT" | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null | openssl pkcs7 -print_certs -noout -text 2>/dev/null | grep "$CURRENT_SKID" > /dev/null; then
         updateEmbeddedCACertFile "$CURRENT_SKID" "$1" "$AUTO_DEPLOY_CA_CERT" 'Auto Deploy CA Cert'
      fi
   fi
   
   if [ $(cat "$VMCA_CERT" | grep 'BEGIN CERTIFICATE' | wc -l) -gt 1 ]; then
      if cat "$VMCA_CERT" | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null | openssl pkcs7 -print_certs -noout -text 2>/dev/null | grep "$CURRENT_SKID" > /dev/null; then
         updateEmbeddedCACertFile "$CURRENT_SKID" "$1" "$VMCA_CERT" 'VMCA Cert'
      fi
   fi
   
   if [[ "$VC_VERSION" =~ ^6 ]]; then
      VMDIR_CERT='/usr/lib/vmware-vmdir/share/config/vmdircert.pem'
      if [ $(cat "$VMDIR_CERT" | grep 'BEGIN CERTIFICATE' | wc -l) -gt 1 ]; then
         if cat "$VMDIR_CERT" | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null | openssl pkcs7 -print_certs -noout -text 2>/dev/null | grep "$CURRENT_SKID" > /dev/null; then
            updateEmbeddedCACertFile "$CURRENT_SKID" "$1" "$VMDIR_CERT" 'VMDir Cert'
         fi
      fi
   fi
}

#------------------------------
# Update CA cert in embedded chain in VECS
#------------------------------
function updateEmbeddedCACertVECS() {
   NEW_CA_SERIAL=$(openssl x509 -noout -serial -in $2 2>/dev/null)
   NEW_CA_SUBJECT=$(openssl x509 -noout -subject -in $2 2>/dev/null)
   NEEDS_UPDATING=0
   logInfo "Splitting certs from alias $4 in store $3"
   $VECS_CLI entry getcert --store "$3" --alias "$4" | csplit -s -z -f $STAGE/update-embedded-ca- -b %02d.crt /dev/stdin '/-----BEGIN CERTIFICATE-----/' '{*}'
   
   for cert in $(ls -d $STAGE/update-embedded-ca-*.crt); do
      CURRENT_CERT_SERIAL=$(openssl x509 -noout -serial -in $cert 2>/dev/null)      
      if openssl x509 -noout -text -in $cert 2>/dev/null | grep -A1 'Subject Key Id' | tail -n1 | grep "$1" > /dev/null; then
         if [ "$NEW_CA_SERIAL" != "$CURRENT_CERT_SERIAL" ]; then
            NEEDS_UPDATING=1
            logInfo "Checking new CA cert ($2) against embedded CA file ($cert)"
            logInfo "Updating CA cert $NEW_CA_SUBJECT in alias $4, store $3"
            logInfo "Checking $NEW_CA_SUBJECT checksum ($NEW_CA_SERIAL) against embedded CA checksum ($CURRENT_CERT_SERIAL)"
         fi
         cat $2 >> $STAGE/update-embedded-cert.pem		 
      else
         cat $cert >> $STAGE/update-embedded-cert.pem
      fi
   done
   
   if [ $NEEDS_UPDATING -gt 0 ]; then
      task 'Updating embedded CA cert in VECS'
      $VECS_CLI entry getkey --store "$3" --alias "$4" > $STAGE/update-embedded-key.key 2>/dev/null || errorMessage "Unable to export key from store $3, alias $4"
      $VECS_CLI entry delete --store "$3" --alias "$4" -y 2>/dev/null || errorMessage "Unable to delete alias $4 from store $3"
      $VECS_CLI entry create --store "$3" --alias "$4" --cert $STAGE/update-embedded-cert.pem --key $STAGE/update-embedded-key.key 2>/dev/null || errorMessage "Unable to create alias $4 in store $3"
      statusMessage 'OK' 'GREEN'
      UPDATED_EMBEDDED=1
   fi
   
   rm $STAGE/update-embedded-* 2>&1 | logDebug
}

#------------------------------
# Update CA cert in embedded chain in a file
#------------------------------
function updateEmbeddedCACertFile() {
   NEW_CA_SERIAL=$(openssl x509 -noout -serial -in $2 2>/dev/null)
   NEW_CA_SUBJECT=$(openssl x509 -noout -subject -in $2 2>/dev/null)
   NEEDS_UPDATING=0
   csplit -s -z -f $STAGE/update-embedded-ca- -b %02d.crt $3 '/-----BEGIN CERTIFICATE-----/' '{*}'
   
   for cert in $(ls -d $STAGE/update-embedded-ca-*.crt); do
      if openssl x509 -noout -text -in $cert 2>/dev/null | grep -A1 'Subject Key Id' | tail -n1 | grep "$1" > /dev/null; then
	     CURRENT_CERT_SERIAL=$(openssl x509 -noout -serial -in $cert 2>/dev/null)      
		 if [ "$NEW_CA_SERIAL" != "$CURRENT_CERT_SERIAL" ]; then
		    NEEDS_UPDATING=1					 
		 fi
		 cat $2 >> $STAGE/update-embedded-cert.pem
		 logInfo "Updating CA cert $NEW_CA_SUBJECT in $3"
	  else
	     cat $cert >> $STAGE/update-embedded-cert.pem
	  fi
   done
   
   if [ $NEEDS_UPDATING -gt 0 ]; then
      task "Updating embedded CA cert in $4"
      cp $3 $BACKUP_DIR/$(basename $3) 2>/dev/null || errorMessage "Unable to backup $3"
      cp $STAGE/update-embedded-cert.pem $3 2>/dev/null || errorMessage "Unable to copy new certificate to $3"
      statusMessage 'OK' 'GREEN'
      UPDATED_EMBEDDED=1
   fi
   
   rm $STAGE/update-embedded-*
}

#------------------------------
# List CA certificates in VECS
#------------------------------
function listVECSCACertificates() {
   VECS_CERTS=()
   VECS_CA_CERT_ALIASES=()   
   for alias in $($VECS_CLI entry list --store TRUSTED_ROOTS | grep '^Alias' | awk -F"[[:space:]]:[[:space:]]" '{print $NF}'); do
      CA_CERT=$($VECS_CLI entry getcert --store TRUSTED_ROOTS --alias $alias 2>/dev/null)
      VECS_CA_CERT_INFO=$(viewBriefCertificateInfo "$CA_CERT" "$alias")
      VECS_CERTS+=("$VECS_CA_CERT_INFO")
      VECS_CA_CERT_ALIASES+=($alias)
   done
   i=0
   while [ $i -lt "${#VECS_CERTS[@]}" ]; do
      n=$((i+1))
      printf "%2s. %s\n\n" $n "${VECS_CERTS[$i]}"
      ((++i))
   done
}

#------------------------------
# View VMDir CA certificate info
#------------------------------
function viewVMDirCACertificate() {
   skid=${VMDIR_CA_CERT_SKIDS[$(($1- 1))]}
   CERT=$($DIR_CLI trustedcert get --id $skid --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" --outcert /dev/stdout | grep -v 'Certificate retrieved successfully')
   if [ -n "$CERT" ]; then
      viewCertificateInfo "$CERT" 'view-path'
   else
      echo $'\n'"${YELLOW}Unable to view the CA certificate with Subject Key ID $skid.${NORMAL}"
   fi
}

#------------------------------
# View VECS CA certificate info
#------------------------------
function viewVECSCACertificate() {
   alias=${VECS_CA_CERT_ALIASES[$(($1 - 1))]}
   viewVECSCertificateInfo 'TRUSTED_ROOTS' "$alias"
}

#------------------------------
# Build certificate from hash
#------------------------------
function buildCertFromHash() {
   if [[ "$1" =~ ^MII ]]; then
      hash=$(echo "$1" | fold -c64)
   elif [[ "$1" =~ ^LS0 ]]; then
      echo "$hash" | base64 -d
      return 0
   else
      hash=$(echo $1 | base64 -d | tr -d '\r\n')
   fi
   
   TEMP_CERT=$'-----BEGIN CERTIFICATE-----\n'
   TEMP_CERT+=$hash
   TEMP_CERT+=$'\n-----END CERTIFICATE-----'
   echo "$TEMP_CERT"
}

#------------------------------
# View certificate info
#------------------------------
function viewCertificateInfo() {
   header 'Certificate Information'
   CERT_INFO=$(echo "$1" | openssl x509 -text -noout -fingerprint -sha1 2>/dev/null)
   logDetails "$CERT_INFO"
   echo "$CERT_INFO"
   if [ -n "$2" ] && [ "$2" == 'view-path' ]; then printCertificationPath "$1"; fi
}

#------------------------------
# Print certification path info
#------------------------------
function printCertificationPath() {
   header 'Certificaton Path'
   CERT_IDS=()
   VMDIR_CA_SKIDS=$($DIR_CLI trustedcert list --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" | grep '^CN' | tr -d '\t' | awk -F':' '{print $2}' 2>&1)
   for skid in $($DIR_CLI trustedcert list --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" | grep '^CN' | tr -d '\t' | awk -F':' '{print $2}' 2>&1); do
      logDebug "Exporting CA certificate with Subject Key ID $skid"
      $DIR_CLI trustedcert get --id $skid --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" --outcert $STAGE_DIR/vmdir-ca-$skid.crt 2>&1 | logDebug
   done
   
   CHAIN_COMPLETE=1
   
   CURRENT_SUBJECT=$(echo "$1" | openssl x509 -noout -text 2>/dev/null | grep 'Subject:' | sed -e 's/[[:space:]]*//' -e 's/Subject: //')
   CURRENT_ISSUER=$(echo "$1" | openssl x509 -noout -text 2>/dev/null | grep 'Issuer:' | sed -e 's/[[:space:]]*//' -e 's/Issuer: //')
   CURRENT_CERT_ID=$(certificationPathCertIdentifier "$CURRENT_SUBJECT")
   NEXT_CERT_ID=$(certificationPathCertIdentifier "$CURRENT_ISSUER")
   CURRENT_AKID=$(echo "$1" | openssl x509 -noout -text 2>/dev/null | grep -A1 'Authority Key Id' | tail -n1 | tr -d ' ' | sed 's/keyid://' | tr -d ':')
   CERT_IDS+=("$CURRENT_CERT_ID")
   if [ "$CURRENT_SUBJECT" != "$CURRENT_ISSUER" ]; then 
      CERT_IDS+=("$NEXT_CERT_ID")
      CHAIN_COMPLETE=0
   fi
   
   while true; do
      CURRENT_CA_CERT="$STAGE_DIR/vmdir-ca-$CURRENT_AKID.crt"
      if [ -f $CURRENT_CA_CERT ]; then	  
         CURRENT_SUBJECT=$(openssl x509 -noout -text -in $CURRENT_CA_CERT 2>/dev/null | grep 'Subject:' | sed -e 's/[[:space:]]*//' -e 's/Subject: //')
         CURRENT_ISSUER=$(openssl x509 -noout -text -in $CURRENT_CA_CERT 2>/dev/null | grep 'Issuer:' | sed -e 's/[[:space:]]*//' -e 's/Issuer: //')
         if [ "$CURRENT_SUBJECT" == "$CURRENT_ISSUER" ]; then
            CHAIN_COMPLETE=1
            break			
         else		    
            CURRENT_AKID=$(openssl x509 -noout -text -in $CURRENT_CA_CERT 2>/dev/null | grep -A1 'Authority Key Id' | tail -n1 | tr -d ' ' | sed 's/keyid://' | tr -d ':')
         fi
         NEXT_CERT_ID=$(certificationPathCertIdentifier "$CURRENT_ISSUER")
         CERT_IDS+=("$NEXT_CERT_ID")		 
      else
         break
      fi
   done
   i=$((${#CERT_IDS[@]} - 1))
   p=0
   CERTIFICATION_PATH=''
   while [ $i -ge 0 ]; do
      if [ $p -gt 0 ]; then
         b=$((p-1))
         s=$(( (p*2)+(b*2) ))
         for (( c=1; c<=$s; c++)); do CERTIFICATION_PATH+=' '; done
         CERTIFICATION_PATH+=$'|_'
      fi
      if [ $p -eq 0 ] && [ $CHAIN_COMPLETE -eq 0 ]; then
         CERTIFICATION_PATH+="[ ${RED}!${NORMAL} ] ${CERT_IDS[$i]}"$'\n'
      else
         CERTIFICATION_PATH+="[ ${GREEN}+${NORMAL} ] ${CERT_IDS[$i]}"$'\n'
      fi
      ((--i))
      ((++p))
   done
   echo "$CERTIFICATION_PATH"
   logDetails "$CERTIFICATION_PATH"
   /usr/bin/rm $STAGE_DIR/vmdir-ca-*.crt 2>&1 | logDebug
}

#------------------------------
# Print certification path info for missing CAs
#------------------------------
function printCertificationPathMissingCA() {
   logInfo 'Printing Certification Path of Missing CA certificates'
   CERT_IDS=()
   CERT_SUBJECTS=()
   CURRENT_SUBJECT=$(openssl x509 -noout -text -in "$1" 2>/dev/null | grep 'Subject:' | sed -e 's/[[:space:]]*//' -e 's/Subject: //')
   CURRENT_ISSUER=$(openssl x509 -noout -text -in "$1" 2>/dev/null | grep 'Issuer:' | sed -e 's/[[:space:]]*//' -e 's/Issuer: //')
   CURRENT_AKID=$(openssl x509 -noout -text -in "$1" 2>/dev/null | grep -A1 'Authority Key Id' | tail -n1 | tr -d ' ' | sed 's/keyid://' | tr -d ':')
   CURRENT_CERT_ID=$(certificationPathCertIdentifier "$CURRENT_SUBJECT")
   csplit -s -z -f $STAGE_DIR/validate-root-chain-tmp- -b %02d.crt $2 '/-----BEGIN CERTIFICATE-----/' '{*}' 2>&1 | logDebug
   for ca in $(ls $STAGE_DIR/validate-root-chain-tmp-*); do
      CURRENT_SKID=$(openssl x509 -noout -text -in $ca | grep -A1 'Subject Key Id' | tail -n1 | tr -d ': ')
      mv $ca $STAGE_DIR/validate-root-chain-ca-$CURRENT_SKID.crt
   done
   CERT_IDS+=("$CURRENT_CERT_ID")
   CERT_SUBJECTS+=("$CURRENT_SUBJECT")
   
   while true; do
      CURRENT_CA_CERT="$STAGE_DIR/validate-root-chain-ca-$CURRENT_AKID.crt"
      if [ -f "$CURRENT_CA_CERT" ]; then
         CURRENT_SUBJECT=$(openssl x509 -noout -text -in $CURRENT_CA_CERT 2>/dev/null | grep 'Subject:' | sed -e 's/[[:space:]]*//' -e 's/Subject: //')
         CURRENT_ISSUER=$(openssl x509 -noout -text -in $CURRENT_CA_CERT 2>/dev/null | grep 'Issuer:' | sed -e 's/[[:space:]]*//' -e 's/Issuer: //')
         CURRENT_AKID=$(openssl x509 -noout -text -in $CURRENT_CA_CERT 2>/dev/null | grep -A1 'Authority Key Id' | tail -n1 | tr -d ' ' | sed 's/keyid://' | tr -d ':')
         CURRENT_CERT_ID=$(certificationPathCertIdentifier "$CURRENT_SUBJECT")
         CERT_IDS+=("$CURRENT_CERT_ID")
         CERT_SUBJECTS+=("$CURRENT_SUBJECT")
      else
         CURRENT_CERT_ID=$(certificationPathCertIdentifier "$CURRENT_ISSUER")
         CERT_IDS+=("$CURRENT_CERT_ID")
         CERT_SUBJECTS+=("$CURRENT_ISSUER")		   
         break
      fi
   done
   
   i=$((${#CERT_IDS[@]} - 1))
   last_index=$i
   p=0
   CERTIFICATION_PATH=''
   while [ $i -ge 0 ]; do
      if [ $p -gt 0 ]; then
         b=$((p-1))
         s=$(( (p*2)+(b*2) ))
         for (( c=1; c<=$s; c++)); do CERTIFICATION_PATH+=' '; done
         CERTIFICATION_PATH+=$'|_'
      fi
      if [ $p -eq 0 ]; then
         CERTIFICATION_PATH+="[ ! ] ${CERT_IDS[$i]}"
      else
         CERTIFICATION_PATH+="[ + ] ${CERT_IDS[$i]}"
      fi	  
      ((--i))
      ((++p))
   done
   CERTIFICATION_PATH+=$'\nPlease ensure that the following certificate (and its issuers, if any) are included in the signing CA chain:'
   CERTIFICATION_PATH+="   Subject: ${CERT_SUBJECTS[$last_index]}"
   echo "$CERTIFICATION_PATH"
   logDetails "$CERTIFICATION_PATH"
   /usr/bin/rm $STAGE_DIR/validate-root-chain-ca-* 2>&1 | logDebug
}

#------------------------------
# Get Certificate Identifier from Subject string
#------------------------------
function certificationPathCertIdentifier() {
   CERT_CN=$(echo "$1" | sed 's/, /\n/g' | grep 'CN=' | awk -F'=' '{print $NF}')
   if [ -z "$CERT_CN" ]; then
      CERT_LAST_OU=$(echo "$1" | sed 's/, /\n/g' | grep 'OU=' | tail -n1 | awk -F'=' '{print $NF}')
	  if [ -z "$CERT_LAST_OU" ]; then
	     CERT_LAST_O=$(echo "$1" | sed 's/, /\n/g' | grep 'O=' | tail -n1 | awk -F'=' '{print $NF}')
		 if [ -z "$CERT_LAST_O" ]; then
		    echo "<unknown>"
		 else
		    echo "$CERT_LAST_O"
		 fi
	  else
	     echo "$CERT_LAST_OU"
	  fi
   else
      echo "$CERT_CN"
   fi
}

#------------------------------
# View brief certificate info
#------------------------------
function viewBriefCertificateInfo() {
   CERT_SUBJECT=$(echo "$1" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject= //')
   CERT_ISSUER=$(echo "$1" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer= //')
   CERT_ENDDATE=$(echo "$1" | openssl x509 -noout -enddate 2>/dev/null | awk -F'=' '{print $NF}')
   CERT_SKID=$(echo "$1" | openssl x509 -noout -text 2>/dev/null | grep -A1 'Subject Key' | tail -n1 | tr -d '[:space:]')
   
   if [ -z "$CERT_SKID" ] && [ -n "$3" ]; then
      CERT_SKID="$3 (computed)"
   fi
   if ! echo "$1" | openssl x509 -noout -subject -serial 2>/dev/null > /dev/null; then
      CERT_INFO="${YELLOW}Invalid format, certificate cannot be parsed!${NORMAL}"
      CERT_INFO+=$'\n'"    Subject Key ID: $CERT_SKID"
   else
      if isCertCA "$1"; then
         CERT_CA='Yes'
      else
         CERT_CA='No'
      fi
      if [ -n "$2" ]; then
         CERT_INFO="Alias: $2"
         CERT_INFO+=$'\n'"    Subject: $CERT_SUBJECT"
      else
         CERT_INFO="Subject: $CERT_SUBJECT"
      fi      
      CERT_INFO+=$'\n'"    Issuer: $CERT_ISSUER"
      CERT_INFO+=$'\n'"    End Date: $CERT_ENDDATE"
      CERT_INFO+=$'\n'"    Subject Key ID: $CERT_SKID"
      CERT_INFO+=$'\n'"    Is CA Cert: $CERT_CA"
   fi
   echo "$CERT_INFO"
}

#------------------------------
# View CRL info
#------------------------------
function viewCRLInfo() {
   echo "$1" | openssl crl -text -noout 2>&1 | logDebug
}

#------------------------------
# View vCenter Extension thumbprints
#------------------------------
function manageVCExtensionThumbprints() {
   header "$1 vCenter Extension Thumbprints"
   if [ "$NODE_TYPE" != 'infrastructure' ] && ! checkService 'vmware-vpostgres'; then
      echo "${YELLOW}The vPostgres service is stopped!"
      echo "Please ensure this service is running before updating vCenter extension thumbprints."
      echo "Hint: Check the number of CRL entries in VECS${NORMAL}"
      return 1 
   fi
   VC_EXT_THUMBPRINT_MISMATCH=0
   VPXD_EXT_THUMBPRINT=$($VECS_CLI entry getcert --store vpxd-extension --alias vpxd-extension 2>/dev/null | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
   MACHINE_SSL_THUMBPRINT=$($VECS_CLI entry getcert --store MACHINE_SSL_CERT --alias __MACHINE_CERT 2>/dev/null | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
   VMCAM_THUMBPRINT=$(openssl x509 -noout -fingerprint -sha1 -in /var/lib/vmware/vmcam/ssl/vmcamcert.pem 2>/dev/null | awk -F'=' '{print $NF}')
   VCENTER_EXTENSIONS="'com.vmware.vsan.health','com.vmware.vcIntegrity','com.vmware.rbd','com.vmware.imagebuilder','com.vmware.vmcam','com.vmware.vim.eam'"
   if [[ "$VC_VERSION" =~ ^8 ]]; then
      if [ $VC_BUILD -ge 22385739 ]; then
         VCENTER_EXTENSIONS="'com.vmware.vsan.health','com.vmware.vcIntegrity','com.vmware.imagebuilder','com.vmware.vmcam','com.vmware.vim.eam'"
      fi
      VCENTER_EXTENSIONS+=",'com.vmware.vlcm.client'"
   fi
   
   IFS=$'\n'

   for record in $($PSQL -d VCDB -U postgres -c "SELECT ext_id,thumbprint FROM vpx_ext WHERE ext_id IN ($VCENTER_EXTENSIONS) ORDER BY ext_id" -t); do
      extension=$(echo $record | awk -F'|' '{print $1}' | tr -d ' ')
      thumbprint=$(echo $record | awk -F'|' '{print $NF}' | tr -d ' ')
      
      case $extension in
         'com.vmware.vmcam')
            COMPARE_TO=$VMCAM_THUMBPRINT
            EXPECTED_CERT='Authentication Proxy'
         ;;
         
         'com.vmware.vsan.health')
            COMPARE_TO=$MACHINE_SSL_THUMBPRINT
            EXPECTED_CERT='Machine SSL'
         ;;
         
         *)
            COMPARE_TO=$VPXD_EXT_THUMBPRINT
            EXPECTED_CERT='vpxd-extension'
         ;;
      esac
      
      case $1 in
         'Checking'|'Check')
            task "$extension ($EXPECTED_CERT)"
            logInfo "Comparing $extension thumbprint of '$thumbprint' to '$COMPARE_TO'"
            if [ "$thumbprint" = "$COMPARE_TO" ]; then
               statusMessage 'MATCHES' 'GREEN'
            else
               VC_EXT_THUMBPRINT_MISMATCH=1
               statusMessage 'MISMATCH' 'YELLOW'
            fi            
         ;;
         
         'View')
            echo "$extension ($EXPECTED_CERT)"
            echo "   $thumbprint"
         ;;
         
         'Update')
            task "$extension ($EXPECTED_CERT)"
            logInfo "Comparing $extension thumbprint of '$thumbprint' to '$COMPARE_TO'"
            if [ "$thumbprint" = "$COMPARE_TO" ]; then
               statusMessage 'MATCHES' 'GREEN'
            else
               $PSQL -d VCDB -U postgres -c "UPDATE vpx_ext SET thumbprint = '$COMPARE_TO' WHERE ext_id = '$extension'" > /dev/null 2>&1 || errorMessage "Unable to update $extension extension thumbprint in VCDB"
               statusMessage 'UPDATED' 'GREEN'
            fi
         ;;
      
      esac
   done
   IFS=$' \t\n'
   if [ "$1" == 'Check' ] && [ "$VC_EXT_THUMBPRINT_MISMATCH" == '1' ]; then 
      unset UPDATE_THUMBPRINTS_INPUT
      echo $'\n'"${YELLOW}------------------------!!! Attention !!!------------------------"
      echo "Mismatched thumbprints detected.${NORMAL}"
      read -p $'\nUpdate extension thumbprints? [n]: ' UPDATE_THUMBPRINTS_INPUT
      
      if [ -z $UPDATE_THUMBPRINTS_INPUT ]; then UPDATE_THUMBPRINTS_INPUT='n'; fi
      
      if [[ "$UPDATE_THUMBPRINTS_INPUT" =~ ^[Yy] ]]; then manageVCExtensionThumbprints 'Update'; fi
   fi
}

#------------------------------
# View VMCA configuration options in VCDB
#------------------------------
function checkVMCADatabaseConfig() {
   VMCA_CONFIG_OUTPUT=''
   header 'Checking VMCA Configurations in VCDB'
   if [ "$NODE_TYPE" != 'infrastructure' ] && ! checkService 'vmware-vpostgres'; then
      task 'Connect to vPostgres database'
	   statusMessage 'ERROR' 'YELLOW'	  
   else
      VMCA_CONFIGS=$($PSQL -d VCDB -U postgres -c "SELECT name,value FROM vpx_parameter WHERE name='vpxd.certmgmt.mode' OR name LIKE 'vpxd.certmgmt.certs.cn.%'" -t)
	   logDetails "$VMCA_CONFIGS"
	   IFS=$'\n'
	   for line in $VMCA_CONFIGS; do
	      config=$(echo $line | awk -F'|' '{print $1}' | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
		   value=$(echo $line | awk -F'|' '{print $NF}' | sed -e 's/^[[:space:]]*//')
		   if [ -z $value ]; then
		      value="${YELLOW}EMPTY${NORMAL}"
			   CERT_STATUS_VMCA_EMPTY_CONFIG=1
		   else
		      if [ "$config" = 'vpxd.certmgmt.mode' ] && [ "$value" = 'thumbprint' ]; then
			      value="${YELLOW}'${value}'${NORMAL}"
			      CERT_STATUS_VMCA_MODE=1
			   else
		         value="${GREEN}'${value}'${NORMAL}"
			   fi
		   fi
         VMCA_CONFIG_OUTPUT+=$'\n'"$config: $value"
      done
      echo "$VMCA_CONFIG_OUTPUT" | column -t -s ':'
      IFS=$' \t\n'
   fi
}

#------------------------------
# Generate configuration file for certool utility
#------------------------------
function generateCertoolConfig() {
   if [[ " ${SOLUTION_USERS[*]} " =~ " $1 " ]]; then
      task "$1"
   else
      task 'Generate certool configuration'
   fi
   case $1 in
      'auth proxy')
         echo "Country = $CSR_COUNTRY" > $STAGE_DIR/auth-proxy.cfg
         echo "Organization = $CSR_ORG" >> $STAGE_DIR/auth-proxy.cfg
         echo "OrgUnit = $CSR_ORG_UNIT" >> $STAGE_DIR/auth-proxy.cfg
         echo "Name = $HOSTNAME" >> $STAGE_DIR/auth-proxy.cfg
         echo "Hostname = $HOSTNAME" >> $STAGE_DIR/auth-proxy.cfg
      ;;
      
      'vmdir')
         echo "Country = $CSR_COUNTRY" > $STAGE_DIR/vmdir.cfg
         echo "Name = $HOSTNAME" >> $STAGE_DIR/vmdir.cfg
         echo "Hostname = $HOSTNAME" >> $STAGE_DIR/vmdir.cfg
      ;;
      
      'sts')
         echo 'Name = ssoserverSign' > $STAGE_DIR/sso-sts.cfg
         echo "Hostname = $HOSTNAME" >> $STAGE_DIR/sso-sts.cfg         
      ;;
      
      *)
         echo "Country = $CSR_COUNTRY" > $STAGE_DIR/$1.cfg
         echo "Name = $2" >> $STAGE_DIR/$1.cfg
         echo "Organization = $CSR_ORG" >> $STAGE_DIR/$1.cfg
         echo "OrgUnit = $CSR_ORG_UNIT" >> $STAGE_DIR/$1.cfg
         echo "State = $CSR_STATE" >> $STAGE_DIR/$1.cfg
         echo "Locality = $CSR_LOCALITY" >> $STAGE_DIR/$1.cfg
   
         if [ "$2" == $IP ]; then
            echo "IPAddress = $2" >> $STAGE_DIR/$1.cfg
         elif [ -n "$CSR_IP" ]; then 
            echo "IPAddress = $CSR_IP" >> $STAGE_DIR/$1.cfg
         fi
   
         if [ -n "$CSR_EMAIL" ]; then echo "Email = $CSR_EMAIL" >> $STAGE_DIR/$1.cfg; fi
   
         printf "Hostname = $HOSTNAME" >> $STAGE_DIR/$1.cfg
   
         if [ "$HOSTNAME_LC" != "$PNID_LC" ] && [ "$IP" != "$PNID" ]; then
            printf ",$PNID" >> $STAGE_DIR/$1.cfg
         fi
   
         if [ -n "$CSR_ADDITIONAL_DNS" ]; then
		    CSR_ADDITIONAL_DNS=$(echo "$CSR_ADDITIONAL_DNS" | tr -d ' ')
            printf ",$CSR_ADDITIONAL_DNS" >> $STAGE_DIR/$1.cfg
         fi
      ;;
   esac
   statusMessage 'OK' 'GREEN'
}

#------------------------------
# Generate a VMCA-signed certificate
#------------------------------
function regenerateVMCASignedCertificate() {
   $CERTOOL --genkey --privkey=$STAGE_DIR/$1.key --pubkey=$STAGE_DIR/$1.pub --server=$PSC_LOCATION > /dev/null 2>&1 || errorMessage "Unable to genereate new keys for $1"
   $CERTOOL --gencert --privkey=$STAGE_DIR/$1.key --cert=$STAGE_DIR/$1.crt --config=$STAGE_DIR/$1.cfg --server=$PSC_LOCATION > /dev/null 2>&1 || errorMessage "Unable to generate self-signed certificate for $1"
}

#------------------------------
# Generate a certificate Signing Request
#------------------------------
function generateCSR() {
   openssl req -new -newkey rsa:2048 -nodes -out $1 -keyout $2 -config $3 > /dev/null 2>&1 || errorMessage "Unable to generate Certificate Signing Request and Private Key"
   return 0
}

#------------------------------
# Reset Certificate Signing Request fields
#------------------------------
function clearCSRInfo() {
   logInfo 'Clearing CSR fields'
   CSR_COUNTRY=''
   CSR_ORG=''
   CSR_ORG_UNIT=''
   CSR_STATE=''
   CSR_LOCALITY=''
   CSR_IP=''
   CSR_EMAIL=''
   CSR_ADDITIONAL_DNS=''
}

#------------------------------
# Collect information for a Certificate Signing Request
#------------------------------
function getCSRInfo() {
   unset CSR_COUNTRY_INPUT
   unset CSR_ORG_INPUT
   unset CSR_ORG_UNIT_INPUT
   unset CSR_STATE_INPUT
   unset CSR_LOCALITY_INPUT
   unset CSR_IP_INPUT
   unset CSR_EMAIL_INPUT
   unset CSR_SAN_INPUT
   if [ -z "$1" ]; then
      header 'Certificate Signing Request Information'
   else
      header "Certificate Signing Request Information [$1]"
   fi
   read -p "Enter the country code [$CSR_COUNTRY_DEFAULT]: " CSR_COUNTRY_INPUT
   
   if [ -z "$CSR_COUNTRY_INPUT" ]; then 
      CSR_COUNTRY=$CSR_COUNTRY_DEFAULT
   else
      while [ "${#CSR_COUNTRY_INPUT}" != 2 ]; do read -p "Please enter the two-character country code [$CSR_COUNTRY_DEFAULT]: " CSR_COUNTRY_INPUT; done
      CSR_COUNTRY=$CSR_COUNTRY_INPUT
	   CSR_COUNTRY_DEFAULT=$CSR_COUNTRY_INPUT
   fi

   if [ -n "$1" ] && [ "$1" == 'VMCA' ]; then
      CSR_ORG_DEFAULT_OPTION="$VMDIR_FQDN"
   else
      CSR_ORG_DEFAULT_OPTION="$CSR_ORG_DEFAULT"
   fi

   read -p "Enter the Organization name [$CSR_ORG_DEFAULT_OPTION]: " CSR_ORG_INPUT
   
   if [ -z "$CSR_ORG_INPUT" ]; then
      CSR_ORG="$CSR_ORG_DEFAULT_OPTION"
   else
      CSR_ORG="$CSR_ORG_INPUT"
	   CSR_ORG_DEFAULT="$CSR_ORG_INPUT"
   fi

   read -p "Enter the Organizational Unit name [$CSR_ORG_UNIT_DEFAULT]: " CSR_ORG_UNIT_INPUT
   
   if [ -z "$CSR_ORG_UNIT_INPUT" ]; then
      CSR_ORG_UNIT="$CSR_ORG_UNIT_DEFAULT"
   else
      CSR_ORG_UNIT="$CSR_ORG_UNIT_INPUT"
	   CSR_ORG_UNIT_DEFAULT="$CSR_ORG_UNIT_INPUT"
   fi

   read -p "Enter the state [$CSR_STATE_DEFAULT]: " CSR_STATE_INPUT
   
   if [ -z "$CSR_STATE_INPUT" ]; then
      CSR_STATE="$CSR_STATE_DEFAULT"
   else
      CSR_STATE="$CSR_STATE_INPUT"
	   CSR_STATE_DEFAULT="$CSR_STATE_INPUT"
   fi

   read -p "Enter the locality (city) name [$CSR_LOCALITY_DEFAULT]: " CSR_LOCALITY_INPUT
   
   if [ -z "$CSR_LOCALITY_INPUT" ]; then
      CSR_LOCALITY="$CSR_LOCALITY_DEFAULT"
   else
      CSR_LOCALITY="$CSR_LOCALITY_INPUT"
	   CSR_LOCALITY_DEFAULT="$CSR_LOCALITY_INPUT"
   fi

   read -p 'Enter the IP address (optional): ' CSR_IP_INPUT

   if [ -n "$CSR_IP_INPUT" ]; then 
      while ! validateIp $CSR_IP_INPUT; do echo "${YELLOW}Invalid IP address, enter valid IP address: " CSR_IP_INPUT; done
      CSR_IP=$CSR_IP_INPUT
   fi

   read -p 'Enter an email address (optional): ' CSR_EMAIL_INPUT
   
   if [ -n "$CSR_EMAIL_INPUT" ]; then CSR_EMAIL=$CSR_EMAIL_INPUT; fi
   
   if [ -n "$1" ]; then
      read -p 'Enter any additional hostnames for SAN entries (comma separated value): ' CSR_SAN_INPUT
   
      if [ -n "$CSR_SAN_INPUT" ]; then CSR_ADDITIONAL_DNS=$CSR_SAN_INPUT; fi      
   fi
}

#------------------------------
# Define the SAN entries for creating an openssl configuration file
#------------------------------
function defineSANEntries() {
   unset ADDITIONAL_SAN_ITEMS
   unset INCLUDE_SHORTNAME_INPUT
   if [ "$1" == 'ESXi' ]; then
      DEFAULT_SANS=("$3")
      if ! echo "$3" | awk -F '.' '{print $1}' | grep '^[0-9]' > /dev/null; then
         ESXi_SHORT=$(echo "$3" | awk -F '.' '{print $1}')
         read -p "Include host short name (${CYAN}${ESXi_SHORT}${NORMAL}) as a Subject Alternative Name entry? [n]: " INCLUDE_SHORTNAME_INPUT
         SHORTNAME_TO_INCLUDE=$ESXi_SHORT
      fi
   else
      DEFAULT_SANS=("$HOSTNAME")
      read -p "Include host short name (${CYAN}${HOSTNAME_SHORT}${NORMAL}) as a Subject Alternative Name entry? [n]: " INCLUDE_SHORTNAME_INPUT
      SHORTNAME_TO_INCLUDE=$HOSTNAME_SHORT
   fi

   if [[ "$INCLUDE_SHORTNAME_INPUT" =~ ^[Yy] ]]; then
      DEFAULT_SANS+=("$SHORTNAME_TO_INCLUDE")
   fi
   if [ "$HOSTNAME_LC" != "$PNID_LC" ]; then
      DEFAULT_SANS+=("$PNID")
   fi

   echo $'\n'"The following items will be added as Subject Alternative Name entries on the '$2' Certificate Signing Request:"
   echo "$CYAN"
   
   for san in "${DEFAULT_SANS[@]}"; do
      echo "$san"
   done

   if [ -n "$CSR_IP" ]; then echo "$CSR_IP"; fi   
   if [ -n "$CSR_EMAIL" ]; then echo "$CSR_EMAIL"; fi
   echo -n "$NORMAL"
   if [ "$1" == "machine-ssl" ] && [ $NODE_TYPE = 'infrastructure' ] && [ -n "$PSC_LB" ]; then
      cat << EOF
${YELLOW}-------------------------!!! WARNING !!!-------------------------"
  This PSC is detected to be in an HA configuration.
  Make sure to add the hostnames of the additional PSCs
  as Subject Alternative Name entries.	  
EOF
      echo $'\n'
   fi

   read -p $'\nIf you want any additional items added as Subject Alternative Name entries, enter them as a comma-separated list (optional): ' ADDITIONAL_SAN_ITEMS
}

#------------------------------
# Generate a configuration file to be used with the openssl commands
#------------------------------
function generateOpensslConfig() {
   echo '[ req ]' > $2
   echo 'prompt = no' >> $2
   echo 'default_bits = 2048' >> $2
   echo 'distinguished_name = req_distinguished_name' >> $2
   echo 'req_extensions = v3_req' >> $2
   echo '' >> $2
   echo '[ req_distinguished_name ]' >> $2
   echo "C = $CSR_COUNTRY" >> $2
   echo "ST = $CSR_STATE" >> $2
   echo "L = $CSR_LOCALITY" >> $2
   echo "O = $CSR_ORG" >> $2
   echo "OU = $CSR_ORG_UNIT" >> $2
   echo "CN = $1" >> $2
   echo '' >> $2
   echo '[ v3_req ]' >> $2
   printf 'subjectAltName = ' >> $2
   
   echo -n "DNS:${DEFAULT_SANS[@]}" | sed 's/ /, DNS:/g' >> $2
   
   for item in $(echo "$ADDITIONAL_SAN_ITEMS" | tr -d ' ' | sed -e 's/,/\n/g'); do
      if [[ $item =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
         printf ", IP:$item" >> $2
      else
         printf ", DNS:$item" >> $2
      fi      
   done

   if [ -n "$CSR_IP" ]; then printf ", IP:$CSR_IP" >> $2; fi

   if [ -n "$CSR_EMAIL" ]; then printf ", email:$CSR_EMAIL" >> $2; fi
}

#------------------------------
# Check if certificate is in DER (binary) format
#------------------------------
function isCertKeyDER() {
   if [ $(file $1 | awk -F':' '{print $NF}' | tr -d ' ') == 'data' ]; then
      logInfo "Provided certificate/keystore $1 is a binary file"
      return 0
   else
      logInfo "Provided certificate/keystore $1 is NOT a binary file"
      return 1
   fi
}

#------------------------------
# Check if certificate is in the correct format (PEM Base64), and convert if necessary
#------------------------------
function getCorrectCertFormat() {
   if isCertKeyDER $1; then
      if openssl x509 -noout -text -inform der -in $1 > /dev/null 2>&1; then
         openssl x509 -inform der -in $1 -outform pem -out $1-converted.pem > /dev/null 2>&1
         logInfo "Converting DER certificate to PEM format: $1-converted.pem"
         declare -g "$2"="$1-converted.pem"
         return 0
      fi
  
      if openssl pkcs7 -print_certs -inform der -in $1 > /dev/null 2>&1; then 
         openssl pkcs7 -print_certs -inform der -in $1 2>/dev/null | grep -vE '^subject|^issuer|^$' > $1-converted.pem
         logInfo "Converting DER PKCS#7 certificate to PEM mulit-cert format: $1-converted.pem"
         declare -g "$2"="$1-converted.pem"
         return 0
      fi

      if openssl pkcs12 -nokeys -info -in $1 -passin pass: 2>&1 | grep 'BEGIN CERTIFICATE' > /dev/null; then
         openssl pkcs12 -nokeys -info -in $1 -passin pass: 2>/dev/null | sed -n '/^-----BEGIN CERTIFICATE-----/,/^-----END CERTIFICATE-----/p' > $1-converted.pem
         openssl pkcs12 -nocerts -nodes -info -in $1 -passin pass: 2>/dev/null | sed -n '/^-----BEGIN PRIVATE KEY-----/,/^-----END PRIVATE KEY-----/p' > $REQUEST_DIR/pkcs12-extracted-key.key
         if [ -s $-converted.pem ]; then logInfo "Extracting certificates from PKCS#12 keystore to $1-converted.pem"; fi
         if [ -s $REQUEST_DIR/pkcs12-extracted-key.key ]; then logInfo "Extracting private key from PKCS#12 keystore to $REQUEST_DIR/pkcs12-extracted-key.key"; fi
         declare -g "$2"="$1-converted.pem"
         return 0
      elif openssl pkcs12 -nokeys -info -in $1 -passin pass:Antidisestablishmentarianism123581321 2>&1 | grep 'invalid password' > /dev/null 2>&1; then
         read -r -s -p $'\n'"Enter password for PKCS#12 keystore: " PKCS12_KEYSTORE_PASSWORD
         PKCS12_KEYSTORE_PASSWORD_VALIDATED=0
         i=0
         while [ $i -lt 3 ]; do
            if [ -z "$PKCS12_KEYSTORE_PASSWORD" ]; then
               read -r -s -p $'\n'"${YELLOW}Enter password for PKCS#12 keystore:${NORMAL} " PKCS12_KEYSTORE_PASSWORD
            elif openssl pkcs12 -nokeys -info -in $1 -passin pass:$PKCS12_KEYSTORE_PASSWORD 2>&1 | grep 'invalid password' > /dev/null 2>&1; then
               read -r -s -p $'\n'"${YELLOW}Invalid password, enter password for PKCS#12 keystore:${NORMAL} " PKCS12_KEYSTORE_PASSWORD
            else
               PKCS12_KEYSTORE_PASSWORD_VALIDATED=1
               break
            fi
            ((++i))
         done
         
         if [ $PKCS12_KEYSTORE_PASSWORD_VALIDATED -eq 0 ]; then errorMessage 'Unable to validate keystore password' '-' '-'; fi

         openssl pkcs12 -nokeys -info -in $1 -passin pass:$PKCS12_KEYSTORE_PASSWORD 2>/dev/null | sed -n '/^-----BEGIN CERTIFICATE-----/,/^-----END CERTIFICATE-----/p' > $1-converted.pem
         openssl pkcs12 -nocerts -nodes -info -in $1 -passin pass:$PKCS12_KEYSTORE_PASSWORD 2>/dev/null | sed -n '/^-----BEGIN PRIVATE KEY-----/,/^-----END PRIVATE KEY-----/p' > $REQUEST_DIR/pkcs12-extracted-key.key
         if [ -s $-converted.pem ]; then logInfo "Extracting certificates from PKCS#12 keystore to $1-converted.pem"; fi
         if [ -s $REQUEST_DIR/pkcs12-extracted-key.key ]; then logInfo "Extracting private key from PKCS#12 keystore to $REQUEST_DIR/pkcs12-extracted-key.key"; fi
         declare -g "$2"="$1-converted.pem"
         echo ''
         return 0
      fi
   else
      if openssl x509 -noout -text -in $1 > /dev/null 2>&1; then
         logInfo "No conversion necessary for $1"
         declare -g "$2"="$1"
         return 0
      fi
      
      if openssl pkcs7 -print_certs -in $1 > /dev/null 2>&1; then 
         openssl pkcs7 -print_certs -in $1 2>/dev/null | grep -vE '^subject|^issuer|^$' > $1-converted.pem
         logInfo "Converting PKCS#7 certificate to PEM multi-cert format: $1-converted.pem"
         declare -g "$2"="$1-converted.pem"
         return 0
      fi 
   fi
   logInfo "Unknown certificate format for $1"
   declare -g "$2"="Unknown format"
   return 0
}

#------------------------------
# Check if private key is in the correct format (PEM Base64), and convert if necessary
#------------------------------
function getCorrectKeyFormat() {
   unset key_path
   unset PKCS12_KEYSTORE_PASSWORD
   if isCertKeyDER $1; then
      logInfo "Converting private key from DER to PEM format: $1-converted.key"
      if openssl rsa -inform der -in $1 > $1-converted.key > /dev/null 2>&1; then
         key_path="$1-converted.key"
      elif openssl pkcs12 -nokeys -info -in $1 -passin pass:VMware123! 2>&1 | grep 'invalid password' > /dev/null 2>&1; then
         read -r -s -p $'\n'"Enter password for PKCS#12 keystore: " PKCS12_KEYSTORE_PASSWORD
         while [ -z "$PKCS12_KEYSTORE_PASSWORD" ]; do read -r -s -p $'\n'"${YELLOW}Enter password for PKCS#12 keystore:${NORMAL} " PKCS12_KEYSTORE_PASSWORD; done
         openssl pkcs12 -nocerts -nodes -info -in $1 -passin pass:$PKCS12_KEYSTORE_PASSWORD 2>/dev/null | sed -n '/^----------BEGIN PRIVATE KEY----------/,/^-----END PRIVATE KEY-----/p' > $REQUEST_DIR/pkcs12-extracted-key.key
         if [ -s $REQUEST_DIR/pkcs12-extracted-key.key ]; then 
            key_path="$REQUEST_DIR/pkcs12-extracted-key.key"
         else
            errorMessage "Unable to export private key from PKCS#12 keystore" '-' '-'
         fi
      else
         errorMessage "Unable to convert private key $1 to PEM format" '-' '-'
      fi
   else
      if grep 'ENCRYPTED' $1 > /dev/null 2>&1; then
         i=1
         read -s -p $'\n'"Private key is encrypted, enter pass phrase to decrypt: " PRIVATE_KEY_PASSPHRASE
         while [ -z "$PRIVATE_KEY_PASSPHRASE" ]; do
            if [ $i -gt 3 ]; then errorMessage "No pass phrase provided" '-' '-'; fi
            read -s -p $'\n'"${YELLOW}Private key is encrypted, enter pass phrase to decrypt:${NORMAL} " PRIVATE_KEY_PASSPHRASE
            ((++i))
         done
         logInfo "Decrypting private key: $1"
         if openssl rsa -in $1 -out $1-decrypted.key -passin pass:$PRIVATE_KEY_PASSPHRASE > /dev/null 2>&1; then
            key_path="$1-decrypted.key"
            echo ''
         else
            openssl rsa -in $1 -out $1-decrypted.key -passin pass:$PRIVATE_KEY_PASSPHRASE > $STAGE_DIR/private-key-decrypt-failure.stdout 2>&1
            if grep 'disabled for fips' $STAGE_DIR/private-key-decrypt-failure.stdout > /dev/null; then
               errorMessage "Private key encrypted with cipher not supported by FIPS, cannot decrypt key" '-' '-'
            else
               errorMessage "Unable to decrypt private key $1" '-' '-'
            fi
         fi
      elif grep 'BEGIN RSA PRIVATE KEY' $1 > /dev/null 2>&1; then
         logInfo "Converting private key $1 from PKCS#1 to PKCS#8"
         if openssl rsa -in $1 -out $1-converted.key > /dev/null 2>&1; then
            key_path="$1-converted.key"
         else
            errorMessage "Unable to convert private key $1 from PKCS#1 to PKCS#8" '-' '-'
         fi
      else
         logInfo "No conversion necessary for $1"
         key_path="$1"
      fi
   fi
   declare -g CURRENT_PRIVATE_KEY_PATH="$key_path"
}

#------------------------------
# Check if certificate contains complete CA signing chain
#------------------------------
function checkEmbeddedCAChain() {
   if [ "$(grep 'BEGIN CERTIFICATE' $1 | wc -l)" -gt 1 ]; then
      CHAIN_START=$(grep -n -m2 'BEGIN CERTIFICATE' $1 | tail -n1 | cut -d':' -f1)
      tail -n+$CHAIN_START $1 > $STAGE_DIR/embedded-root-chain.pem
      
      echo "$STAGE_DIR/embedded-root-chain.pem"
   fi
}

#------------------------------
# Get CA chain from certificate file, or by prompt
#------------------------------
function getCAChain() {
   TRUSTED_ROOT_CHAIN=$(checkEmbeddedCAChain "$1")
         
   if [ -z "$TRUSTED_ROOT_CHAIN" ]; then 
      read -e -p 'Provide path to the Certificate Authority chain: ' TRUSTED_ROOT_CHAIN_INPUT
      while [ ! -f "$TRUSTED_ROOT_CHAIN_INPUT" ]; do read -e -p $'\n'"${YELLOW}File not found, please provide path to the CA-signed Certificate Authority chain:${NORMAL} " TRUSTED_ROOT_CHAIN_INPUT; done
      getCorrectCertFormat "$TRUSTED_ROOT_CHAIN_INPUT" 'TRUSTED_ROOT_CHAIN'
      while true; do
         if ! verifyRootChain "$1" "$TRUSTED_ROOT_CHAIN"; then
            MISSING_CA_OUTPUT=$(printCertificationPathMissingCA "$1" "$TRUSTED_ROOT_CHAIN")
            cat << EOF
$YELLOW
The provided certificate signing chain is not complete!		

$MISSING_CA_OUTPUT
$NORMAL 
EOF
            read -e -p 'Provide path to the Certificate Authority chain: ' TRUSTED_ROOT_CHAIN_INPUT
            while [ ! -f "$TRUSTED_ROOT_CHAIN_INPUT" ]; do read -e -p $'\n'"${YELLOW}File not found, please provide path to the CA-signed Certificate Authority chain:${NORMAL} " TRUSTED_ROOT_CHAIN_INPUT; done
            getCorrectCertFormat "$TRUSTED_ROOT_CHAIN_INPUT" 'TRUSTED_ROOT_CHAIN'
         else
            break
         fi
      done
   fi
}

#------------------------------
# Get location of private key for CA-signed certs
#------------------------------
function getPrivateKey() {
   logInfo "Looking for private key for $2"
   dynamic_key="$2_KEY"
   KEY_FOUND=0
   
   if [ -s $REQUEST_DIR/pkcs12-extracted-key.key ]; then
      CURRENT_KEY_MODULUS_HASH=$(openssl rsa -noout -modulus -in $REQUEST_DIR/pkcs12-extracted-key.key 2>logInfo | md5sum | awk '{print $1}')
      logInfo "Checking modulus of $REQUEST_DIR/pkcs12-extracted-key.key ($CURRENT_KEY_MODULUS_HASH) against '$1'"
      if [ "$1" == "$CURRENT_KEY_MODULUS_HASH" ]; then 
         KEY_FOUND=1;
         getCorrectKeyFormat "$REQUEST_DIR/pkcs12-extracted-key.key"
         declare -g "$dynamic_key"="$CURRENT_PRIVATE_KEY_PATH"
         logInfo "Found private key at $CURRENT_PRIVATE_KEY_PATH"
      fi
   fi

   if [ $KEY_FOUND -eq 0 ]; then
      for key in $(find $TOP_DIR -wholename '*/requests/*.key'); do      
         CURRENT_KEY_MODULUS_HASH=$(openssl rsa -noout -modulus -in $key 2>logInfo | md5sum | awk '{print $1}')
         logInfo "Checking modulus of $key ($CURRENT_KEY_MODULUS_HASH) against '$1'"
         if [ "$1" == "$CURRENT_KEY_MODULUS_HASH" ]; then 
            KEY_FOUND=1;
            getCorrectKeyFormat "$key"
            declare -g "$dynamic_key"="$CURRENT_PRIVATE_KEY_PATH"
            logInfo "Found private key at $CURRENT_PRIVATE_KEY_PATH"
         fi
      done
   fi
   
   if [ $KEY_FOUND -eq 0 ]; then
      if $VECS_CLI entry list --store MACHINE_SSL_CERT | grep '__MACHINE_CSR' > /dev/null; then
         CURRENT_KEY_MODULUS_HASH=$($VECS_CLI entry getkey --store MACHINE_SSL_CERT --alias __MACHINE_CSR | openssl rsa -noout -modulus 2>/dev/null | md5sum | awk '{print $1}')
         logInfo "Checking modulus of key in __MACHINE_CSR alias ($CURRENT_KEY_MODULUS_HASH) against '$1'"
         if [ "$1" == "$CURRENT_KEY_MODULUS_HASH" ]; then
            KEY_FOUND=1;
            $VECS_CLI entry getkey --store MACHINE_SSL_CERT --alias __MACHINE_CSR > $STAGE_DIR/vmca_issued_key.key
            getCorrectKeyFormat "$STAGE_DIR/vmca_issued_key.key"
            declare -g "$dynamic_key"="$CURRENT_PRIVATE_KEY_PATH"
            logInfo 'Found private key in the __MACHINE_CSR entry in VECS'
	     fi
      fi
   fi
		 
   if [ $KEY_FOUND -eq 0 ]; then
      unset CURRENT_PRIVATE_KEY_PATH
      read -e -p "Provide path to the ${CYAN}$3${NORMAL} private key: " PRIVATE_KEY_INPUT
      while [ ! -f "$PRIVATE_KEY_INPUT" ]; do read -e -p $'\n'"${YELLOW}File not found, please provide path to the $3 private key:${NORMAL} " PRIVATE_KEY_INPUT; done
      getCorrectKeyFormat "$PRIVATE_KEY_INPUT"
      declare -g "$dynamic_key"="$CURRENT_PRIVATE_KEY_PATH"
      logInfo "Customer provided key: $CURRENT_PRIVATE_KEY_PATH"
   fi
}

#------------------------------
# Verify a certificate, private key
#------------------------------
function verifyCertAndKey() {
   if [ ! -f $1 ]; then errorMessage "Could not locate certificate $1"; fi
   if [ ! -f $2 ]; then errorMessage "Could not locate private key $2"; fi
   
   CERT_HASH=$(openssl x509 -noout -modulus -in $1 2>/dev/null | md5sum)
   KEY_HASH=$(openssl rsa -noout -modulus -in $2 2>/dev/null| md5sum)
   
   logInfo "Modulus of $1: $CERT_HASH"
   logInfo "Modulus of $2: $KEY_HASH"
   if [ "$CERT_HASH" != "$KEY_HASH" ]; then errorMessage "The private key $2 does not correspond to the certificate $1"; fi
}

#------------------------------
# Verifies root chain by subject/issuer strings
#------------------------------
function verifyRootChain() {
   unset EXPIRED_CA_CERTS
   rm $STAGE_DIR/root-chain-cert-*.crt 2>/dev/null
   csplit -s -z -f $STAGE_DIR/root-chain-cert- -b %02d.crt $2 '/-----BEGIN CERTIFICATE-----/' '{*}' 2>&1 | logDebug
   
   logInfo "Contents of trusted root chain $2"
   openssl crl2pkcs7 -nocrl -certfile $2 2>/dev/null | openssl pkcs7 -print_certs -noout 2>&1 | logInfo
   
   ISSUER_TO_CHECK=$(openssl x509 -noout -issuer -in $1 2>/dev/null | sed -e 's/issuer= //')
   FOUND_ROOT=0
   NUM_CA_CERTS=$(ls $STAGE_DIR/root-chain-cert-* | wc -l)
   i=0
   
   while [ $i -lt $NUM_CA_CERTS ]; do
      logInfo "Looking for issuing CA '$ISSUER_TO_CHECK'"
      for cert in $(ls $STAGE_DIR/root-chain-cert-*); do
         CURRENT_SUBJECT=$(openssl x509 -noout -subject -in $cert 2>/dev/null | sed -e 's/subject= //')
         if [ "$ISSUER_TO_CHECK" == "$CURRENT_SUBJECT" ]; then
            logInfo "Found issuing CA '$ISSUER_TO_CHECK' in $cert"
            if isExpired "$cert" 'file'; then
               logInfo "CA Certificate $CURRENT_SUBJECT is expired!"
               EXPIRED_CA_CERTS+=$'\n\t'"$CURRENT_SUBJECT"
            fi         
            ISSUER_TO_CHECK=$(openssl x509 -noout -issuer -in $cert 2>/dev/null | sed -e 's/issuer= //')
            if [ "$ISSUER_TO_CHECK" == "$CURRENT_SUBJECT" ]; then FOUND_ROOT=1; fi
            break
         fi         
      done
      ((++i))
   done
   if [ -n "$EXPIRED_CA_CERTS" ]; then
      ERROR_MESSAGE='The following provided CA certificates are expired:'
      ERROR_MESSAGE+=$'\n'$(echo "$EXPIRED_CA_CERTS" | sort | uniq | grep -vE '^$')
      ERROR_MESSAGE+=$'\n\nInstallation of the certificates cannot continue'
      errorMessage "$ERROR_MESSAGE" 2
   fi
   if [ $FOUND_ROOT == 0 ]; then
      return 1
   else
      return 0   
   fi
}

#------------------------------
# Verifies CA certificates in signing chain are present in VMware Directory
#------------------------------
function checkCACertsPresent() {
   CHAIN_COMPLETE=0
   CHECK=1
   CURRENT_CERT=$1
   while [ $CHECK -gt 0 ]; do
      CURRENT_SUBJECT=$(echo "$CURRENT_CERT" | openssl x509 -noout -subject 2>/dev/null | sed -e 's/subject= //')
      CURRENT_ISSUER=$(echo "$CURRENT_CERT" | openssl x509 -noout -issuer 2>/dev/null | sed -e 's/issuer= //')   
      if [ "$CURRENT_SUBJECT" != "$CURRENT_ISSUER" ]; then
	     CURRENT_AUTH_KEY_ID=$(echo "$CURRENT_CERT" | openssl x509 -noout -text 2>/dev/null | grep -A1 'Authority Key Id' | grep 'keyid' | sed 's/keyid://' | tr -d ': ')
		 if $DIR_CLI trustedcert list --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" 2>/dev/null | grep 'CN(id)' | grep "$CURRENT_AUTH_KEY_ID" > /dev/null; then
		    CURRENT_CERT=$($DIR_CLI trustedcert get --id $CURRENT_AUTH_KEY_ID --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)"  --outcert /dev/stdout 2>/dev/null)
	     else
		    CHECK=0
		 fi
	  else
	     CHAIN_COMPLETE=1
         CHECK=0
	  fi
   done
   
   if [ $CHAIN_COMPLETE == 1 ]; then
      return 0
   else
      return 1
   fi
}

#------------------------------
# Check for expired CA certificates in certificate chain
#------------------------------
function checkEmbeddedChain() {
   NUM_CERTS=$(echo "$1" | grep 'BEGIN CERTIFICATE' | wc -l)
   if [ $NUM_CERTS -gt 1 ]; then
      echo "$1" > $STAGE_DIR/embedded-chain-check-cert.pem
      csplit -z -s -f $STAGE_DIR/embedded-chain-check- -b %02d.crt $STAGE_DIR/embedded-chain-check-cert.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
	  
      for cert in $(ls $STAGE_DIR/embedded-chain-check-*.crt); do
         logInfo "Running check on embedded CA cert against $cert"
         if isExpired "$cert" 'file'; then
            logInfo "The CA cert $cert is expired"
            rm $STAGE_DIR/embedded-chain-check-* 2>&1 | logDebug
	        return 1
         fi
      done
      rm $STAGE_DIR/embedded-chain-check-* 2>&1 | logDebug
      return 0
   else
      return 0
   fi
}

#------------------------------
# Prompt options for replacing VMCA certificate
#------------------------------
function promptReplaceVMCA() {
   VMCA_REPLACE='SELF-SIGNED'
   unset VMCA_REPLACE_INPUT
   VMCA_REGENERATE_CERTIFICATES=1
   
   header 'Select VMCA Certificate Replacement Method'
   echo '1. Replace VMCA certificate with a self-signed certificate'
   echo '2. Replace VMCA certificate with a self-signed certificate'
   echo '   and regenerate all certificates'
   echo '3. Replace VMCA certificate with a CA-signed certificate'
   read -p $'\nSelect an option [Return to Main Menu]: ' VMCA_REPLACE_INPUT
   
   if [ -z "$VMCA_REPLACE_INPUT" ]; then return 1; fi

   if [ "$VMCA_REPLACE_INPUT" == '1' ]; then VMCA_REGENERATE_CERTIFICATES=0; fi
   if [ "$VMCA_REPLACE_INPUT" == '3' ]; then VMCA_REPLACE='CA-SIGNED'; fi

   logInfo "User selected to replace VMCA certificate with a $VMCA_REPLACE certificate"
   if [ "$VMCA_REGENERATE_CERTIFICATES" == '1' ]; then
      logInfo 'Certificates will be regenerated and signed by the VMCA'
   else
      logInfo 'Certificates will NOT be regenerated'
   fi
   return 0
}

#------------------------------
# Replace all certificates with VMCA-signed certs
#------------------------------
function resetAllCertificates() {
   STS_REPLACE='VMCA-SIGNED'
   MACHINE_SSL_REPLACE='VMCA-SIGNED'
   SOLUTION_USER_REPLACE='VMCA-SIGNED'
   AUTH_PROXY_REPLACE='VMCA-SIGNED'
   AUTO_DEPLOY_CA_REPLACE='SELF-SIGNED'
   
   authenticateIfNeeded
   getCSRInfo
   case $NODE_TYPE in
      embedded|infrastructure)
         replaceMachineSSLCert
         replaceSolutionUserCerts
         if [ $NODE_TYPE = 'embedded' ]; then
            replaceDataEnciphermentCertificate 'replace-only'
            replaceAuthProxyCert
            replaceAutoDeployCACert
            if [[ "$VC_VERSION" =~ ^8 ]]; then replaceSMSCertificate 'VMCA-signed' 'sps-extesion' 'no-restart'; fi
            manageVCExtensionThumbprints 'Update'
            updateAutoDeployDB
         fi
		   if [[ "$VC_VERSION" =~ ^6 ]]; then replaceVMDirCert; fi
         replaceSSOSTSCert
         SSLTrustAnchorSelf
         updateSSLTrustAnchors
         clearCSRInfo         
         promptRestartVMwareServices
         ;;

      management)
         replaceMachineSSLCert
         replaceSolutionUserCerts
         replaceDataEnciphermentCertificate 'replace-only'
         replaceAuthProxyCert
         replaceAutoDeployCACert
         if [[ "$VC_VERSION" =~ ^8 ]]; then replaceSMSCertificate 'VMCA-signed' 'sps-extesion' 'no-restart'; fi
         manageVCExtensionThumbprints 'Update'
         updateAutoDeployDB
         SSLTrustAnchorSelf
         updateSSLTrustAnchors
         clearCSRInfo
         promptRestartVMwareServices
         ;;
   esac   
}

#------------------------------
# Prompt options for replacing STS Signing certificate
#------------------------------
function promptReplaceSTS() {
   STS_REPLACE='VMCA-SIGNED'
   header 'Select STS Signing Certificate Replacement Method'
   echo '1. Replace STS Signing certificate with a VMCA-signed certificate'
   echo '2. Replace STS Signing certificate with a CA-signed certificate'
   read -p $'\nSelect an option [Return to Main Menu]: ' STS_REPLACE_INPUT

   if [ -z "$STS_REPLACE_INPUT" ]; then return 1; fi

   if [ "$STS_REPLACE_INPUT" == '2' ]; then STS_REPLACE='CA-SIGNED'; fi

   logInfo "User selected to replace STS Signing certificate with a $STS_REPLACE certificate"

   retun 0
}

#------------------------------
# Prompt options for replacing Machine SSL certificate
#------------------------------
function promptReplaceMachineSSL() {
   MACHINE_SSL_REPLACE='VMCA-SIGNED'
   unset MACHINE_SSL_REPLACE_INPUT

   header 'Select Machine SSL Certificate Replacement Method'
   echo ' 1. Replace Machine SSL certificate with a VMCA-signed certificate'
   echo ' 2. Replace Machine SSL certificate with a CA-signed certificate'
   read -p $'\nSelect an option [Return to Main Menu]: ' MACHINE_SSL_REPLACE_INPUT

   if [ -z "$MACHINE_SSL_REPLACE_INPUT" ]; then
      return 1
   else
      if [ "$MACHINE_SSL_REPLACE_INPUT" == '2' ]; then MACHINE_SSL_REPLACE='CA-SIGNED'; fi

      logInfo "User selected to replace Machine SSL certificate with a $MACHINE_SSL_REPLACE certificate"
      return 0
   fi
}

#------------------------------
# Prompt options for replacing Solution User certificates
#------------------------------
function promptReplaceSolutionUsers() {
   SOLUTION_USER_REPLACE='VMCA-SIGNED'
   unset SOLUTION_USER_REPLACE_INPUT

   header 'Select Solution User Certificate Replacement Method'
   echo ' 1. Replace Solution User certificates with VMCA-signed certificates'
   echo ' 2. Replace Solution User certificates with CA-signed certificates (not recommended)'
   read -p $'\nSelect an option [Return to Main Menu]: ' SOLUTION_USER_REPLACE_INPUT

   if [ -z "$SOLUTION_USER_REPLACE_INPUT" ]; then return 1; fi

   if [ "$SOLUTION_USER_REPLACE_INPUT" == '2' ]; then
      unset SOLUTION_USER_REPLACE_INPUT
      cat << EOF
${YELLOW}
-------------------------!!! STOP !!!----------------------------

Solution User certificates are used by services internally to 
authenticate into vCenter and the SSO instance.

These certificates are not presented externally (as of 7.0 and later)
and it is VMware's recommendation that they be VMCA-signed
certificates.

The replacement options, again, are:

 1. Replace Solution User certificates with VMCA-signed certificates
 2. Replace Solution User certificates with CA-signed certificates (not recommended)${NORMAL}
EOF
      read -p $'\n'"${YELLOW}Please confirm your selection [Return to Main Menu]:${NORMAL} " SOLUTION_USER_REPLACE_INPUT
   
      if [ -z "$SOLUTION_USER_REPLACE_INPUT" ]; then return 1; fi
   fi

   if [ "$SOLUTION_USER_REPLACE_INPUT" == '2' ]; then
      SOLUTION_USER_REPLACE='CA-SIGNED'
   fi

   logInfo "User selected to replace Solution User certificates with $SOLUTION_USER_REPLACE certificates"
   return 0
}

#------------------------------
# Prompt options for replacing Authentication Proxy certificate
#------------------------------
function promptReplaceAuthProxy() {
   AUTH_PROXY_REPLACE='VMCA-SIGNED'
   unset AUTH_PROXY_REPLACE_INPUT

   header 'Select Authentication Proxy Certificate Replacement Method'
   echo '1. Replace Authentication Proxy certificate with VMCA-signed certificate'
   echo '2. Replace Authentication Proxy certificate with CA-signed certificate'
   read -p $'\nSelect an option [Return to Main Menu]: ' AUTH_PROXY_REPLACE_INPUT

   if [ -z "$AUTH_PROXY_REPLACE_INPUT" ]; then return 1; fi

   if [ "$AUTH_PROXY_REPLACE_INPUT" == '2' ]; then AUTH_PROXY_REPLACE='CA-SIGNED'; fi

   logInfo "User selected to replace Authentication Proxy certifcate with a $AUTH_PROXY_REPLACE certificate"
   return 0
}

#------------------------------
# Prompt options for replacing Auto Deploy CA certificate
#------------------------------
function promptReplaceAutoDeployCA() {
   AUTO_DEPLOY_CA_REPLACE='SELF-SIGNED'
   unset AUTO_DEPLOY_CA_REPLACE_INPUT

   header 'Select Auto Deploy CA Certificate Replacement Method'
   echo '1. Replace Auto Deploy CA certificate with a self-signed certificate'
   echo '2. Replace Auto Deploy CA certificate with a CA-signed certificate'
   read -p $'\nSelect an option [Return to Main Menu]: ' AUTO_DEPLOY_CA_REPLACE_INPUT

   if [ -z "$AUTO_DEPLOY_CA_REPLACE_INPUT" ]; then return 1; fi

   if [ "$AUTO_DEPLOY_CA_REPLACE_INPUT" == '2' ]; then AUTO_DEPLOY_CA_REPLACE='CA-SIGNED'; fi
   
   logInfo "User selected to replace Auto Deploy CA certificate with a $AUTO_DEPLOY_CA_REPLACE certificate"
   return 0
}

#------------------------------
# Prompt options for replacing VMDir certificate
#------------------------------
function promptReplaceVMDir() {
   VMDIR_REPLACE='VMCA-SIGNED'
   unset VMDIR_REPLACE_INPUT

   header 'Select VMDir Certificate Replacement Method'
   echo '1. Replace VMware Directory Service certificate with a VMCA-signed certificate'
   echo '2. Replace VMware Directory Service certificate with a CA-signed certificate'
   read -p $'\nSelect an option [Return to Main Menu]: ' VMDIR_REPLACE_INPUT

   if [ -z "$VMDIR_REPLACE_INPUT" ]; then return 1; fi

   if [ "$VMDIR_REPLACE_INPUT" == '2' ]; then VMDIR_REPLACE='CA-SIGNED'; fi
   
   logInfo "User selected to replace VMDir certificate with a $VMDIR_REPLACE certificate"
   return 0
}

#------------------------------
# Remove legacy VMDir certificate
#------------------------------
function removeVMDirCert() {
   if [ -f /usr/lib/vmware-vmdir/share/config/vmdircert.pem ]; then
      header 'Manage VMware Directory Certificate'
      echo $'\n'"The certificate at ${CYAN}/usr/lib/vmware-vmdir/share/config/vmdircert.pem${NORMAL}"
      echo 'is no longer used in vCenter 7.0 and later.'
      read -p $'\nRemove this certificate and private key [n]: ' REMOVE_LEGACY_VMDIR_CERT_INPUT

      if [ -z $REMOVE_LEGACY_VMDIR_CERT_INPUT ]; then REMOVE_LEGACY_VMDIR_CERT_INPUT='n'; fi

      if [[ "$REMOVE_LEGACY_VMDIR_CERT_INPUT" =~ ^[Yy] ]]; then
         header 'Remove Legacy VMware Directory Certificate'
         backupFilesystemCertKey '/usr/lib/vmware-vmdir/share/config/vmdircert.pem' '/usr/lib/vmware-vmdir/share/config/vmdirkey.pem' 'vmdir'

         task 'Remove legacy VMDir certificate'
         rm /usr/lib/vmware-vmdir/share/config/vmdircert.pem 2>>$LOG || errorMessage 'Unable to remove legacy VMDir certificate'
         statusMessage 'OK' 'GREEN'

         if [ -f /usr/lib/vmware-vmdir/share/config/vmdirkey.pem ]; then
            task 'Remove legacy VMDir private key'
            rm /usr/lib/vmware-vmdir/share/config/vmdirkey.pem 2>>$LOG || errorMessage 'Unable to remove legacy VMDir private key'
            statusMessage 'OK' 'GREEN'
         fi
      fi
   fi
}

#------------------------------
# Replace the VMCA certificate
#------------------------------
function replaceVMCACert() {
   if [ $VMCA_REPLACE == 'SELF-SIGNED' ]; then
      unset VMCA_CN_INPUT
      NEW_VMCA_CERT=$STAGE_DIR/vmca.crt
      NEW_VMCA_KEY=$STAGE_DIR/vmca.key
      
      if [ -z "$CSR_COUNTRY" ]; then getCSRInfo 'VMCA'; fi
      
      read -p $'\n'"Enter a value for the ${CYAN}CommonName${NORMAL} of the certificate [$VMCA_CN_DEFAULT]: " VMCA_CN_INPUT
         
      if [ -z "$VMCA_CN_INPUT" ]; then VMCA_CN_INPUT="$VMCA_CN_DEFAULT"; fi
     
      header 'Replace VMCA Certificate'
   
      generateCertoolConfig 'vmca' "$VMCA_CN_INPUT"
      
      task 'Generate VMCA certificate'
      $CERTOOL --genselfcacert --outcert=$NEW_VMCA_CERT --outprivkey=$NEW_VMCA_KEY --config=$STAGE_DIR/vmca.cfg > /dev/null 2>&1 || errorMessage 'Unable to generate new VMCA certificate'
      statusMessage 'OK' 'GREEN'	  
   else
      unset VMCA_CA_SIGNED_OPTION_INPUT
      header 'Replace VMCA Certificate'   
      echo $'\n1. Generate Certificate Signing Request and Private Key'
      echo '2. Generate Certificate Signing Request and Private Key'
      echo '   from custom OpenSSL configuration file'
      echo '3. Import CA-signed Certificate and Key'
      read -p $'\nSelect an option [Return to Main Menu]: ' VMCA_CA_SIGNED_OPTION_INPUT
	  
	  if [ -z $VMCA_CA_SIGNED_OPTION_INPUT ]; then return 1; fi

      if [ "$VMCA_CA_SIGNED_OPTION_INPUT" == '3' ]; then
         unset VMCA_CERT_INPUT	  
         read -e -p "Provide path to the CA-signed ${CYAN}VMCA${NORMAL} certificate: " VMCA_CERT_INPUT
         while [ ! -f "$VMCA_CERT_INPUT" ]; do read -e -p $'\n'"${YELLOW}File not found, please provide path to the CA-signed VMCA certificate:${NORMAL} " VMCA_CERT_INPUT; done
         getCorrectCertFormat "$VMCA_CERT_INPUT" 'NEW_VMCA_CERT'
         NEW_VMCA_CERT_MODULUS_HASH=$(openssl x509 -noout -modulus -in $NEW_VMCA_CERT 2>/dev/null | md5sum | awk '{print $1}')
		   logInfo "Provided new VMCA certificate:"
         logDetails "$(cat $NEW_VMCA_CERT)"
         logInfo "New VMCA certificate details:"
         logDetails "$(openssl x509 -noout -text -fingerprint -sha1 -in $NEW_VMCA_CERT)"

         getPrivateKey "$NEW_VMCA_CERT_MODULUS_HASH" "NEW_VMCA" 'VMCA'
         getCAChain "$NEW_VMCA_CERT"
         
		   header 'Certificate Verification'
         task 'Verifying certificate and key: '
         verifyCertAndKey $NEW_VMCA_CERT $NEW_VMCA_KEY
         statusMessage 'OK' 'GREEN'
         
         task 'Verifying CA certificate: '
         isCertCA "$(cat $NEW_VMCA_CERT)" || errorMessage "The provided certificate $NEW_VMCA_CERT is not a CA certificate."
		   openssl x509 -in $NEW_VMCA_CERT | cat /dev/stdin $TRUSTED_ROOT_CHAIN > $STAGE_DIR/vmca-complete-chain.pem
		   NEW_VMCA_CERT="$STAGE_DIR/vmca-complete-chain.pem"
         statusMessage 'OK' 'GREEN' 
      else
	      unset VMCA_CN_INPUT
         NEW_VMCA_CSR=$REQUEST_DIR/vmca-$TIMESTAMP.csr
         NEW_VMCA_KEY=$REQUEST_DIR/vmca-$TIMESTAMP.key
         if [ "$VMCA_CA_SIGNED_OPTION_INPUT" == '1' ]; then
            NEW_VMCA_CFG=$REQUEST_DIR/vmca.cfg         
            if [ -z "$CSR_COUNTRY" ]; then getCSRInfo 'VMCA'; fi         
            read -p $'\n'"Enter a value for the ${CYAN}CommonName${NORMAL} of the certificate [CA]: " VMCA_CN_INPUT
            if [ -z "$VMCA_CN_INPUT" ]; then VMCA_CN_INPUT='CA'; fi
            defineSANEntries 'vmca' 'VMCA'
            generateOpensslConfig "$VMCA_CN_INPUT" $NEW_VMCA_CFG 'vmca'
         else
            logInfo 'User has chosen to generate the VMCA private key and CSR from a custom OpenSSL configuration file'
            read -e -p $'\nEnter path to custom OpenSSL configuration file: ' NEW_VMCA_CFG
            while [ ! -f "$NEW_VMCA_CFG" ]; do read -e -p $'\n'"${YELLOW}File not found, enter path to custom OpenSSL configuration file:${NORMAL} " NEW_VMCA_CFG; done
            logDetails "$(cat $NEW_VMCA_CFG)"
         fi
         generateCSR $NEW_VMCA_CSR $NEW_VMCA_KEY "$NEW_VMCA_CFG" || errorMessage "Unable to generate Certificate Signing Request and Private Key"
         
         printf "\nCertificate Signing Request generated at ${CYAN}${NEW_VMCA_CSR}${NORMAL}"
         printf "\nPrivate Key generated at ${CYAN}${NEW_VMCA_KEY}${NORMAL}\n"
         
         return 1
      fi	  
   fi
   
   backupFilesystemCertKey '/var/lib/vmware/vmca/root.cer' '/var/lib/vmware/vmca/privatekey.pem' 'VMCA'
   
   task 'Reconfigure VMCA'
   $CERTOOL --rootca --cert=$NEW_VMCA_CERT --privkey=$NEW_VMCA_KEY > /dev/null 2>&1 || errorMessage 'Unable to reconfigure the VMCA with the new certificate'
   statusMessage 'OK' 'GREEN'
    
   if [ $VMCA_REPLACE == 'CA-SIGNED' ]; then
      task 'Publish CA certificates to VMDir'
      publishCASigningCertificates $TRUSTED_ROOT_CHAIN
   fi
   
   if [ -f /etc/vmware-sso/keys/ssoserverRoot.crt ]; then
      task 'Update VMCA certificate on filesystem'
      mv /etc/vmware-sso/keys/ssoserverRoot.crt /etc/vmware-sso/keys/ssoserverRoot.crt.old > /dev/null 2>&1 || errorMessage 'Unable to backup old SSO server root certificate'
      cp $VMCA_CERT /etc/vmware-sso/keys/ssoserverRoot.crt > /dev/null 2>&1 || errorMessage 'Unable to update SSO server root certificate'
      statusMessage 'OK' 'GREEN'
   fi
   
   return 0
}

#------------------------------
# Replace the Machine SSL certificate
#------------------------------
function replaceMachineSSLCert() {
   if [ "$NODE_TYPE" != 'infrastructure' ] && ! checkService 'vmware-vpostgres'; then
      echo "${YELLOW}The vPostgres service is stopped!"
      echo "Please ensure this service is running before replacing the Machine SSL certificate."
      echo "Hint: Check the number of CRL entries in VECS${NORMAL}"
      return 1 
   fi
   if [ $MACHINE_SSL_REPLACE == 'VMCA-SIGNED' ]; then
      MACHINE_SSL_CERT=$STAGE_DIR/machine-ssl.crt
      MACHINE_SSL_PUBKEY=$STAGE_DIR/machine-ssl.pub
      MACHINE_SSL_KEY=$STAGE_DIR/machine-ssl.key  

      if [ -z "$CSR_COUNTRY" ]; then getCSRInfo 'Machine SSL'; fi
      	 
	   checkPSCHA
	  	  	  
	   if [ -n "$PSC_LB" ]; then
	      unset PSC_LB_ADDITIONAL_HOSTS_INPUT
		   cat << EOF
${YELLOW}-------------------------!!! WARNING !!!-------------------------"
  This PSC is detected to be in an HA configuration!${NORMAL}"
  The Load Balancer address is detected to be: ${CYAN}${PSC_LB}${NORMAL}"
  This hostname will be added to the Subject Altnernative Name field.		 
EOF
         read -p $'\n'"Please add the hostnames of the additional PSCs behind the load balancer (comma-separated list): " PSC_LB_ADDITIONAL_HOSTS_INPUT			
			
		   if [ -z "$PSC_LB_ADDITIONAL_HOSTS_INPUT" ]; then
		      CSR_ADDITIONAL_DNS="$PSC_LB"			   
		   else
		      CSR_ADDITIONAL_DNS="$PSC_LB,$PSC_LB_ADDITIONAL_HOSTS_INPUT"
		   fi		 
	   fi
	  
	   header 'Replace Machine SSL Certificate'
      generateCertoolConfig 'machine-ssl' $PNID 
      
      task 'Regenerate Machine SSL certificate'
      regenerateVMCASignedCertificate 'machine-ssl'
      statusMessage 'OK' 'GREEN'
   else
      unset MACHINE_SSL_CA_SIGNED_OPTION_INPUT
      echo $'\n1. Generate Certificate Signing Request and Private Key'
      echo '2. Generate Certificate Signing Request and Private Key'
      echo '   from custom OpenSSL configuration file'
      echo '3. Import CA-signed Certificate and Key'
      read -p $'\nSelect an option [Return to Main Menu]: ' MACHINE_SSL_CA_SIGNED_OPTION_INPUT
	  
	   if [ -z $MACHINE_SSL_CA_SIGNED_OPTION_INPUT ]; then return 1; fi

      if [ "$MACHINE_SSL_CA_SIGNED_OPTION_INPUT" == '3' ]; then
         logInfo 'User has chosen to import a CA-signed Machine SSL certificate and key'
         read -e -p $'\n'"Provide path to the CA-signed ${CYAN}Machine SSL${NORMAL} certificate: " MACHINE_SSL_CERT_INPUT
         while [ ! -f "$MACHINE_SSL_CERT_INPUT" ]; do read -e -p $'\n'"${YELLOW}File not found, please provide path to the Machine SSL certificate:${NORMAL} " MACHINE_SSL_CERT_INPUT; done
         
         getCorrectCertFormat "$MACHINE_SSL_CERT_INPUT" 'MACHINE_SSL_CERT'
         MACHINE_SSL_CERT_MODULUS_HASH=$(openssl x509 -noout -modulus -in $MACHINE_SSL_CERT 2>/dev/null | md5sum | awk '{print $1}')
		 
         if ! checkCertSignatureAlgorithm "$(cat $MACHINE_SSL_CERT)"; then
            errorMessage 'Certificate is using an unsupported signature algorithm' 'machine-ssl' 'no-task'
         fi
         
         logInfo "Provided new Machine SSL certificate:"
         logDetails "$(cat $MACHINE_SSL_CERT)"
         logInfo "New Machine SSL certificate details:"
         logDetails "$(openssl x509 -noout -text -fingerprint -sha1 -in $MACHINE_SSL_CERT)"

		   getPrivateKey "$MACHINE_SSL_CERT_MODULUS_HASH" "MACHINE_SSL" 'Machine SSL'     
		   getCAChain "$MACHINE_SSL_CERT"

         header 'Certificate Verification'
         task 'Verifying certificate and key'        
        
         logInfo "Using Machine SSL cert: $MACHINE_SSL_CERT"
         logInfo "Using Private Key: $MACHINE_SSL_KEY"
         logInfo "Using trusted root chain: $TRUSTED_ROOT_CHAIN"
        
         verifyCertAndKey "$MACHINE_SSL_CERT" "$MACHINE_SSL_KEY" 
         statusMessage 'OK' 'GREEN'
        
         task 'Verifying root chain'
         verifyRootChain $MACHINE_SSL_CERT $TRUSTED_ROOT_CHAIN || errorMessage 'Certificate Authority chain is not complete'
         statusMessage 'OK' 'GREEN'
                
         task 'Verify PNID included in SAN'
         cat "$MACHINE_SSL_CERT" | openssl x509 -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | grep -i "$PNID" > /dev/null || errorMessage 'The Primary Network Identifier (PNID) is not included in the Subject Alternative Name field'
         statusMessage 'OK' 'GREEN'       
        
         header 'Replace Machine SSL Certificate'       
         
         task 'Publish CA signing certificates'
		   publishCASigningCertificates $TRUSTED_ROOT_CHAIN        
      else
	      unset MACHINE_SSL_CN_INPUT
         MACHINE_SSL_CSR=$REQUEST_DIR/machine-ssl-$TIMESTAMP.csr
         MACHINE_SSL_KEY=$REQUEST_DIR/machine-ssl-$TIMESTAMP.key
                  
         if [ "$MACHINE_SSL_CA_SIGNED_OPTION_INPUT" == '1' ]; then
            MACHINE_SSL_CFG=$REQUEST_DIR/machine-ssl.cfg
            logInfo 'User has chosen to generate the Machine SSL private key and CSR'
            if [ -z "$CSR_COUNTRY" ]; then getCSRInfo 'Machine SSL'; fi

            read -p "Enter a value for the ${CYAN}CommonName${NORMAL} of the certificate [$HOSTNAME]: " MACHINE_SSL_CN_INPUT

            if [ -z "$MACHINE_SSL_CN_INPUT" ]; then MACHINE_SSL_CN_INPUT=$HOSTNAME; fi

            checkPSCHA
            defineSANEntries 'machine-ssl' 'Machine SSL'
            generateOpensslConfig $MACHINE_SSL_CN_INPUT $MACHINE_SSL_CFG 'machine-ssl'
         else
            logInfo 'User has chosen to generate the Machine SSL private key and CSR from a custom OpenSSL configuration file'
            read -e -p $'\nEnter path to custom OpenSSL configuration file: ' MACHINE_SSL_CFG
            while [ ! -f "$MACHINE_SSL_CFG" ]; do read -e -p $'\n'"${YELLOW}File not found, enter path to custom OpenSSL configuration file:${NORMAL} " MACHINE_SSL_CFG; done
            logDetails "$(cat $MACHINE_SSL_CFG)"
         fi
         
         generateCSR $MACHINE_SSL_CSR $MACHINE_SSL_KEY "$MACHINE_SSL_CFG" || errorMessage "Unable to generate Certificate Signing Request and Private Key"
         
         printf "\nCertificate Signing Request generated at ${CYAN}${MACHINE_SSL_CSR}${NORMAL}"
         printf "\nPrivate Key generated at ${CYAN}${MACHINE_SSL_KEY}${NORMAL}\n"
         
         return 1
      fi
	  
   fi
   
   backupVECSCertKey 'machine-ssl'
   updateVECS 'machine-ssl'

   if checkVECSStore 'STS_INTERNAL_SSL_CERT'; then
      updateVECS 'legacy-lookup-service' 'machine-ssl'
   fi
 
   UPDATED_MACHINE_SSL=1

   return 0
}

#------------------------------
# Replace Solution User certificates
#------------------------------
function replaceSolutionUserCerts() {
   if [ "$NODE_TYPE" != 'infrastructure' ] && ! checkService 'vmware-vpostgres'; then
      echo "${YELLOW}The vPostgres service is stopped!"
      echo "Please ensure this service is running before replacing the Solution User certificates."
      echo "Hint: Check the number of CRL entries in VECS${NORMAL}"
      return 1 
   fi
   
   if [ $SOLUTION_USER_REPLACE == 'VMCA-SIGNED' ]; then
      for soluser in "${SOLUTION_USERS[@]}"; do
		   soluser_fix=$(echo $soluser | sed 's/-/_/g')
		   dynamic_cert="${soluser_fix^^}_CERT"
		   dynamic_key="${soluser_fix^^}_KEY"
		   dynamic_pubkey="${soluser_fix^^}_PUBKEY"
		   declare "$dynamic_cert"=$STAGE_DIR/$soluser.crt
		   declare "$dynamic_key"=$STAGE_DIR/$soluser.key
 		   declare "$dynamic_pubkey"=$STAGE_DIR/$soluser.pub
	   done

      header 'Replace Solution User Certificates'
      
	   checkServicePrincipals
	  
	   echo 'Generate new certificates and keys:'
      for soluser in "${SOLUTION_USERS[@]}"; do	  
         task "   $soluser"
		   soluser_fix=$(echo $soluser | sed 's/-/_/g')
		   dynamic_cert="${soluser_fix^^}_CERT"
		   dynamic_key="${soluser_fix^^}_KEY"
		   dynamic_pubkey="${soluser_fix^^}_PUBKEY"
		   $CERTOOL --genkey --privkey=${!dynamic_key} --pubkey=${!dynamic_pubkey} > /dev/null 2>&1 || errorMessage "Unable to generate a key pair for $soluser"
		   if [ $soluser == 'wcp' ]; then
		      $CERTOOL --gencert --server=$PSC_LOCATION --Name=$soluser --genCIScert --dataencipherment --privkey=${!dynamic_key} --cert=${!dynamic_cert} --config=/dev/null --Country="$CSR_COUNTRY_DEFAULT" --State="$CSR_STATE_DEFAULT" --Locality="$CSR_LOCALITY_DEFAULT" --Organization="$CSR_ORG_DEFAULT"  --OrgUnit="mID-$MACHINE_ID" > /dev/null 2>&1 || errorMessage "Unable to generate a VMCA-signed cert for $soluser"
		   else
		      $CERTOOL --gencert --server=$PSC_LOCATION --Name=$soluser --genCIScert --privkey=${!dynamic_key} --cert=${!dynamic_cert}  --config=/dev/null --Country="$CSR_COUNTRY_DEFAULT" --State="$CSR_STATE_DEFAULT" --Locality="$CSR_LOCALITY_DEFAULT" --Organization="$CSR_ORG_DEFAULT" --OrgUnit="mID-$MACHINE_ID" --FQDN=$PNID > /dev/null 2>&1 || errorMessage "Unable to generate a VMCA-signed cert for $soluser"
		   fi
         statusMessage 'OK' 'GREEN'		 
      done	  	 	 
   else
      unset SOLUTION_USERS_CA_SIGNED_OPTION_INPUT
      echo $'\n1. Generate Certificate Signing Requests and Private Keys'
      echo '2. Generate Certificate Signing Request and Private Keys'
      echo '   from custom OpenSSL configuration files'
      echo '3. Import CA-signed Certificates and Keys'
      read -p $'\nSelect an option [Return to Main Menu]: ' SOLUTION_USERS_CA_SIGNED_OPTION_INPUT

      if [ -z $SOLUTION_USERS_CA_SIGNED_OPTION_INPUT ]; then return 1; fi

      if [ "$SOLUTION_USERS_CA_SIGNED_OPTION_INPUT" == '3' ]; then
         logInfo 'User has chosen to import a CA-signed Solution User certificates and keys'
	  
	      for soluser in "${SOLUTION_USERS[@]}"; do
	         unset SOLUTION_USER_CERT_INPUT
		      unset SOLUTION_USER_KEY_INPUT
		      soluser_fix=$(echo $soluser | sed 's/-/_/g')
		      dynamic_cert="${soluser_fix^^}_CERT"
		      dynamic_key="${soluser_fix^^}_KEY"
			   dynamic_cert_modulus="${soluser_fix^^}_MODULUS_HASH"
			
		      read -e -p $'\n'"Provide path to the CA-signed ${CYAN}${soluser}${NORMAL} certificate: " SOLUTION_USER_CERT_INPUT
            while [ ! -f "$SOLUTION_USER_CERT_INPUT" ]; do read -e -p $'\n'"${YELLOW}File not found, please provide path to the ${soluser} certificate:${NORMAL} " SOLUTION_USER_CERT_INPUT; done
            getCorrectCertFormat "$SOLUTION_USER_CERT_INPUT" "$dynamic_cert"

            if ! checkCertSignatureAlgorithm "$(cat ${!dynamic_cert})"; then
               errorMessage 'Certificate is using an unsupported signature algorithm' 'soluser' 'no-task'
            fi

            declare "$dynamic_cert_modulus"=$(openssl x509 -noout -modulus -in ${!dynamic_cert} 2>/dev/null | md5sum | awk '{print $1}')
         
            logInfo "Provided new $soluser certificate:"
            logDetails "$(cat ${!dynamic_cert})"
            logInfo "New $soluser certificate details:"
            logDetails "$(openssl x509 -noout -text -fingerprint -sha1 -in ${!dynamic_cert})"

            getPrivateKey "${!dynamic_cert_modulus}" "${soluser_fix^^}" "$soluser"			
         done	          
         echo ''
         getCAChain "$MACHINE_CERT"      
         
		   header 'Replace Solution User Certificates'
		 
		   checkServicePrincipals
		 
		   echo 'Verify certificates and keys:'
         		 
		   for soluser in "${SOLUTION_USERS[@]}"; do
		      soluser_fix=$(echo $soluser | sed 's/-/_/g')
		      dynamic_cert="${soluser_fix^^}_CERT"
		      dynamic_key="${soluser_fix^^}_KEY"
			   task "   $soluser"
			   verifyCertAndKey "${!dynamic_cert}" "${!dynamic_key}"
			   statusMessage 'OK' 'GREEN'
		   done		         
         
         task 'Verifying root chain'
         verifyRootChain $MACHINE_CERT $TRUSTED_ROOT_CHAIN || errorMessage 'Certificate Authority chain is not complete'
         statusMessage 'OK' 'GREEN'
		 
		   task 'Publish CA signing certificates'
		   publishCASigningCertificates $TRUSTED_ROOT_CHAIN
      else
	      for soluser in "${SOLUTION_USERS[@]}"; do
		      soluser_fix=$(echo $soluser | sed 's/-/_/g')
		      dynamic_csr="${soluser_fix^^}_CSR"
		      dynamic_key="${soluser_fix^^}_KEY"
			   declare "$dynamic_csr"=$REQUEST_DIR/$soluser-$TIMESTAMP.csr
			   declare "$dynamic_key"=$REQUEST_DIR/$soluser-$TIMESTAMP.key
            if [ "$SOLUTION_USERS_CA_SIGNED_OPTION_INPUT" == '1' ]; then
               dynamic_cfg="${soluser_fix^^}_CFG"			   
			      declare "$dynamic_cfg"=$REQUEST_DIR/$soluser-$TIMESTAMP.cfg
            fi
	      done         

         if [ "$SOLUTION_USERS_CA_SIGNED_OPTION_INPUT" == '1' ] && [ -z "$CSR_COUNTRY" ]; then getCSRInfo 'Solution Users'; fi
         defineSANEntries 'soluser' 'Solution User'
         for soluser in "${SOLUTION_USERS[@]}"; do
		      soluser_fix=$(echo $soluser | sed 's/-/_/g')
		      dynamic_csr="${soluser_fix^^}_CSR"
		      dynamic_key="${soluser_fix^^}_KEY"
            dynamic_cfg="${soluser_fix^^}_CFG"			      
            if [ "$SOLUTION_USERS_CA_SIGNED_OPTION_INPUT" == '1' ]; then
			      generateOpensslConfig "$soluser-$MACHINE_ID" "${!dynamic_cfg}" "$soluser"
            else
               logInfo "User has chosen to generate the $soluser private key and CSR from a custom OpenSSL configuration file"
               read -e -p $'\n'"Enter path to custom OpenSSL configuration file for ${CYAN}${soluser}${NORMAL}: " SOLUTION_USER_CFG
               while [ ! -f "$SOLUTION_USER_CFG" ]; do read -e -p $'\n'"${YELLOW}File not found, enter path to custom OpenSSL configuration file for ${soluser}:${NORMAL} " SOLUTION_USER_CFG; done
               declare "$dynamic_cfg"="$SOLUTION_USER_CFG"               
               logDetails "$(cat ${!dynamic_cfg})"
            fi
			   generateCSR "${!dynamic_csr}" "${!dynamic_key}" "${!dynamic_cfg}" || errorMessage "Unable to generate Certificate Signing Request and Private Key for $soluser"
		   done         
         
         echo $'\nCertificate Signing Requests generated at:'
		 
		   for soluser in "${SOLUTION_USERS[@]}"; do
		      soluser_fix=$(echo $soluser | sed 's/-/_/g')
		      dynamic_csr="${soluser_fix^^}_CSR"
		      echo "${CYAN}${!dynamic_csr}${NORMAL}"
		   done
		 
         echo $'\nPrivate Keys generated at:'
		   for soluser in "${SOLUTION_USERS[@]}"; do
		      soluser_fix=$(echo $soluser | sed 's/-/_/g')
		      dynamic_key="${soluser_fix^^}_KEY"
		      echo "${CYAN}${!dynamic_key}${NORMAL}"
		   done             

         return 1
      fi	  
   fi
   
   echo $'\nBackup certificate and private key:'
   
   for soluser in "${SOLUTION_USERS[@]}"; do
      backupVECSCertKey "$soluser"
   done
   
   echo $'\nUpdating certificates and keys in VECS:'
 
   for soluser in "${SOLUTION_USERS[@]}"; do
      updateVECS "$soluser"
   done

   echo $'\nUpdating solution user certificates in VMware Directory:'
   
   for soluser in "${SOLUTION_USERS[@]}"; do
      soluser_fix=$(echo $soluser | sed 's/-/_/g')
      dynamic_cert="${soluser_fix^^}_CERT"
      replaceServicePrincipalCert "$soluser" "${!dynamic_cert}"	  
   done
}

#------------------------------
# Replace a Solution User certificate in VMDir
#------------------------------
function replaceServicePrincipalCert() {
   task "   $1"
   $DIR_CLI service update --name $1-$MACHINE_ID --cert $2 --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" > /dev/null 2>&1 || errorMessage "Unable to update $1-$MACHINE_ID solution user certificate in VMDir"
   statusMessage 'OK' 'GREEN'
}

#------------------------------
# Replace the Authentication Proxy certificate
#------------------------------
function replaceAuthProxyCert() {
   header 'Replace Authentication Proxy Certificate'

   if [ $AUTH_PROXY_REPLACE = 'VMCA-SIGNED' ]; then            
      generateCertoolConfig 'auth proxy'
      
      task 'Regenerate Authentication Proxy certificate'
      regenerateVMCASignedCertificate 'auth-proxy'
      statusMessage 'OK' 'GREEN'
          
      AUTH_PROXY_CERT=$STAGE_DIR/auth-proxy.crt
      AUTH_PROXY_KEY=$STAGE_DIR/auth-proxy.key
   else
      unset AUTH_PROXY_CA_SIGNED_OPTION_INPUT
      echo $'\n1. Generate Certificate Signing Request and Private Key'
      echo '2. Generate Certificate Signing Request and Private Key'
      echo '   from custom OpenSSL configuration file'
      echo '3. Import CA-signed Certificate and Key'
      read -p $'\nSelect an option [Return to Main Menu]: ' AUTH_PROXY_CA_SIGNED_OPTION_INPUT
          
	   if [ -z $AUTH_PROXY_CA_SIGNED_OPTION_INPUT ]; then return 1; fi
	  
      if [ "$AUTH_PROXY_CA_SIGNED_OPTION_INPUT" == '3' ]; then
	      read -e -p $'\n'"Provide path to CA-signed ${CYAN}Authentication Proxy${NORMAL} certificate: " AUTH_PROXY_CERT_INPUT
         while [ ! -f "$AUTH_PROXY_CERT_INPUT" ]; do read -e -p "${YELLOW}File not found, please provide path to the Authentication Proxy certificate:${NORMAL} " AUTH_PROXY_CERT_INPUT; done
         getCorrectCertFormat "$AUTH_PROXY_CERT_INPUT" 'AUTH_PROXY_CERT'
		   
         if ! checkCertSignatureAlgorithm "$(cat $AUTH_PROXY_CERT)"; then
            errorMessage 'Certificate is using an unsupported signature algorithm' 'auth-proxy' 'no-task'
         fi
         
         AUTH_PROXY_CERT_MODULUS_HASH=$(openssl x509 -noout -modulus -in $AUTH_PROXY_CERT 2>/dev/null | md5sum | awk '{print $1}')
		   logInfo "Provided new Authentication Proxy certificate:"
         logDetails "$(cat $AUTH_PROXY_CERT)"
         logInfo "New Authentication Proxy certificate details:"
         logDetails "$(openssl x509 -noout -text -fingerprint -sha1 -in $AUTH_PROXY_CERT)"
         getPrivateKey "$AUTH_PROXY_CERT_MODULUS_HASH" "AUTH_PROXY" 'Authentication Proxy'
         getCAChain "$AUTH_PROXY_CERT" 
         
         task 'Verifying certificates and keys: '
         verifyCertAndKey $AUTH_PROXY_CERT $AUTH_PROXY_KEY
      else
         AUTH_PROXY_CSR=$REQUEST_DIR/auth-proxy-$TIMESTAMP.csr
         AUTH_PROXY_KEY=$REQUEST_DIR/auth-proxy-$TIMESTAMP.key

         if [ "$AUTH_PROXY_CA_SIGNED_OPTION_INPUT" == '1' ]; then
            AUTH_PROXY_CFG=$REQUEST_DIR/auth-proxy.cfg                 
            if [ -z "$CSR_COUNTRY" ]; then getCSRInfo; fi
            defineSANEntries 'auth-proxy' 'Authentication Proxy'             
            generateOpensslConfig $HOSTNAME $AUTH_PROXY_CFG 'Authentication Proxy'
         else
            logInfo 'User has chosen to generate the Authentication Proxy private key and CSR from a custom OpenSSL configuration file'
            read -e -p $'\nEnter path to custom OpenSSL configuration file: ' AUTH_PROXY_CFG
            while [ ! -f "$AUTH_PROXY_CFG" ]; do read -e -p $'\n'"${YELLOW}File not found, enter path to custom OpenSSL configuration file:${NORMAL} " AUTH_PROXY_CFG; done
            logDetails "$(cat $AUTH_PROXY_CFG)"
         fi
         
         generateCSR $AUTH_PROXY_CSR $AUTH_PROXY_KEY "$AUTH_PROXY_CFG" || errorMessage "Unable to generate Certificate Signing Request and Private Key"
		   
         printf "\nCertificate Signing Request generated at ${CYAN}${AUTH_PROXY_CSR}${NORMAL}"
         printf "\nPrivate Key generated at ${CYAN}${AUTH_PROXY_KEY}${NORMAL}\n"

         return 1
      fi
   fi   

   if [ $AUTH_PROXY_REPLACE != 'VMCA-SIGNED' ]; then
      task 'Publish CA signing certificates'
      publishCASigningCertificates $TRUSTED_ROOT_CHAIN
   fi
   
   
   if [ -f /var/lib/vmware/vmcam/ssl/rui.crt ] && [ -f /var/lib/vmware/vmcam/ssl/rui.key ]; then backupFilesystemCertKey '/var/lib/vmware/vmcam/ssl/rui.crt' '/var/lib/vmware/vmcam/ssl/rui.crt' 'auth-proxy'; fi
   
   task 'Replace certificate on filesystem'
   mv /var/lib/vmware/vmcam/ssl/vmcamcert.pem /var/lib/vmware/vmcam/ssl/vmcamcert.pem.old > /dev/null 2>&1 || errorMessage 'Unable to backup Authentication Proxy PEM file'
   
   cp $AUTH_PROXY_CERT /var/lib/vmware/vmcam/ssl/rui.crt > /dev/null 2>&1 || errorMessage 'Unable to update Authentication Proxy certificate'
   cp $AUTH_PROXY_KEY /var/lib/vmware/vmcam/ssl/rui.key > /dev/null 2>&1 || errorMessage 'Unable to update Authentication Proxy private key'
   cat /var/lib/vmware/vmcam/ssl/rui.key <(echo) /var/lib/vmware/vmcam/ssl/rui.crt > /var/lib/vmware/vmcam/ssl/vmcamcert.pem 2>&1 || errorMessage 'Unable to update Authentication Proxy PEM file'
   chmod 600 /var/lib/vmware/vmcam/ssl/*
   statusMessage 'OK' 'GREEN'
            
   return 0
}

#------------------------------
# Replace the Auto Deploy CA certificate
#------------------------------
function replaceAutoDeployCACert() {
   header 'Replace Auto Deploy CA Certificate'
   if [ $AUTO_DEPLOY_CA_REPLACE == 'SELF-SIGNED' ]; then
      task 'Regenerate Auto Deploy CA certificate'
      AUTO_DEPLOY_CA_CONFIG=$(cat << EOF
[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name

encrypt_key         = no
prompt              = no

string_mask         = nombstr
x509_extensions     = x509

[ req_distinguished_name ]
O                   = VMware Auto Deploy

[ x509 ]
basicConstraints    = CA:true, pathlen:0
keyUsage            = keyCertSign
   
EOF
)
      openssl req -new -x509 -config <(echo -n "$AUTO_DEPLOY_CA_CONFIG") -days 4200 -sha256 -keyout $STAGE_DIR/auto-deploy-ca.key -out $STAGE_DIR/auto-deploy-ca.crt > /dev/null 2>&1 || errorMessage 'Unable to generate new Auto Deploy CA certificate and private key. See log for details.'
      #openssl req -new -newkey rsa:2048 -nodes -keyout $STAGE_DIR/auto-deploy-ca.key -x509 -out $STAGE_DIR/auto-deploy-ca.crt -subj '/O=VMware Auto Deploy' -days 3650 > /dev/null  2>&1 || errorMessage 'Unable to generate new Auto Deploy CA certificate and private key. See log for details.'
      statusMessage 'OK' 'GREEN'
      AUTO_DEPLOY_CA_CERT=$STAGE_DIR/auto-deploy-ca.crt
      AUTO_DEPLOY_CA_KEY=$STAGE_DIR/auto-deploy-ca.key        
   else
      unset AUTO_DEPLOY_CA_CA_SIGNED_OPTION_INPUT
      echo $'\n1. Generate Certificate Signing Request and Private Key'
      echo '2. Generate Certificate Signing Request and Private Key'
      echo '   from custom OpenSSL configuration file'
      echo '3. Import CA-signed Certificate and Key'
      read -p $'\nChoose option [Return to Main Menu]: ' AUTO_DEPLOY_CA_CA_SIGNED_OPTION_INPUT
	  
	   if [ -z $AUTO_DEPLOY_CA_CA_SIGNED_OPTION_INPUT ]; then return 1; fi

      if [ "$AUTO_DEPLOY_CA_CA_SIGNED_OPTION_INPUT" == '3' ]; then
	      logInfo 'User has chosen to import a CA-signed Auto Deploy certificate and key'
         read -e -p $'\n'"Provide path to CA-signed ${CYAN}Auto Deploy CA${NORMAL} certificate: " AUTO_DEPLOY_CA_CERT_INPUT
         while [ ! -f "$AUTO_DEPLOY_CA_CERT_INPUT" ]; do read -e -p "${YELLOW}File not found, please provide path to the Auto Deploy CA certificate:${NORMAL} " AUTO_DEPLOY_CA_CERT_INPUT; done
         getCorrectCertFormat "$AUTO_DEPLOY_CA_CERT_INPUT" 'AUTO_DEPLOY_CA_CERT'
		   
         if ! checkCertSignatureAlgorithm "$(cat $AUTO_DEPLOY_CA_CERT)"; then
            errorMessage 'Certificate is using an unsupported signature algorithm' 'auto-deploy-ca' 'no-task'
         fi

         AUTO_DEPLOY_CA_CERT_MODULUS_HASH=$(openssl x509 -noout -modulus -in $AUTO_DEPLOY_CA_CERT 2>/dev/null | md5sum | awk '{print $1}')
         logInfo "Provided new Auto Deploy CA certificate:"
         logDetails "$(cat $AUTO_DEPLOY_CA_CERT)"
         logInfo "New Auto Deploy CA certificate details:"
         logDetails "$(openssl x509 -noout -text -fingerprint -sha1 -in $AUTO_DEPLOY_CA_CERT)"
		   getPrivateKey "$AUTO_DEPLOY_CA_CERT_MODULUS_HASH" "AUTO_DEPLOY_CA" 'Auto Deploy CA'
         getCAChain "$AUTO_DEPLOY_CERT"  
         
         task 'Verifying certificates and keys'
         verifyCertAndKey $AUTO_DEPLOY_CA_CERT $AUTO_DEPLOY_CA_KEY
         
         task 'Verifying CA certificate'
         isCertCA "$(cat $AUTO_DEPLOY_CA_CERT)" || errorMessage "The provided certificate ${AUTO_DEPLOY_CA_CERT} is not a CA certificate."
         statusMessage 'OK' 'GREEN'
      else
         AUTO_DEPLOY_CA_CSR=$REQUEST_DIR/auto-deploy-ca-$TIMESTAMP.csr
         AUTO_DEPLOY_CA_KEY=$REQUEST_DIR/auto-deploy-ca-$TIMESTAMP.key

         if [ "$AUTO_DEPLOY_CA_CA_SIGNED_OPTION_INPUT" == '1' ]; then
            AUTO_DEPLOY_CA_CFG=$REQUEST_DIR/auto-deploy-ca.cfg        
            if [ -z "$CSR_COUNTRY" ]; then getCSRInfo; fi
            defineSANEntries 'rbd' 'Auto Deploy CA'
            generateOpensslConfig $HOSTNAME $AUTO_DEPLOY_CA_CFG 'Auto Deploy'
         else
            logInfo 'User has chosen to generate the Auto Deploy CA private key and CSR from a custom OpenSSL configuration file'
            read -e -p $'\nEnter path to custom OpenSSL configuration file: ' AUTO_DEPLOY_CA_CFG
            while [ ! -f "$AUTO_DEPLOY_CA_CFG" ]; do read -e -p $'\n'"${YELLOW}File not found, enter path to custom OpenSSL configuration file:${NORMAL} " AUTO_DEPLOY_CA_CFG; done
            logDetails "$(cat $AUTO_DEPLOY_CA_CFG)"
         fi
         
         generateCSR $AUTO_DEPLOY_CA_CSR $AUTO_DEPLOY_CA_KEY "$AUTO_DEPLOY_CA_CFG" || errorMessage "Unable to generate Certificate Signing Request and Private Key"
		   
         printf "\n\nCertificate Signing Request generated at ${CYAN}${AUTO_DEPLOY_CA_CFG}${NORMAL}"
         printf "\nPrivate Key generated at ${CYAN}${AUTO_DEPLOY_CA_KEY}${NORMAL}\n"

         return 1
      fi
   fi
   
   if [ $AUTO_DEPLOY_CA_REPLACE != 'SELF-SIGNED' ]; then
      task 'Publish CA signing certificates'
      publishCASigningCertificates $TRUSTED_ROOT_CHAIN
   fi
   
   backupFilesystemCertKey '/etc/vmware-rbd/ssl/rbd-ca.crt' '/etc/vmware-rbd/ssl/rbd-ca.key' 'auto-deploy-ca'
   
   task 'Replace certificate on filesystem'
   cp $AUTO_DEPLOY_CA_CERT /etc/vmware-rbd/ssl/rbd-ca.crt > /dev/null 2>&1 || errorMessage 'Unable to update Auto Deploy CA certificate'
   cp $AUTO_DEPLOY_CA_KEY /etc/vmware-rbd/ssl/rbd-ca.key > /dev/null 2>&1 || errorMessage 'Unable to update Auto Deploy CA private key'
   statusMessage 'OK' 'GREEN'      
   
   return 0
}

#------------------------------
# Manage SMS certificates
#------------------------------
function manageSMSCertificates() {
   case $1 in
      'View')
         listSMSCertificates 'View'
         read -p $'\nSelect certificate [Return to Main Menu]: ' VIEW_SMS_CERT_INPUT
		 
         if [ -n "$VIEW_SMS_CERT_INPUT" ]; then
            SMS_CERT=${SMS_CERT_HASHES[$((VIEW_SMS_CERT_INPUT - 1))]}
            viewCertificateInfo "$SMS_CERT" 'view-path'
         fi
         ;;
      'Manage')
         listSMSCertificates 'Manage'
         header 'Manage SMS Certificates'
         echo ' 1. Replace SMS self-signed certificate'
         echo ' 2. Replace SMS VMCA-signed certificate'
         echo ' 3. Add VASA Provider certificate'
         echo ' 4. Remove VASA Provider certificate'
         read -p $'\nEnter selection [Return to Main Menu]: ' MANAGE_SMS_INPUT
		 
         if [ -n "$MANAGE_SMS_INPUT" ]; then
            case "$MANAGE_SMS_INPUT" in
               1)
                  replaceSMSCertificate 'self-signed' 'sms_self_signed'
                  ;;
               2)
                  replaceSMSCertificate 'VMCA-signed' 'sps-extension'
                  ;;
               3)
                  addSMSVASACertificate
                  ;;
               4)
                  removeSMSVASACertificate
                  ;;
            esac
         fi
         ;;
   esac
}

#------------------------------
# Replace SMS certificate
#------------------------------
function replaceSMSCertificate() {
   header "Replace SMS $1 certifificate"
   task "Remove current SMS $1 certificate"
   $VECS_CLI entry delete --store SMS --alias $2 -y > /dev/null 2>&1 || errorMessage 'Unable to delete current SMS certificate' 
   statusMessage 'OK' 'GREEN'
   if [ -z $3 ]; then restartVMwareServices 'vmware-sps'; fi
}

#------------------------------
# List SMS certificates
#------------------------------
function listSMSCertificates() {
   header "$1 Certificates in the SMS VECS Store"
   SMS_CERTS=()
   SMS_CERT_HASHES=()
   SMS_ALIASES=()
   for alias in $($VECS_CLI entry list --store SMS | grep Alias | sed -e 's/Alias[[:space:]]:[[:space:]]//g'); do
      SMS_CERT=$($VECS_CLI entry getcert --store SMS --alias "$alias")
	  SMS_CERT_INFO=$(viewBriefCertificateInfo "$SMS_CERT")
	  SMS_CERT_HASHES+=("$SMS_CERT")
	  SMS_CERTS+=("$SMS_CERT_INFO")
	  SMS_ALIASES+=("$alias")	  
   done
   i=0
   while [ $i -lt "${#SMS_CERTS[@]}" ]; do
      n=$((i+1))
      printf "%2s. %s\n    %s\n\n" $n "Alias: ${SMS_ALIASES[$i]}" "${SMS_CERTS[$i]}"
      ((++i))
   done
}

#------------------------------
# Add new VASA provider cert to SMS store
#------------------------------
function addSMSVASACertificate() {
   read -e -p $'\n\nEnter path to new VASA provider certificate: ' NEW_VASA_INPUT
   while [ ! -f "$NEW_VASA_INPUT" ]; do read -e -p $'\n'"${YELLOW}File not found, enter path to new VASA provider certificate:${NORMAL} " NEW_VASA_INPUT; done
   read -p 'Enter alias (usually URL for VASA provider): ' NEW_VASA_ALIAS_INPUT
   
   header 'Add New VASA Provider Certificate'
   task 'Add entry to SMS store in VECS'
   $VECS_CLI entry create --store SMS --cert "$NEW_VASA_INPUT" --alias "$NEW_VASA_ALIAS_INPUT" > /dev/null 2>&1 || errorMessage 'Unable to add VASA provider certificate to SMS store'
   statusMessage 'OK' 'GREEN'
}

#------------------------------
# Remove VASA provider cert from SMS store
#------------------------------
function removeSMSVASACertificate() {
   read -p $'\nEnter the number(s) of the VASA provider certificate(s) to remove (comma-separated list): ' REMOVE_VASA_INPUT
   
   if [ -n "$REMOVE_VASA_INPUT" ]; then
      header 'Remove VASA Provider Certificates'
      for index in $(echo "$REMOVE_VASA_INPUT" | tr -d ' ' | sed 's/,/ /g'); do
         vasa_alias=${SMS_ALIASES[$((index - 1))]}
		 task "$vasa_alias"
		 $VECS_CLI entry delete --store SMS --alias "$vasa_alias" -y > /dev/null 2>&1 || errorMessage "Unable to delete alias '$vasa_alias' from SMS store in VECS"
		 statusMessage 'OK' 'GREEN'
      done
   fi
}

#------------------------------
# Replace data-encipherment certificate
#------------------------------
function replaceDataEnciphermentCertificate() {
   if [ "$VC_VERSION" == '6.5' ]; then return 0; fi

   header 'Replace Data Encipherment certificate'
   
   if checkVECSEntry 'data-encipherment' 'data-encipherment'; then
      $VECS_CLI entry getkey --store data-encipherment --alias data-encipherment 2>/dev/null > $STAGE_DIR/data-encipherment.key
   else
      $CERTOOL --genkey --privkey=$STAGE_DIR/data-encipherment.key --pubkey=$STAGE_DIR/data-encipherment.pub
   fi
   
   task 'Generate new Data Enciphermenet certificate'
   $CERTOOL --server=$PSC_LOCATION --genCIScert --privkey=$STAGE_DIR/data-encipherment.key --dataencipherment --cert=$STAGE_DIR/data-encipherment.crt --Name=data-encipherment --FQDN=$HOSTNAME_LC > /dev/null 2>&1 || errorMessage 'Unable to generate new Data Encipherment certificate'
   statusMessage 'OK' 'GREEN'
   
   updateVECS 'data-encipherment' 
   
   if [ -z $1 ]; then promptRestartVMwareServices 'vmware-vpxd'; fi
}

#------------------------------
# Update Machine SSL thumbprint in Auto Deploy DB
#------------------------------
function updateAutoDeployDB() {
   RBD_STARTUP=$($VMON_CLI -s rbd | grep Starttype | awk '{print $NF}')
   if [ "$RBD_STARTUP" = "AUTOMATIC" ]; then 
      header "Updating Auto Deploy Database"
      MACHINE_SSL_THUMB=$($VECS_CLI entry getcert --store MACHINE_SSL_CERT --alias __MACHINE_CERT | openssl x509 -noout -fingerprint -sha1 2>/dev/null | cut -d'=' -f2)
      if checkService 'vmware-rbd-watchdog'; then 
	     task "Stopping Auto Deploy Service"
		 service-control --stop vmware-rbd-watchdog > /dev/null 2>&1 || errorMessage "Unable to stop Auto Deploy service"
		 statusMessage "OK" "GREEN"
	  fi
      task "Updating Machine SSL thumbprint"
	  sqlite3 /var/lib/rbd/db "update vc_servers set thumbprint = '$MACHINE_SSL_THUMB'" || errorMessage "Unable to update Auto Deploy database"
	  statusMessage "OK" "GREEN"
	  task "Starting Auto Deploy Service"
      service-control --start vmware-rbd-watchdog > /dev/null 2>&1 || errorMessage "Unable to start Auto Deploy service"
	  statusMessage "OK" "GREEN"
   fi
}

#------------------------------
# Checks Machine SSL thumbprint in Auto Deploy DB
#------------------------------
function checkAutoDeployDB() {
   RBD_STARTUP=$($VMON_CLI -s rbd | grep Starttype | awk '{print $NF}')
   if [ "$RBD_STARTUP" = "AUTOMATIC" ]; then
      header "Checking Auto Deploy Database"      
      RBD_VC_THUMBPRINT=$(sqlite3 /var/lib/rbd/db "select thumbprint from vc_servers where addr = '$HOSTNAME' collate nocase")
      MACHINE_SSL_THUMB=$($VECS_CLI entry getcert --store MACHINE_SSL_CERT --alias __MACHINE_CERT | openssl x509 -noout -fingerprint -sha1 2>/dev/null | cut -d'=' -f2)
      task "Machine SSL thumbprint"
      if [ -z "$RBD_VC_THUMBPRINT" ]; then
	      statusMessage "BLANK" "GREEN"
      elif [ "$RBD_VC_THUMBPRINT" != "$MACHINE_SSL_THUMB" ]; then
	      statusMessage "MISMATCH" "YELLOW"
		 
		   if [ -n "$1" ]; then
		      read -p $'\nThe Machine SSL thumbprint is mismatched, update thumbprint? [n]: ' UPDATE_RBD_DB_INPUT
			   if [[ "$UPDATE_RBD_DB_INPUT" =~ ^[Yy] ]]; then updateAutoDeployDB; fi
		   fi
	   else
	      statusMessage "MATCHES" "GREEN"
	   fi
   elif [ -n "$1" ]; then
      header "Checking Auto Deploy Database"      
      echo "${YELLOW}The Auto Deploy service is not set to run automatically${NORMAL}"
   fi
}

#------------------------------
# Replace the VMDir certificate
#------------------------------
function replaceVMDirCert() {
   header 'Replace VMware Directory Service Certificate'
   if [ $VMDIR_REPLACE == 'VMCA-SIGNED' ]; then      
      generateCertoolConfig 'vmdir'
      
      task 'Regenerate VMware Directory certificate'
      regenerateVMCASignedCertificate 'vmdir'
      statusMessage 'OK' 'GREEN'

      VMDIR_CERT=$STAGE_DIR/vmdir.crt
      VMDIR_KEY=$STAGE_DIR/vmdir.key
   else
      echo $'\n1. Generate Certificate Signing Request and Private Key'
      echo '2. Generate Certificate Signing Request and Private Key'
      echo '   from custom OpenSSL configuration file'
      echo '3. Import CA-signed Certificate and Key'
      read -p $'\nChoose option [Return to Main Menu]: ' VMDIR_CA_SIGNED_OPTION

      if [ -z "$VMDIR_CA_SIGNED_OPTION" ]; then return 1; fi

      if [ "${VMDIR_CA_SIGNED_OPTION}" == '3' ]; then
	      logInfo 'User has chosen to import a CA-signed VMware Directory certificate and key'
         read -e -p $'\n'"Provide path to CA-signed ${CYAN}VMware Directory Service${NORMAL} certificate: " VMDIR_CERT_INPUT
         while [ ! -f "$VMDIR_CERT_INPUT" ]; do read -e -p "${YELLOW}File not found, please provide path to the VMware Directory Service certificate:${NORMAL} " VMDIR_CERT_INPUT; done
         getCorrectCertFormat "$VMDIR_CERT_INPUT" 'VMDIR_CERT'

         if ! checkCertSignatureAlgorithm "$(cat $VMDIR_CERT)"; then
            errorMessage 'Certificate is using an unsupported signature algorithm' 'vmdir' 'no-task'
         fi

		   VMDIR_CERT_MODULUS_HASH=$(openssl x509 -noout -modulus -in $VMDIR_CERT 2>/dev/null | md5sum | awk '{print $1}')
         
		   getPrivateKey "$VMDIR_CERT_MODULUS_HASH" 'VMDIR' 'VMware Directory Service'    
         getCAChain "$VMDIR_CERT"            
         
         task 'Verifying certificates and keys: '
         verifyCertAndKey $VMDIR_CERT $VMDIR_KEY
      else
         VMDIR_CSR=$REQUEST_DIR/vmdir-$TIMESTAMP.csr
         VMDIR_KEY=$REQUEST_DIR/vmdir-$TIMESTAMP.key

         if [ "${VMDIR_CA_SIGNED_OPTION}" == '1' ]; then
            VMDIR_CFG=$REQUEST_DIR/vmdir.cfg
            if [ -z "$CSR_COUNTRY" ]; then getCSRInfo; fi
            defineSANEntries 'vmdir' 'VMware Directory'
            generateOpensslConfig $HOSTNAME $VMDIR_CFG 'vmdir'
         else
            logInfo 'User has chosen to generate the VMware Directory private key and CSR from a custom OpenSSL configuration file'
            read -e -p $'\nEnter path to custom OpenSSL configuration file: ' VMDIR_CFG
            while [ ! -f "$VMDIR_CFG" ]; do read -e -p $'\n'"${YELLOW}File not found, enter path to custom OpenSSL configuration file:${NORMAL} " VMDIR_CFG; done
         fi
         task "Generating Certificate Signing Request"
         generateCSR $VMDIR_CSR $VMDIR_KEY "$VMDIR_CFG" || errorMessage "Unable to generate Certificate Signing Request and Private Key"
         statusMessage "OK" "GREEN"

         printf "\n\nCertificate Signing Request generated at ${CYAN}${VMDIR_CSR}${NORMAL}"
         printf "\nPrivate Key generated at ${CYAN}${VMDIR_KEY}${NORMAL}\n"

         return 1
      fi
   fi

   if [ $VMDIR_REPLACE != 'VMCA-SIGNED' ]; then
      task 'Publish CA signing certificates'
      publishCASigningCertificates $TRUSTED_ROOT_CHAIN
   fi

   backupFilesystemCertKey '/usr/lib/vmware-vmdir/share/config/vmdircert.pem' '/usr/lib/vmware-vmdir/share/config/vmdirkey.pem' 'VMDir'

   task 'Replace certificate on filesystem'
   cp $VMDIR_CERT /usr/lib/vmware-vmdir/share/config/vmdircert.pem > /dev/null 2>&1 || errorMessage 'Unable to update VMware Directory Services certificate'
   cp $VMDIR_KEY /usr/lib/vmware-vmdir/share/config/vmdirkey.pem > /dev/null 2>&1 || errorMessage 'Unable to update VMware Directory Services private key'
   statusMessage 'OK' 'GREEN'
}

#------------------------------
# Backup certificate and key from VECS
#------------------------------
function backupVECSCertKey() {
   case $1 in
      machine-ssl)
         VECS_STORE='MACHINE_SSL_CERT'
         VECS_ALIAS='__MACHINE_CERT'
         ;;
      *)
         VECS_STORE=$1
         VECS_ALIAS=$1
         ;;
   esac
   
   if [ "$1" == 'machine-ssl' ]; then
      task 'Backing up certificate and private key'
   else
      task "   $1"
   fi
   if $VECS_CLI entry list --store $VECS_STORE | grep $VECS_ALIAS > /dev/null; then
      $VECS_CLI entry getcert --store $VECS_STORE --alias $VECS_ALIAS > $BACKUP_DIR/$1-$TIMESTAMP.crt 2>/dev/null || errorMessage "Unable to backup $1 certificate" 'backup'
      $VECS_CLI entry getkey --store $VECS_STORE --alias $VECS_ALIAS > $BACKUP_DIR/$1-$TIMESTAMP.key 2>/dev/null || errorMessage "Unable to backup $1 private key" 'backup'
      if [ -f $BACKUP_DIR/$1-$TIMESTAMP.crt ] && [ -f $BACKUP_DIR/$1-$TIMESTAMP.key ]; then statusMessage 'OK' 'GREEN'; fi
   else
      statusMessage 'NOT FOUND' 'YELLOW'
   fi
}

#------------------------------
# Replace certificate in VECS
#------------------------------
function updateVECS() {
   case $1 in
      machine-ssl)
         VECS_STORE='MACHINE_SSL_CERT'
         VECS_ALIAS='__MACHINE_CERT'
         VECS_CERT_FILE=$MACHINE_SSL_CERT
         VECS_KEY_FILE=$MACHINE_SSL_KEY
         ;;
      legacy-lookup-service)
         VECS_STORE='STS_INTERNAL_SSL_CERT'
         VECS_ALIAS='__MACHINE_CERT'
         VECS_CERT_FILE=$MACHINE_SSL_CERT
         VECS_KEY_FILE=$MACHINE_SSL_KEY
         ;;
	  data-encipherment)
	     VECS_STORE="$1"
		 VECS_ALIAS="$1"
		 VECS_CERT_FILE=$STAGE_DIR/$1.crt
		 VECS_KEY_FILE=$STAGE_DIR/$1.key
	     ;;
      machine)
         VECS_STORE=$1
         VECS_ALIAS=$1
         VECS_CERT_FILE=$MACHINE_CERT
         VECS_KEY_FILE=$MACHINE_KEY
         ;;
      vpxd)
         VECS_STORE=$1
         VECS_ALIAS=$1
         VECS_CERT_FILE=$VPXD_CERT
         VECS_KEY_FILE=$VPXD_KEY
         ;;
      vpxd-extension)
         VECS_STORE=$1
         VECS_ALIAS=$1
         VECS_CERT_FILE=$VPXD_EXTENSION_CERT
         VECS_KEY_FILE=$VPXD_EXTENSION_KEY
         ;;
      vsphere-webclient)
         VECS_STORE=$1
         VECS_ALIAS=$1
         VECS_CERT_FILE=$VSPHERE_WEBCLIENT_CERT
         VECS_KEY_FILE=$VSPHERE_WEBCLIENT_KEY
         ;;
      wcp)
         VECS_STORE=$1
         VECS_ALIAS=$1
         VECS_CERT_FILE=$WCP_CERT
         VECS_KEY_FILE=$WCP_KEY
         ;;
      hvc)
         VECS_STORE=$1
         VECS_ALIAS=$1
         VECS_CERT_FILE=$HVC_CERT
         VECS_KEY_FILE=$HVC_KEY
         ;;
   esac
   
   if [ "$1" == 'machine-ssl' ] || [ "$1" == 'data-encipherment' ]; then
      task "Updating ${VECS_STORE} certificate"
   else
      task "   $1"
   fi
   if $VECS_CLI entry list --store $VECS_STORE | grep 'Alias :' | grep "$VECS_ALIAS" > /dev/null 2>&1; then
      $VECS_CLI entry delete --store $VECS_STORE --alias $VECS_ALIAS -y > /dev/null 2>&1 || errorMessage "Unable to delete entry $VECS_ALIAS in the VECS store $VECS_STORE"
   fi
   $VECS_CLI entry create --store $VECS_STORE --alias $VECS_ALIAS --cert $VECS_CERT_FILE --key $VECS_KEY_FILE > /dev/null 2>&1 || errorMessage "Unable to create entry $VECS_ALIAS in VECS store $VECS_STORE"
   statusMessage 'OK' 'GREEN'
}

#------------------------------
# Replace certificate in VECS
#------------------------------
function manageSSLTrustAnchors() {
   unset TRUST_ANCHORS_INPUT   
   authenticateIfNeeded
   header 'Manage SSL Trust Anchors'
   echo ' 1. Check SSL Trust Anchors'
   echo ' 2. Update SSL Trust Anchors'
   
   read -p $'\nSelect action [Return to Main Menu]: ' TRUST_ANCHORS_INPUT
   
   case $TRUST_ANCHORS_INPUT in
      1)
         checkSSLTrustAnchors
         ;;
      2)
         SSLTrustAnchorsSelectNode
         updateSSLTrustAnchors
         promptRestartVMwareServices
         ;;
   esac
}

#------------------------------
# List all certificates used as SSL trust anchors
#------------------------------
function checkSSLTrustAnchors() {
   TP_ALGORITHM='sha1'
   TP_REGEX_ITER='19'
   OUTPUT_OPTIONS=''
   header 'Check SSL Trust Anchors'   
   cat << EOF
Additional output options:
 1. None
 2. Show associated Service IDs
 3. Show associated endpoint URIs
 4. Show both associated Service IDs and endpoint URIs
 5. Show the SHA256 fingerprint of the certificates   
EOF
   read -p $'\nPlease select additional information options [1]: ' CHECK_TRUST_ANCHOR_OUTPUT_OPTIONS
   
   case $CHECK_TRUST_ANCHOR_OUTPUT_OPTIONS in
      2)
         OUTPUT_OPTIONS='service-ids'
         ;;
	  
	  3)
         OUTPUT_OPTIONS='endpoints'
         ;;
	  
	  4)
         OUTPUT_OPTIONS='service-ids endpoints'
         ;;
	  
	  5)
         TP_ALGORITHM='sha256'
         TP_REGEX_ITER='31'
         ;;
   esac

   printSSLTrustAnchorInfo "$TP_ALGORITHM" "$TP_REGEX_ITER" "$OUTPUT_OPTIONS"

   getSSODomainNodes
   
   echo ''
   for node in "${SSO_NODES[@]}"; do
      echo "${CYAN}-----Machine SSL Certificate-----${NORMAL}"
      echo "${CYAN}${node}${NORMAL}"
      CURRENT_MACHINE_SSL_CERT_INFO=$(echo | openssl s_client -connect $node:443 2>/dev/null | openssl x509 -text -noout -fingerprint -$TP_ALGORITHM 2>/dev/null | grep -E 'Issuer:|Subject:|Validity|Not Before:|Not After :|Fingerprint' | sed -e 's/SHA[0-9]* Fingerprint/\t&/g' -e "s/Subject:/${GREEN}&${NORMAL}/g" -e "s/[[:xdigit:]]\{2\}\(:[[:xdigit:]]\{2\}\)\{${TP_REGEX_ITER}\}/${YELLOW}&${NORMAL}/g")

      if [ -n "$CURRENT_MACHINE_SSL_CERT_INFO" ]; then
         echo 'Certificate Info:'
         if ! isExpired "$(echo | openssl s_client -connect $node:443 2>/dev/null)" 'hash'; then
            echo "$CURRENT_MACHINE_SSL_CERT_INFO"
         else
            echo "$CURRENT_MACHINE_SSL_CERT_INFO" | sed -e "s/Not Before/${RED}&/"
         fi
      else
         echo "${YELLOW}Unable to get certificate from $node on port 443"
         echo "Please make sure the server is up and the reverse proxy service is running.$NORMAL"
      fi
      echo "${CYAN}---------------------------------${NORMAL}"
   done
}

#------------------------------
# Print SSL trust anchors information
#------------------------------
function printSSLTrustAnchorInfo() {
   CERT_COUNT=1
   TP_ALGORITHM="$1"
   TP_REGEX_ITER="$2"
   OUTPUT_OPTIONS="$3"
   echo -n '' > $STAGE_DIR/trust-anchors.raw
   
   getSSLTrustAnchorHashes

   printf "\n"
   for hash in "${CERT_HASHES[@]}"; do
      echo "${CYAN}-----Endpoint Certificate ${CERT_COUNT}-----${NORMAL}" 
      TEMP_CERT=$(buildCertFromHash "$hash")
      double_encoded_hash=$(echo "$hash" | tr -d '\n' | sed -e 's/.\{76\}/&\r\n/g' | xargs -0 printf "%s\r\n" | base64 -w 0)
      
      if ! isExpired "$TEMP_CERT" 'hash'; then
         DATE_COLOR='NORMAL'
      else
         DATE_COLOR='RED'
      fi
	  
      echo "$TEMP_CERT" | openssl x509 -text -noout -fingerprint -$TP_ALGORITHM 2>/dev/null | grep -E 'Issuer:|Subject:|Validity|Not Before:|Not After :|Fingerprint' | sed -e "s/Not Before/${!DATE_COLOR}&/" -e 's/SHA[0-9]* Fingerprint/\t&/g' -e "s/Subject:/${GREEN}&${NORMAL}/g" -e "s/[[:xdigit:]]\{2\}\(:[[:xdigit:]]\{2\}\)\{${TP_REGEX_ITER}\}/${YELLOW}&${NORMAL}/g"
	  
      if echo "$OUTPUT_OPTIONS" | grep 'service-ids' > /dev/null; then
         USED_BY_SERVICE_IDS=$(getSSLTrustAnchorServiceIds "$hash" "$double_encoded_hash")
         NUM_USED_BY_SERVICE_IDS=$(echo "$USED_BY_SERVICE_IDS" | grep -v '^$' | wc -l)
         echo "Used by $NUM_USED_BY_SERVICE_IDS service registrations:"

         for service in $USED_BY_SERVICE_IDS; do
            echo $'\t'"$service"
         done
	  fi
	  
	  if echo "$OUTPUT_OPTIONS" | grep 'endpoints' > /dev/null; then
         USED_BY_ENDPOINTS=$(getSSLTrustAnchorEndpoints "$hash" "$double_encoded_hash")
         NUM_USED_BY_ENDPOINTS=$(echo "$USED_BY_ENDPOINTS" | grep -v '^$' | wc -l)         
         echo "Used by $NUM_USED_BY_ENDPOINTS endpoints:"
         
         for endpoint in $USED_BY_ENDPOINTS; do
            echo $'\t'"$endpoint"
         done
	  fi
	  echo "${CYAN}--------------------------------${NORMAL}"
      ((++CERT_COUNT))
   done
}

#------------------------------
# Get certificate hashes of unique SSL Trust Anchor
#------------------------------
function getSSLTrustAnchorHashes() {
   CERT_HASHES=()
   LDAP_SEARCH_RESULTS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=Sites,cn=Configuration,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(|(objectclass=vmwLKUPEndpointRegistration)(objectclass=vmwLKUPServiceEndpoint))' vmwLKUPEndpointSslTrust vmwLKUPSslTrustAnchor vmwLKUPURI)
   
   IFS=$'\n'
   dn=''
   attrs=''
   while read line; do
      if [ -n "$line" ]; then
         if [[ "$line" =~ ^dn: ]]; then
	        dn="$line"
	     else
	        if [ -z "$attrs" ]; then 
		       attrs+="$line"
	        else
		       attrs+=$'\n'"$line"
		    fi
	     fi
      else
         echo "$dn" >> $STAGE_DIR/trust-anchors.raw
         echo "$attrs" | sort >> $STAGE_DIR/trust-anchors.raw
         dn=''
         attrs=''
      fi
   done <<<"$LDAP_SEARCH_RESULTS"
   IFS=$' \t\n'
   
   TRUST_ANCHORS=$(cat $STAGE_DIR/trust-anchors.raw | grep -vE '^dn:|^vmwLKUPURI' | awk -F': ' '{print $NF}' | sort | uniq)
   
   for cert in $TRUST_ANCHORS; do 
      if [[ "$cert" =~ ^TUl ]]; then
         CURRENT_CERT=$(echo $cert | base64 --decode | tr -d '\r\n')
      else
         CURRENT_CERT=($cert)
      fi
      if [[ ! "${CERT_HASHES[@]}" =~ "$CURRENT_CERT" ]]; then
         CERT_HASHES+=($CURRENT_CERT)
      fi
   done
}

#------------------------------
# Get the service IDs using a unique SSL Trust Anchor
#------------------------------
function getSSLTrustAnchorServiceIds() {
   USED_BY_SERVICE_IDS=$(cat $STAGE_DIR/trust-anchors.raw | grep -B1 $1 | grep '^dn:' | awk -F',' '{print $2}' | sed -e 's/cn=//g' | sort | uniq)
   USED_BY_SERVICE_IDS+=$'\n'$(cat $STAGE_DIR/trust-anchors.raw | grep -B1 $2 | grep '^dn:' | awk -F',' '{print $2}' | sed -e 's/cn=//g' | sort | uniq | xargs -0 printf "\n%s")
   
   echo "$USED_BY_SERVICE_IDS"
}

#------------------------------
# Get the endpoint URIs using a unique SSL Trust Anchor
#------------------------------
function getSSLTrustAnchorEndpoints() {
   USED_BY_ENDPOINTS=$(cat $STAGE_DIR/trust-anchors.raw | grep -A1 $1 | grep '^vmwLKUPURI' | sed -e 's/vmwLKUPURI: //g' | sort | uniq)              
   USED_BY_ENDPOINTS+=$'\n'$(cat $STAGE_DIR/trust-anchors.raw | grep -A1 $2 | grep '^vmwLKUPURI' | sed -e 's/vmwLKUPURI: //g' | sort | uniq)
   
   echo "$USED_BY_ENDPOINTS"
}

#------------------------------
# Get the PSC and vCenter nodes in an SSO Domain
#------------------------------
function getSSODomainNodes() {
   SSO_NODES=()
   PSC_NODES=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "ou=Domain Controllers,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=computer)' cn | grep '^cn:' | awk '{print $NF}')
   PSC_COUNT=$(echo "$PSC_NODES" | wc -l)
   VCENTER_NODES=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "ou=Computers,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=computer)' cn | grep '^cn:' | awk '{print $NF}')
   VCENTER_COUNT=$(echo "$VCENTER_NODES" | wc -l)
   
   for psc_node in "$PSC_NODES"; do
      if [[ ! "${SSO_NODES[@]}" =~ "$psc_node" ]]; then SSO_NODES+=($psc_node); fi
   done

   for vc_node in "$VCENTER_NODES"; do
      if [[ ! "${SSO_NODES[@]}" =~ "$vc_node" ]]; then SSO_NODES+=($vc_node); fi
   done
}

#------------------------------
# Select which node to update SSL trust anchors
#------------------------------
function SSLTrustAnchorsSelectNode() {
   getSSODomainNodes
   
   NODE_COUNTER=1
   NODE_DEFAULT=1
   PSC_VIP_COUNTER=0   

   printf "\nNodes in SSO domain '$SSO_DOMAIN'\n"
   
   for node in "${SSO_NODES[@]}"; do
      echo " $NODE_COUNTER. $node"
      if [ $HOSTNAME = $node ]; then NODE_DEFAULT=$NODE_COUNTER; fi
      ((++NODE_COUNTER))
   done
   
   if [[ $VCENTER_COUNT -gt 0 && $PSC_COUNT -gt 1 ]]; then
      echo " $NODE_COUNTER. FQDN of PSC Load Balancer"
      PSC_VIP_COUNTER=$NODE_COUNTER
   fi
   
   echo ' C. Custom hostname or IP address'
   
   read -p $'\n'"Select node to update [${NODE_DEFAULT}]: " NODE_SELECT

   if [ -z $NODE_SELECT ]; then
      NODE_FQDN=${SSO_NODES[$((NODE_DEFAULT - 1))]}
      NODE_SSL_FQDN=$NODE_FQDN
   else
      if [[ $PSC_VIP_COUNTER -gt 0 && "${NODE_SELECT}" == "$PSC_VIP_COUNTER" ]]; then
         read -p 'Enter the FQDN of the PSC Load Balancer: ' PSC_LB_FQDN
         while [ -z $PSC_LB_FQDN ]; do
            read -p 'Enter the FQDN of the PSC Load Balancer: ' PSC_LB_FQDN
         done
         NODE_FQDN=$PSC_LB_FQDN
         NODE_SSL_FQDN=$NODE_FQDN
      elif [[ "$NODE_SELECT" =~ ^[Cc] ]]; then
         echo $'\n'"${YELLOW}Note: This operation is used when the endpoint URIs refer to a hostname or IP address"
         echo "other than the target vCenter/PSC hostname or IP address. These situations are very uncommon."
         echo "Only use this option at the direction of VMware Global Support.${NORMAL}"
         read -p $'\nEnter hostname or IP address of registration endpoint URIs to update: ' CUSTOM_NODE_SELECT
         while [ -z "$CUSTOM_NODE_SELECT" ]; do read -p $'\n'"${YELLOW}Enter hostname or IP address of registration endpoint URIs to update:${NORMAL} " CUSTOM_NODE_SELECT; done
         NODE_FQDN="$CUSTOM_NODE_SELECT"
         read -p $'\n'"Enter the hostname or IP address of the node serving the SSL certificate to update [$NODE_FQDN]: " NODE_SSL_FQDN_INPUT
         if [ -z $NODE_SSL_FQDN_INPUT ]; then
            NODE_SSL_FQDN=$NODE_FQDN
         else
            NODE_SSL_FQDN=$NODE_SSL_FQDN_INPUT
         fi
      else
         NODE_FQDN=${SSO_NODES[$((NODE_SELECT - 1))]}
         NODE_SSL_FQDN=$NODE_FQDN
      fi
   fi

   logInfo "User has selected '$NODE_FQDN'"
   logInfo "SSL certificate to update will be obtained from $NODE_SSL_FQDN:443"

   echo | openssl s_client -connect $NODE_SSL_FQDN:443 2>/dev/null | openssl x509 > $STAGE_DIR/trust-anchor-machine-ssl.crt 2>/dev/null
}

#------------------------------
# Setup environment to update SSL trust anchors for the current node
#------------------------------
function SSLTrustAnchorSelf() {
   openssl x509 -in $MACHINE_SSL_CERT >  $STAGE_DIR/trust-anchor-machine-ssl.crt 2>/dev/null
   NODE_FQDN="$PNID"
}

#------------------------------
# Update the SSL trust anchors
#------------------------------
function updateSSLTrustAnchors() {
   TOTAL_SERVICES_UPDATED=0
   header "Update SSL Trust Anchors ($NODE_FQDN)"

   find $STAGE_DIR -type f -iname 'ls-service-reg-*.ldif' -exec rm {} \;

   if [ "$VMDIR_FQDN" != "$PNID" ]; then
      read -r -s -p $'\n'"Enter the root password for $PSC_LOCATION: " SSHPASS
      PSC_INFO=$(sshpass -p "$SSHPASS" ssh -q -o StrictHostKeyChecking=no -t -t root@$PSC_LOCATION "/opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\services\vmdir]' | grep -E 'dcAccountPassword|dcAccountDN'" | grep 'dcAccount')
      
      logInfo "PSC info is: $PSC_INFO"
      
      if [ -z "$PSC_INFO" ]; then
         echo $'\n\n'"${YELLOW}Unable to get machine account password for $PSC_LOCATION."
         echo $'\n'"This is usually because the default shell on the PSC is /bin/appliancesh instead of /bin/bash"
         echo $'\n'"Please change the default shell on $PSC_LOCATION,"
         echo "or run this script on $PSC_LOCATION to update the SSL trust anchors.${NORMAL}"
         
         return 1
      fi
      
      UPDATE_MACHINE_PASSWORD=$(echo "$PSC_INFO" | grep 'dcAccountPassword' | awk -F"  " '{print $NF}' | awk '{print substr($0,2,length($0)-3)}' | sed -e 's/\\"/"/g' -e 's/\\\\/\\/g')
      UPDATE_MACHINE_ACCOUNT_DN=$(echo "$PSC_INFO" | grep 'dcAccountDN' | awk -F"  " '{print $NF}' | awk '{print substr($0,2,length($0)-3)}')
      printf "\n\n"
   else
      UPDATE_MACHINE_ACCOUNT_DN=$VMDIR_MACHINE_ACCOUNT_DN
      UPDATE_MACHINE_PASSWORD=$VMDIR_MACHINE_PASSWORD
   fi

   echo -n "$UPDATE_MACHINE_PASSWORD" > $STAGE_DIR/.update-machine-account-password
   chmod 640 $STAGE_DIR/.update-machine-account-password
   cat $STAGE_DIR/trust-anchor-machine-ssl.crt | grep -vE '^-----' | tr -d '\n' > $STAGE_DIR/trust-anchor-machine-ssl.hash
   openssl x509 -outform der -in $STAGE_DIR/trust-anchor-machine-ssl.crt -out $STAGE_DIR/trust-anchor-machine-ssl.der 2>/dev/null
   SERVICE_REGISTRATION_DNS=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=Sites,cn=Configuration,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password "(&(|(vmwLKUPURI=https://$NODE_FQDN:*)(vmwLKUPURI=https://$NODE_FQDN/*))(|(objectclass=vmwLKUPServiceEndpoint)(objectclass=vmwLKUPEndpointRegistration)))" vmwLKUPEndpointSslTrust vmwLKUPSslTrustAnchor | grep '^dn:' | sed -r 's/cn=Endpoint[0-9]+,//g' | sed -e 's/dn: //g' -e 's/, cn=/,cn=/g' | sort | uniq)
   logInfo 'Service Registration DNs to update:'
   logDetails "'$SERVICE_REGISTRATION_DNS'"
   SSO_ALL_SITES=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -b "cn=Sites,cn=Configuration,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password -s one '(objectclass=*)' cn | grep '^cn:' | awk -F': ' '{print $NF}')

   for svc_dn in $SERVICE_REGISTRATION_DNS; do
      LEGACY_REGISTRATION=0
      
      for site in $SSO_ALL_SITES; do
         SVC_LOWER=$(echo "$svc_dn" | awk -F',' '{print $1}' | awk -F'=' '{print $2}' | tr '[:upper:]' '[:lower:]')
         SITE_LOWER=$(echo "$site" | tr '[:upper:]' '[:lower:]')
         if [[ $SVC_LOWER =~ ^$SITE_LOWER: ]]; then LEGACY_REGISTRATION=1; fi
      done
      
      logInfo "Updating service $svc_dn"      
      if [ $LEGACY_REGISTRATION = 1 ]; then
         updateLegacySSLTrustAnchorTargeted $svc_dn
      else
         updateSSLTrustAnchorTargeted $svc_dn
      fi
   done

   echo "Updated $TOTAL_SERVICES_UPDATED service(s)"

   UPDATED_TRUST_ANCHORS=1

   return 0
}

#------------------------------
# Update a legacy SSL trust anchor
#------------------------------
function updateLegacySSLTrustAnchorTargeted() {
   SERVICE_DN=$1
   SERVICE_ID=$(echo "$SERVICE_DN" | awk -F',' '{print $1}' | awk -F'=' '{print $2}')   
   ENDPOINT_INFO=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "$SERVICE_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(|(objectclass=vmwLKUPServiceEndpoint)(objectclass=vmwLKUPEndpointRegistration))' vmwLKUPEndpointSslTrust vmwLKUPSslTrustAnchor 2>/dev/null | sed -e 's/, cn=/,cn=/g' -e '/^$/d')
   
   IFS=$'\n'
   for line in $ENDPOINT_INFO; do
      if [[ $line =~ ^dn: ]]; then
         CURRENT_DN=$line
      elif [[ $line =~ ^vmwLKUP ]]; then
         echo "$CURRENT_DN" >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
         echo 'changetype: modify' >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
         if echo $line | grep 'vmwLKUPSslTrustAnchor' > /dev/null; then
            echo 'replace: vmwLKUPSslTrustAnchor' >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
            echo "vmwLKUPSslTrustAnchor:< file://$STAGE_DIR/trust-anchor-machine-ssl.der" >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
         else
            echo 'replace: vmwLKUPEndpointSslTrust' >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
            echo "vmwLKUPEndpointSslTrust:< file://$STAGE_DIR/trust-anchor-machine-ssl.hash" >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
         fi
         echo '' >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
      fi
   done
   IFS=$' \t\n'
   if [ -f $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif ]; then
      logInfo "Updating legacy Lookup Service entry: $1"
      logDebug "Contents of LDIF file $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif"
      logDebugDetails "'$(cat $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif)'"
      echo "Updating service: ${SERVICE_ID}"
      if ! $LDAP_MODIFY -v -h $PSC_LOCATION -p $VMDIR_PORT -D "${UPDATE_MACHINE_ACCOUNT_DN}" -y $STAGE_DIR/.update-machine-account-password -f $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif > /dev/null 2>&1; then
         echo 'Error updating service: please check logs for details'
         logError "Error updating service $1, ldapmodify return code: $?"
      else
         logInfo "Service $1 successfully updated"
         ((++TOTAL_SERVICES_UPDATED))
      fi
   fi
}

#------------------------------
# Update an SSL trust anchor
#------------------------------
function updateSSLTrustAnchorTargeted() {
   SERVICE_DN=$1
   SERVICE_ID=$(echo "$SERVICE_DN" | awk -F',' '{print $1}' | awk -F'=' '{print $2}')
   ENDPOINT_INFO=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "$SERVICE_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=vmwLKUPEndpointRegistration)' vmwLKUPEndpointSslTrust 2>/dev/null | sed -e 's/, cn=/,cn=/g' -e '/^$/d')
   
   IFS=$'\n'   
   for line in $ENDPOINT_INFO; do
      if [[ $line =~ ^dn: ]]; then
         CURRENT_DN=$line
      elif [[ $line =~ ^vmwLKUPEndpointSslTrust: ]]; then
         echo "$CURRENT_DN" >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
         echo 'changetype: modify' >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
         echo 'replace: vmwLKUPEndpointSslTrust' >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
         echo "vmwLKUPEndpointSslTrust:< file://$STAGE_DIR/trust-anchor-machine-ssl.hash" >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
         echo '' >> $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif
      fi
   done
   IFS=$' \t\n'
   if [ -f $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif ]; then
      logInfo "Updating Lookup Service entry: $1"
      logDebug "Contents of LDIF file $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif"
      logDebugDetails "'$(cat $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif)'"
      echo "Updating service: $SERVICE_ID"
      if ! $LDAP_MODIFY -v -h $PSC_LOCATION -p $VMDIR_PORT -D "$UPDATE_MACHINE_ACCOUNT_DN" -y $STAGE_DIR/.update-machine-account-password -f $STAGE_DIR/ls-service-reg-$SERVICE_ID.ldif > /dev/null 2>&1; then
         echo 'Error updating service: please check logs for details'
         logError "Error updating service $1, ldapmodify return code: $?"
      else
         logInfo "Service $1 successfully updated"
         ((++TOTAL_SERVICES_UPDATED))
      fi
   fi
}

#------------------------------
# Print configuration check menu
#------------------------------
function checkConfigurationMenu() {
   unset CONFIGURATION_CHECK_INPUT
   header "Configuration Check Menu"
   cat << EOF
 1. Check for SSL Interception
 2. Check STS server certificate configuration
 3. Check SSO Smart Card configuration options
 4. Check VECS store status and permissions
 5. Check Auto Deploy configuration 
EOF
   read -p $'\nSelect an option [Return to Main Menu]: ' CONFIGURATION_CHECK_INPUT
   
   case $CONFIGURATION_CHECK_INPUT in
      1)
         checkSSLInterception
         ;;	  
      2)
         if [ $NODE_TYPE != 'management' ]; then
            checkSTSConfig
         else
            echo $'\n'"${YELLOW}This operation must be done on the Platform Services Controller${NORMAL}"$'\n'
         fi
         ;;	  
      3)
         checkSmartCardOptions
         ;;	  
      4)
         checkVECSStores
         ;;
      5)
         if [ $NODE_TYPE != 'infrastructure' ]; then checkAutoDeployDB 'check'; fi
         ;;
   esac
}

#------------------------------
# Check if SSL Interception is in play
#------------------------------
function checkSSLInterception() {
   header 'Checking for SSL Interception'
   task 'Checking hostupdate.vmware.com'
   HOSTUPDATE_ISSUER=$(echo | openssl s_client -connect hostupdate.vmware.com:443 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null | awk -F'/' '{for(i=1; i<=NF;i++) if($i ~ /^CN/) {print $i}}' |  sed 's/CN=//')
   
   if [ -n "$HOSTUPDATE_ISSUER" ]; then
      statusMessage 'OK' 'GREEN'
      if [ "$HOSTUPDATE_ISSUER" != "$HOSTUPDATE_ISSUER_EXPECTED" ]; then
	     unset DOWNLOAD_PROXY_CA_CERTS_INPUT
         echo $'\n'"Issuing CA for hostupdate.vmware.com is ${YELLOW}${HOSTUPDATE_ISSUER}${NORMAL}"
         echo "The expected issuer is ${GREEN}${HOSTUPDATE_ISSUER_EXPECTED}${NORMAL}"
         echo $'\n'"${YELLOW}SSL Interception is likely taking place.${NORMAL}"
         
         header "SSL Interception Certificate Management"
         echo " 1. Download and import CA certificates from the proxy"
         echo " 2. Import CA certificate(s) from a file"

         read -p $'\nSelect an option [Return to Main Menu]: ' PROXY_CA_CERTS_INPUT
         
         case $PROXY_CA_CERTS_INPUT in
            1)
               downloadProxyCACerts
               ;;
            2)
               provideProxyCACerts
               ;;
         esac
      else
         echo $'\n'"Issuing CA for hostupdate.vmware.com is ${GREEN}${HOSTUPDATE_ISSUER}${NORMAL}"$'\n'
      fi
   else
      statusMessage 'ERROR' 'YELLOW'
      echo $'\n'"${YELLOW}Could not identify the issuer of the certificate for hostupdate.vmware.com"
      echo "Check your network connection and try again.${NORMAL}"$'\n'
   fi
}

#------------------------------
# Download CA certs from proxy used for SSL Interception
#------------------------------
function downloadProxyCACerts() {
   authenticateIfNeeded
   if [ -f $STAGE_DIR/proxy-ca-chain.pem ]; then rm $STAGE_DIR/proxy-ca-chain.pem; fi
   header "Processing Proxy CA certificates"   
   task 'Downloadng certificate chain from the proxy'
   echo | openssl s_client -connect hostupdate.vmware.com:443 2>/dev/null -showcerts | sed -n '/^-----BEGIN CERTIFICATE-----/,/^-----END CERTIFICATE-----/p' | csplit -z -f $STAGE_DIR/proxy-cert- -b%02d.crt /dev/stdin '/-----BEGIN CERTIFICATE-----/' '{*}' 2>&1 | logDebug
   if [ "$(ls -l $STAGE_DIR/proxy-cert* 2>/dev/null)" != '' ]; then
      statusMessage 'OK' 'GREEN'
      for cert in $(ls $STAGE_DIR/proxy-cert-* 2>/dev/null); do 
         if isCertCA "$(cat $cert)"; then cat $cert >> $STAGE_DIR/proxy-ca-chain.pem; fi
      done
      if [ -f $STAGE_DIR/proxy-ca-chain.pem ]; then
         importProxyCACerts

         NUM_PROXY_CA_CERTS=$(ls -l $STAGE_DIR/proxy-cert-* | wc -l)
         CERT_FILE_INDEX=$(printf "%02d" $((NUM_PROXY_CA_CERTS-1)))
         LAST_PROXY_CA_SUBJECT=$(openssl x509 -noout -subject -in $STAGE_DIR/proxy-cert-$CERT_FILE_INDEX.crt 2>/dev/null | sed -e 's/subject= //')
         LAST_PROXY_CA_ISSUER=$(openssl x509 -noout -issuer -in $STAGE_DIR/proxy-cert-$CERT_FILE_INDEX.crt 2>/dev/null | sed -e 's/issuer= //')
            
         if [ "$LAST_PROXY_CA_SUBJECT" != "$LAST_PROXY_CA_ISSUER" ]; then
            echo $'\n'"${YELLOW}There proxy does not provide the Root CA certificate in the chain."
            echo "Please aquire this certificate and import it.${NORMAL}"$'\n'
         fi
      else
         echo $'\n'"${YELLOW}There proxy does not appear to provide any of the CA certificates."
         echo "Please aquire these certificates and import them.${NORMAL}"$'\n'
      fi      
   fi
}

#------------------------------
# Manually provide CA certs that signed proxy certificate used for SSL Interception
#------------------------------
function provideProxyCACerts() {
   authenticateIfNeeded
   if [ -f $STAGE_DIR/proxy-ca-chain.pem ]; then rm $STAGE_DIR/proxy-ca-chain.pem; fi

   read -e -p $'\n'"Enter path to CA certificate (or chain): " PROXY_CA_CERT_INPUT
   while [ ! -f $PROXY_CA_CERT_INPUT ]; do read -e -p $'\n'"${YELLOW}Enter path to CA certificate (or chain):${NORMAL} " PROXY_CA_CERT_INPUT; done

   getCorrectCertFormat "$PROXY_CA_CERT_INPUT" 'PROXY_CA_CERT_FILE'
   csplit -s -z -f $STAGE_DIR/proxy-cert- -b%02d.crt $PROXY_CA_CERT_FILE '/-----BEGIN CERTIFICATE-----/' '{*}'

   if [ "$(ls -l $STAGE_DIR/proxy-cert* 2>/dev/null)" != '' ]; then
      header "Processing Proxy CA certificates"
      task "Checking CA file"
      for cert in $(ls $STAGE_DIR/proxy-cert-* 2>/dev/null); do 
         if isCertCA "$(cat $cert)"; then cat $cert >> $STAGE_DIR/proxy-ca-chain.pem; fi
      done
      if [ -f $STAGE_DIR/proxy-ca-chain.pem ]; then
         statusMessage "OK" "GREEN"
         importProxyCACerts
      else
         errorMessage "No CA certificates found in $PROXY_CA_CERT_INPUT"
      fi
   fi
}

function importProxyCACerts() {
   if [ -f $STAGE_DIR/proxy-ca-chain.pem ]; then
      task 'Publishing certificates to VMware Directory'
      $DIR_CLI trustedcert publish --chain --cert $STAGE_DIR/proxy-ca-chain.pem --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" 2>&1 | logInfo || errorMessage 'Unable to publish proxy CA certificates to VMware Directory'
      statusMessage 'OK' 'GREEN'
      task 'Refreshing CA certificates to VECS'
      $VECS_CLI force-refresh || errorMessage 'Unable to refresh CA certificates in VECS'
      statusMessage 'OK' 'GREEN'

      if [[ "$VC_VERSION" =~ ^[78] ]] && [[ $VC_BUILD -ge 17327517 ]]; then
         if [ ! -f /usr/lib/python3.7/site-packages/certifi/cacert.pem.backup ]; then
            task "Backup Python CA store"
            cp /usr/lib/python3.7/site-packages/certifi/cacert.pem /usr/lib/python3.7/site-packages/certifi/cacert.pem.backup 2>/dev/null || errorMessage "Could not backup the Python CA store at /usr/lib/python3.7/site-packages/certifi/cacert.pem"
            statusMessage "OK" "GREEN"
         fi
         task 'Adding certificates to python CA store'
         cat $STAGE_DIR/proxy-ca-chain.pem >> /usr/lib/python3.7/site-packages/certifi/cacert.pem
         statusMessage 'OK' 'GREEN'

         NUM_PROXY_CERTS_PEM=$(grep 'END CERTIFICATE' $STAGE_DIR/proxy-ca-chain.pem | wc -l)
         NUM_PROXY_CERTS_KEYSTORE=$(keytool -list -keystore /usr/java/jre-vmware/lib/security/cacerts -storepass changeit 2>/dev/null | grep sslproxyca | wc -l)

         if [ ! -f /usr/java/jre-vmware/lib/security/cacerts.backup ]; then
            task "Backup Java keystore"
            cp /usr/java/jre-vmware/lib/security/cacerts /usr/java/jre-vmware/lib/security/cacerts.backup 2>/dev/null || errorMessage "Could not backup the Java keystore at /usr/java/jre-vmware/lib/security/cacerts"
            statusMessage "OK" "GREEN"
         fi
         for N in $(seq 0 $(($NUM_PROXY_CERTS_PEM - 1))); do
            SSL_PROXY_CA_ALIAS="sslproxyca$(($NUM_PROXY_CERTS_KEYSTORE + $N))"
            task "Import $SSL_PROXY_CA_ALIAS to Java keystore"
            cat $STAGE_DIR/proxy-ca-chain.pem | awk "n==$N { print }; /END CERTIFICATE/ { n++ }" | keytool -noprompt -import -file /dev/stdin -trustcacerts -alias "$SSL_PROXY_CA_ALIAS" -storepass changeit -keystore /usr/java/jre-vmware/lib/security/cacerts 2>&1 | logDebug
            statusMessage "OK" "GREEN"
         done
      fi
   fi
}

#------------------------------
# Quick check of the STS server configuration
#------------------------------
function quickCheckSTSConfig() {
   header 'Checking STS Server Configuration'
   task 'Check STS VECS store configuration'
   if quickCheckSTSCertConfig; then
      statusMessage 'OK' 'GREEN'
   else
      statusMessage 'LEGACY' 'YELLOW'
      CERT_STATUS_STS_VECS_CONFIG=1
   fi

   task 'Check STS ConnectionStrings configuration'
   if quickCheckSTSConnectionStrings; then
      statusMessage 'OK' 'GREEN'
   else
      statusMessage 'MISCONFIG' 'YELLOW'
         CERT_STATUS_STS_CONNECTION_STRINGS=1
   fi
}

#------------------------------
# Quick check of the STS server VECS configuration
#------------------------------
function quickCheckSTSCertConfig() {
   STS_LOCALHOST_CONNECTOR_STORE=$(grep 'bio-ssl-localhost.https.port' /usr/lib/vmware-sso/vmware-sts/conf/server.xml | grep 'store=' | awk '{for(i=1;i<=NF;i++) if($i ~ /^store/) {print $i}}' | tr -d '>' | awk -F'=' '{print $NF}' | tr -d '"')
   STS_LOCALHOST_CERTIFICATE_STORE=$(grep -A2 'bio-ssl-localhost.https.port' /usr/lib/vmware-sso/vmware-sts/conf/server.xml | grep 'certificateKeystoreFile=' | awk '{for(i=1;i<=NF;i++) if($i ~ /^certificateKeystoreFile/) {print $i}}' | tr -d '>' | awk -F'=' '{print $NF}' | tr -d '"')
   STS_CLIENTAUTH_CONNECTOR_STORE=$(grep 'bio-ssl-clientauth.https.port' /usr/lib/vmware-sso/vmware-sts/conf/server.xml | grep 'store=' | awk '{for(i=1;i<=NF;i++) if($i ~ /^store/) {print $i}}' | tr -d '>' | awk -F'=' '{print $NF}' | tr -d '"')
   STS_CLIENTAUTH_CERTIFICATE_STORE=$(grep -A2 'bio-ssl-clientauth.https.port' /usr/lib/vmware-sso/vmware-sts/conf/server.xml | grep 'certificateKeystoreFile=' | awk '{for(i=1;i<=NF;i++) if($i ~ /^certificateKeystoreFile/) {print $i}}' | tr -d '>' | awk -F'=' '{print $NF}' | tr -d '"')
   
   if [[ "$VC_VERSION" =~ ^8 ]]; then
      if [ "$STS_LOCALHOST_CONNECTOR_STORE" != 'STS_INTERNAL_SSL_CERT' ] && [ "$STS_LOCALHOST_CERTIFICATE_STORE" != 'STS_INTERNAL_SSL_CERT' ] && [ "$STS_CLIENTAUTH_CONNECTOR_STORE" != 'STS_INTERNAL_SSL_CERT' ] && [ "$STS_CLIENTAUTH_CERTIFICATE_STORE" != 'STS_INTERNAL_SSL_CERT' ]; then
         return 0
      else
         return 1
      fi
   else
      if [ "$STS_LOCALHOST_CONNECTOR_STORE" != 'STS_INTERNAL_SSL_CERT' ] && [ "$STS_LOCALHOST_CERTIFICATE_STORE" != 'STS_INTERNAL_SSL_CERT' ]; then
         return 0
      else
         return 1
      fi
   fi
}

#------------------------------
# Check STS Connection String for ELM configurations
#------------------------------
function quickCheckSTSConnectionStrings() {
   STS_CONNECTION_STRINGS=$($LDAP_SEARCH -LLL -o ldif-wrap=no -h $PSC_LOCATION -p $VMDIR_PORT -b "cn=$SSO_DOMAIN,cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password vmwSTSConnectionStrings | grep vmwSTSConnectionStrings | awk '{print $2}')
   NUM_PSC_NODES=$($LDAP_SEARCH -o ldif-wrap=no -LLL -h $PSC_LOCATION -p $VMDIR_PORT -b "ou=Domain Controllers,$VMDIR_DOMAIN_DN" -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password '(objectclass=computer)' cn | grep '^cn:' | wc -l)
   logInfo "vmwSTSConnectionStrings value: $STS_CONNECTION_STRINGS"
   if [ "$STS_CONNECTION_STRINGS" == "ldap://localhost:$VMDIR_PORT" ]; then
      return 0
   else
      if [ "$NUM_PSC_NODES" -gt 1 ]; then
         return 1
      else
         return 0
      fi
   fi   
}

#------------------------------
# Check of the STS server configuration
#------------------------------
function checkSTSConfig() {
   authenticateIfNeeded

   checkSTSCertConfig

   checkSTSConnectionStrings
}

#------------------------------
# Check configuration of the STS server
#------------------------------
function checkSTSCertConfig() {
   VECS_STORES_TO_REPLACE='STS_INTERNAL_SSL_CERT'
   UPDATE_STS_CONFIG=0
   header 'Checking STS server configuration'   
   task 'Checking VECS store configuration'
   #STS_LOCALHOST_CONNECTOR_STORE=$(grep 'bio-ssl-localhost.https.port' /usr/lib/vmware-sso/vmware-sts/conf/server.xml | grep 'store=' | awk '{for(i=1;i<=NF;i++) if($i ~ /^store/) {print $i}}' | tr -d '>' | awk -F'=' '{print $NF}' | tr -d '"')
   #STS_LOCALHOST_CERTIFICATE_STORE=$(grep -A2 'bio-ssl-localhost.https.port' /usr/lib/vmware-sso/vmware-sts/conf/server.xml | grep 'certificateKeystoreFile=' | awk '{for(i=1;i<=NF;i++) if($i ~ /^certificateKeystoreFile/) {print $i}}' | tr -d '>' | awk -F'=' '{print $NF}' | tr -d '"')
   #STS_CLIENTAUTH_CONNECTOR_STORE=$(grep 'bio-ssl-clientauth.https.port' /usr/lib/vmware-sso/vmware-sts/conf/server.xml | grep 'store=' | awk '{for(i=1;i<=NF;i++) if($i ~ /^store/) {print $i}}' | tr -d '>' | awk -F'=' '{print $NF}' | tr -d '"')
   #STS_CLIENTAUTH_CERTIFICATE_STORE=$(grep -A2 'bio-ssl-clientauth.https.port' /usr/lib/vmware-sso/vmware-sts/conf/server.xml | grep 'certificateKeystoreFile=' | awk '{for(i=1;i<=NF;i++) if($i ~ /^certificateKeystoreFile/) {print $i}}' | tr -d '>' | awk -F'=' '{print $NF}' | tr -d '"')
   STS_LOCALHOST_CONNECTOR_STORE=$(xmllint --xpath 'string(//Server/Service/Connector[@port="${bio-ssl-localhost.https.port}"]/@store)' /usr/lib/vmware-sso/vmware-sts/conf/server.xml)
   STS_LOCALHOST_CERTIFICATE_STORE=$(xmllint --xpath 'string(//Server/Service/Connector[@port="${bio-ssl-localhost.https.port}"]/SSLHostConfig/Certificate/@certificateKeystoreFile)' /usr/lib/vmware-sso/vmware-sts/conf/server.xml)
   STS_CLIENTAUTH_CONNECTOR_STORE=$(xmllint --xpath 'string(//Server/Service/Connector[@port="${bio-ssl-clientauth.https.port}"]/@store)' /usr/lib/vmware-sso/vmware-sts/conf/server.xml)
   STS_CLIENTAUTH_CERTIFICATE_STORE=$(xmllint --xpath 'string(//Server/Service/Connector[@port="${bio-ssl-clientauth.https.port}"]/SSLHostConfig/Certificate/@certificateKeystoreFile)' /usr/lib/vmware-sso/vmware-sts/conf/server.xml)
   statusMessage 'OK' 'GREEN'
   
   if [[ "$VC_VERSION" =~ ^8 ]] || ([[ "$VC_VERSION" =~ ^7 ]] && [ $VC_BUILD -ge 20845200 ]); then
      if [ "$STS_LOCALHOST_CONNECTOR_STORE" == 'MACHINE_SSL_CERT' ] && [ "$STS_LOCALHOST_CERTIFICATE_STORE" == 'MACHINE_SSL_CERT' ] && [ "$STS_CLIENTAUTH_CONNECTOR_STORE" == 'MACHINE_SSL_CERT' ] && [ "$STS_CLIENTAUTH_CERTIFICATE_STORE" == 'MACHINE_SSL_CERT' ]; then
         echo $'\n'"The STS server is using the ${GREEN}MACHINE_SSL_CERT${NORMAL} VECS store."$'\n'
      else
         UPDATE_STS_CONFIG=1
         if [ "$STS_LOCALHOST_CONNECTOR_STORE" != 'STS_INTERNAL_SSL_CERT' ]; then VECS_STORES_TO_REPLACE+=" $STS_LOCALHOST_CONNECTOR_STORE"; fi
         if [ "$STS_LOCALHOST_CERTIFICATE_STORE" != 'STS_INTERNAL_SSL_CERT' ]; then VECS_STORES_TO_REPLACE+=" $STS_LOCALHOST_CERTIFICATE_STORE"; fi
         if [ "$STS_CLIENTAUTH_CONNECTOR_STORE" != 'STS_INTERNAL_SSL_CERT' ]; then VECS_STORES_TO_REPLACE+=" $STS_CLIENTAUTH_CONNECTOR_STORE"; fi
         if [ "$STS_CLIENTAUTH_CERTIFICATE_STORE" != 'STS_INTERNAL_SSL_CERT' ]; then VECS_STORES_TO_REPLACE+=" $STS_CLIENTAUTH_CERTIFICATE_STORE"; fi
         echo $'\nThe STS server is using the following VECS stores:'
         echo "Server > Service > Connector (localhost port): ${YELLOW}${STS_LOCALHOST_CONNECTOR_STORE}${NORMAL}"
         echo "Server > Service > Connector (localhost port) > SSLHostConfig > Certificate: ${YELLOW}${STS_LOCALHOST_CERTIFICATE_STORE}${NORMAL}"
         echo "Server > Service > Connector (client auth port): ${YELLOW}${STS_CLIENTAUTH_CONNECTOR_STORE}${NORMAL}"
         echo "Server > Service > Connector (client auth port) > SSLHostConfig > Certificate: ${YELLOW}${STS_CLIENTAUTH_CERTIFICATE_STORE}${NORMAL}"$'\n'
      fi
   else
      if [ "$STS_LOCALHOST_CONNECTOR_STORE" == 'MACHINE_SSL_CERT' ] && [ "$STS_LOCALHOST_CERTIFICATE_STORE" == 'MACHINE_SSL_CERT' ]; then
         echo $'\n'"The STS server is using the ${GREEN}MACHINE_SSL_CERT${NORMAL} VECS store."$'\n'
      else
         UPDATE_STS_CONFIG=1
         if [ "$STS_LOCALHOST_CONNECTOR_STORE" != 'STS_INTERNAL_SSL_CERT' ]; then VECS_STORES_TO_REPLACE+=" $STS_LOCALHOST_CONNECTOR_STORE"; fi
         if [ "$STS_LOCALHOST_CERTIFICATE_STORE" != 'STS_INTERNAL_SSL_CERT' ]; then VECS_STORES_TO_REPLACE+=" $STS_LOCALHOST_CERTIFICATE_STORE"; fi
         echo $'\nThe STS server is using the following VECS stores:'
         echo "Server > Service > Connector (localhost port): ${YELLOW}${STS_LOCALHOST_CONNECTOR_STORE}${NORMAL}"
         echo "Server > Service > Connector (localhost port) > SSLHostConfig > Certificate: ${YELLOW}${STS_LOCALHOST_CERTIFICATE_STORE}${NORMAL}"$'\n'         
      fi
   fi
   if [ $UPDATE_STS_CONFIG -eq 1 ]; then
      read -p $'\n'"Update STS server configuration to use the ${GREEN}MACHINE_SSL_CERT${NORMAL} store? [n]: " UPDATE_STS_CONFIG_INPUT
     
      if [ -z $UPDATE_STS_CONFIG_INPUT ]; then UPDATE_STS_CONFIG_INPUT='n'; fi
     
      if [[ $UPDATE_STS_CONFIG_INPUT =~ ^[Yy] ]]; then
         logInfo 'User has selected to update the STS server configuration'
         header 'Updating STS server configuration'
         task 'Backing up configuration'
         cp /usr/lib/vmware-sso/vmware-sts/conf/server.xml /usr/lib/vmware-sso/vmware-sts/conf/server.xml.backup 2>/dev/null || errorMessage 'Unable to backup /usr/lib/vmware-sso/vmware-sts/conf/server.xml'
         statusMessage 'OK' 'GREEN'

         task 'Backing up certificate'
         $VECS_CLI entry getcert --store STS_INTERNAL_SSL_CERT --alias __MACHINE_CERT > $BACKUP_DIR/STS_INTERNAL_SSL_CERT.crt || errorMessage 'Unable to backup STS_INTERNAL_SSL_CERT certificate'
         statusMessage 'OK' 'GREEN'

         task 'Backing up private key'
         $VECS_CLI entry getkey --store STS_INTERNAL_SSL_CERT --alias __MACHINE_CERT > $BACKUP_DIR/STS_INTERNAL_SSL_CERT.key || errorMessage 'Unable to backup STS_INTERNAL_SSL_CERT private key'
         statusMessage 'OK' 'GREEN'
         
         task 'Changing STS server configuration'
         for store in $VECS_STORES_TO_REPLACE; do
            sed -i "s/$store/MACHINE_SSL_CERT/g" /usr/lib/vmware-sso/vmware-sts/conf/server.xml || errorMessage 'Unable to update STS server configuration'
         done
         statusMessage 'OK' 'GREEN'

         if $VECS_CLI store list | grep 'STS_INTERNAL_SSL_CERT' > /dev/null; then          
            task 'Remove legacy STS VECS store'
            $VECS_CLI store delete --name STS_INTERNAL_SSL_CERT -y > /dev/null|| errorMessage 'Unable to delete VECS store STS_INTERNAL_SSL_CERT'
            statusMessage 'OK' 'GREEN'
         fi

         task 'Stopping STS service'
         service-control --stop vmware-stsd > /dev/null 2>&1 || errorMessage 'Unable to stop the STS service'
         statusMessage 'OK' 'GREEN'
        
         task 'Starting STS service'
         service-control --start vmware-stsd > /dev/null 2>&1 || errorMessage 'Unable to start the STS service'
         statusMessage 'OK' 'GREEN'
      fi
   else
      if $VECS_CLI store list | grep 'STS_INTERNAL_SSL_CERT' > /dev/null; then
         read -p 'Legacy STS SSL certificate store found. Remove store from VECS [n]: ' REMOVE_STS_STORE_INPUT

         if [ -z $REMOVE_STS_STORE_INPUT ]; then REMOVE_STS_STORE_INPUT='n'; fi

         if [[ "$REMOVE_STS_STORE_INPUT" =~ ^[Yy] ]]; then
            echo ''
            task 'Remove legacy STS VECS store'
            $VECS_CLI store delete --name STS_INTERNAL_SSL_CERT -y > /dev/null|| errorMessage 'Unable to delete VECS store STS_INTERNAL_SSL_CERT'
            statusMessage 'OK' 'GREEN'
         else
            echo ''
         fi         
      fi
   fi
}

function checkSTSConnectionStrings() {
   task 'Checking STS ConnectionStrings'
   if quickCheckSTSConnectionStrings; then
      statusMessage 'OK' 'GREEN'
   else
      statusMessage 'MISCONFIG' 'YELLOW'

      read -p $'\n'"Update STS ConnectionStrings value to ${GREEN}ldap://localhost:${VMDIR_PORT}${NORMAL}? [n]: " UPDATE_STS_CONNECTIONSTRINGS

      if [ -z $UPDATE_STS_CONNECTIONSTRINGS ]; then UPDATE_STS_CONNECTIONSTRINGS='n'; fi

      if [[ $UPDATE_STS_CONNECTIONSTRINGS =~ ^[Yy] ]]; then
         header 'Update STS ConnectionStrings'
         task 'Change ConnectionStrings value'
         $LDAP_MODIFY -h $PSC_LOCATION -p $VMDIR_PORT -D "cn=$VMDIR_USER,cn=users,$VMDIR_DOMAIN_DN" -y $STAGE_DIR/.vmdir-user-password 2>&1 >> $LOG <<EOF
dn: cn=$SSO_DOMAIN,cn=IdentityProviders,cn=$SSO_DOMAIN,cn=Tenants,cn=IdentityManager,cn=Services,$VMDIR_DOMAIN_DN
changetype: modify
replace: vmwSTSConnectionStrings
vmwSTSConnectionStrings: ldap://localhost:$VMDIR_PORT
EOF
         if [ $? -eq 0 ]; then
            statusMessage 'OK' 'GREEN'
         else
            errorMessage 'Unable to update the STS ConnectionStrings value. See log for details'
         fi
      fi
   fi
}

#------------------------------
# Check Smart Card configuration options
#------------------------------
function checkSmartCardOptions() {
   header 'Smart Card SSO options'
   echo -n 'Gathering authn SSO options...'
   SC_SSO_CONFIG=$(sso-config.sh -get_authn_policy -t $SSO_DOMAIN 2>/dev/null)
   if [ -n "$SC_SSO_CONFIG" ]; then
      echo -ne "\r"
      SC_SSO_USE_CRL=$(echo "$SC_SSO_CONFIG" | grep useCertCRL | awk '{print $NF}')
      SC_SSO_CRL_URL=$(echo "$SC_SSO_CONFIG" | grep CRLUrl | awk '{print $NF}')
      SC_SSO_CRL_FAILOVER=$(echo "$SC_SSO_CONFIG" | grep useCRLAsFailOver | awk '{print $NF}')
      SC_SSO_USE_OCSP=$(echo "$SC_SSO_CONFIG" | grep useOCSP | awk '{print $NF}')
   
      task 'Use CRL in certificate'
      if [ "$SC_SSO_USE_CRL" == 'false' ]; then
         statusMessage 'FALSE' 'YELLOW'
      else
         statusMessage 'TRUE' 'GREEN'
      fi
   
      task 'CRL override URL'
      if [ "$SC_SSO_CRL_URL" == 'UndefinedConfig' ]; then
         statusMessage 'NONE' 'YELLOW'
      else
         statusMessage "$SC_SSO_CRL_URL" 'GREEN'
      fi
   
      task 'Use CRL as failover'
      if [ "$SC_SSO_CRL_FAILOVER" == 'false' ]; then
         statusMessage 'FALSE' 'YELLOW'
      else
         statusMessage 'TRUE' 'GREEN'
      fi
   
      task 'Use OCSP'
      if [ "$SC_SSO_USE_OCSP" == 'false' ]; then
         statusMessage 'FALSE' 'YELLOW'
      else
         statusMessage 'TRUE' 'GREEN'
      fi
   else
      echo -ne "\r"
	  echo "${YELLOW}Unable to obtain SSO Authn policy options.${NORMAL}"
   fi
}

#------------------------------
# Manage ESXi certificates
#------------------------------
function manageESXiCertificates() {
   authenticateIfNeeded
   unset ESXI_MANAGE_INPUT
   header 'Manage ESXi Certificates'
   echo ' 1. Check ESXi/vCenter certificate trust'
   echo ' 2. Check ESXi certificate against vCenter database'
   echo ' 3. Replace ESXi certificate'
   
   read -p $'\nSelect an option [Return to Main Menu]: ' ESXI_MANAGE_INPUT
   
   case $ESXI_MANAGE_INPUT in
      1)
         checkESXivCenterTrustMenu
         ;;	 
      2)
         checkESXiAgainstVCDBMenu
         ;;
      3)
         replaceESXiCertificate
         ;;
   esac
}

#------------------------------
# Check certificates trust of ESXi hosts and vCenter
#------------------------------
function checkESXivCenterTrustMenu() {
   NUM_HOSTS=$($PSQL -d VCDB -U postgres -c "SELECT COUNT(id) FROM vpx_host WHERE enabled=1" -t | tr -d ' \n')
   
   echo $'\n'"There are ${GREEN}${NUM_HOSTS}${NORMAL} hosts connected to vCenter."$'\n'
   cat << EOF
 1. Perform check on all hosts (requires uniform root password on all hosts)
 2. Perform check on all hosts in a cluster (requires uniform root password on all hosts)
 3. Perform check on single host
EOF
   read -p $'\nSelect an option [Return to Main Menu]: ' ESXI_TRUST_INPUT
   
   CERT_MGMT_MODE=$($PSQL -d VCDB -U postgres -c "SELECT value FROM vpx_parameter WHERE name='vpxd.certmgmt.mode'" -t | grep -v '^$' | tr -d ' ')
   
   case $ESXI_TRUST_INPUT in
      1)
         checkAllESXivCenterTrust "$CERT_MGMT_MODE"
         ;;
      2)
         checkClusteredESXivCenterTrust "$CERT_MGMT_MODE"
         ;;
      3)
         checkSingleESXivCenterTrust "$CERT_MGMT_MODE"
         ;;
   esac
}

#------------------------------
# Check ESXi certificate against vCenter database
#------------------------------
function checkESXiAgainstVCDBMenu() {
   NUM_HOSTS=$($PSQL -d VCDB -U postgres -c "SELECT COUNT(id) FROM vpx_host WHERE enabled=1" -t | tr -d ' \n')
   
   echo $'\n'"There are ${GREEN}${NUM_HOSTS}${NORMAL} hosts connected to vCenter."$'\n'
   cat << EOF
 1. Perform check on all hosts
 2. Perform check on all hosts in a cluster
 3. Perform check on single host
EOF
   read -p $'\nSelect an option [Return to Main Menu]: ' ESXI_CERT_VCDB_INPUT

   CERT_MGMT_MODE=$($PSQL -d VCDB -U postgres -c "SELECT value FROM vpx_parameter WHERE name='vpxd.certmgmt.mode'" -t | grep -v '^$' | tr -d ' ')
   
   case $ESXI_CERT_VCDB_INPUT in
      1)
         checkAllESXiAgainstVCDB "$CERT_MGMT_MODE"
         ;;
      2)
         checkClusteredESXiAgainstVCDB "$CERT_MGMT_MODE"
         ;;
      3)
         checkSingleESXiAgainstVCDB "$CERT_MGMT_MODE"
         ;;
   esac
}

#------------------------------
# List clusters in vCenter inventory
#------------------------------
function listVCClusters() {
   CLUSTER_IDS=()
   CLUSTER_NAMES=()
   unset CHECK_CLUSTER_INPUT
   
   CLUSTERS=$($PSQL -d VCDB -U postgres -c "SELECT ent.id,ent.name FROM vpx_entity AS ent LEFT JOIN vpx_object_type AS obj ON ent.type_id = obj.id WHERE obj.name = 'CLUSTER_COMPUTE_RESOURCE'" -t)
   echo $'\nCompute clusters:'
   i=1
   logInfo 'List of clusters:'
   logDetails $CLUSTERS
   
   IFS=$'\n'
   for cluster in $CLUSTERS; do
      id=$(echo "$cluster" | awk -F'|' '{print $1}' | sed -e 's/[[:space:]]*//')
      name=$(echo "$cluster" | awk -F'|' '{print $2}' | sed -e 's/[[:space:]]*//')
      "$name"
      CLUSTER_IDS+=($id)
      CLUSTER_NAMES+=($name)
      ((++i))
   done
   IFS=$' \t\n'
   
   read -p $'\n\nSelect cluster: ' CHECK_CLUSTER_INPUT
}

#------------------------------
# Check certificates of all ESXi hosts
#------------------------------
function checkAllESXivCenterTrust() {
   HOSTS=$($PSQL -d VCDB -U postgres -c "SELECT id, dns_name, ip_address FROM vpx_host WHERE enabled=1 ORDER BY dns_name ASC, ip_address ASC" -t)
   
   checkESXivCenterTrust "$1" "$HOSTS"
}

#------------------------------
# Check certificates of ESXi hosts in a cluster
#------------------------------
function checkClusteredESXivCenterTrust() {
   listVCClusters
   
   while [ -z $CHECK_CLUSTER_INPUT ]; do read -p $'\n'"${YELLOW}Select cluster:${NORMAL} " CHECK_CLUSTER_INPUT; done
   
   HOSTS=$($PSQL -d VCDB -U postgres -c "SELECT id, dns_name, ip_address FROM vpx_host WHERE id IN (SELECT e.id FROM vpx_entity AS e LEFT JOIN vpx_object_type AS obj ON e.type_id=obj.id WHERE obj.name='HOST' AND e.parent_id=${CLUSTER_IDS[$((CHECK_CLUSTER_INPUT-1))]}) AND enabled=1 ORDER BY dns_name ASC, ip_address ASC" -t)
   
   checkESXivCenterTrust "$1" "$HOSTS"
}

#------------------------------
# Check certificate trust status between vCenter and ESXi hosts
#------------------------------
function checkESXivCenterTrust() {
   NEED_TO_RESTART_SPS=0
   ENTRIES_UPDATED=0
   ENTRIES_CREATED=0   
   HOSTS="$2"
   
   read -r -s -p $'\nEnter root password for all ESXi hosts: ' ESXI_PASSWORD_INPUT
   
   while [ -z $ESXI_PASSWORD_INPUT ]; do read -r -s -p $'\n'"${YELLOW}Enter root password for all ESXi hosts:${NORMAL} " ESXI_PASSWORD_INPUT; done
   echo $'\n\n'"Certificate Management Mode: ${GREEN}$1${NORMAL}"
   
   IFS=$'\n'
   for host_info in $HOSTS; do
      id=$(echo "$host_info" | awk -F'|' '{print $1}' | tr -d ' ')   
      name=$(echo "$host_info" | awk -F'|' '{print $2}' | tr -d ' ')
      ip=$(echo "$host_info" | awk -F'|' '{print $3}' | tr -d ' ')

      if [ -n "$name" ]; then
         viewESXiCertificateTrust "$name" "$1" "$ESXI_PASSWORD_INPUT"
      else
         viewESXiCertificateTrust "$ip" "$1" "$ESXI_PASSWORD_INPUT"
      fi
   done   
   IFS=$' \t\n'
   
   if [ "$1" == 'thumbprint' ]; then
      echo $'\n'"Entries updated: $ENTRIES_UPDATED"
      echo "Entries created: $ENTRIES_CREATED"
	  
      if [ $NEED_TO_RESTART_SPS -gt 0 ]; then
         echo $'\nRestarting the SPS service...'

         restartVMwareServices 'vmware-sps'
      else
         echo $'\nDone!'
fi
   fi
}

#------------------------------
# Check certificates of a single ESXi host
#------------------------------
function checkSingleESXivCenterTrust() {
   header 'ESXi Certificate Trust Check'
   unset ESXI_NAME_INPUT
   read -p 'Enter FQDN or IP of the ESXi host: ' ESXI_NAME_INPUT
   
   while [ -z $ESXI_NAME_INPUT ]; do read -p 'Enter FQDN or IP of the ESXi host: ' ESXI_NAME_INPUT; done
   
   ESXI_VALID_NAME=0

   while [ $ESXI_VALID_NAME -eq 0 ]; do
      if [[ $ESXI_NAME_INPUT =~ ^[a-zA-Z] ]]; then
         logDetails "Verifying name resolution of $ESXI_NAME_INTPUT"
         if ! nslookup $ESXI_NAME_INPUT > /dev/null 2>&1; then 
            read -p $'\n'"${YELLOW}Unable to resolve '$ESXI_NAME_INPUT', enter FQDN or IP of the ESXi host:${NORMAL} " ESXI_NAME_INPUT
         else
            ESXI_VALID_NAME=1
         fi
      else
         if ! validateIp $ESXI_NAME_INPUT; then 
            read -p $'\n'"${YELLOW}Invalid IP address, enter FQDN or IP of the ESXi host:${NORMAL} " ESXI_NAME_INPUT
         else
            ESXI_VALID_NAME=1
         fi
      fi
   done
   
   read -r -s -p $'\n'"Enter root password for $ESXI_NAME_INPUT: " ESXI_PASSWORD_INPUT
   
   while [ -z $ESXI_PASSWORD_INPUT ]; do read -r -s -p $'\n'"${YELLOW}Enter root password for $ESXI_NAME_INPUT:${NORMAL} " ESXI_PASSWORD_INPUT; done
   
   echo $'\n\n'"Certificate Management Mode: ${GREEN}$1${NORMAL}"
   
   viewESXiCertificateTrust "$ESXI_NAME_INPUT" "$1" "$ESXI_PASSWORD_INPUT"
}

#------------------------------
# View trust information between vCenter and a host
#------------------------------
function viewESXiCertificateTrust() {
   echo $'\n'"Host: ${CYAN}$1${NORMAL}"
   HOST_HASH=$(timeout 3 openssl s_client -connect $1:443 2>/dev/null | openssl x509 2>/dev/null)
   
   if [ -n "$HOST_HASH" ]; then
      HOST_CERT_INFO=$(viewCertificateInfo "$HOST_HASH")
      HOST_CERT_ISSUER=$(echo "$HOST_CERT_INFO" | grep 'Issuer:' | awk -F'Issuer: ' '{print $NF}')
      HOST_CERT_SUBJECT=$(echo "$HOST_CERT_INFO" | grep 'Subject:' | awk -F'Subject: ' '{print $NF}')
      HOST_CERT_VALID_START=$(echo "$HOST_HASH" | openssl x509 -noout -startdate 2>/dev/null | sed 's/notBefore=//')
      HOST_CERT_VALID_END=$(echo "$HOST_HASH" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
      HOST_CERT_FINGERPRINT=$(echo "$HOST_HASH" | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
      HOST_CERT_ALGORITHM=$(echo "$HOST_CERT_INFO" | grep 'Signature Algorithm' | head -n1 | awk '{print $NF}')
      HOST_CERT_SAN=$(echo "$HOST_CERT_INFO" | grep 'X509v3 Subject Alternative Name' -A1 | tail -n1 | sed -e 's/^ *//g' -e 's/, /\n/g' | grep -v '^$' | sort)
	  
      echo "   Issuer: $HOST_CERT_ISSUER"
      echo "   Subject: $HOST_CERT_SUBJECT"
      if isExpired "$HOST_HASH" 'hash'; then echo "${RED}"; fi
      echo "      Not Before: $HOST_CERT_VALID_START"
      echo "      Not After : $HOST_CERT_VALID_END"
      echo "      ${NORMAL}SHA1 Fingerprint : $HOST_CERT_FINGERPRINT"
      echo "      Signature Algorithm: $HOST_CERT_ALGORITHM"

      echo '      Subject Alternative Name entries:'
      if [ -n "$HOST_CERT_SAN" ]; then         
         IFS=$'\n'
         for san in $(echo "$HOST_CERT_SAN"); do
            echo "         |_$san"
         done
         IFS=$' \t\n'
      fi

      echo $'\n   Certificate Trusts:'	  
	  
      if [ "$2" = 'thumbprint' ]; then
         CURRENT_HOST_SMS_THUMBPRINT=$($VECS_CLI entry getcert --store SMS --alias "https://$1:9080/version.xml" 2>/dev/null | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F'=' '{print $NF}')
		 
         if [ -n "$CURRENT_HOST_SMS_THUMBPRINT" ]; then
            echo '      Host IOFILTER provider found in VECS, checking certificate...'              
      
            if [[ "$CURRENT_SMS_THUMBPRINT" != "$HOST_THUMBPRINT" ]]; then
               echo '      Mismatch found, re-creating entry...'
               if $VECS_CLI entry delete --store SMS --alias "https://$1:9080/version.xml" -y > /dev/null; then
                  if echo | openssl s_client -connect $1:443 2>/dev/null | openssl x509 > $STAGE_DIR/$1.crt 2>/dev/null; then
                     if $VECS_CLI entry create --store SMS --alias "https://$1:9080/version.xml" --cert $STAGE_DIR/$1.crt > /dev/null; then
                        echo '      IOFILTER provider certificate updated!'
                        ((++ENTRIES_UPDATED))
                        NEED_TO_RESTART_SPS=1
                     else
                        echo "      ${YELLOW}Unable to re-create the IOFILTER provider certificate in VECS!${NORMAL}"
                     fi
                  else
                     echo "      ${YELLOW}Unable to obtain host's SSL certificate on port 443!${NORMAL}"
                  fi
               else
                  echo "      ${YELLOW}Unable to delete the IOFILTER provider certificate from VECS!${NORMAL}"
               fi
            else
               echo "      ${GREEN}Certificate matches, no need to update.${NORMAL}" 
            fi
         else
            echo '      Host IOFILTER provider certificate not in VECS. Creating entry...'
            if echo | openssl s_client -connect $1:443 2>/dev/null | openssl x509 > $STAGE_DIR/$1.crt 2>/dev/null; then
               if $VECS_CLI entry create --store SMS --alias "https://$1:9080/version.xml" --cert $STAGE_DIR/$1.crt > /dev/null; then
                  echo '      IOFILTER provider certificate created!'
                  ((++ENTRIES_CREATED))
                  NEED_TO_RESTART_SPS=1
               else
                  echo "      ${YELLOW}Unable to re-create the IOFILTER provider certificate in VECS!${NORMAL}"
               fi
            else
               echo "      ${YELLOW}Unable to obtain host's SSL certificate on port 443!${NORMAL}"
            fi
         fi
      else
         HOST_RHTTPPROXY_CERT=$(echo | openssl s_client -connect $1:443 2>/dev/null | openssl x509 2>/dev/null)
         HOST_IOFILTERVP_CERT=$(echo | openssl s_client -connect $1:9080 2>/dev/null | openssl x509 2>/dev/null)
         VCENTER_MACHINE_SSL_CERT=$($VECS_CLI entry getcert --store MACHINE_SSL_CERT --alias __MACHINE_CERT)
         SPS_CERT=$($VECS_CLI entry getcert --store SMS --alias sms_self_signed)
		 
         echo -n '      Reverse Proxy cert (port 443): '
		 
         SEARCH_CERTS="$(find /etc/vmware-vpx/docRoot/certs/ -type f | grep -v '\.r')"
         if checkForCACerts "$HOST_RHTTPPROXY_CERT"; then
            echo "${GREEN}Trusted by vCenter${NORMAL}"
         else
            echo "${YELLOW}Not trusted by vCenter${NORMAL}"
         fi
		 
         echo -n '      IOFilter VASA provider cert (port 9080): '
         if [ -n "$HOST_IOFILTERVP_CERT" ]; then
            if checkForCACerts "$HOST_IOFILTERVP_CERT"; then
               echo "${GREEN}Trusted by vCenter${NORMAL}"
            else
               echo "${YELLOW}Not trusted by vCenter${NORMAL}"
            fi
         else
	        echo "${YELLOW}unknown${NORMAL}"
         fi
         ESXI_CASTORE_HTTP_CODE=$(curl -k -X GET -u "root:$3" https://$1/host/castore -o $STAGE_DIR/$1-castore.pem -s -w "%{http_code}\n")
         logInfo "Getting castore.pem file from host $1"
         logInfo "Response from host $1 - HTTP status code: $ESXI_CASTORE_HTTP_CODE"
         if [  "$ESXI_CASTORE_HTTP_CODE" == '200' ]; then
            sed -i '/^$/d' $STAGE_DIR/$1-castore.pem
            csplit -s -z -f $STAGE_DIR/$1-ca- -b %02d.crt $STAGE_DIR/$1-castore.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
			
            SEARCH_CERTS=$(ls $STAGE_DIR/$1-ca-*.crt 2>/dev/null)
			
            if [ -n "$SEARCH_CERTS" ]; then
               echo -n '      vCenter Machine SSL cert: '
               if checkForCACerts "$VCENTER_MACHINE_SSL_CERT"; then
                  echo "${GREEN}Trusted by host${NORMAL}"
               else
                  echo "${YELLOW}Not trusted by host${NORMAL}"
               fi
			
               echo -n '      SPS service connection: '
               if checkForCACerts "$SPS_CERT"; then
                  echo "${GREEN}Trusted by host${NORMAL}"
               else
                  echo "${YELLOW}Not trusted by host (maybe)${NORMAL}"
               fi
            else
               echo "      vCenter Machine SSL cert: ${YELLOW}No CA certs in /etc/vmware/ssl/castore.pem${NORMAL}"
               echo "      SPS service connection: ${YELLOW}No CA certs in /etc/vmware/ssl/castore.pem${NORMAL}"
            fi
         elif [  "$ESXI_CASTORE_HTTP_CODE" == '401' ]; then
            echo "      vCenter Machine SSL cert: ${YELLOW}unknown (possible bad ESXi root password)${NORMAL}"			
            echo "      SPS service connection: ${YELLOW}unknown (possible bad ESXi root password)${NORMAL}"
         else
            echo "      vCenter Machine SSL cert: ${YELLOW}unknown${NORMAL}"			
            echo "      SPS service connection: ${YELLOW}unknown${NORMAL}"
         fi
      fi
   else
      echo $'\n'"${YELLOW}Unable to obtain SSL certificate from host $1.${NORMAL}"
   fi
}

#------------------------------
# Check the SSL certificate of all ESXi hosts against VCDB
#------------------------------
function checkAllESXiAgainstVCDB() {
   HOSTS=$($PSQL -d VCDB -U postgres -c "SELECT id, dns_name, ip_address FROM vpx_host WHERE enabled=1 ORDER BY dns_name ASC, ip_address ASC" -t)
   
   checkESXiAgainstVCDB "$1" "$HOSTS"
}

#------------------------------
# Check the SSL certificate of ESXi hosts in a cluster against VCDB
#------------------------------
function checkClusteredESXiAgainstVCDB() {
   listVCClusters
   
   while [ -z $CHECK_CLUSTER_INPUT ]; do read -p $'\n'"${YELLOW}Select cluster:${NORMAL} " CHECK_CLUSTER_INPUT; done
   
   HOSTS=$($PSQL -d VCDB -U postgres -c "SELECT id, dns_name, ip_address FROM vpx_host WHERE id IN (SELECT e.id FROM vpx_entity AS e LEFT JOIN vpx_object_type AS obj ON e.type_id=obj.id WHERE obj.name='HOST' AND e.parent_id=${CLUSTER_IDS[$((CHECK_CLUSTER_INPUT-1))]}) AND enabled=1 ORDER BY dns_name ASC, ip_address ASC" -t)
   
   checkESXiAgainstVCDB "$1" "$HOSTS"
}

#------------------------------
# Check the SSL certificate of a single ESXi host against VCDB
#------------------------------
function checkSingleESXiAgainstVCDB() {
   unset ESXI_NAME_INPUT
   read -p 'Enter FQDN or IP of the ESXi host: ' ESXI_NAME_INPUT
   
   while [ -z $ESXI_NAME_INPUT ]; do read -p 'Enter FQDN or IP of the ESXi host: ' ESXI_NAME_INPUT; done
   
   ESXI_VALID_NAME=0

   while [ $ESXI_VALID_NAME -eq 0 ]; do
      if [[ $ESXI_NAME_INPUT =~ ^[a-zA-Z] ]]; then
         logDetails "Verifying name resolution of $ESXI_NAME_INTPUT"
         if ! nslookup $ESXI_NAME_INPUT > /dev/null 2>&1; then 
            read -p $'\n'"${YELLOW}Unable to resolve '$ESXI_NAME_INPUT', enter FQDN or IP of the ESXi host:${NORMAL} " ESXI_NAME_INPUT
         else
            HOSTS="|$ESXI_NAME_INPUT|"
            ESXI_VALID_NAME=1
         fi
      else
         if ! validateIp $ESXI_NAME_INPUT; then 
            read -p $'\n'"${YELLOW}Invalid IP address, enter FQDN or IP of the ESXi host:${NORMAL} " ESXI_NAME_INPUT
         else
            HOSTS="||$ESXI_NAME_INPUT"
            ESXI_VALID_NAME=1
         fi
      fi
   done

   checkESXiAgainstVCDB "$1" "$HOSTS"

}

#------------------------------
# Output information on SSL certificate of a host compared to VCDB
#------------------------------
function checkESXiAgainstVCDB() {
   header 'Checking ESXi SSL Thumbprints Against vCenter Database'
   if [ "$1" == 'thumbprint' ]; then
      echo "${YELLOW}VMCA Certificate Management Mode is set to 'thumbprint'${NORMAL}"
   else
      IFS=$'\n'
      for host_info in $HOSTS; do
         id=$(echo "$host_info" | awk -F'|' '{print $1}' | tr -d ' ')   
         name=$(echo "$host_info" | awk -F'|' '{print $2}' | tr -d ' ')
         ip=$(echo "$host_info" | awk -F'|' '{print $3}' | tr -d ' ')

         if [ -n "$name" ]; then
            viewESXiAgainstVCDB "$name"
         else
            viewESXiAgainstVCDB "$ip"
         fi
      done   
      IFS=$' \t\n'
   fi
}

#------------------------------
# Output information on SSL certificate of a host compared to VCDB
#------------------------------
function viewESXiAgainstVCDB() {
   echo $'\n'"${CYAN}$1${NORMAL}"
   
   THUMBPRINT_INFO_VCDB=$($PSQL -U postgres -d VCDB -c "SELECT expected_ssl_thumbprint,host_ssl_thumbprint FROM vpx_host WHERE dns_name = '$1' OR ip_address = '$1'" -t)
   EXPECTED_SSL_THUMBPRINT=$(echo "$THUMBPRINT_INFO_VCDB" | awk -F '|' '{print $1}' | tr -d ' ')
   HOST_SSL_THUMBPRINT=$(echo "$THUMBPRINT_INFO_VCDB" | awk -F '|' '{print $2}' | tr -d ' ')
   ACTUAL_SSL_THUMBPRINT=$(echo | openssl s_client -connect $1:443 2>/dev/null | openssl x509 -noout -fingerprint -sha1 2>/dev/null | awk -F '=' '{print $NF}')

   echo "   Expected Thumbprint (VCDB)  : $EXPECTED_SSL_THUMBPRINT"
   echo "   Host Thumbprint (VCDB)      : $HOST_SSL_THUMBPRINT"
   if [ -z "$ACTUAL_SSL_THUMBPRINT" ]; then
      echo "   Actual Thumbprint (openssl) : ${YELLOW}Cannot connect to host${NORMAL}"
      echo "   Status: ${YELLOW}UNKNOWN${NORMAL}"
   else
      echo "   Actual Thumbprint (openssl) : $ACTUAL_SSL_THUMBPRINT"
      if [ "$EXPECTED_SSL_THUMBPRINT" != "$ACTUAL_SSL_THUMBPRINT" ] && [ "$HOST_SSL_THUMBPRINT" != "$ACTUAL_SSL_THUMBPRINT" ] && [ "$EXPECTED_SSL_THUMBPRINT" != "$HOST_SSL_THUMBPRINT" ]; then
         echo "   Status: ${YELLOW}MISMATCH${NORMAL}"
      else
         echo "   Status: ${GREEN}MATCH${NORMAL}"
      fi
   fi
}

#------------------------------
# Check for signing certificates of a leaf certificate
#------------------------------
function checkForCACerts() {
   SEARCH=0
   FOUND_ROOT=0
   FOUND_ANY=0
   SEARCH_ISSUER=$(echo "$1" | openssl x509 -noout -text 2>/dev/null | grep 'Issuer:' | sed -e 's/Issuer: //' -e 's/[[:space:]]*//')
   SEARCH_AUTH_KEY_ID=$(echo "$1" | openssl x509 -noout -text 2>/dev/null | grep -A1 'Authority Key Id' | grep 'keyid:' | sed -e 's/keyid://' | tr -d ' ')
   while [ $SEARCH -eq 0 ]; do
      
	  IFS=$'\n'   
      for cert in $SEARCH_CERTS; do  
         SEARCH_CURRENT_SUBJECT=$(openssl x509 -noout -text -in $cert 2>/dev/null | grep 'Subject:' | sed -e 's/Subject: //' -e 's/[[:space:]]*//')
         SEARCH_CURRENT_ISSUER=$(openssl x509 -noout -text -in $cert 2>/dev/null | grep 'Issuer:' | sed -e 's/Issuer: //' -e 's/[[:space:]]*//')
         SEARCH_SKID=$(openssl x509 -noout -text -in $cert 2>/dev/null | grep -A1 'Subject Key Id' | tail -n1 | tr -d ' ')
         SEARCH_CURRENT_AUTH_KEY_ID=$(openssl x509 -noout -text -in $cert 2>/dev/null | grep -A1 'Authority Key Id' | grep 'keyid:' | sed -e 's/keyid://' -e 's/[[:space:]]*//')
         if [ "$SEARCH_ISSUER" = "$SEARCH_CURRENT_SUBJECT" ] && [ "$SEARCH_AUTH_KEY_ID" = "$SEARCH_SKID" ]; then
            if [ "$SEARCH_CURRENT_SUBJECT" = "$SEARCH_CURRENT_ISSUER" ]; then
               SEARCH=1
               FOUND_ROOT=1
               break 2
            else
               SEARCH_ISSUER=$SEARCH_CURRENT_ISSUER
               SEARCH_AUTH_KEY_ID=$SEARCH_CURRENT_AUTH_KEY_ID
               FOUND_ANY=1
            fi              
         fi
      done
      IFS=$' \t\n'
      if [ $FOUND_ANY -eq 0 ]; then
         SEARCH=1
      else
         FOUND_ANY=0
      fi
   done
   
   if [ $FOUND_ROOT -eq 0 ]; then
      return 1
   else
      return 0
   fi
}

#------------------------------
# Replace SSL certificate, private key, and CA store on ESXi host
#------------------------------
function replaceESXiCertificate() {
   unset ESXI_CA_SIGNED_OPTION_INPUT
   header 'ESXi Certificate Options'
   
   echo $'\n1. Generate Certificate Signing Request and Private Key'
   echo '2. Generate Certificate Signing Request and Private Key'
   echo '   from custom OpenSSL configuration file'
   echo '3. Import CA-signed certificate and key'
   read -p $'\nSelect an option [Return to Main Menu]: ' ESXI_CA_SIGNED_OPTION_INPUT
   
   if [ -z $ESXI_CA_SIGNED_OPTION_INPUT ]; then return 1; fi
   
   if [ "$ESXI_CA_SIGNED_OPTION_INPUT" == '3' ]; then
      authenticateIfNeeded
	  
      logInfo 'User has chosen to import a CA-signed ESXi SSL certificate and key'
      read -p $'\nEnter FQDN or IP of the ESXi host: ' ESXI_NAME_INPUT
   
      ESXI_VALID_NAME=0

      while [ $ESXI_VALID_NAME -eq 0 ]; do 
         if [[ $ESXI_NAME_INPUT =~ ^[a-zA-Z] ]]; then
            if ! nslookup $ESXI_NAME_INPUT > /dev/null 2>&1; then
               read -p $'\n'"${YELLOW}Unable to resolve '$ESXI_NAME_INPUT'${NORMAL}', enter FQDN or IP of the ESXi host:${NORMAL} " ESXI_NAME_INPUT
            else
               ESXI_VALID_NAME=1
            fi
         else
            if ! validateIp $ESXI_NAME_INPUT; then
               read -p $'\n'"${YELLOW}Invalid IP address, enter FQDN or IP of the ESXi host:${NORMAL} " ESXI_NAME_INPUT
            else
               ESXI_VALID_NAME=1
            fi
         fi
      done

   
      read -r -s -p $'\n'"Enter root password for $ESXI_NAME_INPUT: " ESXI_PASSWORD_INPUT   
      while [ -z $ESXI_PASSWORD_INPUT ]; do read -r -s -p $'\n'"${YELLOW}Enter root password for $ESXI_NAME_INPUT:${NORMAL} " ESXI_PASSWORD_INPUT; done
   
      read -e -p $'\n\nEnter path to new ESXi certificate: ' ESXI_NEW_CERT_INPUT   
      while [ ! -f $ESXI_NEW_CERT_INPUT ]; do read -e -p $'\n'"${YELLOW}File not found, enter path to new ESXi certificate:${NORMAL} " ESXI_NEW_CERT_INPUT; done
   
      getCorrectCertFormat "$ESXI_NEW_CERT_INPUT" 'NEW_ESXI_CERT'
      NEW_ESXI_CERT_MODULUS=$(openssl x509 -noout -modulus -in $NEW_ESXI_CERT 2>/dev/null | md5sum | awk '{print $1}')

      getPrivateKey "$NEW_ESXI_CERT_MODULUS" "NEW_ESXI" "ESXi host"
   
      verifyCertAndKey "$NEW_ESXI_CERT" "$NEW_ESXI_KEY"
      getCAChain "$NEW_ESXI_CERT"   
   
      header 'Replace ESXi Certificate'
      task 'Publish CA signing certificates'
      $DIR_CLI trustedcert publish --chain --cert $TRUSTED_ROOT_CHAIN --login $VMDIR_USER_UPN --password "$(cat $STAGE_DIR/.vmdir-user-password)" 2>&1 | logInfo || errorMessage 'Unable to publish trusted root chain to VMDir'
	   $VECS_CLI force-refresh > /dev/null 2>&1 || errorMessage 'Unable to perform a force-refresh of CA certificates in VECS'
      statusMessage 'OK' 'GREEN'
   
      SEARCH_CERTS="$(find /etc/vmware-vpx/docRoot/certs/ -type f | grep -v '\.r')"
   
      if [ -f $STAGE_DIR/$ESXI_NAME_INPUT-castore.pem ]; then echo '' > $STAGE_DIR/$ESXI_NAME_INPUT-castore.pem; fi
   
      for cert in "$SEARCH_CERTS"; do
	      if isCertCA "$(cat $cert)"; then cat $cert >> $STAGE_DIR/$ESXI_NAME_INPUT-castore.pem; fi
      done
   
      $VECS_CLI entry getcert --store SMS --alias sms_self_signed >> $STAGE_DIR/$ESXI_NAME_INPUT-castore.pem
   
      task 'Replace ESXi certificate'
      logInfo "Replacing ESXi certificate with $NEW_ESXI_CERT"
      logInfo "Replacing ESXi private key with $CURRENT_PRIVATE_KEY_PATH
      "
      ESXI_CERT_REPLACEMENT_HTTP_CODE=$(curl -k -X PUT -u "root:$ESXI_PASSWORD_INPUT" https://$ESXI_NAME_INPUT/host/ssl_cert --data-binary @$NEW_ESXI_CERT -s -w "%{http_code}\n")
      if [[ "$ESXI_CERT_REPLACEMENT_HTTP_CODE" =~ ^20 ]]; then
         statusMessage 'OK' 'GREEN'
      else
	      errorMessage "Unable to replace certificate, HTTP return code: $ESXI_CERT_REPLACEMENT_HTTP_CODE"
      fi
	  
	   task 'Replace ESXi private key'
	   ESXI_KEY_REPLACEMENT_HTTP_CODE=$(curl -k -X PUT -u "root:$ESXI_PASSWORD_INPUT" https://$ESXI_NAME_INPUT/host/ssl_key --data-binary @$CURRENT_PRIVATE_KEY_PATH -s -w "%{http_code}\n")
	   if [[ "$ESXI_KEY_REPLACEMENT_HTTP_CODE" =~ ^20 ]]; then
	      statusMessage 'OK' 'GREEN'
      else
	      errorMessage "Unable to replace private key, HTTP return code: $ESXI_KEY_REPLACEMENT_HTTP_CODE"
	   fi
	  
	   task 'Replace castore.pem'
      ESXI_CASTORE_REPLACEMENT_HTTP_CODE=$(curl -k -X PUT -u "root:$ESXI_PASSWORD_INPUT" https://$ESXI_NAME_INPUT/host/castore --data-binary @$STAGE_DIR/$ESXI_NAME_INPUT-castore.pem -s -w "%{http_code}\n")
      if [[ "$ESXI_CASTORE_REPLACEMENT_HTTP_CODE" =~ ^20 ]]; then
         statusMessage 'OK' 'GREEN'
      else
         errorMessage "Unable to replace castore.pem, HTTP return code: $ESXI_CASTORE_REPLACEMENT_HTTP_CODE"
      fi
      
	   cat << EOF

${YELLOW}Additional steps are necessary to complete this process:
 1. Run the following command on the ESXi host to save
    the new certificate and key to the bootbank:
	   /bin/auto-backup.sh
 2. Either reboot the ESXi host, or restart the
    Management Agents (rhttpproxy, hostd, vpxa, etc.)
 3. Disconnect and Re-connect the host in vCenter to
    update certificate information in the vCenter database${NORMAL}
EOF
   else
      clearCSRInfo
      read -p $'\n'"Enter a value for the ${CYAN}CommonName${NORMAL} of the certificate: " ESXI_CN_INPUT
	  
	   while [ -z $ESXI_CN_INPUT ]; do read -p $'\n'"${YELLOW}Enter a value for the CommonName of the certificate:${NORMAL} " ESXI_CN_INPUT; done
	  
	   ESXI_CSR=$REQUEST_DIR/$ESXI_CN_INPUT-$TIMESTAMP.csr
      ESXI_KEY=$REQUEST_DIR/$ESXI_CN_INPUT-$TIMESTAMP.key
      
      if [ "$ESXI_CA_SIGNED_OPTION_INPUT" == '1' ]; then
         logInfo 'User has chosen to generate the ESXi SSL private key and CSR'
	      ESXI_CFG=$REQUEST_DIR/$ESXI_CN_INPUT.cfg
         
         if [ -z "$CSR_COUNTRY" ]; then getCSRInfo; fi
         defineSANEntries 'ESXi' 'ESXi' "$ESXI_CN_INPUT"
         generateOpensslConfig $ESXI_CN_INPUT $ESXI_CFG "ESXi"
      else
         logInfo 'User has chosen to generate the ESXi SSL private key and CSR from a custom OpenSSL configuration file'
         read -e -p $'\nEnter path to custom OpenSSL configuration file: ' ESXI_CFG
         while [ ! -f "$ESXI_CFG" ]; do read -e -p $'\n'"${YELLOW}File not found, enter path to custom OpenSSL configuration file:${NORMAL} " ESXI_CFG; done
      fi
      header "Replace ESXi Certificate"
      task "Generating Certificate Signing Request"
      generateCSR $ESXI_CSR $ESXI_KEY $ESXI_CFG || errorMessage "Unable to generate Certificate Signing Request and Private Key"
      statusMessage "OK" "GREEN"
         
      printf "\nCertificate Signing Request generated at ${CYAN}${ESXI_CSR}${NORMAL}"
      printf "\nPrivate Key generated at ${CYAN}${ESXI_KEY}${NORMAL}\n"      
   fi
}

#------------------------------
# Prompt to restart VMware services
#------------------------------
function promptRestartVMwareServices() {
   if [ -z $1 ]; then
      read -p $'\nRestart VMware services [no]: ' RESTART_SERVICES_INPUT
   else
      read -p $'\n'"Restart service $1 [no]: " RESTART_SERVICES_INPUT
   fi
   
   if [[ "$RESTART_SERVICES_INPUT" =~ ^[yY] ]]; then 
      if [ -z $1 ]; then
         restartVMwareServices
      else
         restartVMwareServices $1
      fi
      operationMenu
      processOperationMenu
   elif [ -n "$1" ]; then
      operationMenu
      processOperationMenu
   fi
}

#------------------------------
# Menu to restart VMware services
#------------------------------
function restartServicesMenu() {
   header 'Restart VMware Services'
   echo ' 1. Restart all VMware services'
   echo ' 2. Restart specific VMware service'
   
   read -p $'\nSelect an option [Return to Main Menu]: ' RESTART_SERVICES_INPUT
   
   case $RESTART_SERVICES_INPUT in
      1)
         restartVMwareServices
         ;;
      2)
         read -p $'\nEnter VMware service to restart: ' RESTART_SERVICE_INPUT
         while [ -z "$RESTART_SERVICE_INPUT" ]; do read -p $'\n'"${YELLOW}Enter VMware service to restart:${NORMAL} " RESTART_SERVICE_INPUT; done
		 
         if echo "$VMWARE_SERVICES" | grep "^$RESTART_SERVICE_INPUT$" > /dev/null; then
            restartVMwareServices "$RESTART_SERVICE_INPUT"
         else
            echo $'\n'"${YELLOW}Unknown service '$RESTART_SERVICE_INPUT'${NORMAL}"
         fi
         ;;
   esac
}

#------------------------------
# Restart all VMware services
#------------------------------
function restartVMwareServices() {
   header 'Restarting Services'        
   if [ $# -eq 0 ]; then
      task 'Stopping VMware services'
      service-control --stop $VMON_SERVICE_PROFILE > /dev/null 2>&1 || errorMessage 'Unable to stop all VMware services, check log for details'
      statusMessage 'OK' 'GREEN'
   
      task 'Starting VMware services'
      service-control --start $VMON_SERVICE_PROFILE > /dev/null 2>&1 || errorMessage 'Unable to start all VMware services, check log for details'
      statusMessage 'OK' 'GREEN'
  
      if [[ "$VC_VERSION" =~ ^6 ]]; then
         task 'Restarting VAMI service'
         systemctl restart vami-lighttp
         if [ $(systemctl status vami-lighttp | grep 'Active:' | awk '{print $3}') == '(running)' ]; then
            statusMessage 'OK' 'GREEN'
         else
            statusMessage 'ERROR' 'YELLOW'
         fi
      fi
      if [[ $UPDATED_MACHINE_SSL -eq 1 || $UPDATED_TRUST_ANCHORS -eq 1 ]] && [ "$NODE_TYPE" != 'embedded' ]; then
         printf "\n\n${YELLOW}Please restart services on all other vCenter/PSC nodes in this environment.${NORMAL}\n\n"
      fi
   else
      while [ $# -gt 0 ]; do
         task "Stopping $1"
         service-control --stop $1 > /dev/null 2>&1 || errorMessage "Unable to stop service $1, check log for details"
         statusMessage 'OK' 'GREEN'
      
         task "Starting $1"
         service-control --start $1 > /dev/null 2>&1 || errorMessage "Unable to start service $1, check log for details"
         statusMessage 'OK' 'GREEN'
		 shift
	  done
   fi
}

# commands
VECS_CLI='/usr/lib/vmware-vmafd/bin/vecs-cli'
DIR_CLI='/usr/lib/vmware-vmafd/bin/dir-cli'
VMAFD_CLI='/usr/lib/vmware-vmafd/bin/vmafd-cli'
if [ -f '/usr/sbin/vmon-cli' ]; then 
   VMON_CLI='/usr/sbin/vmon-cli'
else
   VMON_CLI='/usr/lib/vmware-vmon/vmon-cli'
fi
CERTOOL='/usr/lib/vmware-vmca/bin/certool'
LDAP_DELETE='/usr/bin/ldapdelete'
LDAP_SEARCH='/usr/bin/ldapsearch'
LDAP_MODIFY='/usr/bin/ldapmodify'
PSQL='/opt/vmware/vpostgres/current/bin/psql'

# variables
VC_VERSION=$(grep 'CLOUDVM_VERSION:' /etc/vmware/.buildInfo | awk -F ':' '{print $NF}' | awk -F'.' '{print $1"."$2}')
VC_BUILD=$(grep '"build":' /etc/applmgmt/appliance/update.conf | awk -F ':' '{print $NF}' | tr -d '", ')
LOG_DIR='/var/log/vmware/vCert'
LOG="$LOG_DIR/vCert.log"
DEBUG=0
CLEANUP=1
EXIT_ON_BACKUP_FAILURE=1
READ_TIMEOUTS=120
VERIFY_PASSED_CREDENTIALS=0
TOP_DIR='/root/vCert-master'
WORK_DIR="$TOP_DIR/$(date +%Y%m%d)"
STAGE_DIR="$WORK_DIR/stage"
REQUEST_DIR="$WORK_DIR/requests"
BACKUP_DIR="$WORK_DIR/backup"
VC_REPORT="$LOG_DIR/vcenter-certificate-report.txt"
#ESXi_REPORT="$LOG_DIR/esxi-certificate-report.txt"
VMCA_CERT='/var/lib/vmware/vmca/root.cer'
VMON_SERVICE_PROFILE='--all'
VMWARE_SERVICES=$(service-control --list | awk '{print $1}' | sort)
NODE_TYPE=$(cat /etc/vmware/deployment.node.type)
HOSTNAME=$(hostname -f)
HOSTNAME_LC=$(echo $HOSTNAME | awk '{print tolower($0)}')
HOSTNAME_SHORT=$(hostname -s)
IP=$(ip a | grep -A 2 eth0 | grep inet | awk '{print $2}' | awk -F'/' '{print $1}')
PNID=$($VMAFD_CLI get-pnid --server-name localhost)
PNID_LC=$(echo $PNID | awk '{print tolower($0)}')
MACHINE_ID=$($VMAFD_CLI get-machine-id --server-name localhost)
SSO_DOMAIN=$($VMAFD_CLI get-domain-name --server-name localhost)
SSO_SITE=$($VMAFD_CLI get-site-name --server-name localhost)
VMDIR_FQDN=$($VMAFD_CLI get-ls-location --server-name localhost | sed -e 's/:443//g' | awk -F'/' '{print $3}')
VMDIR_PORT='389'
VMDIR_DOMAIN_DN="dc=$(echo $SSO_DOMAIN | sed 's/\./,dc=/g')"
VMDIR_MACHINE_PASSWORD=$(/opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\services\vmdir]' | grep dcAccountPassword | awk -F'  ' '{print $NF}' | awk '{print substr($0,2,length($0)-2)}' | sed -e 's/\\"/"/g' -e 's/\\\\/\\/g')
VMDIR_MACHINE_ACCOUNT_DN=$(/opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\services\vmdir]' | grep '"dcAccountDN"' | awk -F'  ' '{print $NF}' | awk '{print substr($0,2,length($0)-2)}')
VMDIR_USER_UPN_DEFAULT="administrator@$SSO_DOMAIN"
VMDIR_USER=''
VMDIR_USER_UPN=''
VMDIR_USER_PASSWORD=''
if [ $NODE_TYPE != 'management' ]; then
   PSC_LOCATION='localhost'
else
   PSC_LOCATION=$VMDIR_FQDN
fi
HOSTUPDATE_ISSUER_EXPECTED='DigiCert TLS RSA SHA256 2020 CA1'
UNSUPPORTED_SIGNATURE_ALGORITHMS='md2WithRSAEncryption|md5WithRSAEncryption|RSASSA-PSS|dsaWithSHA1|ecdsa_with_SHA1|sha1WithRSAEncryption'
CERT_HASHES=()
TRUSTED_ROOT_CHAIN=''
VMCA_REPLACE='SELF-SIGNED'
STS_REPLACE='VMCA-SIGNED'
MACHINE_SSL_REPLACE='VMCA-SIGNED'
SOLUTION_USER_REPLACE='VMCA-SIGNED'
VMDIR_REPLACE='VMCA-SIGNED'
AUTH_PROXY_REPLACE='VMCA-SIGNED'
AUTO_DEPLOY_CA_REPLACE='SELF-SIGNED'

# CSR defaults and variables
VMCA_CN_DEFAULT='CA'
CSR_COUNTRY_DEFAULT='US'
CSR_ORG_DEFAULT='VMware'
CSR_ORG_UNIT_DEFAULT='VMware Engineering'
CSR_STATE_DEFAULT='California'
CSR_LOCALITY_DEFAULT='Palo Alto'

# script workflow
preStartOperations $@

operationMenu

processOperationMenu
