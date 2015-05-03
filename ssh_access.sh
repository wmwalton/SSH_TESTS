#-/bin/bash
#
# SSH account access audit tool.
#
# Display list of all users who have ability to SSH into the box remotely
# List users who can access current host.
# - Clear list for basic or multi-host audit
# - Validate few basic sshd settings considered insecure (all access)
#   - daemon exist - port listening 
#   - no "back door" sshd non-std ports, bindings (on port 22)
# - Check possible per user overrides if AllowOverride
# - If PKI enabled - indicate in output (keys present)

# Initial Spec does't specify ROOT explicitly.
#   - Include any user in namespace, especially root 
# Can't ignore system accts / validate all
#   - Root should be thorough check. Add'l checks to confirm root is secure
# Can't assume secure policies present
#   - Validate based on policy 
#   - With defined policy we can ensure compliance
# Can't just list /home/user/  for list 
# - Need to pull any user that can auth, then sshd global, then per-user conf

# Establish some global vars
# - Set vars using $HOME  ~ or %h to avoid redundancy
# - Set some default flags, counter 0, parameter arrays
#
# Exclude users without access (remove bulk / sys accts)
# - Check configs first for AllowUsers / AllowGroup
# - Check for existing .ssh/ folders in homedir
# - Check per user UserAllow in /etc/ssh/sshd_config ????
# - Check logs to rule out [N/A]
#
# FUTURE
# For confirmed users - check hosts in known_hosts
# - Ubuntu hashes known_hosts - hostnames not available
# - Ubuntu 15.xx services differences - String "running" valid in both
# - Query NIS users [this ver check for config settings, fail if ext names in usep]
#


# Allow no Arguments, but use Arg if provided

echo "##############################"
if [ $# -eq 0 ]
  then
    echo "No ARGS - Parse users"
    declare -a USERS
    USERS=`getent passwd | awk -F ':' '{print $1}'`
  else
    declare -a USERS
    USERS=$1
fi

# getent is same with NIS or other directory - need env to test on

# Establish paths and vars
SSHSVC=`service ssh status`
# service output on 14.04 and 15.xx is different

# Cant use global var $HOME - only gets ENV curr user running script
# Set if needed
HOMEDIR="$HOME"
#SSHDIR="$HOME/.ssh/"
HOSTNAME=`hostname`
# Loop counter for number of exempt eliminations
EXEMPT=${EXEMPT:-0}
VALID=${VALID:-0}
TOTAL=${TOTAL:-0}
SSHACL=${SSHACL:-0}

# debug var and arrays
#echo $USERS
#echo $HOSTNAME
#echo $SSHSVC
#echo $SSHDIR
#ls -a $SSHDIR
#echo $HOMEDIR
#getent passwd | awk -F ':' '{print $1echo $HOME
#echo $1

function svcchk () 
{
if [[ "$SSHSVC" == *"running"* ]]
  then
    printf "$HOSTNAME: SSHd Running"
      if [ $SSHACL -eq 0 ]
        then
          echo " W/ACLs"
        else
          echo " NO ACLs"
      fi
  else
    echo "$HOSTNAME: SSHd Not Running";
    echo "** Keep Going : Daemon may be stopped";
    # Color Attrib not implemented -- \e[1;31mSSHd Not Running:\e[0m
    # Unless we do an ANSI mode check first - root rarely does, so forget it
fi
#echo "svcchk finished"
}

function useracl () 
{
  # echo "useracl start"
  # echo "$SSHACL"
  if [ $SSHACL -eq 0 ]
    # echo "  SSH is restricted via AllowUsers";
    # test if $user is on the ACL
    then
      # echo "CHECKING USER ON AllowUsers"
      # To be thorough, do file check - perms check
      # echo $user
      if [[ `grep AllowUsers /etc/ssh/sshd_config` == *$user* ]]
        then
          # echo ""
          printf " $user +ACL "
          # return 0
          usracl="0"
          validflag="0"
        else
          usracl="1"
          validflag="1"
          # return 1
          # printf "$user restricted SSH - Not in AllowUsers"
      fi
    else
      echo "No users in AllowedUsers = Access Denied"
      # printf "exempted"
      # return 1
  fi
}


# Simple grep wont do - need to account for commented lines
#
function aclchk () 
{
# echo "AllowUsers CHECK"
# echo "aclchk start"

# This PITA broke for a while - the pipe not working?

if [[ $(grep AllowUsers /etc/ssh/sshd_config) == *"AllowUsers"* ]]
  
  # grep -v '^#' 
  # echo "if statement pass"
  # echo "$SSHCHK"
  then
    # echo "$SSHACL"
    SSHACL="0"
  else
    echo "AllowUsers check failed"
    SSHACL="1"
    # echo " Recommend creating ACL group or users"
fi
# echo "$SSHACL"
}

function pkichk () 
{
if [ -e /home/$user/.ssh/authorized_keys ]
  then
    pkiflag="0"
    printf "PKI "
  else
    pkiflag="1"
fi
}

function cfgchk () 
{
if [ -f /home/$user/.ssh/config ]
  then
    cfgflag="0"
    printf "CFG "
  else
    cfgflag="1"
fi
}

# check for x or null value for hash in shadow password
# Also some non-empty '!' entries in ubuntu.. means user never entered password
# or that user has just been created
#
function hashchk ()
{
userhash=`getent shadow | grep $user | awk -F: '{print $2}'`
# echo "$userhash"
# if [ -v (`getent passwd | awk -F \':' '{print $2}`) ]
#
# Try to match both replacement chars
# if [[ $userhash = @( "x" "!" ) ]]
if [ $userhash != "x" ]
  then
    hashflag="0"    
    # There are regex to parse first few chars of crypt for hash type
    # Would be best way of validating actual hash
  else
    hashflag="1"
    false
fi
}

# eliminate exempt
#
function usercheck () 
{
# echo "usercheck function start"
# debug:show list before eliminating negatives
# echo $USERS

for user in $USERS; do
  # echo $user
  useracl
  if usracl="0"
    # echo "EXEMPT LOOP start"
    then   
      if [ $validflag -eq 0 ]
        then
            
        # Was going to parse if ssh_config directive for nopass login
        # PermitEmptyPasswords no   -  which would be really dumb
        #
        # 
        # echo "Looking for valid configs for $user"
        # set validflag=1 for fail shell OR fail hash (+emptypasswords)
        #         hashcheck
          hashchk
            if [ $hashflag -eq 0 ] 
            then
              printf "+HASH "
            else
              printf '%s' "-HASH "
              validflag="1"
            fi

        #         shellcheck
        #         homecheck wont add much


        # It would be easier (for "info" files) to create an array of files in a "checkfiles" loop after validation
        # The below is just to get the indicators in the usercheck loop.
          # INFO ONLY - next step to validate / check for any "loose" settings in user override config files
          cfgchk
            if [ $cfgflag -eq 0 ] 
            then
              printf "+CFG "
            else
              printf '%s' "-CFG "
            fi
          # This is INFO ONLY - adding a directivecheck for enforced PKI would make this a good validation 
          pkichk
            if [ $pkiflag -eq 0 ] 
            then
              echo "+PKI "
            else
              printf '%s' "-PKI "
            fi
          VALID=$[VALID + 1]
          printf '%s\n' "VALID"
        else
          # increment number of users eliminated
          EXEMPT=$[EXEMPT + 1]
          # echo $user "CANT SSH"

#         There are exceptions for root / separate config options
#         root should have a few extra checks for basic poor config choices
#         
          # printf "  = SSH VALID for $user"
      fi
    else
      echo "INVALID"
      false
  fi
done
}

# A lot more validation could be done.  Checking all users for a valid hash in /etc/shadow for example.

svcchk
# echo "svcchk ran"
aclchk
# echo "aclchk ran"

echo "------------------------------"
usercheck

TOTAL=$(($VALID + $EXEMPT))
echo ""
echo "------------------------------"
#echo " $HOSTNAME SSH CHECKED"
echo " $TOTAL Users TOTAL"
echo " $EXEMPT Users EXEMPT"
echo " $VALID  Users VALID"
echo "##############################"
