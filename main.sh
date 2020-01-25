#!/bin/bash

# <Project Name>
# Desc:
# Author: Pascal

# ======== Credit ========
# This is based on the jshielder project
# Link: github.com/jsitech/jshielder

constant_banner(){
echo
echo "
███████╗██╗   ██╗ ██████╗██╗  ██╗██╗████████╗
██╔════╝██║   ██║██╔════╝██║ ██╔╝██║╚══██╔══╝
█████╗  ██║   ██║██║     █████╔╝ ██║   ██║   
██╔══╝  ██║   ██║██║     ██╔═██╗ ██║   ██║   
██║     ╚██████╔╝╚██████╗██║  ██╗██║   ██║   
╚═╝      ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   
"
echo
echo
}

###############################################
# HELPER MODULES
###############################################
spinner (){
    bar=" ++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    barlength=${#bar}
    i=0
    while ((i < 100)); do
        n=$((i*barlength / 100))
        printf "\e[00;34m\r[%-${barlength}s]\e[00m" "${bar:0:n}"
        ((i += RANDOM%5+2))
        sleep 0.02
    done
}
# Show "Done."
function say_done() {
    echo " "
    echo -e "Done."
    say_continue
}
# Ask to Continue
function say_continue() {
    echo -n " To EXIT Press x Key, Press ENTER to Continue"
    read acc
    if [ "$acc" == "x" ]; then
        exit
    fi
    echo " "
}
# Obtain Server IP
function __get_ip() {
    serverip=$(ip route get 1 | awk '{print $NF;exit}')
    echo $serverip
}

###############################################
# FUNCTION CALLS
###############################################

#Securing /tmp Folder
secure_tmp(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Securing /tmp Folder"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  echo -n "Did you Create a Separate /tmp partition during the Initial Installation? (y/n): "; read tmp_answer
  if [ "$tmp_answer" == "n" ]; then
      echo "We will create a FileSystem for the /tmp Directory and set Proper Permissions "
      spinner
      dd if=/dev/zero of=/usr/tmpDISK bs=1024 count=2048000
      mkdir /tmpbackup
      cp -Rpf /tmp /tmpbackup
      mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDISK /tmp
      chmod 1777 /tmp
      cp -Rpf /tmpbackup/* /tmp/
      rm -rf /tmpbackup
      echo "/usr/tmpDISK  /tmp    tmpfs   loop,nosuid,nodev,noexec,rw  0 0" >> /etc/fstab
      sudo mount -o remount /tmp
      say_done
  else
      echo "Nice Going, Remember to set proper permissions in /etc/fstab"
      echo ""
      echo "Example:"
      echo ""
      echo "/dev/sda4   /tmp   tmpfs  loop,nosuid,noexec,rw  0 0 "
      say_done
  fi
}

# Configure Hostname
config_host() {
      echo -n "Do you Wish to Set a HostName? (y/n): "; read config_host
      if [ "$config_host" == "y" ]; then
      serverip=$(__get_ip)
      echo " Type a Name to Identify this server :"
      echo -n " (For Example: myserver): "; read host_name
      echo -n "Type Domain Name?: "; read domain_name
      echo $host_name > /etc/hostname
      hostname -F /etc/hostname
      echo "127.0.0.1    localhost.localdomain      localhost" >> /etc/hosts
      echo "$serverip    $host_name.$domain_name    $host_name" >> /etc/hosts
      #Creating Legal Banner for unauthorized Access
      # echo ""
      # echo "Creating legal Banners for unauthorized access"
      # spinner
      # cat templates/motd > /etc/motd
      # cat templates/motd > /etc/issue
      # cat templates/motd > /etc/issue.net
      sed -i s/server.com/$host_name.$domain_name/g /etc/motd /etc/issue /etc/issue.net
      echo "OK "
      fi
      say_done
}

# Update System, Install sysv-rc-conf tool
update_system(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Updating the System"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   apt update
   apt upgrade -y
   apt dist-upgrade -y
   apt install -y sysv-rc-conf
   say_done
}

# Setting a more restrictive UMASK
restrictive_umask(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Setting UMASK to a more Restrictive Value (027)"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   #cp templates/login.defs /etc/login.defs
   echo "#
# /etc/login.defs - Configuration control definitions for the login package.
#
# Three items must be defined:  MAIL_DIR, ENV_SUPATH, and ENV_PATH.
# If unspecified, some arbitrary (and possibly incorrect) value will
# be assumed.  All other items are optional - if not specified then
# the described action or option will be inhibited.
#
# Comment lines (lines beginning with \"#\") and blank lines are ignored.
#
# Modified for Linux.  --marekm

# REQUIRED for useradd/userdel/usermod
#   Directory where mailboxes reside, _or_ name of file, relative to the
#   home directory.  If you _do_ define MAIL_DIR and MAIL_FILE,
#   MAIL_DIR takes precedence.
#
#   Essentially:
#      - MAIL_DIR defines the location of users mail spool files
#        (for mbox use) by appending the username to MAIL_DIR as defined
#        below.
#      - MAIL_FILE defines the location of the users mail spool files as the
#        fully-qualified filename obtained by prepending the user home
#        directory before \$MAIL_FILE
#
# NOTE: This is no more used for setting up users MAIL environment variable
#       which is, starting from shadow 4.0.12-1 in Debian, entirely the
#       job of the pam_mail PAM modules
#       See default PAM configuration files provided for
#       login, su, etc.
#
# This is a temporary situation: setting these variables will soon
# move to /etc/default/useradd and the variables will then be
# no more supported
MAIL_DIR        /var/mail
#MAIL_FILE      .mail

#
# Enable logging and display of /var/log/faillog login failure info.
# This option conflicts with the pam_tally PAM module.
#
FAILLOG_ENAB		yes

#
# Enable display of unknown usernames when login failures are recorded.
#
# WARNING: Unknown usernames may become world readable.
# See #290803 and #298773 for details about how this could become a security
# concern
LOG_UNKFAIL_ENAB	no

#
# Enable logging of successful logins
#
LOG_OK_LOGINS		no

#
# Enable \"syslog\" logging of su activity - in addition to sulog file logging.
# SYSLOG_SG_ENAB does the same for newgrp and sg.
#
SYSLOG_SU_ENAB		yes
SYSLOG_SG_ENAB		yes

#
# If defined, all su activity is logged to this file.
#
#SULOG_FILE	/var/log/sulog

#
# If defined, file which maps tty line to TERM environment parameter.
# Each line of the file is in a format something like \"vt100  tty01\".
#
#TTYTYPE_FILE	/etc/ttytype

#
# If defined, login failures will be logged here in a utmp format
# last, when invoked as lastb, will read /var/log/btmp, so...
#
FTMP_FILE	/var/log/btmp

#
# If defined, the command name to display when running \"su -\".  For
# example, if this is defined as \"su\" then a \"ps\" will display the
# command is \"-su\".  If not defined, then \"ps\" would display the
# name of the shell actually being run, e.g. something like \"-sh\".
#
SU_NAME		su

#
# If defined, file which inhibits all the usual chatter during the login
# sequence.  If a full pathname, then hushed mode will be enabled if the
# user's name or shell are found in the file.  If not a full pathname, then
# hushed mode will be enabled if the file exists in the user's home directory.
#
HUSHLOGIN_FILE	.hushlogin
#HUSHLOGIN_FILE	/etc/hushlogins

#
# *REQUIRED*  The default PATH settings, for superuser and normal users.
#
# (they are minimal, add the rest in the shell startup files)
ENV_SUPATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH	PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

#
# Terminal permissions
#
#	TTYGROUP	Login tty will be assigned this group ownership.
#	TTYPERM		Login tty will be set to this permission.
#
# If you have a \"write\" program which is \"setgid\" to a special group
# which owns the terminals, define TTYGROUP to the group number and
# TTYPERM to 0620.  Otherwise leave TTYGROUP commented out and assign
# TTYPERM to either 622 or 600.
#
# In Debian /usr/bin/bsd-write or similar programs are setgid tty
# However, the default and recommended value for TTYPERM is still 0600
# to not allow anyone to write to anyone else console or terminal

# Users can still allow other people to write them by issuing
# the \"mesg y\" command.

TTYGROUP	tty
TTYPERM		0600

#
# Login configuration initializations:
#
#	ERASECHAR	Terminal ERASE character ('\010' = backspace).
#	KILLCHAR	Terminal KILL character ('\025' = CTRL/U).
#	UMASK		Default \"umask\" value.
#
# The ERASECHAR and KILLCHAR are used only on System V machines.
#
# UMASK is the default umask value for pam_umask and is used by
# useradd and newusers to set the mode of the new home directories.
# 022 is the \"historical\" value in Debian for UMASK
# 027, or even 077, could be considered better for privacy
# There is no One True Answer here : each sysadmin must make up his/her
# mind.
#
# If USERGROUPS_ENAB is set to \"yes\", that will modify this UMASK default value
# for private user groups, i. e. the uid is the same as gid, and username is
# the same as the primary group name: for these, the user permissions will be
# used as group permissions, e. g. 022 will become 002.
#
# Prefix these values with \"0\" to get octal, \"0x\" to get hexadecimal.
#
ERASECHAR	0177
KILLCHAR	025
UMASK		027

#
# Password aging controls:
#
#	PASS_MAX_DAYS	Maximum number of days a password may be used.
#	PASS_MIN_DAYS	Minimum number of days allowed between password changes.
#	PASS_WARN_AGE	Number of days warning given before a password expires.
#
PASS_MAX_DAYS	90
PASS_MIN_DAYS	7
PASS_WARN_AGE	7

#
# Min/max values for automatic uid selection in useradd
#
UID_MIN			 1000
UID_MAX			60000
# System accounts
#SYS_UID_MIN		  100
#SYS_UID_MAX		  999

#
# Min/max values for automatic gid selection in groupadd
#
GID_MIN			 1000
GID_MAX			60000
# System accounts
#SYS_GID_MIN		  100
#SYS_GID_MAX		  999

#
# Max number of login retries if password is bad. This will most likely be
# overriden by PAM, since the default pam_unix module has it's own built
# in of 3 retries. However, this is a safe fallback in case you are using
# an authentication module that does not enforce PAM_MAXTRIES.
#
LOGIN_RETRIES		5

#
# Max time in seconds for login
#
LOGIN_TIMEOUT		60

#
# Which fields may be changed by regular users using chfn - use
# any combination of letters \"frwh\" (full name, room number, work
# phone, home phone).  If not defined, no changes are allowed.
# For backward compatibility, \"yes\" = \"rwh\" and \"no\" = \"frwh\".
#
CHFN_RESTRICT		rwh

#
# Should login be allowed if we can't cd to the home directory?
# Default in no.
#
DEFAULT_HOME	yes

#
# If defined, this command is run when removing a user.
# It should remove any at/cron/print jobs etc. owned by
# the user to be removed (passed as the first argument).
#
#USERDEL_CMD	/usr/sbin/userdel_local

#
# Enable setting of the umask group bits to be the same as owner bits
# (examples: 022 -> 002, 077 -> 007) for non-root users, if the uid is
# the same as gid, and username is the same as the primary group name.
#
# If set to yes, userdel will remove the user´s group if it contains no
# more members, and useradd will create by default a group with the name
# of the user.
#
USERGROUPS_ENAB yes

#
# Instead of the real user shell, the program specified by this parameter
# will be launched, although its visible name (argv[0]) will be the shell's.
# The program may do whatever it wants (logging, additional authentification,
# banner, ...) before running the actual shell.
#
# FAKE_SHELL /bin/fakeshell

#
# If defined, either full pathname of a file containing device names or
# a ":" delimited list of device names.  Root logins will be allowed only
# upon these devices.
#
# This variable is used by login and su.
#
#CONSOLE	/etc/consoles
#CONSOLE	console:tty01:tty02:tty03:tty04

#
# List of groups to add to the user's supplementary group set
# when logging in on the console (as determined by the CONSOLE
# setting).  Default is none.
#
# Use with caution - it is possible for users to gain permanent
# access to these groups, even when not logged in on the console.
# How to do it is left as an exercise for the reader...
#
# This variable is used by login and su.
#
#CONSOLE_GROUPS		floppy:audio:cdrom

#
# If set to \"yes\", new passwords will be encrypted using the MD5-based
# algorithm compatible with the one used by recent releases of FreeBSD.
# It supports passwords of unlimited length and longer salt strings.
# Set to \"no\" if you need to copy encrypted passwords to other systems
# which don't understand the new algorithm.  Default is \"no\".
#
# This variable is deprecated. You should use ENCRYPT_METHOD.
#
#MD5_CRYPT_ENAB	no

#
# If set to MD5 , MD5-based algorithm will be used for encrypting password
# If set to SHA256, SHA256-based algorithm will be used for encrypting password
# If set to SHA512, SHA512-based algorithm will be used for encrypting password
# If set to DES, DES-based algorithm will be used for encrypting password (default)
# Overrides the MD5_CRYPT_ENAB option
#
# Note: It is recommended to use a value consistent with
# the PAM modules configuration.
#
ENCRYPT_METHOD SHA512

#
# Only used if ENCRYPT_METHOD is set to SHA256 or SHA512.
#
# Define the number of SHA rounds.
# With a lot of rounds, it is more difficult to brute forcing the password.
# But note also that it more CPU resources will be needed to authenticate
# users.
#
# If not specified, the libc will choose the default number of rounds (5000).
# The values must be inside the 1000-999999999 range.
# If only one of the MIN or MAX values is set, then this value will be used.
# If MIN > MAX, the highest value will be used.
#
# SHA_CRYPT_MIN_ROUNDS 5000
# SHA_CRYPT_MAX_ROUNDS 5000

################# OBSOLETED BY PAM ##############
#						#
# These options are now handled by PAM. Please	#
# edit the appropriate file in /etc/pam.d/ to	#
# enable the equivelants of them.
#
###############

#MOTD_FILE
#DIALUPS_CHECK_ENAB
#LASTLOG_ENAB
#MAIL_CHECK_ENAB
#OBSCURE_CHECKS_ENAB
#PORTTIME_CHECKS_ENAB
#SU_WHEEL_ONLY
#CRACKLIB_DICTPATH
#PASS_CHANGE_TRIES
#PASS_ALWAYS_WARN
#ENVIRON_FILE
#NOLOGINS_FILE
#ISSUE_FILE
#PASS_MIN_LEN
#PASS_MAX_LEN
#ULIMIT
#ENV_HZ
#CHFN_AUTH
#CHSH_AUTH
#FAIL_DELAY

################# OBSOLETED #######################
#						  #
# These options are no more handled by shadow.    #
#                                                 #
# Shadow utilities will display a warning if they #
# still appear.                                   #
#                                                 #
###################################################

# CLOSE_SESSIONS
# LOGIN_STRING
# NO_PASSWORD_CONSOLE
# QMAIL_DIR
" > /etc/login.defs
   sed -i s/umask\ 022/umask\ 027/g /etc/init.d/rc
   echo ""
   echo "OK"
   say_done
}

#Disabling Unused Filesystems

unused_filesystems(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Disabling Unused FileSystems"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
   echo " OK"
   say_done
}

# Disable uncommon protocols
uncommon_netprotocols(){
   clear
   f_banner
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo -e "\e[93m[+]\e[00m Disabling Uncommon Network Protocols"
   echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
   echo ""
   spinner
   echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
   echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
   echo " OK"
   say_done

}

# Tune and Secure Kernel
tune_secure_kernel(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Tuning and Securing the Linux Kernel"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo " Securing Linux Kernel"
    spinner
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "# Kernel sysctl configuration file for Ubuntu
# Modified by Jason Soto <jsitech2016@gmail.com>
#
# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and
# sysctl.conf(5) for more details.

# Controls IP packet forwarding
net.ipv4.ip_forward = 0

# Controls source route verification
net.ipv4.conf.default.rp_filter = 1

# Do not accept source routing
net.ipv4.conf.default.accept_source_route = 0

# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1

# Controls the use of TCP syncookies
net.ipv4.tcp_syncookies = 1

# Disable netfilter on bridges.
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0

# Controls the default maxmimum size of a mesage queue
kernel.msgmnb = 65536

# Controls the maximum size of a message, in bytes
kernel.msgmax = 65536

# Controls the maximum shared segment size, in bytes
kernel.shmmax = 68719476736

# Controls the maximum number of shared memory segments, in pages
kernel.shmall = 4294967296

######### GENERAL SECURITY OPTIONS ################

# Automatically Reboot Server in 30 Seconds after a Kernel Panic
vm.panic_on_oom = 1
kernel.panic = 30
kernel.panic_on_oops = 30

# Enable ExecShield
kernel.exec-shield = 1

kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2

########## COMMUNICATIONS SECURITY ##############
# No Redirections
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Do not Accept Packets with SRR
net.ipv4.conf.all.accept_source_route = 0

# Do not accept Redirections
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.secure_redirects = 0

# Disable Packets Forwarding
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

# Log Suspicious Packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore ICMP ECHO or TIMESTAMP sent by broadcast/multicast
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_timestamps = 0

# Protect Against 'syn flood attack'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Enable Reverse Source Validation (Protects Against IP Spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore Bogus Error Response
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reduce KeepAlive
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

fs.suid_dumpable = 0
~
" > /etc/sysctl.con
echo "OK"
echo "# /etc/default/ufw
#

# Set to yes to apply rules to support IPv6 (no means only IPv6 on loopback
# accepted). You will need to 'disable' and then 'enable' the firewall for
# the changes to take affect.
IPV6=yes

# Set the default input policy to ACCEPT, DROP, or REJECT. Please note that if
# you change this you will most likely want to adjust your rules.
DEFAULT_INPUT_POLICY=\"DROP\"

# Set the default output policy to ACCEPT, DROP, or REJECT. Please note that if
# you change this you will most likely want to adjust your rules.
DEFAULT_OUTPUT_POLICY=\"ACCEPT\"

# Set the default forward policy to ACCEPT, DROP or REJECT.  Please note that
# if you change this you will most likely want to adjust your rules
DEFAULT_FORWARD_POLICY=\"DROP\"

# Set the default application policy to ACCEPT, DROP, REJECT or SKIP. Please
# note that setting this to ACCEPT may be a security risk. See 'man ufw' for
# details
DEFAULT_APPLICATION_POLICY=\"SKIP\"

# By default, ufw only touches its own chains. Set this to 'yes' to have ufw
# manage the built-in chains too. Warning: setting this to 'yes' will break
# non-ufw managed firewall rules
MANAGE_BUILTINS=no

#
# IPT backend
#
# only enable if using iptables backend
IPT_SYSCTL=/etc/sysctl.conf

# Extra connection tracking modules to load. Complete list can be found in
# net/netfilter/Kconfig of your kernel source. Some common modules:
# nf_conntrack_irc, nf_nat_irc: DCC (Direct Client to Client) support
# nf_conntrack_netbios_ns: NetBIOS (samba) client support
# nf_conntrack_pptp, nf_nat_pptp: PPTP over stateful firewall/NAT
# nf_conntrack_ftp, nf_nat_ftp: active FTP support
# nf_conntrack_tftp, nf_nat_tftp: TFTP support (server side)
IPT_MODULES=\"nf_conntrack_ftp nf_nat_ftp nf_conntrack_netbios_ns\"
" > /etc/default/ufw
    echo "OK"
    sysctl -e -p
    say_done
}

# Install RootKit Hunter
install_rootkit_hunter(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installing RootKit Hunter"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Rootkit Hunter is a scanning tool to ensure you are you're clean of nasty tools. This tool scans for rootkits, backdoors and local exploits by running tests like:

          - MD5 hash compare
          - Look for default files used by rootkits
          - Wrong file permissions for binaries
          - Look for suspected strings in LKM and KLD modules
          - Look for hidden files
          - Optional scan within plaintext and binary files "
    sleep 1
    cd rkhunter-1.4.6/
    sh installer.sh --layout /usr --install
    cd ..
    rkhunter --update
    rkhunter --propupd
    echo ""
    echo " ***To Run RootKit Hunter ***"
    echo "     rkhunter -c --enable all --disable none"
    echo "     Detailed report on /var/log/rkhunter.log"
    say_done
}

# Tuning
tune_nano_vim_bashrc(){
    nanorc=
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Tunning bashrc, nano and Vim"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""

# Tune .bashrc
    echo "Tunning .bashrc......"
    spinner
    echo "[ -z \"\$PS1\" ] && return

HISTCONTROL=ignoredups:ignorespace

shopt -s histappend

HISTSIZE=1000
HISTFILESIZE=2000

shopt -s checkwinsize

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval \"\$(SHELL=/bin/sh lesspipe)\"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z \"\$debian_chroot\" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we \"want\" color)
case \"\$TERM\" in
    xterm-color) color_prompt=yes;;
esac


force_color_prompt=yes

if [ -n \"\$force_color_prompt\" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ \"\$color_prompt\" = yes ]; then
    PS1='\${debian_chroot:+(\$debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='\${debian_chroot:+(\$debian_chroot)}\u@\h:\w\\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case \"\$TERM\" in
xterm*|rxvt*)
    PS1=\"\[\e]0;\${debian_chroot:+(\$debian_chroot)}\u\@\h: \w\a\]\$PS1\"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval \"\$(dircolors -b ~/.dircolors)\" || eval \"\$(dircolors -b)\"
    alias ls='ls -lh --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias .='cd ..'
alias ls='ls -l --color=auto'
alias arestart='service apache2 restart'
alias sysupdate='apt-get update; apt-get upgrade -y'
alias doinstall='apt-get install'
alias mv='mv -i'
alias cp='cp -i'
alias rm='rm -i'
alias mysql='mysql -uroot -p'
alias tree='tree --dirsfirst'


if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi


function md5 {
    php -r \"echo md5('\$1') . chr(10);\"
}" > /root/.bashrc
    echo "[ -z \"\$PS1\" ] && return

HISTCONTROL=ignoredups:ignorespace

shopt -s histappend

HISTSIZE=1000
HISTFILESIZE=2000

shopt -s checkwinsize

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z \"\$debian_chroot\" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we \"want\" color)
case \"\$TERM\" in
    xterm-color) color_prompt=yes;;
esac

force_color_prompt=yes

if [ -n \"\$force_color_prompt\" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ \"\$color_prompt\" = yes ]; then
    PS1='\${debian_chroot:+(\$debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\\$ '
else
    PS1='\${debian_chroot:+($debian_chroot)}\u@\h:\w\\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case \"\$TERM\" in
xterm*|rxvt*)
    PS1=\"\[\e]0;\${debian_chroot:+(\$debian_chroot)}\u@\h: \w\a\]\$PS1\"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval \"\$(dircolors -b ~/.dircolors)\" || eval \"\$(dircolors -b)\"
    alias ls='ls -lh --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF --color=auto'
alias la='ls -A --color=auto'
alias l='ls -CF --color=auto'
alias .='cd ..'
alias ls='ls -l --color=auto'
alias arestart='sudo service apache2 restart'
alias sysupdate='sudo apt-get update; sudo apt-get upgrade -y'
alias doinstall='sudo apt-get install'
alias mv='mv -i'
alias cp='cp -i'
alias rm='rm -i'
alias mysql='mysql -uroot -p'
alias tree='tree --dirsfirst'

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

function md5 {
    php -r \"echo . md5('\$1') . chr(10);\"
}

" > /home/$username/.bashrc
    chown $username:$username /home/$username/.bashrc
    echo "OK"


# Tune Vim
    echo "Tunning Vim......"
    spinner
#     tunning vimrc
    echo "runtime! debian.vim

if has(\"syntax\")
  syntax on
endif

if has(\"autocmd\")
  au BufReadPost * if line("'\"") > 1 && line("'\\\"") <= line("$") | exe \"normal! g'\"\" | endif
endif

if has(\"autocmd\")
  filetype plugin indent on
endif


set showmatch
set ignorecase
set hlsearch
set incsearch
set mouse=a
set number
set textwidth=80
set softtabstop=4
set shiftwidth=4
set tabstop=4
set expandtab

\"set showcmd
\"set smartcase
\"set autowrite
\"set hidden

if filereadable(\"/etc/vim/vimrc.local\")
  source /etc/vim/vimrc.local
endif
" > /root/.vimrc
    cp /root/.vimrc /home/$username/.vimrc
    echo "OK"


# Tune Nano
    echo "Tunning Nano......"
    spinner
#     tunning nanorc
    echo "set autoindent
unset backup
set const
set morespace
set nowrap
set tabsize 4        
set tabstospaces        
" > /root/.nanorc
    cp /root/.nanorc /home/$username/.nanorc
    echo "OK"
    say_done
}

# Install PortSentry
install_portsentry(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installing PortSentry"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install portsentry
    mv /etc/portsentry/portsentry.conf /etc/portsentry/portsentry.conf-original
    cp templates/portsentry /etc/portsentry/portsentry.conf
    sed s/tcp/atcp/g /etc/default/portsentry > salida.tmp
    mv salida.tmp /etc/default/portsentry
    /etc/init.d/portsentry restart
    say_done
}

# Additional Hardening Steps
additional_hardening(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Running additional Hardening Steps"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Running Additional Hardening Steps...."
    spinner
    echo tty1 > /etc/securetty
    chmod 0600 /etc/securetty
    chmod 700 /root
    chmod 600 /boot/grub/grub.cfg
    #Protect Against IP Spoofing
    echo nospoof on >> /etc/host.conf
    #Remove AT and Restrict Cron
    apt purge at
    apt install -y libpam-cracklib
    echo ""
    echo " Securing Cron "
    spinner
    touch /etc/cron.allow
    chmod 600 /etc/cron.allow
    awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
    echo ""
    echo -n " Do you want to Disable USB Support for this Server? (y/n): " ; read usb_answer
    if [ "$usb_answer" == "y" ]; then
       echo ""
       echo "Disabling USB Support"
       spinner
       echo "blacklist usb-storage" | sudo tee -a /etc/modprobe.d/blacklist.conf
       update-initramfs -u
       echo "OK"
       say_done
    else
       echo "OK"
       say_done
    fi
}

# Install Unhide
install_unhide(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installing UnHide"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Unhide is a forensic tool to find hidden processes and TCP/UDP ports by rootkits / LKMs or by another hidden technique."
    sleep 1
    apt -y install unhide
    echo ""
    echo " Unhide is a tool for Detecting Hidden Processes "
    echo " For more info about the Tool use the manpages "
    echo " man unhide "
    say_done
}

# Install Tiger
#Tiger is and Auditing and Intrusion Detection System
install_tiger(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installing Tiger"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Tiger is a security tool that can be use both as a security audit and intrusion detection system"
    sleep 1
    apt -y install tiger
    echo ""
    echo " For More info about the Tool use the ManPages "
    echo " man tiger "
    say_done
}

install_psad(){
      clear
      f_banner
      echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
      echo -e "\e[93m[+]\e[00m Install PSAD"
      echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
      echo " PSAD is a piece of Software that actively monitors you Firewall Logs to Determine if a scan
            or attack event is in Progress. It can alert and Take action to deter the Threat

            NOTE:
            IF YOU ARE ONLY RUNNING THIS FUNCTION, YOU MUST ENABLE LOGGING FOR iptables

            iptables -A INPUT -j LOG
            iptables -A FORWARD -j LOG

            "
      echo ""
      echo -n " Do you want to install PSAD (Recommended)? (y/n): " ; read psad_answer
      if [ "$psad_answer" == "y" ]; then
      iptables -A INPUT -j LOG
      iptables -A FORWARD -j LOG
      echo -n " Type an Email Address to Receive PSAD Alerts: " ; read inbox1 # This may need later touching
      apt install psad
      sed -i s/INBOX/$inbox1/g templates/psad.conf
      sed -i s/CHANGEME/$host_name.$domain_name/g templates/psad.conf  
      cp templates/psad.conf /etc/psad/psad.conf
      psad --sig-update
      service psad restart
      echo "Installation and Configuration Complete"
      echo "Run service psad status, for detected events"
      echo ""
      say_done
      else
      echo "OK"
      say_done
      fi
}

# Disable Compilers
disable_compilers(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Disabling Compilers"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Disabling Compilers....."
    spinner
    chmod 000 /usr/bin/as >/dev/null 2>&1
    chmod 000 /usr/bin/byacc >/dev/null 2>&1
    chmod 000 /usr/bin/yacc >/dev/null 2>&1
    chmod 000 /usr/bin/bcc >/dev/null 2>&1
    chmod 000 /usr/bin/kgcc >/dev/null 2>&1
    chmod 000 /usr/bin/cc >/dev/null 2>&1
    chmod 000 /usr/bin/gcc >/dev/null 2>&1
    chmod 000 /usr/bin/*c++ >/dev/null 2>&1
    chmod 000 /usr/bin/*g++ >/dev/null 2>&1
    spinner
    echo ""
    echo " If you wish to use them, just change the Permissions"
    echo " Example: chmod 755 /usr/bin/gcc "
    echo " OK"
    say_done
}

file_permissions(){
 clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Setting File Permissions on Critical System Files"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  spinner
  sleep 2
  chmod -R g-wx,o-rwx /var/log/*

  chown root:root /etc/ssh/sshd_config
  chmod og-rwx /etc/ssh/sshd_config

  chown root:root /etc/passwd
  chmod 644 /etc/passwd

  chown root:shadow /etc/shadow
  chmod o-rwx,g-wx /etc/shadow

  chown root:root /etc/group
  chmod 644 /etc/group

  chown root:shadow /etc/gshadow
  chmod o-rwx,g-rw /etc/gshadow

  chown root:root /etc/passwd-
  chmod 600 /etc/passwd-

  chown root:root /etc/shadow-
  chmod 600 /etc/shadow-

  chown root:root /etc/group-
  chmod 600 /etc/group-

  chown root:root /etc/gshadow-
  chmod 600 /etc/gshadow-


  echo -e ""
  echo -e "Setting Sticky bit on all world-writable directories"
  sleep 2
  spinner

  df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

  echo " OK"
  say_done

}

#Install and Enable sysstat

install_sysstat(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Installing and enabling sysstat"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install sysstat
  sed -i 's/ENABLED="false"/ENABLED="true"/g' /etc/default/sysstat
  service sysstat start
  echo "OK"
  say_done
}

#Install and enable auditd

install_auditd(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Installing auditd"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install auditd

  # Using CIS Benchmark configuration
  
  #Ensure auditing for processes that start prior to auditd is enabled 
  echo ""
  echo "Enabling auditing for processes that start prior to auditd"
  spinner
  sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1"/g' /etc/default/grub
  update-grub

  echo ""
  echo "Configuring Auditd Rules"
  spinner

  cp templates/audit-CIS.rules /etc/audit/audit.rules

  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
  "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
  -k privileged" } ' >> /etc/audit/audit.rules

  echo " " >> /etc/audit/audit.rules
  echo "#End of Audit Rules" >> /etc/audit/audit.rules
  echo "-e 2" >>/etc/audit/audit.rules

  sysv-rc-conf auditd on
  service auditd restart
  echo "OK"
  say_done
}

# Enable Process Accounting
enable_proc_acct(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Enable Process Accounting"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install acct
  touch /var/log/wtmp
  echo "OK"
}

# Install Apache
install_apache(){
  clear
  f_banner
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo -e "\e[93m[+]\e[00m Installing Apache Web Server"
  echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
  echo ""
  apt install apache2
  say_done
}

# Configure and optimize Apache
secure_optimize_apache(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Optimizing Apache"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    cp templates/apache /etc/apache2/apache2.conf
    echo " -- Enabling ModRewrite"
    spinner
    a2enmod rewrite
    service apache2 restart
    say_done
}

# Restrict Access to Apache Config Files
apache_conf_restrictions(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Restricting Access to Apache Config Files"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo " Restricting Access to Apache Config Files......"
    spinner
     chmod 750 /etc/apache2/conf* >/dev/null 2>&1
     chmod 511 /usr/sbin/apache2 >/dev/null 2>&1
     chmod 750 /var/log/apache2/ >/dev/null 2>&1
     chmod 640 /etc/apache2/conf-available/* >/dev/null 2>&1
     chmod 640 /etc/apache2/conf-enabled/* >/dev/null 2>&1
     chmod 640 /etc/apache2/apache2.conf >/dev/null 2>&1
     echo " OK"
     say_done
}

# Configure OWASP ModSecurity Core Rule Set (CRS3)
set_owasp_rules(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Setting UP OWASP ModSecurity Core Rule Set (CRS3)"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""

    for archivo in /usr/share/modsecurity-crs/base_rules/*
        do ln -s $archivo /usr/share/modsecurity-crs/activated_rules/
    done

    for archivo in /usr/share/modsecurity-crs/optional_rules/*
        do ln -s $archivo /usr/share/modsecurity-crs/activated_rules/
    done
    spinner
    echo "OK"

    sed s/SecRuleEngine\ DetectionOnly/SecRuleEngine\ On/g /etc/modsecurity/modsecurity.conf-recommended > salida
    mv salida /etc/modsecurity/modsecurity.conf

    echo 'SecServerSignature "AntiChino Server 1.0.4 LS"' >> /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf
    echo 'Header set X-Powered-By "Plankalkül 1.0"' >> /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf
    echo 'Header set X-Mamma "Mama mia let me go"' >> /usr/share/modsecurity-crs/modsecurity_crs_10_setup.conf

    a2enmod headers
    service apache2 restart
    say_done
}

# Install ModSecurity
install_modsecurity(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installing ModSecurity"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "WARNING ***** THIS WILL RESTART APACHE2 ******"
    echo -n "To EXIT Press x Key, Press ENTER to Continue"
    read acc
    if [ "$acc" == "x" ]; then
        echo "Return "
    else
      apt install libxml2 libxml2-dev libxml2-utils -y
      apt install libaprutil1 libaprutil1-dev -y
      apt install libapache2-mod-security2 -y
      service apache2 restart
      say_done
    fi
}

# Configure and optimize Apache
secure_optimize_apache(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Optimizing Apache"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo "Mutex file:\${APACHE_LOCK_DIR} default
PidFile \${APACHE_PID_FILE}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 1000
KeepAliveTimeout 2

<IfModule mpm_prefork_module>
    StartServers 1
    MinSpareServers 3
    MaxSpareServers 6
    MaxClients 24
    MaxRequestsPerChild 3000
</IfModule>

<IfModule mpm_worker_module>
    StartServers 2
    MinSpareThreads 25
    MaxSpareThreads 75
    ThreadLimit 64
    ThreadsPerChild 25
    MaxClients 150
    MaxRequestsPerChild 0
</IfModule>

<IfModule mpm_event_module>
    StartServers 2
    MinSpareThreads 25
    MaxSpareThreads 75
    ThreadLimit 64
    ThreadsPerChild 25
    MaxClients 150
    MaxRequestsPerChild 0
</IfModule>

User \${APACHE_RUN_USER}
Group \${APACHE_RUN_GROUP}
AccessFileName .htaccess
<Files ~ \"^\.ht\">
    Order allow,deny
    Deny from all
    Satisfy all
</Files>

<Directory />
    Options -Indexes -Includes -ExecCGI
    <LimitExcept GET POST HEAD>
       deny from all
    </LimitExcept>
</Directory>

HostnameLookups Off
ErrorLog \${APACHE_LOG_DIR}/error.log
LogLevel warn

# Include module configuration:
Include mods-enabled/*.load
Include mods-enabled/*.conf

# Include ports listing
Include ports.conf

LogFormat \"%v:%p %h %l %u %t \\\"%r\\\" %>s %O \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\"\" vhost_combined
LogFormat \"%h %l %u %t \\\"%r\\\" %>s %O \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\"\" combined
LogFormat \"%h %l %u %t \\\"%r\\\" %>s %O\" common
LogFormat \"%{Referer}i -> %U\" referer

<IfModule security2_module>
    Include /usr/share/modsecurity-crs/*.conf
    Include /usr/share/modsecurity-crs/base_rules/*.conf
</IfModule>

LogFormat \"%{User-agent}i\" agent

IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf

ServerSignature Off
ServerTokens Prod

ErrorDocument 404 \"File not Found\"
ErrorDocument 500 \"Maintenance tasks in progress. sorry for the inconvenience\"


FileETag None
Header unset ETag
TraceEnable off

# Security Headers

Header set X-XSS-Protection \"1; mode=block\"
Header set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"
Header always append X-Frame-Options DENY
Header set X-Content-Type-Options nosniff
Header edit Set-Cookie ^(.*)\$ \$1;HttpOnly;Secure
Header set Referrer-Policy \"no-referrer-when-downgrade" > /etc/apache2/apache2.conf
    echo " -- Enabling ModRewrite"
    spinner
    a2enmod rewrite
    service apache2 restart
    say_done
}

# Install ModEvasive
install_modevasive(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installing ModEvasive"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " Type Email to Receive Alerts "; read inbox
    apt install libapache2-mod-evasive
    mkdir /var/log/mod_evasive
    chown www-data:www-data /var/log/mod_evasive/
    sed s/MAILTO/$inbox/g templates/mod-evasive > /etc/apache2/mods-available/mod-evasive.conf
    service apache2 restart
    say_done
}

# Install fail2ban
    # To Remove a Fail2Ban rule use:
    # iptables -D fail2ban-ssh -s IP -j DROP
install_fail2ban(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Installing Fail2Ban"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    apt install sendmail
    apt install fail2ban
    say_done
}

## Secure SSH
secure_ssh(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Securing SSH"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " Securing SSH..."
    spinner
    sed s/USERNAME/$username/g templates/sshd_config > /etc/ssh/sshd_config; echo "OK"
    chattr -i /home/$username/.ssh/authorized_keys
    service ssh restart
    say_done
}
# Set IPTABLES Rules
set_iptables(){
    clear
    f_banner
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo -e "\e[93m[+]\e[00m Setting IPTABLE RULES"
    echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
    echo ""
    echo -n " Setting Iptables Rules..."
    spinner
    # Backup current stored ruleset
    iptables-save > /etc/init.d/savedrules.txt
    echo "#! /bin/sh
### BEGIN INIT INFO
# Provides:          iptables
# Required-Start:    \$remote_fs \$syslog
# Required-Stop:     \$remote_fs \$syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Applies Iptable Rules
# Description:
### END INIT INFO
iptables -F
#Defaults
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
#Rules fr PSAD
iptables -A INPUT -j LOG
iptables -A FORWARD -j LOG
# INPUT
# Aceptar loopback input
iptables -A INPUT -i lo -p all -j ACCEPT
# Allow three-way Handshake
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Stop Masked Attackes
iptables -A INPUT -p icmp --icmp-type 13 -j DROP
iptables -A INPUT -p icmp --icmp-type 17 -j DROP
iptables -A INPUT -p icmp --icmp-type 14 -j DROP
iptables -A INPUT -p icmp -m limit --limit 1/second -j ACCEPT
# Discard invalid Packets
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
## Drop Spoofing attacks
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 127.0.0.0/8 -j DROP
iptables -A INPUT -s 192.168.0.0/24 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -d 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP
iptables -A INPUT -d 240.0.0.0/5 -j DROP
iptables -A INPUT -s 0.0.0.0/8 -j DROP
iptables -A INPUT -d 0.0.0.0/8 -j DROP
iptables -A INPUT -d 239.255.255.0/24 -j DROP
iptables -A INPUT -d 255.255.255.255 -j DROP
# Drop packets with excessive RST to avoid Masked attacks
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
# Any IP that performs a PortScan will be blocked for 24 hours
iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
# After 24 hours remove IP from block list
iptables -A INPUT   -m recent --name portscan --remove
iptables -A FORWARD -m recent --name portscan --remove
# This rule logs the port scan attempt
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix \"Portscan:\"
iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix \"Portscan:\"
iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
# Inbound Rules
# smtp
iptables -A INPUT -p tcp -m tcp --dport 25 -j ACCEPT
# http
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
# https
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
# ssh & sftp
iptables -A INPUT -p tcp -m tcp --dport 372 -j ACCEPT
# Allow Ping
iptables -A INPUT -p icmp --icmp-type 0 -j ACCEPT
# OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Outbound Rules
# smtp
iptables -A OUTPUT -p tcp -m tcp --dport 25 -j ACCEPT
# http
iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
# https
iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT
# ssh & sftp
iptables -A OUTPUT -p tcp -m tcp --dport 372 -j ACCEPT
# Limit SSH connection from a single IP
iptables -A INPUT -p tcp --syn --dport 372 -m connlimit --connlimit-above 2 -j REJECT
# Allow Pings
iptables -A OUTPUT -p icmp --icmp-type 0 -j ACCEPT
# Reject Forwarding
iptables -A FORWARD -j REJECT
" > /etc/init.d/iptables.sh
      sh /etc/init.d/iptables.sh
#     sh templates/iptables.sh
#     cp templates/iptables.sh /etc/init.d/
    chmod +x /etc/init.d/iptables.sh
    ln -s /etc/init.d/iptables.sh /etc/rc2.d/S99iptables.sh
    say_done
}


###############################################
# FUNCTION OS CALLS
###############################################



#ubuntu_eighteen() {
#
#}


ubuntu_sixteen() {
menu2=""
until [ "$menu2" = "34" ]; do

clear
constant_banner

echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m SELECT THE DESIRED OPTION"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "1. Configure Host Name, Create Legal Banners, Update Hosts Files"
echo "3. Update System"
echo "4. Create Admin User"
echo "6. Secure SSH Configuration"
echo "7. Set Restrictive IPTable Rules"
echo "8. Install and Configure Fail2Ban"
echo "9. Install, Optimize and Secure Apache"
echo "15. Install ModSecurity (Apache)and Set Owasp Rules"
echo "16. Install ModEvasive"
echo "18. Tune and Secure Linux Kernel"
echo "19. Install RootKit Hunter"
echo "20. Tune Vim, Nano, Bashrc"
echo "21. Install PortSentry"
echo "22. Secure tty, root home, grub configs, cron"
echo "23. Install Unhide"
echo "24. Install Tiger"
echo "25. Disable Compilers"
echo "27. Enable Process Accounting"
echo "30. Set More Restrictive UMASK Value (027)"
echo "32. Install PSAD IDS"
echo "34. Exit"
echo " "

read menu2
case $menu2 in

1)
config_host
;;

2)
config_timezone
;;

3)
update_system
;;

4)
admin_user
;;

5)
rsa_keygen
rsa_keycopy
;;

6)
echo "key Pair must be created "
echo "What user will have access via SSH? " ; read username
rsa_keygen
rsa_keycopy
secure_ssh
;;

7)
set_iptables
;;

8)
echo "Type Email to receive Alerts: " ; read inbox
install_fail2ban
config_fail2ban
;;

9)
install_apache
secure_optimize_apache
apache_conf_restrictions
;;

10)
install_nginx_modsecurity
set_nginx_modsec_OwaspRules
;;

11)
set_nginx_vhost
;;


12)
set_nginx_vhost_nophp
;;

13)
install_secure_php
;;

14)
install_php_nginx
;;

15)
install_modsecurity
set_owasp_rules
;;

16)
install_modevasive
;;

17)
install_qos_spamhaus
;;

18)
tune_secure_kernel
;;

19)
install_rootkit_hunter
;;

20)
tune_nano_vim_bashrc
;;

21)
install_portsentry
;;

22)
additional_hardening
;;

23)
install_unhide
;;

24)
install_tiger
;;

25)
disable_compilers;
;;

26)
unattended_upgrades
;;

27)
enable_proc_acct
;;

#28)
#install_phpsuhosin
#;;

29)
install_secure_mysql
;;

30)
restrictive_umask
;;

31)
secure_tmpsecure_tmp
;;

32)
install_psad
;;

33)
set_grubpassword
;;

34)
break ;;

*) ;;

esac
done

}


if [ "$USER" != "root" ]; then
      echo "Permission Denied"
      echo "Can only be run by root"
      exit
else
      clear
      constant_banner
fi

menu=""

until [ "$menu" = "7" ]; do

clear
constant_banner

echo ""
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\e[93m[+]\e[00m SELECT YOUR LINUX DISTRIBUTION"
echo -e "\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo "1. Ubuntu Server 16.04 LTS"
echo "2. Ubuntu Server 18.04 LTS"
echo "3. Linux CentOS 7 "
echo "4. Solaris"
echo "5. Debian"
echo "6. Fedora/Redhat"
echo "7. Exit"
echo

read menu
case $menu in

1) #Ubuntu 16.04
echo "HERE"
ubuntu_sixteen
;;

2) #Ubuntu 18.04
ubuntu_eighteen
;;

3) #CentOS <ver>

;;

4) #SolarisOS <ver>

;;

5) #DebianOS

;;

6) #MintOS

;;

7) #Fedora/Redhat

;;
8)
break
;;

*) ;;

esac
done



###############################################
# FUNCTION CALLS
###############################################
