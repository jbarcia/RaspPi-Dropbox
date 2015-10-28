#!/bin/bash
#-Metadata----------------------------------------------------#
#  Filename: raspi-config.sh             (Update: 2015-10-26) #
#-Info--------------------------------------------------------#
#  Raspberry Pi Kali dropbox automated script                 #
#-Author(s)---------------------------------------------------#
#  jbarcia                                                    #
#-Operating System--------------------------------------------#
#  Designed for: Raspberry Pi 2 - Kali Linux 2 [ARM]          #
#     Tested on: Raspberry Pi 2 - Kali Linux 2 [ARM]          #
#-Licence-----------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT           #
#-Notes-------------------------------------------------------#
#  Run as root, just after a fresh/clean install of Kali 2.0. #
#                             ---                             #
#  Command line arguments:                                    #
#   --base    = Base configuration hostname/password/ssh keys #
#   --tft     = Installs and configures TFT patched kernel    #
#   --expand  = Expands Image size to fill SD card            #
#   --wifi    = Configure wifi AP to start on boot            #
#   --ssh     = Configure ssh phone home                      #
#   e.g. # bash raspi-config.sh --tft                         #
#                             ---                             #
#                                                             #
# Blog Posts:                                                 #
#   https://www.offensive-security.com/kali-linux/            #
#                 raspberry-pi-luks-disk-encryption/          #
#                                                             #
# Image Location:                                             #
#   https://www.offensive-security.com/                       #
#                 kali-linux-vmware-arm-image-download/       #
#                                                             #
# unxz file.tar.xz                                            #
# tar xf archive.tar.xz                                       #
#                                                             #
# dd if=/root/kali-1.1.0-rpi.img of=/dev/sdb bs=4M            #
# gparted - resize partition                                  #
#                                                             #
#-------------------------------------------------------------#


##### Optional steps
BaseConfig=false             # Do not config base                            [ --base ]
TFTinstall=false             # Do not install TFT patched kernel             [ --tft ]
Expand=false                 # Do not expand image to fill SD card           [ --expand ]
ConfigSSH=false				 # Do not config SSH 							 [ --ssh ]
ConfigWifi=false			 # Do not config Wifi 							 [ --wifi ]

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal


#-Arguments------------------------------------------------------------#

##### Read command line arguments
for x in $( tr '[:upper:]' '[:lower:]' <<< "$@" ); do
  if [ "${x}" == "--tft" ]; then
    TFTinstall=true
  elif [ "${x}" == "--expand" ]; then
    Expand=true
  elif [ "${x}" == "--base" ]; then
    BaseConfig=true
  elif [ "${x}" == "--ssh" ]; then
    ConfigSSH=true
  elif [ "${x}" == "--wifi" ]; then
    ConfigWifi=true
  else
    echo -e ' '${RED}'[!]'${RESET}" Unknown option: ${RED}${x}${RESET}" 1>&2
    exit 1
  fi
done



#-Start----------------------------------------------------------------#

echo -e "\n ${BLUE}[USAGE:]${RESET} raspi-config.sh ${BLUE}--base --tft --ssh --wifi ${RESET}"

##### Install TFT patched kernel
if [ "${TFTinstall}" != "false" ]; then
	if [ ! -f /root/tft ]; then
		echo -e "\n ${GREEN}[+]${RESET} Installing ${GREEN}Adafruit TFT Screen${RESET} ~ touch screen patched kernel"
		echo foo > /root/tft
		mount /dev/mmcblk0p1 /boot
		wget http://adafruit-download.s3.amazonaws.com/adafruit_pitft_kernel_1.20150420-1.tar.gz
		tar xf adafruit_pitft_kernel_1.20150420-1.tar.gz
		cd adafruit_pitft_kernel_1.20150420-1
		./install.sh
		echo -e "\n ${YELLOW}[i]${RESET} Installed ${YELLOW}TFT Screen Kernel${RESET}."
		echo -e "\n ${BOLD}Press ANY KEY to reboot for changes to take effect. Restart the script after reboot to continue.${RESET}"
		read -p ""
		reboot
	fi
fi

#Config TFT
if [ -f /root/tft ]; then
	echo -e "\n ${GREEN}[+]${RESET} Configuring ${GREEN}TFT Screen ${RESET}(HINT: Y/N)"
	git clone https://github.com/adafruit/Adafruit-PiTFT-Helper.git
	mount /dev/mmcblk0p1 /boot
	cd Adafruit-PiTFT-Helper
	./adafruit-pitft-helper -u /root/ -t 28r
	rm /root/tft
fi


##### Expand Raspberry Pi base image
# Currently Not Working
#if [ "${Expand}" != "false" ]; then
#	echo -e "\n ${GREEN}[+]${RESET} Expanding Raspberry Pi base image"
#	wget https://raw.github.com/dweeber/rpiwiggle/master/rpi-wiggle
#	chmod +x rpi-wiggle
#	./rpi-wiggle
#fi


##### Configuring base pi
if [ "${BaseConfig}" != "false" ]; then
echo -e "\n ${GREEN}[+]${RESET} Configuring ${GREEN}Raspberry Pi${RESET} ~ Hostname, password, and SSH keys"
echo -e "\n ${YELLOW}[i]${RESET} Enter a hostname for the pi:"
read piname
hostname "$piname"
cat /etc/hosts | sed s/"kali"/"$piname"/ > /tmp/newhosts
mv /tmp/newhosts /etc/hosts
cat /etc/hostname | sed s/"kali"/"$piname"/ > /tmp/newhostname
mv /tmp/newhostname /etc/hostname
echo -e "\n ${YELLOW}[i]${RESET} Changing root password:"
passwd
echo -e "\n ${YELLOW}[i]${RESET} Changing default SSH keys:"
update-rc.d -f ssh remove
update-rc.d -f ssh defaults
dpkg-reconfigure openssh-server

##### Change to text based
echo -e "\n ${GREEN}[+]${RESET} Changing ${GREEN}Raspberry Pi${RESET} to text-based"
#systemctl get-default
#systemctl set-default graphical.target
systemctl set-default multi-user.target
fi


##### Update Raspberry Pi
echo -e "\n ${GREEN}[+]${RESET} Updating ${GREEN}Raspberry Pi${RESET}"
apt-get update && apt-get install kali-linux-full && apt-get -y upgrade && apt-get -y dist-upgrade
apt-get install -y screen tmux hostapd dnsmasq wireless-tools iw wvdial resolvconf bridge-utils ebtables iptables arptables isc-dhcp-server


##### Backup default config files
cp /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.orig
cp /etc/dnsmasq.conf /etc/dnsmasq.conf.orig


##### Wifi AP Auto Run
if [ "${ConfigWifi}" != "false" ]; then
	echo -e "\n ${GREEN}[+]${RESET} Configuring WIFI AP auto run"

	echo -e "\n ${YELLOW}[i]${RESET} Enter the SSID:"
	read BSSID
	echo -e "\n ${YELLOW}[i]${RESET} Enter the passphrase:"
	read PASSPH

#Config AP
cat <<EOF > "/etc/hostapd/hostapd.conf"
interface=wlan0
driver=nl80211
ssid=$BSSID
hw_mode=g
channel=11
wpa=2
wpa_passphrase=$PASSPH
wpa_key_mgmt=WPA-PSK
wpa_ptk_rekey=600
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF
# Config DHCP
cat <<EOF > "/etc/dnsmasq.conf"
log-facility=/var/log/dnsmasq.log
address=/#/10.0.0.1
interface=wlan0
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
no-resolv
log-queries
EOF

cat <<EOF > "/root/config_ap.sh"
#Start AP
sleep 30
service network-manager stop
ifconfig wlan0 10.0.0.1
sleep 1m
dnsmasq -C /etc/dnsmasq.conf
hostapd -B /etc/hostapd/hostapd.conf
EOF

##### Make Executable
chmod 755 /root/config_ap.sh

cat <<EOF > "/etc/rc.local"
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

sh /root/config_ap.sh
exit 0

EOF

fi


##### SSH Auto Run
if [ "${ConfigSSH}" != "false" ]; then
echo -e "\n ${GREEN}[+]${RESET} Configuring SSH auto run"

echo -e "\n ${YELLOW}[i]${RESET} Enter server name/IP to phone home to:"
read SERVER
echo -e "\n ${YELLOW}[i]${RESET} Enter the username for the home box:"
read SERVUSR
echo -e "\n ${YELLOW}[i]${RESET} Enter the pivot port:"
read PIVPORT

##### Generate SSH Keys and add to authorized keys on main server
ssh-keygen -t rsa
cat ~/.ssh/id_rsa.pub | ssh $SERVUSR@$SERVER "cat - >> ~/.ssh/authorized_keys"
		
##### Create autossh script
cat <<EOF > "/root/autossh.sh"
#!/bin/sh
# Based on http://www.brandonhutchinson.com/ssh_tunnelling.html
# $REMOTE_HOST is the name of the remote system
REMOTE_HOST=$SERVER
 
# Setting username for home box
USER_NAME=$SERVUSR
 
# $REMOTE_PORT is the remote port number that will be used to tunnel
# back to this system
REMOTE_PORT=$PIVPORT
 
EOF
cat <<\EOF >> "/root/autossh.sh"
# $COMMAND is the command used to create the reverse ssh tunnel
COMMAND="ssh -q -N -R $REMOTE_PORT:localhost:22 $USER_NAME@$REMOTE_HOST"
 
# Is the tunnel up? Perform two tests:
 
# 1. Check for relevant process ($COMMAND)
pgrep -f -x "$COMMAND" > /dev/null 2>&1 || $COMMAND
 
# 2. Test tunnel by looking at "netstat" output on $REMOTE_HOST
ssh $REMOTE_HOST netstat -an | egrep "tcp.*:$REMOTE_PORT.*LISTEN" \
  	> /dev/null 2>&1
if [ $? -ne 0 ] ; then
  	pkill -f -x "$COMMAND"
  	$COMMAND
fi
EOF
	
##### Make Executable
chmod 755 /root/autossh.sh

##### Configure cron job to call home every 5 min
cat <<EOF > "/etc/cron.d/autossh"
*/5 * * * * root bash /root/autossh.sh
EOF

##### DONE
echo -e "From The Main Server:   ssh -D 1080 -p $PIVPORT pi@localhost"
fi

