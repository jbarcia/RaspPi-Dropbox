#Config AP
cat <<EOF > "/etc/hostapd/hostapd.conf"
interface=wlan0
driver=nl80211
ssid=Nothingtoseehere
hw_mode=g
channel=11
wpa=2
wpa_passphrase=hackallthethings
wpa_key_mgmt=WPA-PSK
wpa_ptk_rekey=600
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF
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
#cat <<EOF > "/etc/dhcp/dhcpd.conf"
#default-lease-time 600;
#max-lease-time 7200;
#authoritative;
#subnet 10.0.0.0 netmask 255.255.255.0 {
#    option subnet-mask 255.255.255.0;
#    option broadcast-address 10.0.0.255;
#    option routers 10.0.0.254;
#    option domain-name-servers 8.8.8.8;
#    range 10.0.0.1 10.0.0.140;
#}
#EOF

#Start AP
sleep 30
service network-manager stop
ifconfig wlan0 10.0.0.1
sleep 1m
#service dnsmasq start
#service hostapd start
#hostapd -d /etc/hostapd/hostapd.conf
dnsmasq -C /etc/dnsmasq.conf
#dhcpd -d -cf /etc/dhcp/dhcpd.conf -pf /var/run/dhcpd.pid wlan0
hostapd -B /etc/hostapd/hostapd.conf

