#!/bin/sh

echo "Stopping IP forwarding"
echo 0 > /proc/sys/net/ipv4/ip_forward
echo "Removing rule:  iptables -t nat -D POSTROUTING -j MASQUERADE"
iptables -t nat -D POSTROUTING -j MASQUERADE
# line=`iptables -t nat --list-rules | grep DNAT | cut -d ' ' -f 2-`
echo "Flushing NAT rules"
iptables -t nat -F
