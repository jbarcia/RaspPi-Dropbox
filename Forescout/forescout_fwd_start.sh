#!/bin/sh

if [ $# -eq 0 ]
  then
    echo "Usage:  $0 <NAC scanner> <target host>"
    echo
    echo "Or just answer these questions:"
    echo "What is the NAC scanner IP?  This is the IP that scans your system."
    read nac_ip
    echo "Where should the traffic be forwarded to?"
    read forward_ip
  else
    nac_ip=$1
    forward_ip=$2
fi


echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -t nat -A PREROUTING -s $nac_ip -j DNAT --to-destination $forward_ip
