#!/usr/bin/python2
# Author: @jkadijk
# Base decoderthread layout from the Impacket examples.

import sys
import string
from threading import Thread

import struct

import time
import socket
import os
import re
import pcapy
from pcapy import findalldevs, open_live
import impacket
import impacket.ImpactPacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder, IPDecoder

class DecoderThread(Thread):
    def __init__(self, pcapObj,subnet,arptable):
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.pcap = pcapObj
        self.subnet = subnet
        self.arptable = arptable
        Thread.__init__(self)
        #super(Thread, self).__init__()

    def run(self):
        # Sniff ad infinitum.
        # PacketHandler shall be invoked by pcap for every packet.
        self.pcap.loop(0, self.packetHandler)


    def packetHandler(self, hdr, data):
        e = self.decoder.decode(data)
        if e.get_ether_type() == impacket.ImpactPacket.IP.ethertype:
          #print e.child().get_ip_src()
          ip = e.child()
          ttl = ip.get_ip_ttl()
          ## Uneven but not 1 or 255 ttl means it's probably coming from a router ##
          if (ttl % 2) > 0 and ttl > 1 and ttl != 255:
              self.subnet.gatewaymac = e.get_ether_shost()
              self.subnet.sourcemac = e.get_ether_dhost()
              self.subnet.sourceaddress = ip.get_ip_dst()

        if e.get_ether_type() == impacket.ImpactPacket.ARP.ethertype:
          arp = e.child()
          self.subnet.registeraddress(arp.get_ar_tpa())
          self.subnet.registeraddress(arp.get_ar_spa())
          
          if arp.get_op_name(arp.get_ar_op()) == "REPLY":
              print "got arp reply"
              self.arptable.registeraddress(arp.get_ar_spa(), arp.as_hrd(arp.get_ar_sha()))
	  if arp.get_op_name(arp.get_ar_op()) == "REQUEST":
              self.arptable.registeraddress(arp.get_ar_spa(), arp.as_hrd(arp.get_ar_sha()))



class ArpTable():
    table = {}

    def registeraddress(self,ip_array, hw_address):
        ip = self.printip(ip_array)
	if ip != "0.0.0.0":
 		self.table[ip] = hw_address
		print "%s : %s" % (ip, hw_address)
        
    def printip(self,ip_array):
        ip_string = socket.inet_ntoa(struct.pack('BBBB', *ip_array))        
        return ip_string

    def updatekernel(self):
        for ip, mac in self.table.iteritems():
            p = os.popen("arp -i mibr -s %s %s" % (ip, mac))
            result = p.read()
            p.close()
            p = os.popen("ip route add %s/32 dev mibr" % ip)
            result = p.read()
            p.close()

## Only supports /24 or smaller
class Subnet():
    sourcemac = None
    gatewaymac = None
    subnet = None
    minaddress = None
    maxaddress = None
    sourceaddress = None
    gatewayaddress = ""
    
    confidence = 0

    def registeraddress(self,ip_array):
        if self.printip(ip_array) == "0.0.0.0":
            return False
        if(ip_array[0] == 169):
            return False
        if self.checksubnet(ip_array):
            if self.minaddress is None or self.minaddress[3] > ip_array[3]:
                self.minaddress = ip_array
            if self.maxaddress is None or self.maxaddress[3] < ip_array[3]:
                self.maxaddress = ip_array
        else:
            print self.printip(ip_array)
            print "[!] Error, duplicate or big subnet detected"

        
    def checksubnet(self,ip_array):
        if self.subnet == None:
            self.subnet = ip_array
            return True
        if ip_array[0] == self.subnet[0] and ip_array[1] == self.subnet[1]:
            return True
        else:
            return False

    def printip(self,ip_array):
        ip_string = socket.inet_ntoa(struct.pack('BBBB', *ip_array))        
        return ip_string

    def getcidr(self):
        if self.maxaddress and self.minaddress:
            bits = 0
            discovered_hosts = self.maxaddress[3] - self.minaddress[3] + 1
            hosts = 0
            while(hosts < discovered_hosts and bits <= 8):
                bits += 1
                hosts = 2**bits
            return bits
        else:
            return 0
    def get_gatewaymac(self):
        ethernet = impacket.ImpactPacket.Ethernet()
	temp = ethernet.as_eth_addr(self.gatewaymac)
        temp = re.sub(r':(\d):',r':0\1:', temp)
        return temp

    def get_sourcemac(self):
        ethernet = impacket.ImpactPacket.Ethernet()
        return ethernet.as_eth_addr(self.sourcemac)
    
    def __str__(self):
        ethernet = impacket.ImpactPacket.Ethernet()
        header = "Network config: \n"
        output = ""
        if self.minaddress and self.maxaddress:
            output += "cidr bits: %i\n" % self.getcidr()


        if self.sourcemac and self.gatewaymac:
            output += "source: %s gateway: %s\n" % (ethernet.as_eth_addr(self.sourcemac), ethernet.as_eth_addr(self.gatewaymac))

        if self.sourceaddress:
            output += "source ip: %s gateway ip: %s\n" % (self.sourceaddress, self.gatewayaddress)

        if output == "":
            return "Network config unknown"
        else:
            return header + output

## Create ebtables, arptables and iptables rules based on a subnet object
class Netfilter():
    subnet = None
    bridge = None

    switchsidemac = None
    radiosilence = False
    gatewayinterface = "eth9"
    bridgeinterface = "mibr"
    bridgeip = "169.254.66.77"
    def __init__(self, subnet, bridge):
        self.subnet = subnet
        os.system("sh ./ebtables-init")
        os.system("ebtables -A OUTPUT -j DROP")
        os.system("arptables -A OUTPUT -j DROP")

        

    def updatetables(self):
        os.system("sh ./ebtables-init")
        os.system("ebtables -A OUTPUT -j DROP")
        os.system("arptables -A OUTPUT -j DROP")
        print "searching for mac: %s ..." % subnet.get_gatewaymac()
        f=os.popen("brctl showmacs %s | grep %s | awk '{print $1}'" % (self.bridgeinterface, subnet.get_gatewaymac()))            
        portnumber =  f.read().rstrip()
        f.close()
        if(portnumber == ""):
            print "portnumber not found bailing"
            return False
        print "portnumber is: %s" % portnumber
        run = "brctl showstp %s | grep '(%s)' | head -n1 | awk '{print $1}'" % (self.bridgeinterface, portnumber)
        print run
                                                                                
        x = os.popen(run)
        interface = x.read()
        x.close()
        interface = interface.rstrip()
        print "got interface: %s .." % interface
        if(interface == ""):
            print "error getting interface is the bridge setup right?"
            return False
        print "switchside interface: %s" % interface
        self.gatewayinterface = interface
        f = os.popen("ip link show %s" % interface)
        result = f.read()
        f.close()
        matches = re.search("..:..:..:..:..:..", result)
        print "switchsidemac: %s" % matches.group(0)
        self.switchsidemac = matches.group(0)
        os.system("macchanger -m %s %s" % (self.switchsidemac, bridge.bridgename))
        print "Updating netfilter"
        os.system("ip addr add 169.254.66.77/24 dev mibr")
        os.system("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" % (self.switchsidemac, self.gatewayinterface, self.subnet.get_sourcemac()))
        os.system("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" % (self.switchsidemac, self.bridgeinterface, self.subnet.get_sourcemac()))

        os.system("arp -s -i %s 169.254.66.55 %s" % (self.bridgeinterface, self.subnet.get_gatewaymac()))
        print "[*] Setting up layer 3 NAT"
        os.system("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -p tcp -j SNAT --to %s:61000-62000" % (self.bridgeinterface,  self.subnet.sourceaddress ) )
        os.system("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -p udp -j SNAT --to %s:61000-62000" % (self.bridgeinterface,  self.subnet.sourceaddress ) )
        os.system("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -p icmp -j SNAT --to %s" % (self.bridgeinterface,  self.subnet.sourceaddress ) )
        if not self.radiosilence:
            os.system("ebtables -D OUTPUT -j DROP")
            os.system("arptables -D OUTPUT -j DROP")
        os.system("ip route del default")
        os.system("ip route add default via 169.254.66.55 dev mibr")


class Bridge():
    subnet = None
    bridgename = None
    
    def __init__(self, bridgename, interfaces):
        self.bridgename = bridgename
        os.system("brctl addbr %s" % bridgename)
        os.system("ip link set %s down" % bridgename)
        os.system("ip addr flush dev %s" % bridgename)
        os.system("macchanger -p %s" % bridgename)
        os.system("ip link set up %s" % bridgename)
        
      
        for interface in interfaces:
            os.system("ip link set %s down" % interface)
            os.system("sysctl -w net.ipv6.conf.%s.autoconf=0" % interface)
            os.system("sysctl -w net.ipv6.conf.%s.accept_ra=0" % interface)
            os.system("brctl addif %s %s" % (bridgename, interface))
            os.system("ip link set %s up" % interface)
            os.system("ip link set promisc on %s" % interface)
        os.system("sysctl -w net.ipv6.conf.%s.autoconf=0" % bridgename)
        os.system("sysctl -w net.ipv6.conf.%s.accept_ra=0" % bridgename)            
        os.system("ip link set promisc on %s" % bridgename)
        os.system("echo 8 > /sys/class/net/mibr/bridge/group_fwd_mask")





if __name__ == '__main__':
    #dev = getInterface()
    dev = 'eth1'
    bridge = Bridge("mibr", ["eth2", "eth1"])
    # Open interface for capturing.
    p = open_live(dev, 1500, 0, 100)

    print "Listening on %s: net=%s, mask=%s, linktype=%d" % (dev, p.getnet(), p.getmask(), p.datalink())
    subnet = Subnet()
    arptable = ArpTable()
    # Start sniffing thread and finish main thread.
    thread = DecoderThread(p,subnet,arptable)
    thread.start()


    netfilter = Netfilter(subnet, bridge)
    while(1):
        if subnet.sourceaddress and subnet.gatewaymac and subnet.sourcemac:
            print subnet

            netfilter.updatetables()
            break
        else:
            print "not enough info..."
            print subnet
	    time.sleep(20)

    # setup routing and dhcp on builtin ethernet
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
#    os.system("ifconfig wlan0 169.254.44.44/24")
#    os.system("ifconfig wlan0 up")
    #os.system("/usr/sbin/dhcpd -4 -pf /run/dhcpd4.pid wlan0")
#    os.system("udhcpd /etc/udhcpd-wlan0.conf")
#    os.system("/usr/local/bin/hostapd -B /etc/hostapd/hostapd.conf")
    time.sleep(5)

    ## arp setup ##
    try:
		while(1):
		    f = open('/root/subnetinfo', 'w')
		    f.write(str(subnet))
		    f.close()

		    arptable.updatekernel()

		    time.sleep(20)
    except KeyboardInterrupt:
		pass # handle ctrl-c

