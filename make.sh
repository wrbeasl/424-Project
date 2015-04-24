#!/bin/bash
# Make the files
#make arp
#make dns
#make sniffer
#make traceroute

# Open the terminals
#sudo ./sniffer wlan0 > sniff.log &
#sudo ./traceroute    > trace.log &
#sudo ./dns wlan0     > dns.log   &
#sudo ./arp wlan0     > arp.log
gnome-terminal -e "sudo ./sniffer wlan0"
gnome-terminal -e "sudo ./traceroute"
gnome-terminal -e "sudo ./dns wlan0"
gnome-terminal -e "sudo ./arp wlan0"

