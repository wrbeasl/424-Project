
all: sniffer traceroute dns arp

sniffer: sniffer.cpp
	g++-4.7 -std=c++11 sniffer.cpp -o sniffer -ltins -lpthread 

traceroute: traceroute.cpp
	g++-4.7 -std=c++11 traceroute.cpp -o traceroute -ltins -lpthread

dns: dns.cpp
	g++-4.7 -std=c++11 dns.cpp -o dns -ltins -lpthread

arp: arp-monitor.cpp
	g++-4.7 -std=c++11 arp-monitor.cpp -o arp -ltins -lpthread

clean:
	rm arp dns traceroute sniffer
