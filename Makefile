sniffer: sniffer.cpp
	g++ -std=c++11 sniffer.cpp -o sniffer -ltins -lpthread 

traceroute: traceroute.cpp
	g++ -std=c++11 traceroute.cpp -o traceroute -ltins -lpthread

dns: dns.cpp
	g++ -std=c++11 dns.cpp -o dns -ltins -lpthread

arp: arp-monitor.cpp
	g++ -std=c++11 arp-monitor.cpp -o arp -ltins -lpthread