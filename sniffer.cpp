#include <vector>
#include <string>
#include <tins/tins.h>
#include <tins/sniffer.h>
#include <iostream>

using namespace Tins;

// This is a handler used in Sniffer::sniff_loop
bool handler(const PDU& pkt) {

    // Lookup the UDP PDU
    const UDP &udp = pkt.rfind_pdu<UDP>();

    if(udp.sport() == 53 || udp.dport() == 53) {

        Tins::DNS dns = pkt.rfind_pdu<RawPDU>().to<DNS>();
        Tins::IP ip = pkt.rfind_pdu<RawPDU>().to<IP>();




        for(const auto &query : dns.queries()){
            std::cout << "New Connection found. \n "
                      << "--------------------- \n ";

            std::cout << "Source IP: " << ip.src_addr();
            std::cout << " Destination IP: " << ip.dst_addr();
            std::cout << " DNS Name: ";
            std::cout << query.dname() << std::endl;
        }

        for(const auto &rsc : dns.answers()){
            std::cout << "Packet data: " << rsc.data() << std::endl;
            std::cout << "TTL Field data: " << rsc.ttl() << std::endl;
        }
    }
    return true;
}

int main(int argc, char* argv[]) {
    std::string Wire;
    std::string Port;

    std::cout << "Hello and welcome to the Packet Sniffer\n";
    std::cout << "Starting the Packet Snifer...\n";
    if(argv[1] == NULL) { std::cout << "Error: No wire arugment given, please either specify wlan0 or eth0.\n"; std::cin >> Wire; }
    else Wire = argv[1];
    std::vector<Packet> vt;

    Tins::SnifferConfiguration config;
    config.set_promisc_mode(true);
    
    Tins::Sniffer sniffer(Wire, config);
    sniffer.sniff_loop(handler);

}