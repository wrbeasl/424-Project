#include <vector>
#include <string>
#include <tins/tins.h>
#include <iostream>

using namespace Tins;

// This is a handler used in Sniffer::sniff_loop
bool handler(const PDU& pkt) {

    // Lookup the UDP PDU
    const UDP &udp = pkt.rfind_pdu<UDP>();

    if(udp.sport() == 53 || udp.dport() == 53) {

        DNS dns = pkt.rfind_pdu<RawPDU>().to<DNS>();
        IP ip = pkt.rfind_pdu<RawPDU>().to<IP>();




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

int main() {
    std::string Wire;
    std::string Port;

    std::cout << "Hello and welcome to the Packet Sniffer\n";
    std::cout << "Please give which wire to sniff on: \n";
    std::cin >> Wire;
    std::vector<Packet> vt;

    SnifferConfiguration config;
    config.set_promisc_mode(true);
    
    Sniffer sniffer(Wire, config);
    sniffer.sniff_loop(handler);
    /*
    while(vt.size() != 10)
        // next_packet returns a PtrPacket, which can be implicitly converted to Packet.
        vt.push_back(sniffer.next_packet());
    // Done, now let's check the packets
    for(const auto& packet : vt) {
        // Is there an IP PDU somewhere?
        if(packet.pdu()->find_pdu<IP>()) {
            // Just print timestamp's seconds and IP source address
            std::cout << "At: " << packet.timestamp().seconds()
                    << " - " << packet.pdu()->rfind_pdu<IP>().src_addr() 
                    << std::endl;

            //handler(packet.pdu()->find_pdu<IP>());
        }
    } */
}