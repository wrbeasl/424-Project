#include <tins/tins.h>

using namespace Tins;

bool doo(PDU&) {
    return false;
}

struct foo {
    void bar() {
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("ip src 192.168.0.100");
        Sniffer sniffer("wlan0", config);
        /* Uses the helper function to create a proxy object that
         * will call this->handle. If you're using boost or C++11,
         * you could use boost::bind or std::bind, that will also
         * work.
         */
        sniffer.sniff_loop(make_sniffer_handler(this, &foo::handle));
        // Also valid
        sniffer.sniff_loop(doo);
    }
    
    bool handle(PDU&) {
        // Don't process anything
        return false;
    }
};

int main() {
    foo f;
    f.bar();
}