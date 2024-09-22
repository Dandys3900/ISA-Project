#ifndef NETWORKDATACLASS_H
#define NETWORKDATACLASS_H

/*** Includes ***/
#include "Includes.h"
#include "Outputter.h"

#define IPv4_TYPE 0x0800
#define IPv6_TYPE 0x86DD
#define ETHERNET_HEADER 14
#define IPV6_HEADER 40

// Handles captured packet
void handlePacket(u_char*, const struct pcap_pkthdr*, const u_char*);

class NetworkData {
    private:
        const int interface;
        vector<NetRecord> netData;
        pcap_t* descr;
        mutex vector_mutex;

        // Captures packets
        void capturePackets();

    public:
        NetworkData (const int interface);
       ~NetworkData ();

        // Starts packet capturing
        void startCapture();
        // Stops packet capturing
        void stopCapture();

        // Adds captured data to vector
        void addRecord(string, string, string, uint16_t);

        // Returns array of captured traffic and sets its length
        const vector<NetRecord> getCurrentData(unsigned int&);
};

#endif // NETWORKDATACLASS_H
