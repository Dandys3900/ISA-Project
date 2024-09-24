#ifndef NETWORKDATACLASS_H
#define NETWORKDATACLASS_H

/*** Includes ***/
#include "Includes.h"
#include "Outputter.h"

// Handles captured packet
void handlePacket(u_char*, const struct pcap_pkthdr*, const u_char*);

class NetworkData {
    private:
        const string interface;
        vector<NetRecord> netData;
        pcap_t* descr;
        mutex vector_mutex;
        // Error buffer
        char errbuf[PCAP_ERRBUF_SIZE];

        // Captures packets
        void capturePackets();

        // Check if provided interface is valid
        void validateInterface();

    public:
        NetworkData (const string);
       ~NetworkData ();

        // Starts packet capturing
        void startCapture();
        // Stops packet capturing
        void stopCapture();

        // Adds captured data to vector
        void addRecord(string, string, string, uint16_t);

        // Returns array of captured traffic and sets its length
        const vector<NetRecord> getCurrentData();
};

#endif // NETWORKDATACLASS_H
