#ifndef NETWORKDATACLASS_H
#define NETWORKDATACLASS_H

/*** Includes ***/
#include "Includes.h"
#include "Outputter.h"

class NetworkData {
    private:
        const int interface;
        vector<NetRecord> netData;
        pcap_t* descr;
        mutex vector_mutex;

        // Handles captured packet
        void handlePacket(u_char* data, const struct pcap_pkthdr* pkthdr, const u_char* packet);
        // Captures packets
        void capturePackets();

    public:
        NetworkData (const int interface);
       ~NetworkData ();

        // Starts packet capturing
        void startCapture();
        // Stops packet capturing
        void stopCapture();

        // Returns array of captured traffic and sets its length
        const vector<NetRecord> getCurrentData(unsigned int& length);
};

#endif // NETWORKDATACLASS_H
