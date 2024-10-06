/**
 * Author: Tomas Daniel
 * Login:  xdanie14
*/

#ifndef NETWORKDATACLASS_H
#define NETWORKDATACLASS_H

/*** Includes ***/
#include "Includes.h"
#include "Outputter.h"

// Get MAC address of selected interface
vector<string> getMACAddr(pcap_addr*);

// Handles captured packet
void handlePacket(u_char*, const struct pcap_pkthdr*, const u_char*);

class NetworkData {
    private:
        const string interface;
        vector<string> macAddrs;
        netMap netData;
        pcap_t* descr;
        mutex vector_mutex;
        jthread captureThread;
        atomic<bool> mp_stopCapture;
        // Error buffer
        char errbuf[PCAP_ERRBUF_SIZE];

        // Captures packets
        void capturePackets();

        // Check if provided interface is valid
        bool validateInterface();

    public:
        NetworkData (const string);
       ~NetworkData ();

        // Starts packet capturing
        void startCapture();
        // Stops packet capturing
        void stopCapture();

        // Adds captured data to vector
        void addRecord(const string, const string, const string, uint16_t);

        // Returns array of captured traffic
        netMap getCurrentData();

        // Returns interface's MAC addresses
        const vector<string> getMACAddrs();
};

#endif // NETWORKDATACLASS_H
