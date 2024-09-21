///*** Includes ***/
#include "NetworkData.h"

NetworkData::NetworkData(const int interface)
    : interface (interface),
      netData   (),
      descr     (nullptr)
{
}

NetworkData::~NetworkData()
{
}

void NetworkData::handlePacket(u_char* data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    lock_guard<std::mutex> lock(this->vector_mutex);
}

void NetworkData::capturePackets() {
    // Used device name
    char* dev;
    // Error buffer
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find device to use for sniffing
    if (!(dev = pcap_lookupdev(errbuf)))
        throw logic_error(format("Error in {}: {}", __FUNCTION__, errbuf));

    // Open device for sniffing
    if (!(this->descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf)))
        throw logic_error(format("Error in {}: {}", __FUNCTION__, errbuf));

    // Begin capturing loop
    while(true) {
        if (pcap_loop(descr, 1, handlePacket, nullptr) < 0)
            throw logic_error(format("Error in {}: {}", __FUNCTION__, errbuf));
    }
}

void NetworkData::startCapture() {
    // Create thread for capturing loop
    jthread(capturePackets);
}

void NetworkData::stopCapture() {
    pcap_breakloop(this->descr);
    pcap_close(this->descr);
}

const vector<NetRecord> NetworkData::getCurrentData(unsigned int& length) {
    lock_guard<std::mutex> lock(this->vector_mutex);
    // Set length of network data array
    length = this->netData.size();
    // Return data
    return this->netData;
}
