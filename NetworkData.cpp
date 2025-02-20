/**
 * Author: Tomas Daniel
 * Login:  xdanie14
*/

/*** Includes ***/
#include "NetworkData.h"

// Convert protocol enum to string
map<uint8_t, string> protocolsMap = {
    {IPPROTO_IP,   "ip"  },
    {IPPROTO_IPV6, "ipv6"},
    {IPPROTO_ICMP, "icmp"},
    {IPPROTO_IGMP, "igmp"},
    {IPPROTO_TCP,  "tcp" },
    {IPPROTO_UDP,  "udp" }
};

NetworkData::NetworkData(const string interface)
    : interface      (interface),
      netData        (),
      descr          (nullptr),
      captureThread  (),
      mp_stopCapture (false)
{
    // Validate provided interface
    if (!this->validateInterface())
        throw ProgramException(string("Provided interface not found: " + this->interface));
}

NetworkData::~NetworkData()
{
}

void NetworkData::addRecord(const string sourceIP, const string destIP, const string protocol, uint16_t bytes) {
    // Add parsed data to vector
    lock_guard<std::mutex> lock(this->vector_mutex);
    // Create map key
    netKey key    = make_tuple(sourceIP, destIP, protocol);
    netKey revKey = make_tuple(destIP, sourceIP, protocol);

    if (this->netData.contains(revKey)) {
        // Get key value stored in map
        netRecord& curData = this->netData[revKey];
        // Direction: TX
        curData.bytes_tx   += bytes;
        curData.packets_tx += 1;
    }
    else {
        // Get key value stored in map
        netRecord& curData = this->netData[key];
        // Direction: RX
        curData.bytes_rx   += bytes;
        curData.packets_rx += 1;
    }
}

bool NetworkData::validateInterface() {
    // List of all devices
    pcap_if_t* alldevs;
    pcap_if* dev;

    // Get all available devices
    if (pcap_findalldevs(&alldevs, this->errbuf) == -1)
        throw ProgramException(string(this->errbuf));

    // Iterate over device to find user-provided interface
    for (dev = alldevs; dev; dev = dev->next) {
        // Device found, return it
        if (dev->name == this->interface) {
            pcap_freealldevs(alldevs);
            return true;
        }
    }
    pcap_freealldevs(alldevs);
    return false;
}

void NetworkData::capturePackets() {
    // Open device for sniffing
    if (!(this->descr = pcap_open_live(this->interface.c_str(), BUFSIZ, NON_PROMISCUOUS_MODE, -1, this->errbuf)))
        throw ProgramException(string(this->errbuf));

    // Begin capturing loop
    while(!this->mp_stopCapture) {
        // Setup loop and callback function
        if (pcap_loop(this->descr, 1, handlePacket, reinterpret_cast<u_char*>(this)) < 0)
            break;
    }
    // Free resources
    pcap_close(this->descr);
    this->descr = nullptr;
}

void NetworkData::startCapture() {
    // Create thread for capturing loop
    this->captureThread = jthread(&NetworkData::capturePackets, this);
}

void NetworkData::stopCapture() {
    this->mp_stopCapture = true;
    if (this->descr != nullptr)
        pcap_breakloop(this->descr);
}

netMap NetworkData::getCurrentData() {
    lock_guard<std::mutex> lock(this->vector_mutex);
    // Make copy
    auto map_copy = this->netData;
    // Clear original map
    this->netData.clear();
    // Return copy
    return map_copy;
}

/******************************************************************************/

void handlePacket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    // Ignore invalid packet
    if (header->len < sizeof(struct ip))
        return;

    // Get class pointer
    NetworkData* classPtr = reinterpret_cast<NetworkData*>(args);
    // Allocate string for IP addresses
    string sourceIP, destIP, protocol;
    uint16_t bytes;

    auto ethHeader = (struct ether_header*)packet;
    // Adapt parsing to IP version
    switch(ntohs(ethHeader->ether_type)) {
        case ETHERTYPE_IP: { // IPv4
            // Extract data from packet
            auto ipHeader = (struct ip*)(packet + ETHERNET_HEADER);

            // Get source, destination, protocol and bytes
            sourceIP = inet_ntoa(ipHeader->ip_src);
            destIP   = inet_ntoa(ipHeader->ip_dst);
            bytes    = ntohs(ipHeader->ip_len);
            // Unsupported protocol -> ignore it
            if (protocolsMap.contains(ipHeader->ip_p))
                protocol = (protocolsMap.find(ipHeader->ip_p))->second;
            else return;

            // Depending on used protocol, also add source and destination ports
            if (ipHeader->ip_p == IPPROTO_TCP || ipHeader->ip_p == IPPROTO_UDP) {
                // Interested src and dest values have same ofset for both TCP and UDP, so we can treat them same
                auto header = (struct tcphdr*)(packet + ETHERNET_HEADER + (4 * ipHeader->ip_hl));
                // Add ports to IP addresses
                sourceIP = sourceIP + ":" + to_string(ntohs(header->source));
                destIP   = destIP   + ":" + to_string(ntohs(header->dest));
            }
            break;
        }
        case ETHERTYPE_IPV6: { // IPv6
            // Extract data from packet
            auto ipHeader = (struct ip6_hdr*)(packet + ETHERNET_HEADER);
            // Create buffers for addresses
            char src_addr[INET6_ADDRSTRLEN];
            char dest_addr[INET6_ADDRSTRLEN];

            // Get source, destination, protocol and bytes
            inet_ntop(AF_INET6, &(ipHeader->ip6_src), src_addr, sizeof(src_addr));
            sourceIP = src_addr;
            inet_ntop(AF_INET6, &(ipHeader->ip6_dst), dest_addr, sizeof(dest_addr));
            destIP = dest_addr;
            bytes = ntohs(ipHeader->ip6_plen);
            // Unsupported protocol -> ignore it
            if (protocolsMap.contains(ipHeader->ip6_nxt))
                protocol = (protocolsMap.find(ipHeader->ip6_nxt))->second;
            else return;

            // Depending on used protocol, also add source and destination ports
            if (ipHeader->ip6_nxt == IPPROTO_TCP || ipHeader->ip6_nxt == IPPROTO_UDP) {
                // Interested src and dest values have same ofset for both TCP and UDP, so we can treat them same
                auto header = (struct tcphdr*)(packet + ETHERNET_HEADER + IPV6_HEADER);
                // Add ports to IP addresses
                sourceIP = "[" + sourceIP + "]" + ":" + to_string(ntohs(header->source));
                destIP   = "[" + destIP   + "]" + ":" + to_string(ntohs(header->dest));
            }
            break;
        }
        case ETHERTYPE_ARP:    // ARP
        case ETHERTYPE_REVARP: // RARP
            return;
        default:
            throw ProgramException("Unknown EHT-type provided");
    }
    // Add parsed data to vector
    classPtr->addRecord(sourceIP, destIP, protocol, bytes);
}
