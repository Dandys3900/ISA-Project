///*** Includes ***/
#include "NetworkData.h"

// Convert protocol enum to string
map<uint8_t, string> protocolsMap = {
    {IPPROTO_IP, "ip"},
    {IPPROTO_IPV6, "ipv6"},
    {IPPROTO_ICMP, "icmp"},
    {IPPROTO_IGMP, "igmp"},
    {IPPROTO_TCP, "tcp"},
    {IPPROTO_UDP, "udp"}
};

void handlePacket(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    // Ignore invalid packet
    if (header->len < sizeof(struct ip))
        return;

    // Get class pointer
    NetworkData* classPtr = reinterpret_cast<NetworkData*>(args);
    // Allocate string for IP addresses
    string sourceIP, destIP, protocol;
    uint16_t bytes;

    auto ethHeader = (const struct ether_header*)packet;
    // Adapt parsing to IP version
    switch(ntohs(ethHeader->ether_type)) {
        case ETHERTYPE_IP: { // IPv4
            // Extract data from packet
            auto ipHeader = (const struct ip*)(packet + ETHERNET_HEADER);

            // Get source, destination, protocol and bytes
            sourceIP =  inet_ntoa(ipHeader->ip_src);
            destIP   =  inet_ntoa(ipHeader->ip_dst);
            protocol = (protocolsMap.find(ipHeader->ip_p))->second;
            bytes    = ntohs(ipHeader->ip_len);

            // Depending on used protocol, also add source and destination ports
            if (ipHeader->ip_p == IPPROTO_TCP || ipHeader->ip_p == IPPROTO_UDP) {
                // Interested src and dest values have same ofset for both TCP and UDP, so we can treat them same
                auto header = (const struct tcphdr*)(packet + ETHERNET_HEADER + (4 * ipHeader->ip_hl));
                // Add ports to IP addresses
                sourceIP = format("{}:{}", sourceIP, ntohs(header->th_sport));
                destIP   = format("{}:{}", destIP,   ntohs(header->th_dport));
            }
            break;
        }
        case ETHERTYPE_IPV6: { // IPv6
            // Extract data from packet
            auto ipHeader = (const struct ip6_hdr*)(packet + ETHERNET_HEADER);
            // Ensure enough size of address strings
            sourceIP.reserve(INET6_ADDRSTRLEN);
            destIP.reserve(INET6_ADDRSTRLEN);

            // Get source, destination, protocol and bytes
            inet_ntop(AF_INET6, &(ipHeader->ip6_src), sourceIP.data(), INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipHeader->ip6_dst), destIP.data(), INET6_ADDRSTRLEN);
            protocol = (protocolsMap.find(ipHeader->ip6_nxt))->second;
            bytes    = ntohs(ipHeader->ip6_plen) + IPV6_HEADER;

            // Depending on used protocol, also add source and destination ports
            if (ipHeader->ip6_nxt == IPPROTO_TCP || ipHeader->ip6_nxt == IPPROTO_UDP) {
                // Interested src and dest values have same ofset for both TCP and UDP, so we can treat them same
                auto header = (const struct tcphdr*)(packet + ETHERNET_HEADER + IPV6_HEADER);
                // Add ports to IP addresses
                sourceIP = format("[{}]:{}", sourceIP, ntohs(header->th_sport));
                destIP   = format("[{}]:{}", destIP,   ntohs(header->th_dport));
            }
            break;
        }
        case ETHERTYPE_ARP: // ARP
            break;
        case ETHERTYPE_REVARP: // RARP
            break;
        default:
            throw ProgramException("Unknown protocol provided");
    }
    // Add parsed data to vector
    classPtr->addRecord(sourceIP, destIP, protocol, bytes);
}

NetworkData::NetworkData(const string interface)
    : interface (interface),
      netData   (),
      descr     (NULL),
      devc      (NULL)
{
    // Validate provided interface
    devc = this->validateInterface();
}

NetworkData::~NetworkData()
{
}

void NetworkData::addRecord(string srcIP, string destIP, string protocol, uint16_t bytes) {
    // Add parsed data to vector
    lock_guard<std::mutex> lock(this->vector_mutex);
    this->netData.push_back((NetRecord){
        .sourceIP = srcIP,
        .destIP   = destIP,
        .protocol = protocol,
        .bytes    = bytes
    });
}

pcap_if_t* NetworkData::validateInterface() {
    // List of all devices
    pcap_if_t* alldevs;

    // Get all available devices
    if (pcap_findalldevs(&alldevs, this->errbuf) == -1)
        throw ProgramException(format("Error in {}: {}", __FUNCTION__, errbuf));

    // Iterate over device to find user-provided interface
    for ( ; alldevs; alldevs = alldevs->next) {
        // Device found, return it
        if (alldevs->name == this->interface)
            return alldevs;
    }
    // Device not found - throw error
    throw ProgramException(format("Provided interface: {} not found", this->interface));
}

void NetworkData::capturePackets() {
    // Open device for sniffing
    if (!(this->descr = pcap_open_live(this->interface.c_str(), BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, -1, this->errbuf)))
        throw ProgramException(format("Error in {}: {}", __FUNCTION__, this->errbuf));

    // Begin capturing loop
    while(true) {
        if (pcap_loop(this->descr, 1, handlePacket, reinterpret_cast<u_char*>(this)) < 0)
            throw ProgramException(format("Error in {}: {}", __FUNCTION__, this->errbuf));
    }
}

void NetworkData::startCapture() {
    // Create thread for capturing loop
    jthread(&NetworkData::capturePackets, this);
}

void NetworkData::stopCapture() {
    pcap_freealldevs(this->devc);
    pcap_breakloop(this->descr);
    pcap_close(this->descr);
}

const vector<NetRecord> NetworkData::getCurrentData() {
    lock_guard<std::mutex> lock(this->vector_mutex);
    // Return data
    return this->netData;
}
