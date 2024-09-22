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
    // Get IP version
    auto ethHeader = (const struct ether_header*)packet;
    uint16_t ipVer = ntohs(ethHeader->ether_type);

    // Allocate string for IP addresses
    string sourceIP, destIP, protocol;
    uint16_t bytes;
    // Ensure enough size of address strings
    sourceIP.reserve(INET_ADDRSTRLEN ? ipVer == IPv4_TYPE : INET6_ADDRSTRLEN),
    destIP.reserve(INET_ADDRSTRLEN ? ipVer == IPv4_TYPE : INET6_ADDRSTRLEN);

    // Adapt parsing to IP version
    switch(ipVer) {
        case IPv4_TYPE: {
            // Extract data from packet
            auto ipHeader = (const struct ip*)(packet + ETHERNET_HEADER);
            // Get source, destination, protocol and bytes
            inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP.data(), INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP.data(), INET_ADDRSTRLEN);
            protocol = (protocolsMap.find(ipHeader->ip_p))->second;
            bytes = ntohs(ipHeader->ip_len);
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
        case IPv6_TYPE: {
            // Extract data from packet
            auto ipHeader = (const struct ip6_hdr*)(packet + ETHERNET_HEADER);
            // Get source, destination, protocol and bytes
            inet_ntop(AF_INET6, &(ipHeader->ip6_src), sourceIP.data(), INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipHeader->ip6_dst), destIP.data(), INET6_ADDRSTRLEN);
            protocol = (protocolsMap.find(ipHeader->ip6_nxt))->second;
            bytes = ntohs(ipHeader->ip6_plen) + IPV6_HEADER;
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
        default:
            throw logic_error("Unknown IP version provided");
    }
    // Add parsed data to vector
    classPtr->addRecord(sourceIP, destIP, protocol, bytes);
}

NetworkData::NetworkData(const int interface)
    : interface (interface),
      netData   (),
      descr     (nullptr)
{
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

void NetworkData::capturePackets() {
    // List of all devices
    pcap_if_t* alldevs;
    // Error buffer
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        throw logic_error(format("Error in {}: {}", __FUNCTION__, errbuf));

    // Iterate over device list to get n-device by given interface value
    for (int pos = 1; pos != this->interface && alldevs; ++pos, alldevs = alldevs->next) {}
    // Check if found
    if (!alldevs)
        throw logic_error("Requested interface number not found");

    // Open device for sniffing
    if (!(this->descr = pcap_open_live(alldevs->name, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, -1, errbuf)))
        throw logic_error(format("Error in {}: {}", __FUNCTION__, errbuf));

    // Begin capturing loop
    while(true) {
        if (pcap_loop(descr, 1, handlePacket, reinterpret_cast<u_char*>(this)) < 0)
            throw logic_error(format("Error in {}: {}", __FUNCTION__, errbuf));
    }
    // Cleanup
    pcap_freealldevs(alldevs);
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
