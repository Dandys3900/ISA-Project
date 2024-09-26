///*** Includes ***/
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
    : interface (interface),
      macAddrs  (),
      netData   (),
      descr     (NULL),
      devc      (NULL),
      stop      (false)
{
    // Validate provided interface
    this->devc = this->validateInterface();
    // Get interface MAC address(es)
    this->macAddrs = getMACAddr(this->devc->addresses);
}

NetworkData::~NetworkData()
{
}

void NetworkData::addRecord(netKey key, uint16_t bytes, string direction) {
    // Add parsed data to vector
    lock_guard<std::mutex> lock(this->vector_mutex);
    // Get key value stored in map
    NetRecord& curData = this->netData[key];
    // Update record value
    if (direction == TX) {
        curData.bytes_tx   += bytes;
        curData.packets_tx += 1;
    }
    else { // direction == RX
        curData.bytes_rx   += bytes;
        curData.packets_rx += 1;
    }
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
    if (!(this->descr = pcap_open_live(this->interface.c_str(), BUFSIZ, NON_PROMISCUOUS_MODE, -1, this->errbuf)))
        throw ProgramException(format("Error in {}: {}", __FUNCTION__, this->errbuf));

    // Begin capturing loop
    while(!this->stop) {
        // Avoid throwing exception when capturing is purposely closed
        if (pcap_loop(this->descr, 1, handlePacket, reinterpret_cast<u_char*>(this)) < 0 && !stop)
            throw ProgramException(format("Error in {}: {}", __FUNCTION__, this->errbuf));
    }
}

void NetworkData::startCapture() {
    // Create thread for capturing loop
    jthread(&NetworkData::capturePackets, this);
}

void NetworkData::stopCapture() {
    this->stop = true;
    pcap_freealldevs(this->devc);
    pcap_breakloop(this->descr);
    pcap_close(this->descr);
}

netMap NetworkData::getCurrentData() {
    lock_guard<std::mutex> lock(this->vector_mutex);
    // Return data
    return this->netData;
}

const vector<string> NetworkData::getMACAddrs() {
    return this->macAddrs;
}

/******************************************************************************/

// Convert MAC of validated interface to string
vector<string> getMACAddr(pcap_addr* addrs) {
    vector<string> results;
    for ( ; addrs != nullptr; addrs = addrs->next) {
        // Make sure to handle only MAC
        if (addrs->addr->sa_family == AF_PACKET) {
            struct sockaddr_ll* mac = (struct sockaddr_ll*) addrs->addr;
            // Create string for address
            string macAddr;
            // Parse address to string
            for (int i = 0; i < mac->sll_halen; ++i) {
                macAddr += format("{:02x}", mac->sll_addr[i]);
                macAddr += (i != (mac->sll_halen - 1)) ? ":" : "";
            }
            // Add parsed address to vector
            results.push_back(macAddr);
        }
    }
    // Make sure vector is not empty
    if (results.empty())
        throw ProgramException("None MAC address found for given interface");
    // Return parsed addresses
    return results;
}

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
    // Extract source and destination MAC addresses to determine packet direction
    const string srcMAC  = ether_ntoa((struct ether_addr*)&ethHeader->ether_shost);
    const string destMAC = ether_ntoa((struct ether_addr*)&ethHeader->ether_dhost);

    // Determine packet direction
    auto macAddrs = classPtr->getMACAddrs();
    const string direction = (count(macAddrs.begin(), macAddrs.end(), srcMAC) > 0) ? TX : RX;

    // Adapt parsing to IP version
    switch(ntohs(ethHeader->ether_type)) {
        case ETHERTYPE_IP: { // IPv4
            // Extract data from packet
            auto ipHeader = (struct ip*)(packet + ETHERNET_HEADER);

            // Get source, destination, protocol and bytes
            sourceIP = inet_ntoa(ipHeader->ip_src);
            destIP   = inet_ntoa(ipHeader->ip_dst);
            protocol = (protocolsMap.find(ipHeader->ip_p))->second;
            bytes    = ntohs(ipHeader->ip_len);

            // Depending on used protocol, also add source and destination ports
            if (ipHeader->ip_p == IPPROTO_TCP || ipHeader->ip_p == IPPROTO_UDP) {
                // Interested src and dest values have same ofset for both TCP and UDP, so we can treat them same
                auto header = (struct tcphdr*)(packet + ETHERNET_HEADER + (4 * ipHeader->ip_hl));
                // Add ports to IP addresses
                sourceIP = format("{}:{}", sourceIP, ntohs(header->th_sport));
                destIP   = format("{}:{}", destIP,   ntohs(header->th_dport));
            }
            break;
        }
        case ETHERTYPE_IPV6: { // IPv6
            // Extract data from packet
            auto ipHeader = (struct ip6_hdr*)(packet + ETHERNET_HEADER);
            // Ensure enough size of address strings
            sourceIP.resize(INET6_ADDRSTRLEN);
            destIP.resize(INET6_ADDRSTRLEN);

            // Get source, destination, protocol and bytes
            inet_ntop(AF_INET6, &(ipHeader->ip6_src), sourceIP.data(), INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ipHeader->ip6_dst), destIP.data(),   INET6_ADDRSTRLEN);
            protocol = (protocolsMap.find(ipHeader->ip6_nxt))->second;
            bytes    = ntohs(ipHeader->ip6_plen) + IPV6_HEADER;

            // Depending on used protocol, also add source and destination ports
            if (ipHeader->ip6_nxt == IPPROTO_TCP || ipHeader->ip6_nxt == IPPROTO_UDP) {
                // Interested src and dest values have same ofset for both TCP and UDP, so we can treat them same
                auto header = (struct tcphdr*)(packet + ETHERNET_HEADER + IPV6_HEADER);
                // Add ports to IP addresses
                sourceIP = format("[{}]:{}", sourceIP, ntohs(header->th_sport));
                destIP   = format("[{}]:{}", destIP,   ntohs(header->th_dport));
            }
            break;
        }
        case ETHERTYPE_ARP:    // ARP
        case ETHERTYPE_REVARP: // RARP
            return;
        default:
            throw ProgramException("Unknown protocol provided");
    }
    // Add parsed data to vector
    classPtr->addRecord(make_tuple(sourceIP, destIP, protocol), bytes, direction);
}
