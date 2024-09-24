#ifndef INCLUDES_H
#define INCLUDES_H

/*** File containing necessary project includes ***/
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <map>
#include <format>
#include <csignal>
#include <vector>
#include <thread>
#include <pcap.h>
#include <mutex>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include "CustomException.cpp"

using namespace std;

// Network constants
#define ETHERNET_HEADER 14
#define IPV6_HEADER 40

// Output constants
#define BYTES "b" // Default selection
#define PACKETS "p"

#endif // INCLUDES_H
