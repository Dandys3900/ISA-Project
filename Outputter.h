#ifndef OUTPUTTERCLASS_H
#define OUTPUTTERCLASS_H

/*** Includes ***/
#include "Includes.h"

// Structure representing captured network traffic
typedef struct {
    unsigned long long packets_tx = 0;
    unsigned long long packets_rx = 0;
    unsigned long long bytes_tx   = 0;
    unsigned long long bytes_rx   = 0;
} NetRecord;

// Key = (source IP, destination IP, protocol)
using netKey = tuple<string, string, string>;
using netMap = map<netKey, NetRecord>;

class Outputter {
    private:
        const string sortby;

        // Use ncurses to display data in terminal
        void showData(const vector<pair<netKey, NetRecord>>);

    public:
        Outputter (const string);
       ~Outputter ();

       // Process captured data
       void processData(netMap);
};

#endif // OUTPUTTERCLASS_H
