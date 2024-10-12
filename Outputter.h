/**
 * Author: Tomas Daniel
 * Login:  xdanie14
*/

#ifndef OUTPUTTERCLASS_H
#define OUTPUTTERCLASS_H

/*** Includes ***/
#include "Includes.h"

// Typedef for used data type
typedef long double longVal;

// Structure representing captured network traffic
typedef struct {
    longVal packets_tx = 0.0;
    longVal packets_rx = 0.0;
    longVal bytes_tx   = 0.0;
    longVal bytes_rx   = 0.0;
} netRecord;

// Key = (source IP, destination IP, protocol)
using netKey = tuple<string, string, string>;
using netMap = map<netKey, netRecord>;

class Outputter {
    private:
        const string sortby;
        longVal KILO, MEGA, GIGA;

        // Use ncurses to display data in terminal
        void showData(const vector<pair<netKey, netRecord>>&);

        // Convert values to kilo, mega, giga
        string convertValue(longVal);

    public:
        Outputter (const string);
       ~Outputter ();

       // Process captured data
       void processData(netMap);
};

#endif // OUTPUTTERCLASS_H
