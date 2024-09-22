#ifndef OUTPUTTERCLASS_H
#define OUTPUTTERCLASS_H

/*** Includes ***/
#include "Includes.h"

enum SORTBY {
    BYTES = 0, // Default selection
    PACKETS
};

// Structure representing captured network traffic
typedef struct {
    string sourceIP          = "";
    string destIP            = "";
    string protocol          = "";
    unsigned long long bytes = 0;
} NetRecord;

class Outputter {
    private:
        const int sortby;

    public:
        Outputter (const unsigned int);
       ~Outputter ();
};

#endif // OUTPUTTERCLASS_H
