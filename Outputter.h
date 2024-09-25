#ifndef OUTPUTTERCLASS_H
#define OUTPUTTERCLASS_H

/*** Includes ***/
#include "Includes.h"

// Structure representing captured network traffic
typedef struct {
    unsigned long long packets = 0;
    unsigned long long bytes   = 0;
} NetRecord;

class Outputter {
    private:
        const string sortby;

    public:
        Outputter (const string);
       ~Outputter ();
};

#endif // OUTPUTTERCLASS_H
