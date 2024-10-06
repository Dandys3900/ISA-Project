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

// Custom struct for avoiding value overflowing
struct safeValue {
    longVal value;
    // Constructor
    safeValue()
        : value (0)
    {
    }

    // Overload += to handle value overflows
    safeValue& operator+=(int incr_value) {
        // If overflow, reset current value back to 0
        if (this->value > (numeric_limits<longVal>::max() - incr_value))
            this->value = 0;
        // Do increment when safe
        this->value += incr_value;
        return *this;
    }
    // Overload + operator
    friend safeValue operator+(const safeValue& leftVal, const safeValue& rightVal) {
        safeValue result(leftVal);
        // Use overloaded += operator
        result += rightVal.value;
        return result;
    }
    // Overload > operator
    friend bool operator>(const safeValue& leftVal, const safeValue& rightVal) {
        return leftVal.value > rightVal.value;
    }
};

// Structure representing captured network traffic
typedef struct {
    safeValue packets_tx;
    safeValue packets_rx;
    safeValue bytes_tx;
    safeValue bytes_rx;
} NetRecord;

// Key = (source IP, destination IP, protocol)
using netKey = tuple<string, string, string>;
using netMap = map<netKey, NetRecord>;

class Outputter {
    private:
        const string sortby;
        longVal KILO, MEGA, GIGA;

        // Use ncurses to display data in terminal
        void showData(const vector<pair<netKey, NetRecord>>);

        // Convert values to kilo, mega, giga
        string convertValue(longVal);

    public:
        Outputter (const string);
       ~Outputter ();

       // Process captured data
       void processData(netMap);
};

#endif // OUTPUTTERCLASS_H
