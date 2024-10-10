/**
 * Author: Tomas Daniel
 * Login:  xdanie14
*/

/*** Includes ***/
#include <iostream>
#include <exception>

using namespace std;

class ProgramException: public exception {
    private:
        const string message;
    public:
        // Constructor to initialize the exception message
        ProgramException(const string& msg)
            : message(msg)
        {
        }

        // Override what() method to return error message
        const char* what() const noexcept {
            return this->message.c_str();
        }
};
