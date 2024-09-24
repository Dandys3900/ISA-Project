#include <iostream>
#include <exception>

class ProgramException: public std::exception {
    private:
        const std::string message;
    public:
        // Constructor to initialize the exception message
        ProgramException(const std::string& msg)
            : message(msg)
        {
        }
};
