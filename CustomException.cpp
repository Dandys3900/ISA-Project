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

        // Override what() method to return error message
        const char* what() const noexcept {
            return this->message.c_str();
        }
};
