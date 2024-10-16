/**
 * Author: Tomas Daniel
 * Login:  xdanie14
*/

/*** Includes ***/
#include "NetworkData.h"
#include "Outputter.h"

// Global class instances
unique_ptr<NetworkData> netClass = nullptr;
unique_ptr<Outputter> outClass   = nullptr;
// Global bool for stopping sniffing loop in main()
bool stop = false;

void stopProgram(int sig_val) {
    (void) sig_val;
    // Gracefully exit when terminated
    netClass->stopCapture();
    // Stop main() while loop
    stop = true;
}

void showHelp() {
    std::string help_text;
    help_text += "Tool for displaying network statistics:\n";
    help_text += "  -i for specifying source interface\n";
    help_text += "  -s (optional) for specifying sort metrics, 'b'-number of bites/second; 'p'-number of packets/second\n";
    help_text += "  -h for help";
    // Output constructed help text to stdout
    cout << help_text << endl;
}

int main (int argc, char *argv[]) {
    // Set interrupt signal handling
    signal(SIGINT,  stopProgram);
    signal(SIGTERM, stopProgram);
    signal(SIGQUIT, stopProgram);

    try {
        // Parse cli arguments
        map<string, string> args;
        // Iterate over given arguments
        for (int pos = 1; pos < argc; ++pos) {
            // Parse argument value
            const string ident(argv[pos]);
            // Special case for help argument
            if (ident == "-h") {
                showHelp();
                return EXIT_SUCCESS;
            }
            // Check if there is following argument to read value from
            if ((++pos) >= argc)
                throw ProgramException("Missing value of argument");
            // Check if argument is not duplicit
            if (args.contains(ident))
                throw ProgramException(string("Argument is already given: " + ident));
            // Determine type of argument
            if (ident == "-i" || ident == "-s")
                args.insert({ident, argv[pos]});
            else // Unknown argument
                throw ProgramException(string("Unknown argument: " + ident));
        }
        // Check compulsory flag "-i" is present
        if (!args.contains("-i"))
            throw ProgramException("Missing compulsory '-i' flag");
        // Add "-s" default value if not given
        if (!args.contains("-s"))
            args.insert({"-s", BYTES});

        // Construct classes
        netClass = make_unique<NetworkData>((args.find("-i"))->second);
        outClass = make_unique<Outputter>((args.find("-s"))->second);

        // Begin capturing and processing packets
        netClass->startCapture();
        // Main function loop
        while(!stop) {
            outClass->processData(netClass->getCurrentData());
            sleep(1);
        }
    } catch (const ProgramException& e) {
        cout << "Error: " << e.what() << endl;
        // Exit with failure status
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
