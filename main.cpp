/*** Includes ***/
#include "NetworkData.h"
#include "Outputter.h"

void showHelp() {
    std::string help_text;
    help_text += "Tool for displaying network statistics:\n";
    help_text += "  -i for specifying source interface\n";
    help_text += "  -s (optional) for specifying sort metrics, 'b'-number of bites/second; 'p'-number of packets/second\n";
    help_text += "  -h for help";
    // Output constructed help text to stdout
    cout << help_text << endl;
}

map<string, int> parseCLIargs(int argc, char *argv[]) {
    map<string, int> values;
    // Iterate over given arguments
    for (int pos = 1; pos < argc; ++pos) {
        // Parse argument value
        const string ident(argv[pos]);
        // Check if there is following argument to read value from
        if ((++pos) >= argc)
            throw logic_error("Missing value of argument");
        // Check if argument is not duplicit
        if (!values.contains(ident))
            throw logic_error(format("Argument {} is already given", ident));

        /* TODO:
        // Special case for help argument
        if (ident == "-h") {
            showHelp();
            continue;
        }
        */

        if (ident == "-i" || ident == "-s")
            values.insert({ident, stoi(argv[pos])});
        else // Unknown argument
            throw logic_error(format("Unknown argument {}", ident));
    }
    // Check compulsory flag "-i" is present
    if (!values.contains("-i"))
        throw logic_error("Missing compulsory '-i' flag");
    // Return parsed cli arguments
    return values;
}

int main (int argc, char *argv[]) {
    // Set interrupt signal handling - CTRL+C
    signal(SIGINT, [](int sig_val) {
        // Gracefully exit when terminated
        if (sig_val == SIGINT)
            exit(EXIT_SUCCESS);
    });

    try {
        // Parse cli arguments
        auto args = parseCLIargs(argc, argv);

        // Construct helper classes
        NetworkData netClass((args.find("-i"))->second);
        Outputter output(args.contains("-s") ? (args.find("-s"))->second : BYTES);

        // Main function loop
        while(true) {
            sleep(1);
        }
    } catch (const logic_error& e) {
        cout << "Error: " << e.what() << endl;
        // Exit with failure status
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
