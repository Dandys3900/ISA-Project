/**
 * Author: Tomas Daniel
 * Login:  xdanie14
*/

/*** Includes ***/
#include "Outputter.h"

Outputter::Outputter(const string sortby)
    : sortby (sortby),
      KILO   (1000),
      MEGA   (KILO * 1000),
      GIGA   (MEGA * 1000)
{
    // Init curses mode
    initscr();
    // Avoid echoing
    noecho();
    // Disable line buffering
    cbreak();
}

Outputter::~Outputter()
{
    // End curses mode
    endwin();
}

const string Outputter::formatOutput(double value, char suffix='\0') {
    char buffer[50];
    snprintf(buffer, sizeof(buffer), "%.1f%c", value, suffix);
    return string(buffer);
}

const string Outputter::convertValue(longVal value) {
    if (value >= this->GIGA)
        return this->formatOutput(double(value/this->GIGA), 'G');
    if (value >= this->MEGA)
        return this->formatOutput(double(value/this->MEGA), 'M');
    if (value >= this->KILO)
        return this->formatOutput(double(value/this->KILO), 'K');
    return this->formatOutput(double(value));
}

void Outputter::processData(netMap data) {
    // Convert given map to vector to sort it
    vector<pair<netKey, netRecord>> dataVec(data.begin(), data.end());

    // Descending sort by (bytes_rx + bytes_tx) or (packets_rx + packets_tx)
    sort(dataVec.begin(), dataVec.end(), [this](const auto& a, const auto& b) {
        if (this->sortby == PACKETS)
            return ((a.second.packets_tx + a.second.packets_rx) > (b.second.packets_tx + b.second.packets_rx));
        // sortby == BYTES
        return ((a.second.bytes_tx + a.second.bytes_rx) > (b.second.bytes_tx + b.second.bytes_rx));
    });
    // Get top 10 records
    if (dataVec.size() > 10)
        dataVec.resize(10);
    // Trigger data being displayed
    this->showData(dataVec);
}

void Outputter::showData(const vector<pair<netKey, netRecord>>& data) {
    // Clear before new showing
    clear();
    /*** Define styling ***/
    // Column titles
    mvprintw(0, 0, "%-35s %-35s %-10s %-20s %-20s", "Src IP:port", "Dst IP:port", "Proto", "Rx", "Tx");
    mvprintw(1, 0, "%-35s %-35s %-10s %-10s %-10s %-10s %-10s", "", "", "", "b/s", "p/s", "b/s", "p/s");

    // Row index - start from third one
    size_t pos = 2;
    // Show data
    for (auto record : data) {
        mvprintw(pos, 0, "%-35s %-35s %-10s %-10s %-10s %-10s %-10s",
                    get<0>(record.first).c_str(),
                    get<1>(record.first).c_str(),
                    get<2>(record.first).c_str(),
                    this->convertValue(record.second.bytes_rx).c_str(),
                    this->convertValue(record.second.packets_rx).c_str(),
                    this->convertValue(record.second.bytes_tx).c_str(),
                    this->convertValue(record.second.packets_tx).c_str());
        ++pos;
    }
    // Refresh with new data
    refresh();
}
