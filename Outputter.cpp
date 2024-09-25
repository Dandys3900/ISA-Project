///*** Includes ***/
#include "Outputter.h"

Outputter::Outputter(const string sortby)
    : sortby (sortby)
{
}

Outputter::~Outputter()
{
}

void Outputter::processData(netMap data) {
    // Convert given map to vector to sort it
    vector<pair<netKey, NetRecord>> dataVec(data.begin(), data.end());

    // Descending sort by (bytes_rx + bytes_tx) or (packets_rx + packets_tx)
    sort(dataVec.begin(), dataVec.end(), [this](const auto& a, const auto& b) {
        if (sortby == BYTES)
            return ((a.second.bytes_tx + a.second.bytes_rx) > (b.second.bytes_tx + b.second.bytes_rx));
        // sortby == PACKETS
        return ((a.second.packets_tx + a.second.packets_rx) > (b.second.packets_tx + b.second.packets_rx));
    });
    // Get top 10 records
    if (dataVec.size() > 10)
        dataVec.resize(10);
    // Trigger data being displayed
    this->showData(dataVec);
}

void Outputter::showData(const vector<pair<netKey, NetRecord>> data) {
    // Init curses mode
    initscr();
    // Avoid echoing
    noecho();
    // Disable line buffering
    cbreak();

    /*** Define styling ***/
    // Column titles
    mvprintw(0, 0, "%-35s %-35s %-10s %-20s %-20s", "Src IP:port", "Dst IP:port", "Proto", "Rx", "Tx");
    mvprintw(1, 0, "%-35s %-35s %-10s %-10s %-10s %-10s %-10s", "", "", "", "b/s", "p/s", "b/s", "p/s");
    // Show data
    for (auto record : data) {
        mvprintw(0, 0, "%-35s %-35s %-10s %-10llu %-10llu %-10llu %-10llu",
                    get<0>(record.first).c_str(),
                    get<1>(record.first).c_str(),
                    get<2>(record.first).c_str(),
                    record.second.bytes_rx,
                    record.second.packets_rx,
                    record.second.bytes_tx,
                    record.second.packets_tx);
    }
    // Refresh with new data
    refresh();
    // End curses mode
    endwin();
}
