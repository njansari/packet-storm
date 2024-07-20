#include <algorithm>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap.h>

using namespace std;

// Hash function for in_addr to use it as a key in unordered_map
struct in_addr_hash {
    size_t operator()(const in_addr &addr) const noexcept {
        return hash<uint32_t>()(addr.s_addr);
    }
};

// Equality comparison for in_addr to use it as a key in unordered_map
struct in_addr_equal {
    bool operator()(const in_addr &lhs, const in_addr &rhs) const noexcept {
        return lhs.s_addr == rhs.s_addr;
    }
};

// Structure to hold packet statistics
struct packet_stats {
    int total_packets = 0;
    long long total_volume = 0;
    double max_packet_size = 0;

    int tcp_packets = 0;
    int udp_packets = 0;

    unordered_map<in_addr, int, in_addr_hash, in_addr_equal> src_ip_freq;
    unordered_map<in_addr, int, in_addr_hash, in_addr_equal> dest_ip_freq;

    int malformed_packets = 0;

    // Output the analysis results
    void output_analysis() const {
        cout << "Total number of packets: " << total_packets << endl;
        cout << "Total volume of data: " << total_volume << " bytes" << endl;

        cout << endl;

        const double avg_packet_size = total_packets ? static_cast<double>(total_volume) / total_packets : 0;
        cout << "Average packet size: " << avg_packet_size << " bytes" << endl;
        cout << "Maximum packet size: " << max_packet_size << " bytes" << endl;

        cout << endl;

        cout << "TCP packets: " << tcp_packets << endl;
        cout << "UDP packets: " << udp_packets << endl;

        cout << endl;

        output_ip_frequencies("Most Frequent Source IPs:", src_ip_freq);
        output_ip_frequencies("Most Frequent Destination IPs:", dest_ip_freq);

        cout << "Malformed packets: " << malformed_packets << endl;
    }

private:
    // Template function to output IP frequencies
    template<typename MapType> void output_ip_frequencies(const char *title, const MapType &freq_map) const {
        cout << title << endl;

        vector<const typename MapType::value_type *> entries;
        entries.reserve(freq_map.size());

        for (const auto &item: freq_map) {
            entries.push_back(&item);
        }

        size_t top_n = min(static_cast<size_t>(5), entries.size());

        partial_sort(entries.begin(), entries.begin() + top_n, entries.end(), [](const auto *a, const auto *b) {
            return a->second > b->second;
        });

        for (size_t i = 0; i < top_n; i++) {
            const auto *entry = entries[i];
            cout << i + 1 << ") " << inet_ntoa(entry->first) << " - " << entry->second << " packets" << endl;
        }

        cout << endl;
    }
};

// Calculate checksum for IP headers
uint16_t calculate_checksum(const uint16_t *buf, int nwords) {
    uint32_t sum;

    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += sum >> 16;

    return static_cast<uint16_t>(~sum);
}

// Validate the checksum of an IP header
bool validate_ip_checksum(ip *ip_header) {
    if (ip_header == nullptr) return false;

    const uint16_t original_checksum = ip_header->ip_sum;
    ip_header->ip_sum = 0;

    const uint16_t computed_checksum = calculate_checksum(reinterpret_cast<uint16_t *>(ip_header), ip_header->ip_hl * 2);
    ip_header->ip_sum = original_checksum;

    return original_checksum == computed_checksum;
}

// Callback function to process each packet
void packet_handler(u_char *args, const pcap_pkthdr *header, const u_char *packet) {
    constexpr size_t ether_header_len = sizeof(ether_header);

    auto *stats = reinterpret_cast<packet_stats *>(args);

    // Check if the packet is an IP packet
    if (
        auto *eth_header = reinterpret_cast<struct ether_header *>(const_cast<u_char *>(packet));
        ntohs(eth_header->ether_type) != ETHERTYPE_IP
    ) {
        return;
    }

    const auto ip_header = reinterpret_cast<ip *>(const_cast<u_char *>(packet) + ether_header_len);

    // Validate IP version and header length
    if (ip_header->ip_v != 4 || ip_header->ip_hl < 5) {
        stats->malformed_packets++;
        return;
    }

    // Validate IP checksum
    if (!validate_ip_checksum(ip_header)) {
        stats->malformed_packets++;
        return;
    }

    // Ensure the captured length matches the IP packet length
    if (header->caplen < ntohs(ip_header->ip_len)) {
        stats->malformed_packets++;
        return;
    }

    // Ensure captured length is at least as large as the Ethernet header
    if (header->caplen < ether_header_len) {
        stats->malformed_packets++;
        return;
    }

    // Ensure captured length is at least as large as the Ethernet header + IP header
    if (header->caplen < ether_header_len + sizeof(ip)) {
        stats->malformed_packets++;
        return;
    }

    const int ip_header_len = ip_header->ip_hl * 4;

    // Ensure captured length is at least as large as the Ethernet header + full IP header length
    if (header->caplen < ether_header_len + ip_header_len) {
        stats->malformed_packets++;
        return;
    }

    // Update packet statistics
    stats->total_packets++;
    stats->total_volume += header->len;
    stats->max_packet_size = max(static_cast<double>(header->len), stats->max_packet_size);

    // Process the packet based on the transport layer protocol
    switch (ip_header->ip_p) {
    case IPPROTO_TCP:
        // Ensure captured length is sufficient for TCP header
        if (header->caplen < ether_header_len + ip_header_len + sizeof(tcphdr)) {
            stats->malformed_packets++;
            return;
        }

        stats->tcp_packets++;
        break;

    case IPPROTO_UDP:
        // Ensure captured length is sufficient for UDP header
        if (header->caplen < ether_header_len + ip_header_len + sizeof(udphdr)) {
            stats->malformed_packets++;
            return;
        }

        stats->udp_packets++;
        break;

    default:
        // Unhandled IP protocol
        break;
    }

    // Update IP frequency maps
    stats->src_ip_freq[ip_header->ip_src]++;
    stats->dest_ip_freq[ip_header->ip_dst]++;
}

int main(const int argc, char *argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <pcap file>" << endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);

    if (handle == nullptr) {
        cerr << "Failed to open pcap file: " << errbuf << endl;
        return 1;
    }

    // Create a unique pointer for packet statistics
    const auto stats = make_unique<packet_stats>();

    // Start packet capture loop and check for errors
    if (pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char *>(stats.get())) == PCAP_ERROR) {
        cerr << "Error occurred whilst reading pcap file: " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        return 1;
    }

    // Close the pcap handle
    pcap_close(handle);

    // Output analysis results
    stats->output_analysis();

    return 0;
}
