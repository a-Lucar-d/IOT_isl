void packet_handler(u_char *args,
                    const struct pcap_pkthdr *header,
                    const u_char *packet);

// Thread entry function for HTTP sniffer
void *http_sniffer_thread(void *arg);