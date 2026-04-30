#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <signal.h>

/* external controls */
extern volatile sig_atomic_t running;
extern pcap_t *global_handle;

/* Ethernet */
struct ethheader {
    u_char dst[6];
    u_char src[6];
    u_short type;
};

/* IP */
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short iph_len;
    unsigned short iph_ident;
    unsigned short iph_flag:3, iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

/* TCP */
struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int tcp_seq;
    u_int tcp_ack;
    u_char tcp_offx2;
    u_char tcp_flags;
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

/* -------- PACKET HANDLER -------- */
void packet_handler(u_char *args,
                    const struct pcap_pkthdr *header,
                    const u_char *packet)
{
    (void)args;

    if (header->caplen < sizeof(struct ethheader))
        return;

    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->type) != 0x0800)
        return;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_len = ip->iph_ihl * 4;

    if (header->caplen < sizeof(struct ethheader) + ip_len)
        return;

    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    struct tcpheader *tcp =
        (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_len);

    int tcp_len = ((tcp->tcp_offx2 & 0xF0) >> 4) * 4;

    size_t total = sizeof(struct ethheader) + ip_len + tcp_len;

    if (header->caplen < total)
        return;

    const char *payload = (const char *)(packet + total);
    int payload_len = header->caplen - total;

    if (payload_len <= 0)
        return;

    if (!strncmp(payload, "GET", 3) ||
        !strncmp(payload, "POST", 4) ||
        !strncmp(payload, "HEAD", 4) ||
        !strncmp(payload, "PUT", 3) ||
        !strncmp(payload, "DELETE", 6) ||
        !strncmp(payload, "OPTIONS", 7))
    {
	syslog(LOG_ALERT, "----- HTTP START -----");
	syslog(LOG_ALERT, "SRC: %s -> DST: %s",
        inet_ntoa(ip->iph_sourceip),
        inet_ntoa(ip->iph_destip));
	syslog(LOG_ALERT, "%.*s", 200, payload);
	syslog(LOG_ALERT, "----- HTTP END -----");
        
    }
}

/* -------- THREAD ENTRY -------- */
void *http_sniffer_thread(void *arg)
{
    (void)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "wlan0"; //change if needed

    global_handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!global_handle)
    {
        syslog(LOG_ERR, "pcap_open_live failed: %s", errbuf);
        return NULL;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp port 80";

    if (pcap_compile(global_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(global_handle, &fp) == -1)
    {
        syslog(LOG_ERR, "pcap filter failed");
        return NULL;
    }

    syslog(LOG_INFO, "[*] HTTP Sniffer started on %s", dev);

    // TRUE real-time capture
    pcap_loop(global_handle, 0, packet_handler, NULL);

    pcap_close(global_handle);
    return NULL;
}
