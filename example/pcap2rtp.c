#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

typedef unsigned char mac_addr_t [6]; 

struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in bytes */
    uint32_t network;        /* data link type */
};

struct pkt_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

struct ethernet_hdr_s {
    mac_addr_t dst_mac; 
    mac_addr_t src_mac;
    uint16_t type_length;  /* NETWORK ORDER */ 
};

struct ipv4_hdr_s {
    uint8_t vers_hdrlen;
    uint8_t dscp_ecn;
    uint16_t total_len;         /* NETWORK ORDER */
    uint16_t identification;         /* NETWORK ORDER */
    uint16_t flags_frag_ofs;        /* NETWORK ORDER */
    uint8_t ttl;
    uint8_t proto; 
    uint16_t hdr_checksum;         /* NETWORK ORDER */
    uint32_t src_ip;         /* NETWORK ORDER */
    uint32_t dst_ip;         /* NETWORK ORDER */
};

struct udp_hdr_s {
    uint16_t src_port;        /* NETWORK ORDER */
    uint16_t dst_port;         /* NETWORK ORDER */
    uint16_t total_len;        /* NETWORK ORDER */
    uint16_t checksum;         /* NETWORK ORDER */
};

void pcap_file_parse(const char *filename)
{
    struct pcap_hdr_s pcap_hdr;
    struct pkt_hdr_s pkt_hdr;
    struct ethernet_hdr_s *eth_hdr;
    struct ipv4_hdr_s *ip_hdr; 
    struct udp_hdr_s *udp_hdr;

    FILE *fd = fopen (filename, "rb");
    if (fd < 0) {
        printf ("error reading file %s\n", filename);
        return;
    }
    int32_t rc = fread (&pcap_hdr, 1, sizeof(struct pcap_hdr_s), fd); 
    if (rc < sizeof(struct pcap_hdr_s)) {
        printf ("could not read pcap hdr\n");
        return;
    }

    char data[65535];
    char *buf = &data[0];

    int32_t linklen = sizeof(struct ethernet_hdr_s);
    int32_t linktype = ntohl(pcap_hdr.network);
    if (linktype != 0x01){
        linklen += 2;
        printf("link type is : %d\n", linktype);
    }

    FILE *fout = fopen ("rtp.raw", "wb");

    while (1)
    {
        rc = fread (&pkt_hdr, 1, sizeof(struct pkt_hdr_s), fd);
        if (rc < sizeof(struct pkt_hdr_s)) {
            printf ("pkt header len\n");
            break;
        }

        rc = fread (buf, 1, pkt_hdr.incl_len, fd);
        if (rc < pkt_hdr.incl_len) {
            printf ("pkt payload len error\n");
            break;
        }

        uint32_t udpoffset = linklen + sizeof(struct ipv4_hdr_s);
        struct udp_hdr_s *udp = (struct udp_hdr_s *) (buf + udpoffset);
        uint16_t rtp_data_len = ntohs(udp->total_len) - sizeof(struct udp_hdr_s);
        printf("rtp data len : %d\n", rtp_data_len);
        uint8_t *rtpdata = (uint8_t *)buf + udpoffset + sizeof(struct udp_hdr_s);

        fwrite(&rtp_data_len, 1, 2, fout);
        fwrite(rtpdata, 1, rtp_data_len, fout);
    }
    
    return;
}

int main()
{
    pcap_file_parse("./amrwb.pcap");
}