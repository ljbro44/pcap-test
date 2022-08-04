#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b)) // a,b 중 작은 수 반환

// tcpdump에서 사용되는 헤더를 사용했습니다.
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/* ip헤더에서 tcp인지 확인, tcp가 맞다면 패킷 길이 반환 */
int is_TCP(const u_char* data)
{
  struct sniff_ip* ip_header;
  ip_header = (struct sniff_ip*)data;
  if(ip_header->ip_p != 0x06)
    {
      printf("[*]protocol is not TCP\n");
      return -1;
    }
  printf("[1]protocol is tcp\n");
  return ntohs(ip_header->ip_len);
}

/* ethernet 헤더에서 mac주소 출력 */
void print_ethernet_header(const u_char* data)
{
  struct sniff_ethernet* ethernet_header;
  ethernet_header = (struct sniff_ethernet*)data;
  printf("[2]src mac=(%02x:%02x:%02x:%02x:%02x:%02x)\n"
         ,ethernet_header->ether_shost[0]
      ,ethernet_header->ether_shost[1]
      ,ethernet_header->ether_shost[2]
      ,ethernet_header->ether_shost[3]
      ,ethernet_header->ether_shost[4]
      ,ethernet_header->ether_shost[5]
      );
  printf("[3]dst mac=(%02x:%02x:%02x:%02x:%02x:%02x)\n"
         ,ethernet_header->ether_dhost[0]
      ,ethernet_header->ether_dhost[1]
      ,ethernet_header->ether_dhost[2]
      ,ethernet_header->ether_dhost[3]
      ,ethernet_header->ether_dhost[4]
      ,ethernet_header->ether_dhost[5]
      );
  return;
}

/* ip헤더에서 ip주소 출력 (IPv6는 구현안했습니다..) , ip헤더 길이를 반환합니다 */
int print_ip_header(const u_char* data)
{
  struct sniff_ip* ip_header;
  ip_header = (struct sniff_ip*)data;
  if(IP_V(ip_header) == 4)
    {
      printf("[4]src ip=%s\n", inet_ntoa(ip_header->ip_src));
      printf("[5]dst ip=%s\n", inet_ntoa(ip_header->ip_dst));
    }
  else
    {
      printf("ipv6 header needed!\n");
    }
  return IP_HL(ip_header)*4;
}

/* tcp 헤더에서 port번호 출력 , tcp 오프셋 길이를 반환합니다 */
int print_tcp_header(const u_char* data)
{
  struct sniff_tcp* tcp_header;
  tcp_header = (struct sniff_tcp*)data;
  printf("[6]src port:%d\n", ntohs(tcp_header->th_sport));
  printf("[7]dst port:%d\n", ntohs(tcp_header->th_dport));

  return TH_OFF(tcp_header)*4;
}

/* 최대 10바이트까지 데이터 출력 */
void print_data(const u_char* data, int offset, int data_length)
{
  if(offset>data_length)
    {
      printf("[8]no data\n");
    }
  else
    {
      printf("[8]data:");
      for(int i=0; i<MIN(10,data_length-offset); i++)
        {
          printf("%02x ",*(data+i));
        }
      printf("\n");
    }
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		printf("\n");
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

                int offset = 0;
                offset += sizeof(sniff_ethernet);

                int total_length = is_TCP(packet+offset); // TCP인지 체크

                if(total_length > 0)
		  {
                   print_ethernet_header(packet); // mac주소 출력
                   int size_ip = print_ip_header(packet+offset); // ip주소 출력
                   if (size_ip < 20) {
			   printf("Invalid IP header length: %u bytes\n", size_ip);
			   continue;
		   }
		   offset += size_ip;
                   int size_tcp = print_tcp_header(packet+offset); // tcp포트 출력
		   offset += size_tcp;
                   print_data(packet+offset, offset, total_length); // 데이터 출력
		  }
	}

	pcap_close(pcap);
}
