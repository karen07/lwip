#include "lwip/netif.h"
#include "lwip/init.h"
#include "lwip/etharp.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "net.h"
#include "common.h"
#include "http_ans.h"

#include "sha1.h"
#include "base64.h"

#include "lwip_u_boot_port.h"

typedef struct dhcps_msg {
        uint8_t op, htype, hlen, hops;
        uint8_t xid[4];
        uint8_t secs[2];
        uint8_t flags[2];
        uint8_t ciaddr[4];
        uint8_t yiaddr[4];
        uint8_t siaddr[4];
        uint8_t giaddr[4];
        uint8_t chaddr[16];
        uint8_t sname[64];
        uint8_t file[128];
        uint8_t options[576];
}dhcps_msg;

struct netif netif;

int web_socket_open;
struct tcp_pcb* globa_tcp;
char tcp_get;

const char HTTP_RSP[] = \
	"HTTP/1.1 200 OK\r\n" \
	"Content-Length: %d\r\n" \
	"Content-Type: text/html\r\n\r\n";

const char WS_RSP[] = \
	"HTTP/1.1 101 Switching Protocols\r\n" \
	"Upgrade: websocket\r\n" \
	"Connection: Upgrade\r\n" \
	"Sec-WebSocket-Accept: %s\r\n\r\n";
const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const char WS_KEY[] = "Sec-WebSocket-Key: ";

void eth_save_packet_lwip(void* packet, int length) {
	if (length > 0) {
		struct pbuf* p = pbuf_alloc(PBUF_RAW, length, PBUF_POOL);
		if (p != NULL) {
			pbuf_take(p, packet, length);
			if (netif.input(p, &netif) != ERR_OK) {
				pbuf_free(p);
			}
		}
	}
}

err_t websocket_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
	if (p == NULL) {
		web_socket_open = 0;
		globa_tcp = NULL;
		tcp_get = 0;
		return ERR_OK;
	}

	int data_len = 	p->tot_len;
	char tcp_rec[data_len];
	pbuf_copy_partial(p, (void*)tcp_rec, data_len, 0);
	tcp_recved(tpcb, data_len);

	if(web_socket_open == 0){
		char * sec_websocket_position_start = strstr(tcp_rec, WS_KEY);
		if(sec_websocket_position_start){

			sec_websocket_position_start += strlen(WS_KEY);
			char * sec_websocket_position_end = strstr(sec_websocket_position_start , "\r\n");

			char sec_and_uid_websockeet[100];
			memcpy(sec_and_uid_websockeet, sec_websocket_position_start, sec_websocket_position_end - sec_websocket_position_start);
			sec_and_uid_websockeet[sec_websocket_position_end - sec_websocket_position_start] = 0;
			strcat(sec_and_uid_websockeet, WS_GUID);

			char result_sha[20];
			SHA1((unsigned char *)result_sha, (unsigned char *)sec_and_uid_websockeet, strlen(sec_and_uid_websockeet));

			char web_socket_base64[100];
			bintob64(web_socket_base64, result_sha, 20);

			char answer_html[1000];
			sprintf(answer_html, WS_RSP, web_socket_base64);

			tcp_write(tpcb, answer_html, strlen(answer_html), 1);

			web_socket_open = 1;
			globa_tcp = tpcb;

			printf(CONFIG_SYS_PROMPT);
		}
	} else {
		uint8_t opcode = tcp_rec[0] & 0x0F;
		switch (opcode) {
            case 0x01:
            case 0x02:
				if (data_len > 6) {
                    data_len -= 6;

                    for (int i = 0; i < data_len; i++)
                        tcp_rec[i + 6] ^= tcp_rec[2 + i % 4];

					tcp_rec[6 + data_len] = 0;

					tcp_get = tcp_rec[6];
                }
                break;
			case 0x08:
				break;
		}
	}

	pbuf_free(p);
	return ERR_OK;
}

int http_ans_sended = 0;

err_t http_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
	int data_len = 	p->tot_len;
	char tcp_rec[data_len];
	pbuf_copy_partial(p, (void*)tcp_rec, data_len, 0);
	tcp_recved(tpcb, data_len);
	pbuf_free(p);

	char answer_html[1000];
	sprintf(answer_html, HTTP_RSP, http_ans_len);

	tcp_write(tpcb, answer_html, strlen(answer_html), 0x01);

	http_ans_sended = 0;

	return ERR_OK;
}

err_t http_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    int send_size = 1000;

	if(http_ans_len - http_ans_sended > send_size){
		tcp_write(tpcb, http_ans + http_ans_sended, send_size, 0x01);
	} else {
		tcp_write(tpcb, http_ans + http_ans_sended, http_ans_len - http_ans_sended, 0x01);
	}

	http_ans_sended += send_size;

	return ERR_OK;
}

void dhcp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
	if(p == NULL)
		return;

	dhcps_msg dhcp_rec;

	int data_len = 	p->tot_len;
	pbuf_copy_partial(p, (void*)&dhcp_rec, data_len, 0);
	pbuf_free(p);

	int i = 4;
	while(dhcp_rec.options[i] != 255 && dhcp_rec.options[i] != 53) {
		i += dhcp_rec.options[i+1] + 2;
	}

	uint8_t dchp_state;

	if(dhcp_rec.options[i] == 53) {
		dchp_state = dhcp_rec.options[i+2];
	} else {
		return;
	}

	memset(&dhcp_rec.options, 0, 576);

	dhcp_rec.op = 0x02;

	dhcp_rec.yiaddr[0] = 0xc0;
	dhcp_rec.yiaddr[1] = 0xa8;
	dhcp_rec.yiaddr[2] = 0x0a;
	dhcp_rec.yiaddr[3] = 0x02;

	dhcp_rec.siaddr[0] = 0xc0;
	dhcp_rec.siaddr[1] = 0xa8;
	dhcp_rec.siaddr[2] = 0x0a;
	dhcp_rec.siaddr[3] = 0x01;

	dhcp_rec.options[0] = 99;
	dhcp_rec.options[1] = 130;
	dhcp_rec.options[2] = 83;
	dhcp_rec.options[3] = 99;

	if (dchp_state == 1) {
        dhcp_rec.options[4] = 53;
        dhcp_rec.options[5] = 1;
        dhcp_rec.options[6] = 2;
    }

	if (dchp_state == 3) {
        dhcp_rec.options[4] = 53;
        dhcp_rec.options[5] = 1;
        dhcp_rec.options[6] = 5;
    }

	dhcp_rec.options[7] = 54;
	dhcp_rec.options[8] = 4;
	dhcp_rec.options[9] = 0xc0;
	dhcp_rec.options[10] = 0xa8;
	dhcp_rec.options[11] = 0x0a;
	dhcp_rec.options[12] = 0x01;

	dhcp_rec.options[13] = 1;
	dhcp_rec.options[14] = 4;
	dhcp_rec.options[15] = 0xff;
	dhcp_rec.options[16] = 0xff;
	dhcp_rec.options[17] = 0xff;
	dhcp_rec.options[18] = 0x00;

	dhcp_rec.options[19] = 28;
	dhcp_rec.options[20] = 4;
	dhcp_rec.options[21] = 0xc0;
	dhcp_rec.options[22] = 0xa8;
	dhcp_rec.options[23] = 0x0a;
	dhcp_rec.options[24] = 0xff;

	dhcp_rec.options[25] = 51;
    dhcp_rec.options[26] = 4;
    dhcp_rec.options[27] = 0x00;
    dhcp_rec.options[28] = 0x01;
    dhcp_rec.options[29] = 0x51;
    dhcp_rec.options[30] = 0x80;

    dhcp_rec.options[31] = 255;

	p = pbuf_alloc(PBUF_TRANSPORT, data_len, PBUF_RAM);
    memcpy(p->payload, &dhcp_rec, data_len);

	udp_sendto(pcb, p, IP_ADDR_BROADCAST, 68);

	pbuf_free(p);
}

err_t websocket_accept(void* arg, struct tcp_pcb* newpcb, err_t err) {
	LWIP_UNUSED_ARG(arg);
	LWIP_UNUSED_ARG(err);

	if(!web_socket_open) {
		tcp_recv(newpcb, websocket_recv);
		return ERR_OK;
	} else {
		tcp_abort(newpcb);
		return ERR_ABRT;
	}
}

err_t http_accept(void* arg, struct tcp_pcb* newpcb, err_t err) {
	LWIP_UNUSED_ARG(arg);
	LWIP_UNUSED_ARG(err);

	if(!web_socket_open) {
		tcp_recv(newpcb, http_recv);
		tcp_sent(newpcb, http_sent);
		return ERR_OK;
	} else {
		tcp_abort(newpcb);
		return ERR_ABRT;
	}
}

err_t netif_output(struct netif* netif, struct pbuf* p) {
	unsigned char mac_send_buffer[p->tot_len];
	pbuf_copy_partial(p, (void*)mac_send_buffer, p->tot_len, 0);
	eth_send(mac_send_buffer, p->tot_len);
	return ERR_OK;
}

err_t netif_set_opts(struct netif* netif) {
	netif->linkoutput = netif_output;
	netif->output = etharp_output;
	netif->mtu = 1500;
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_LINK_UP | NETIF_FLAG_UP;
	netif->hwaddr_len = 6;

	if (env_get("ethaddr"))
		string_to_enetaddr(env_get("ethaddr"), netif->hwaddr);
	else
		memset(netif->hwaddr, 0, 6);

	return ERR_OK;
}

void lwip_u_boot_port() {
	eth_halt();
	eth_init();

	ip4_addr_t addr;
	ip4_addr_t netmask;
	ip4_addr_t gw;

	IP4_ADDR(&addr, 192, 168, 10, 1);
	IP4_ADDR(&netmask, 255, 255, 255, 0);
	IP4_ADDR(&gw, 192, 168, 10, 2);

	lwip_init();

	netif_add(&netif, &addr, &netmask, &gw, NULL, netif_set_opts, netif_input);

	netif.name[0] = 'e';
	netif.name[1] = '0';
	netif_set_default(&netif);

	struct tcp_pcb* websocket = tcp_new();
	tcp_bind(websocket, IP_ADDR_ANY, 3000);
	websocket = tcp_listen_with_backlog(websocket, TCP_DEFAULT_LISTEN_BACKLOG);
	tcp_accept(websocket, websocket_accept);

	struct tcp_pcb* http = tcp_new();
	tcp_bind(http, IP_ADDR_ANY, 80);
	http = tcp_listen_with_backlog(http, TCP_DEFAULT_LISTEN_BACKLOG);
	tcp_accept(http, http_accept);

	struct udp_pcb *dhcp = udp_new();
	udp_bind(dhcp, IP_ADDR_ANY, 67);
	udp_recv(dhcp , dhcp_recv, NULL);

	web_socket_open = 0;
	globa_tcp = NULL;
	tcp_get = 0;

	push_packet = eth_save_packet_lwip;
}
