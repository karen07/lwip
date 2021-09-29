#include "lwip/netif.h"
#include "lwip/init.h"
#include "lwip/etharp.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/apps/httpd.h"
#include "lwip/opt.h"
#include "lwip/apps/fs.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "net.h"

#include "linux/delay.h"
#include "u-boot/sha1.h"
#include "u-boot/sha256.h"
#include "common.h"
#include "console.h"
#include "command.h"

#include "base64.h"

#include "lwip_u_boot_port.h"

struct netif netif;

int web_socket_open;
struct tcp_pcb* globa_tcp;
char tcp_get;

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

err_t tcp_echoserver_recv(void* arg, struct tcp_pcb* tpcb, struct pbuf* p, err_t err) {
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
			sha1_csum((unsigned char *)sec_and_uid_websockeet, strlen(sec_and_uid_websockeet), (unsigned char *)result_sha);
			
			char web_socket_base64[100];
			bintob64(web_socket_base64, result_sha, 20);

			char answer_html[1000];
			sprintf(answer_html, WS_RSP, web_socket_base64);

			tcp_write(tpcb, answer_html, strlen(answer_html), 1);
			
			web_socket_open = 1;
			globa_tcp = tpcb;
			
			printf("malta #");
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

err_t tcp_echoserver_accept(void* arg, struct tcp_pcb* newpcb, err_t err) {
	LWIP_UNUSED_ARG(arg);
	LWIP_UNUSED_ARG(err);

	if(!web_socket_open) {
		tcp_recv(newpcb, tcp_echoserver_recv);
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

int lwip_u_boot_port(struct cmd_tbl * arg1, int arg2,  int arg3,  char * const* arg4) {
	eth_halt();
	eth_init();
	
	ip4_addr_t addr;
	ip4_addr_t netmask;
	ip4_addr_t gw;

	IP4_ADDR(&addr, 192, 168, 1, 1);
	IP4_ADDR(&netmask, 255, 255, 255, 0);
	IP4_ADDR(&gw, 192, 168, 1, 2);

	lwip_init();

	netif_add(&netif, &addr, &netmask, &gw, NULL, netif_set_opts, netif_input);

	netif.name[0] = 'e';
	netif.name[1] = '0';
	netif_set_default(&netif);
	
	struct tcp_pcb* tcp_echoserver_pcb = tcp_new();
	tcp_bind(tcp_echoserver_pcb, IP_ADDR_ANY, 3000);
	tcp_echoserver_pcb = tcp_listen_with_backlog(tcp_echoserver_pcb, TCP_DEFAULT_LISTEN_BACKLOG);
	tcp_accept(tcp_echoserver_pcb, tcp_echoserver_accept);
	
	web_socket_open = 0;
	globa_tcp = NULL;
	tcp_get = 0;

	push_packet = eth_save_packet_lwip;
	
	return 0;
}