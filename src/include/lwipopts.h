#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

#define NO_SYS                  		1
#define SYS_LIGHTWEIGHT_PROT    		0

#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0

#define MEM_ALIGNMENT           		4
#define MEM_SIZE                        (8 * 1024 * 1024)
#define MEMP_NUM_PBUF                   1024
#define MEMP_NUM_TCP_PCB                32
#define PBUF_POOL_SIZE                  1024
#define TCP_WND                         (4*TCP_MSS)
#define TCP_SND_BUF                     65535
#define TCP_OVERSIZE                    TCP_MSS
#define TCP_SND_QUEUELEN                512
#define MEMP_NUM_TCP_SEG                512

#define LWIP_NOASSERT					1

#endif /* __LWIPOPTS_H__ */