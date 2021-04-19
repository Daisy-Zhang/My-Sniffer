#ifndef PROTOCOL_H
#define PROTOCOL_H

#define PROTO_ICMP 1
#define PROTO_TCP 6					
#define PROTO_UDP 17					 
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321


//以太网帧头
typedef struct eth_hdr
{
	u_char src[6];				//源地址
	u_char dest[6];				//目标地址
	u_short type;				//类型
};

//IP 头 
typedef struct ip_hdr
{
	u_char version: 4;		//版本号
	u_char ihl: 4;			//头部长度

	u_char proto;			//协议
	u_short checksum;		//校验和
	u_int saddr;			//源地址
	u_int daddr;			//目的地址
	u_int op_pad;			//选项等
	u_char tos;				//TOS 服务类型
	u_short tlen;			//包总长 u_short占两个字节
	u_short id;				//标识
	u_short frag_off;		//片位移
	u_char ttl;				//生存时间
};

//ARP 头
typedef struct arp_hdr
{
	u_char ar_srcmac[6];				//发送方MAC
	u_char ar_srcip[4];					//发送方IP
	u_char ar_destmac[6];				//接收方MAC
	u_char ar_destip[4];				//接收方IP

	u_short ar_hrd;						//硬件类型
	u_short ar_pro;						//协议类型
	u_char ar_hln;						//硬件地址长度
	u_char ar_pln;						//协议地址长度
	u_short ar_op;						//操作码
};

//ICMP 头
typedef struct icmp_hdr
{
	u_char type;			//类型
	u_char code;			//代码
	u_char chksum;			//校验和
	u_char seq;				//序列号
};

//TCP 头
typedef struct tcp_hdr
{
	u_short tcp_srcport;							//源端口地址  16位
	u_short tcp_dstport;							//目的端口地址 16位
	u_int seq;										//序列号 32位
	u_int ack_seq;									//确认序列号 
	u_short window;									//窗口大小 16位
	u_short checksum;								//校验和 16位
	u_short urg_ptr;								//紧急指针 16位
	u_int opt;										//选项

	u_short res1:4, doff:4, rst:1, psh:1, ack:1, urg:1, fin:1, syn:1, ece:1, cwr:1;
													// 标志位
};

//UDP头
typedef struct udp_hdr
{
	u_short udp_srcport;		//源端口  16位
	u_short udp_dstport;		//目的端口 16位
	u_short checksum;			//校验和 16位
	u_short len;				//数据报长度 16位
};

//数据包
typedef struct packet
{	
	char  pktType[8];					//类型
	int time[6];						//时间
	int len;							//长度

	struct ethhdr* ethh;				//链路层包头
	struct arphdr* arph;				//ARP包头
	struct iphdr* iph;					//IP包头
	struct tcphdr* tcph;				//TCP包头
	struct udphdr* udph;				//UDP包头
	struct icmphdr* icmph;				//ICMP包头

	void *apph;							//应用层包头
};
#endif