#ifndef PROTOCOL_H
#define PROTOCOL_H

#define PROTO_ICMP 1
#define PROTO_TCP 6					
#define PROTO_UDP 17					 
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321


//��̫��֡ͷ
typedef struct eth_hdr
{
	u_char src[6];				//Դ��ַ
	u_char dest[6];				//Ŀ���ַ
	u_short type;				//����
};

//IP ͷ 
typedef struct ip_hdr
{
	u_char version: 4;		//�汾��
	u_char ihl: 4;			//ͷ������

	u_char proto;			//Э��
	u_short checksum;		//У���
	u_int saddr;			//Դ��ַ
	u_int daddr;			//Ŀ�ĵ�ַ
	u_int op_pad;			//ѡ���
	u_char tos;				//TOS ��������
	u_short tlen;			//���ܳ� u_shortռ�����ֽ�
	u_short id;				//��ʶ
	u_short frag_off;		//Ƭλ��
	u_char ttl;				//����ʱ��
};

//ARP ͷ
typedef struct arp_hdr
{
	u_char ar_srcmac[6];				//���ͷ�MAC
	u_char ar_srcip[4];					//���ͷ�IP
	u_char ar_destmac[6];				//���շ�MAC
	u_char ar_destip[4];				//���շ�IP

	u_short ar_hrd;						//Ӳ������
	u_short ar_pro;						//Э������
	u_char ar_hln;						//Ӳ����ַ����
	u_char ar_pln;						//Э���ַ����
	u_short ar_op;						//������
};

//ICMP ͷ
typedef struct icmp_hdr
{
	u_char type;			//����
	u_char code;			//����
	u_char chksum;			//У���
	u_char seq;				//���к�
};

//TCP ͷ
typedef struct tcp_hdr
{
	u_short tcp_srcport;							//Դ�˿ڵ�ַ  16λ
	u_short tcp_dstport;							//Ŀ�Ķ˿ڵ�ַ 16λ
	u_int seq;										//���к� 32λ
	u_int ack_seq;									//ȷ�����к� 
	u_short window;									//���ڴ�С 16λ
	u_short checksum;								//У��� 16λ
	u_short urg_ptr;								//����ָ�� 16λ
	u_int opt;										//ѡ��

	u_short res1:4, doff:4, rst:1, psh:1, ack:1, urg:1, fin:1, syn:1, ece:1, cwr:1;
													// ��־λ
};

//UDPͷ
typedef struct udp_hdr
{
	u_short udp_srcport;		//Դ�˿�  16λ
	u_short udp_dstport;		//Ŀ�Ķ˿� 16λ
	u_short checksum;			//У��� 16λ
	u_short len;				//���ݱ����� 16λ
};

//���ݰ�
typedef struct packet
{	
	char  pktType[8];					//����
	int time[6];						//ʱ��
	int len;							//����

	struct ethhdr* ethh;				//��·���ͷ
	struct arphdr* arph;				//ARP��ͷ
	struct iphdr* iph;					//IP��ͷ
	struct tcphdr* tcph;				//TCP��ͷ
	struct udphdr* udph;				//UDP��ͷ
	struct icmphdr* icmph;				//ICMP��ͷ

	void *apph;							//Ӧ�ò��ͷ
};
#endif