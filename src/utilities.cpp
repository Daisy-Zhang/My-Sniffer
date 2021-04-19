#include <stdafx.h> 
#include "utilities.h"

//解析以太网帧
int process_frame(const u_char * pkt,struct packet * data,struct pktcount *npacket)
{
		struct eth_hdr *ethh = (struct eth_hdr*)pkt;
		data -> ethh = (struct eth_hdr*)malloc(sizeof(struct eth_hdr));
		if(NULL == data -> ethh)
			return -1;
	
		for(int i = 0; i < 6; i ++) {
			data -> ethh -> dest[i] = ethh -> dest[i];
			data -> ethh -> src[i] = ethh -> src[i];
		}
	
		npacket -> n_sum;
		n_sum ++;
		data -> ethh -> type = ntohs(ethh -> type);

		switch(data -> ethh -> type)
		{
			case 0x0800:
				return process_ip((u_char*)pkt+14,data,npacket);
				break;
			case 0x0806:
				return process_arp((u_char*)pkt+14,data,npacket);
				break;
			default:
				npacket->n_other++;
				return -1;
				break;
		}
		return 1;
}

//解析IP报文
int process_ip(const u_char* pkt,packet *data,struct pktcount *npacket)
{
	struct ip_hdr *iph = (struct ip_hdr*)pkt;
	data -> iph = (struct ip_hdr*)malloc(sizeof(struct ip_hdr));
	
	if(NULL == data -> iph)
		return -1;
	
	npacket->n_ip++;
	data->iph->check = iph->check;
	data->iph->daddr = iph->daddr;
	data->iph->saddr = iph->saddr;
	data->iph->id = iph->id;
	data->iph->tos = iph->tos;
	data->iph->ttl = iph->ttl;
	data->iph->ihl = iph->ihl;
	data->iph->proto = iph->proto;
	data->iph->version = iph->version;
	data->iph->op_pad = iph->op_pad;
	data->iph->frag_off = iph->frag_off;
	data->iph->tlen = ntohs(iph->tlen);

	int iplen = iph -> ihl * 4;
	switch(iph->proto)
	{
		case PROTO_UDP:
			return process_udp((u_char*)iph+iplen,data,npacket);
			break;
		case PROTO_TCP:
			return process_tcp((u_char*)iph+iplen,data,npacket);
			break;
		case PROTO_ICMP:
			return process_icmp((u_char*)iph+iplen,data,npacket);
			break;
		default :
			return-1;
			break;
	}
	return 1;
}

//解析ARP报文
int process_arp(const u_char* pkt,packet *data,struct pktcount *npacket)
{
	struct arp_hdr *arph = (struct arp_hdr*)pkt;
	data -> arph = (struct arp_hdr*)malloc(sizeof(struct arp_hdr));
	
	if(NULL == data -> arph )
		return -1;
	
	for(int i=0;i<6;i++) {
		if(i < 4) {
			data -> arph -> ar_destip[i] = arph -> ar_destip[i];
			data -> arph -> ar_srcip[i] = arph -> ar_srcip[i];
		}
		else {
			data -> arph -> ar_destmac[i] = arph -> ar_destmac[i];
			data -> arph -> ar_srcmac[i] = arph -> ar_srcmac[i];
		}
	}

	data -> arph -> ar_hrd = ntohs(arph -> ar_hrd);
	data -> arph -> ar_hln = arph -> ar_hln;
	data -> arph -> ar_pln = arph -> ar_pln;
	data -> arph -> ar_pro = ntohs(arph -> ar_pro);
	data -> arph -> ar_op = ntohs(arph -> ar_op);

	strcpy(data->pktType,"ARP");
	npacket -> n_arp;
	n_arp ++;
	return 1;
}

//解析TCP报文
int process_tcp(const u_char* pkt,packet *data,struct pktcount *npacket)
{
	struct tcp_hdr *tcph = (struct tcp_hdr*)pkt;
	data -> tcph = (struct tcp_hdr*)malloc(sizeof(struct tcp_hdr));
	if(NULL == data -> tcph)
		return -1;
	
	data->tcph->ack_seq = tcph->ack_seq;
	data->tcph->check = tcph->check;
	
	data->tcph->cwr = tcph->cwr;
	data->tcph->ece = tcph->ece;
	data->tcph->urg = tcph->urg;
	data->tcph->ack = tcph->ack;
	data->tcph->psh = tcph->psh;
	data->tcph->rst = tcph->rst;
	data->tcph->syn = tcph->syn;
	data->tcph->fin = tcph->fin;

	data->tcph->doff = tcph->doff;
	data->tcph->res1 = tcph->res1;

	data->tcph->seq = tcph->seq;
	data->tcph->urg_ptr = tcph->urg_ptr;
	data->tcph->window = tcph->window;
	data->tcph->opt = tcph->opt;
	data->tcph->tcp_srcport = ntohs(tcph->tcp_srcport);
	data->tcph->tcp_dstport = ntohs(tcph->tcp_dstport);
	
	if(ntohs(tcph->tcp_dstport) == 80 || ntohs(tcph->tcp_srcport)==80)
	{
		npacket -> n_http ++;
		strcpy(data -> pktType, "HTTP");
	}
	else{
		npacket -> n_tcp ++;
		strcpy(data -> pktType, "TCP");	
	}
	return 1;
}

//解析UDP报文
int process_udp(const u_char* pkt,packet *data,struct pktcount *npacket)
{
	struct udp_hdr* udph = (struct udp_hdr*)pkt;
	data->udph = (struct udp_hdr*)malloc(sizeof(struct udp_hdr));
	if(NULL == data->udph )
		return -1;

	data->udph->tcp_dstport = ntohs(udph->tcp_dstport);
	data->udph->len = ntohs(udph->len);
	data->udph->udp_srcport = ntohs(udph->udp_srcport);
	data->udph->check = udph->check;

	strcpy(data->pktType,"UDP");
	npacket->n_udp++;
	return 1;
}
	
//解析ICMP报文
int process_icmp(const u_char* pkt,packet *data,struct pktcount *npacket)
{
	struct icmp_hdr* icmph = (struct icmp_hdr*)pkt;
	data -> icmph = (struct icmp_hdr*)malloc(sizeof(struct icmp_hdr));
	
	if(NULL == data -> icmph)
		return -1;

	data -> icmph -> chksum = icmph -> chksum;
	data -> icmph -> code = icmph -> code;
	data -> icmph-> seq = icmph -> seq;
	data -> icmph -> type = icmph -> type;

	strcpy(data -> pktType, "ICMP");
	npacket -> n_icmp ++;
	return 1;
}

//按十六进制输出数据字段
void print_packet(const u_char* pkt,int size_pkt,CString *buf)
{
	int rowcount = -1;
	u_char ch;

	char tempbuf[256];
	memset(tempbuf,0,256);

	for(int i = 0;i<size_pkt;i+=16)
	{
		buf->AppendFormat(_T("%04x:  "),(u_int)i);
		rowcount = (size_pkt-i) > 16 ? 16 : (size_pkt-i);			

		for (int j = 0; j < rowcount; j++)		
			buf->AppendFormat(_T("%02x  "),(u_int)pkt[i+j]);	

		if(rowcount <16)
			for(j=rowcount;j<16;j++)
					buf->AppendFormat(_T("    "));	


		for (int j = 0; j < rowcount; j++) 
		{
             ch = pkt[i+j];
             ch = isprint(ch) ? ch : '.';
			 buf->AppendFormat(_T("%c"),ch);
		}

		buf->Append(_T("\r\n"));

		if(rowcount<16)
			return;
	}
}

