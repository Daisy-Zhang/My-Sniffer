#include "afxcmn.h"
#include "afxwin.h"
#include <malloc.h> 
#include <Winsock2.h>
#include "protocol_struct.h"
#ifndef UTILITIES_H
#define UTILITIES_H

int process_frame(const u_char * pkt,struct packet * data,struct pktcount *npakcet);
int process_ip(const u_char* pkt,struct packet *data,struct pktcount *npakcet);
int process_arp(const u_char* pkt,struct packet *data,struct pktcount *npakcet);
int process_tcp(const u_char* pkt,struct packet *data,struct pktcount *npakcet);
int process_udp(const u_char* pkt,struct packet *dtat,struct pktcount *npakcet);
int process_icmp(const u_char* pkt,struct packet *data,struct pktcount *npakcet);

void print_packet(const u_char* pkt,int size_pkt,CString *buf);

#endif