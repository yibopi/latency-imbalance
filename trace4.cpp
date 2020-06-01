/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "flipr.h"

struct ip *
prepPkt(struct sockaddr_in &source) 
{
    struct ip *ip;
    ip = (struct ip *)calloc(1, PKTSIZE);
    ip->ip_v = IPVERSION;
    ip->ip_hl = sizeof(struct ip) >> 2;
    ip->ip_src.s_addr = source.sin_addr.s_addr;
    return ip;
}

Traceroute4::Traceroute4(YarrpConfig *_config) : Traceroute(_config)
{
    if ((rcvsk_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        cout << "yarrp listener socket error:" << strerror(errno) << endl;
    }
    if ((rcvsk_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        cout << "yarrp listener socket error:" << strerror(errno) << endl;
    }
	infer_my_ip(&source);
    sndsock = raw_sock(&source);
    payloadlen = 0;
    outip = prepPkt(source);
    outip_icmp = prepPkt(source);
    pthread_create(&recv_thread, NULL, listener, this);
    /* give listener thread time to startup */
    sleep(1);
    /* Open output ytr file */
    //if (config->output)
    //    openOutput();
}

Traceroute4::~Traceroute4() {
    free(outip);
    free(outip_icmp);
}

void
Traceroute4::probe(uint32_t srcip, const char *targ, ip_timestamp *option) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
#ifdef _BSD
    target.sin_len = sizeof(target);
#endif
    inet_aton(targ, &(target.sin_addr));
    probe(srcip, &target, option);
}

void
Traceroute4::probe(uint32_t targetip, uint32_t dst, ip_timestamp *option) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
#ifdef _BSD
    target.sin_len = sizeof(target);
#endif
    target.sin_addr.s_addr = dst;
    probe(targetip, &target, option);
}

void
Traceroute4::probe(uint32_t targetip, struct sockaddr_in *target, ip_timestamp *option)
{
    uint16_t pktid = regPkt(targetip, ttl, pktType, sport, dport);

    //printf("send type:%d, pktid:%d, ip:%lu, ttl:%d, sport:%d, dport:%d\n",
    //        pktType, pktid, targetip, (int)ttl, sport, dport);

    struct ip *ptr; 
    
    if (pktType == TR_ICMP_VAR || pktType == TR_ICMP_FIX) {
        ptr = outip_icmp;
    } else { 
        ptr = outip;
    }

    ptr->ip_ttl = ttl;
    ptr->ip_id = htons(pktid);
    ptr->ip_off = 0; // htons(IP_DF);
    ptr->ip_dst.s_addr = (target->sin_addr).s_addr;
    ptr->ip_sum = 0;

    if (pktType == TR_UDP) {
        probeUDP(target, option);
    } else if (pktType == TR_TCP_SYN) {
        probeTCP(target, option);
    } else if (pktType == TR_TCP_ACK) {
        probeTCP(target, option);
        regIP(ntohl(target->sin_addr.s_addr), pktid); 
    } else if (pktType == TR_ICMP_VAR || pktType == TR_ICMP_FIX) {
        probeICMP(target, pktid, option);
    } else {
        cerr << "** bad trace type:" << pktType << endl;
        assert(false);
    }
}

/*
void
Traceroute4::probeUDP(struct sockaddr_in *target, int ttl) {
    unsigned char *ptr = (unsigned char *)outip;
    struct udphdr *udp = (struct udphdr *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + sizeof(struct udphdr));
    int cc;

    uint32_t diff = elapsed();
    payloadlen = 2;
    // encode MSB of timestamp in UDP payload length 
    if (diff >> 16)
        payloadlen += (diff>>16);
    if (verbose) {
        cout << ">> UDP probe target: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff;
        (config->coarse) ? cout << "ms" << endl : cout << "us" << endl;
    }

    packlen = sizeof(struct ip) + sizeof(struct udphdr) + payloadlen;

    outip->ip_p = IPPROTO_UDP;
#ifdef _BSD
    outip->ip_len = packlen;
    outip->ip_off = IP_DF;
#else
    outip->ien = htons(packlen);
    outip->ip_off = ntohs(IP_DF);
#endif
    // encode destination IPv4 address as cksum(ipdst)
    uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    udp->uh_sport = htons(dport);
    udp->uh_dport = htons(dstport);
    udp->uh_ulen = htons(sizeof(struct udphdr) + payloadlen);
    udp->uh_sum = 0;

    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));

    // compute UDP checksum
    memset(data, 0, 2);
    u_short len = sizeof(struct udphdr) + payloadlen;
    udp->uh_sum = p_cksum(outip, (u_short *) udp, len);

    // encode LSB of timestamp in checksum
    uint16_t crafted_cksum = diff & 0xFFFF;
    // craft payload such that the new cksum is correct
    uint16_t crafted_data = compute_data(udp->uh_sum, crafted_cksum);
    memcpy(data, &crafted_data, 2);
    if (crafted_cksum == 0x0000)
        crafted_cksum = 0xFFFF;
    udp->uh_sum = crafted_cksum;

    if ((cc = sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target))) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> UDP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}
*/

void
Traceroute4::probeUDP(struct sockaddr_in *target, ip_timestamp *option) {
    // assemble option in packets
    uint8_t iptlen = 0;
    unsigned char *ptr = (unsigned char *)outip;
    if (option) {
        iptlen = MAX_IPOPTLEN;
        memcpy(ptr + sizeof(struct ip), (unsigned char *)option, iptlen); 
        outip->ip_hl = (sizeof(struct ip) + iptlen) >> 2;
    }
    struct udphdr *udp = (struct udphdr *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + sizeof(struct udphdr));
    int cc;


    payloadlen = 0;
    packlen = sizeof(struct ip) + iptlen + sizeof(struct udphdr) + payloadlen;

    outip->ip_p = IPPROTO_UDP;
#ifdef _BSD
    outip->ip_len = packlen;
    outip->ip_off = IP_DF;
#else
    outip->ip_len = htons(packlen);
    outip->ip_off = ntohs(IP_DF);
#endif
    // encode destination IPv4 address as cksum(ipdst) 
    //uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    udp->uh_sport = htons(sport);
    udp->uh_dport = htons(dport);
    udp->uh_ulen = htons(sizeof(struct udphdr) + payloadlen);
    udp->uh_sum = 0;

    outip->ip_sum = in_cksum((unsigned short *)outip, 20);

    // compute UDP checksum
    memset(data, 0, 2);
	//unsigned short *dataptr = (unsigned short *)data;
	//*dataptr = 200;
    u_short len = sizeof(struct udphdr) + payloadlen;
    udp->uh_sum = p_cksum(outip, (u_short *) udp, len);

    if ((cc = sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target))) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> UDP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
    }
}

void
Traceroute4::probeTCP(struct sockaddr_in *target, ip_timestamp *option) {
    // assemble option in packets
    int iptlen = 0, iphdrlen = sizeof(struct ip);
    unsigned char *ptr = (unsigned char *)outip;
    if (option) {
        iptlen = MAX_IPOPTLEN;
        iphdrlen += iptlen;
        memcpy(ptr + sizeof(struct ip), (unsigned char*)option, iptlen); 
        ip_timestamp *ts = (ip_timestamp *)(ptr + sizeof(struct ip));
        //for (int i = 0; i < 4; i++) 
        //    printf("%lu %lu ", ts->data[2*i], ts->data[2*i+1]);
        outip->ip_hl = iphdrlen >> 2;
    }
    struct tcphdr *tcp = (struct tcphdr *)(ptr + iphdrlen);
    int cc;

    payloadlen = 0;
    packlen = sizeof(struct ip) + iptlen + sizeof(struct tcphdr) + payloadlen;
    outip->ip_p = IPPROTO_TCP;
    outip->ip_len = htons(packlen);
#ifdef _BSD
    outip->ip_len = packlen;
    outip->ip_off = 0; //IP_DF;
#endif
    /* encode destination IPv4 address as cksum(ipdst) */
    // uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    tcp->th_sport = htons(sport);
    tcp->th_dport = htons(dport);
    /* encode send time into seq no as elapsed milliseconds */
    uint32_t diff = elapsed();
    //if (verbose) {
    //    cout << ">> TCP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
    //    cout << ttl << " t=" << diff;
    //    (config->coarse) ? cout << "ms" << endl : cout << "us" << endl;
    //}
    tcp->th_seq = htonl(diff);
	//tcp->th_seq = 0;
    //take effects when routers reply to TCP packets
	//tcp->th_seq = p_cksum(outip, (u_short *) tcp, sizeof(struct udphdr));
    tcp->th_off = 5;
    tcp->th_win = htons(0xFFFE);
    tcp->th_sum = 0;
    /* don't want to set SYN, lest we be tagged as SYN flood. */
    if (TR_TCP_SYN == pktType) {
        tcp->th_flags |= TH_SYN;
    } else {
        tcp->th_flags |= TH_ACK;
        tcp->th_ack = htonl(target->sin_addr.s_addr);
    }
    /*
     * explicitly computing cksum probably not required on most machines
     * these days as offloaded by OS or NIC.  but we'll be safe.
     */
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, iphdrlen));
    /*
     * bsd rawsock requires host ordered len and offset; rewrite here as
     * chksum must be over htons() versions
     */
    u_short len = sizeof(struct tcphdr) + payloadlen;
    tcp->th_sum = p_cksum(outip, (u_short *) tcp, len);
    if ((cc = sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target))) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> TCP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        // cout << ttl << " t=" << diff << endl;
    }
}

void
Traceroute4::probeICMP(struct sockaddr_in *target, uint16_t pktid, ip_timestamp *option) {
    int iptlen = 0, iphdrlen = sizeof(struct ip); 
 	unsigned char *ptr = (unsigned char *)outip_icmp;
    if (option) {
        iptlen = MAX_IPOPTLEN;
        iphdrlen += iptlen;
        memcpy(ptr + sizeof(struct ip), (unsigned char*)option, iptlen); 
        ip_timestamp *ts = (ip_timestamp *)(ptr + sizeof(struct ip));
        //printf("code:%d, len:%d, ptr:%d, flag:%d\n", ts->ipt_code, ts->ipt_len, ts->ipt_ptr, ts->ipt_flg);
        //for (int i = 0; i < 4; i++) 
        //    printf("%lu %lu ", ntohl(ts->data[2*i]), ntohl(ts->data[2*i+1]));
        outip_icmp->ip_hl = iphdrlen >> 2;
    }
	struct icmp *icmp = (struct icmp *)(ptr + iphdrlen);
	int cc;
	
	// packlen for port unreachable message
	packlen = iphdrlen + sizeof(struct icmp);
	outip_icmp->ip_p = IPPROTO_ICMP; 
	outip_icmp->ip_len = htons(packlen);

#ifdef _BSD
	outip_icmp->ip_len = packlen;
	outip_icmp->ip_off = IP_DF;
#endif

	outip_icmp->ip_sum = htons(in_cksum((unsigned short *)outip_icmp, iphdrlen));

	// ICMP unreachable
	icmp->icmp_type = 8;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 400;
	icmp->icmp_id = htons(pktid);  // identifier
	icmp->icmp_seq = 0;

    if (pktType == TR_ICMP_FIX) {
        icmp->icmp_seq = in_cksum((unsigned short *)icmp, 8);
    } else if (pktType == TR_ICMP_VAR) {
        icmp->icmp_seq = in_cksum((unsigned short *)icmp, 8);
        icmp->icmp_seq += sport;
    }

    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = in_cksum((unsigned short *)icmp, 8);

	//printf("icmp cksum:%d icmp cksum net order:%d\n", icmp->icmp_cksum, ntohs(icmp->icmp_cksum));
    //printf("SENDICMP payload: seqnum:%lu sport:%d dport:%d th_ack:%lu th_cksum:%lu\n", 
	//		ntohl(tcp->th_seq), ntohs(tcp->th_sport), ntohs(tcp->th_dport), 
    //                    ntohl(tcp->th_ack), ntohs(tcp->th_sum));

	//printf("iphdr:%d, icmp:%d, icmp cksum:%d\n", (int)sizeof(struct ip), 
	//											 (int)sizeof(struct icmp), 
	//											 in_cksum((unsigned short *)icmp, iphdrLen + 16));

    //printf("send pktid:%d\n", pktid);
    if ((cc = sendto(sndsock, (char *)outip_icmp, packlen, 0, (struct sockaddr *)target, sizeof(*target))) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> ICMP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
    }
}

void
Traceroute4::openOutput() {
    Traceroute::openOutput(inet_ntoa(getSource()->sin_addr));  
}
