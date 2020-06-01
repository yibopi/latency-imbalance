/****************************************************************************
   Program:     $Id: listener.cpp 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp listener thread
****************************************************************************/
#include "flipr.h"

ICMP::ICMP() : 
   rtt(0), ttl(0), type(0), code(0), sport(0), dport(0), ipid(0),
   probesize(0), replysize(0), replyttl(0), replytos(0), pktid(UINT16_MAX)
{
    gettimeofday(&tv, NULL);
}

ICMP4::ICMP4(struct ip *ip, struct icmp *icmp, uint32_t elapsed, bool _coarse): ICMP()
{
    coarse = _coarse;
    memset(&ip_src, 0, sizeof(struct in_addr));
    type = (uint8_t) icmp->icmp_type;
    code = (uint8_t) icmp->icmp_code;
    ip_src = ip->ip_src;

#ifdef _BSD
    ipid = ip->ip_id;
#else
    ipid = ntohs(ip->ip_id);
#endif

    replytos = ip->ip_tos;
    replysize = ntohs(ip->ip_len);
    replyttl = ip->ip_ttl;
    unsigned char *ptr = NULL;

    quote = NULL;
    ipts = NULL;
    if (type == ICMP_ECHOREPLY) {
        pktid = ntohs(icmp->icmp_id);
        int iphdrlen = (sizeof(struct ip) + MAX_IPOPTLEN) >> 2;
        if (ip->ip_hl == iphdrlen) {
            ipts = (ip_timestamp *)((unsigned char *)ip + sizeof(struct ip));
        }
    } else if (((type == ICMP_TIMXCEED) and (code == ICMP_TIMXCEED_INTRANS)) or
        (type == ICMP_UNREACH) or (type == ICMP_REDIRECT)) 
    {
        ptr = (unsigned char *) icmp;
        quote = (struct ip *) (ptr + 8);
        pktid = ntohs(quote->ip_id);
        probesize = ntohs(quote->ip_len);
        ttl = quote->ip_ttl;
        /* Original probe was TCP */
        if (quote->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *) (ptr + 8 + (quote->ip_hl << 2));
            rtt = elapsed - ntohl(tcp->th_seq);
            //if (elapsed < ntohl(tcp->th_seq))
            //    cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << ntohl(tcp->th_seq) << endl;
            sport = ntohs(tcp->th_sport);
            dport = ntohs(tcp->th_dport);
        }
        /* Original probe was UDP */
        else if (quote->ip_p == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *) (ptr + 8 + (quote->ip_hl << 2));
            /* recover timestamp from UDP.check and UDP.payloadlen */
            int payloadlen = ntohs(udp->uh_ulen) - sizeof(struct icmp);
            int timestamp = udp->uh_sum;
            sport = ntohs(udp->uh_sport);
            dport = ntohs(udp->uh_dport);
            if (payloadlen > 2)
                timestamp += (payloadlen-2) << 16;
            if (elapsed >= timestamp) {
                rtt = elapsed - timestamp;
            /* checksum was 0x0000 and because of RFC, 0xFFFF was transmitted
             * causing us to see packet as being 65 (2^{16}/1000) seconds in future */
            } else if (udp->uh_sum == 0xffff) {
                timestamp = (payloadlen-2) << 16;
                rtt = elapsed - timestamp;
            }
            //if (elapsed < timestamp) {
            //    cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << timestamp << endl;
            //    sport = dport = 0;
            //}
        } 
        //if ( (quote->ip_p == IPPROTO_TCP) || (quote->ip_p == IPPROTO_UDP) ) {
        //    uint16_t sum = in_cksum((unsigned short *)&(quote->ip_dst), 4);
            /*
             * According to Malone PAM 2007, 2% of replies have bad IP dst. 
             * For now, detect by setting sport=dport=0
             */
        //    if (sport != sum) {
        //        cerr << "** IP dst in ICMP reply quote invalid!" << endl;
        //        sport = dport = 0;
        //    }
        //}
    }
}

/**
 * Create ICMP6 object on received response.
 *
 * @param ip   Received IPv6 hdr
 * @param icmp Received ICMP6 hdr
 * @param qpayload Payload of quoted packet
 * @param elapsed Total running time
 */
ICMP6::ICMP6(struct ip6_hdr *ip, struct icmp6_hdr *icmp, struct ypayload *qpayload, 
             uint32_t elapsed, bool _coarse) : ICMP()
{
    coarse = _coarse;
    memset(&ip_src, 0, sizeof(struct in6_addr));
    type = (uint8_t) icmp->icmp6_type;
    code = (uint8_t) icmp->icmp6_code;
    ip_src = ip->ip6_src;
    replysize = ntohs(ip->ip6_plen);
    replyttl = ip->ip6_hlim;
    ttl = qpayload->ttl;
    uint32_t diff = qpayload->diff;
    unsigned char *ptr = NULL;
    if (elapsed >= diff)
        rtt = elapsed - diff;
    else
        cerr << "** RTT decode, elapsed: " << elapsed << " encoded: " << diff << endl;

    /* ICMP6 echo replies (ie if we hit the target) don't contain quote */
    quote = NULL;
    if (((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) or
        (type == ICMP6_DST_UNREACH)) {
        ptr = (unsigned char *) icmp;
        quote = (struct ip6_hdr *) (ptr + sizeof(icmp6_hdr));
        probesize = ntohs(quote->ip6_plen);
        if (quote->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *) (ptr + sizeof(icmp6_hdr) + sizeof(struct ip6_hdr));
            sport = ntohs(tcp->th_sport);
            dport = ntohs(tcp->th_dport);
        } else if (quote->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *) (ptr + sizeof(icmp6_hdr) + sizeof(struct ip6_hdr));
            sport = ntohs(udp->uh_sport);
            dport = ntohs(udp->uh_dport);
        }
        
		//if ( (quote->ip6_nxt == IPPROTO_TCP) || (quote->ip6_nxt == IPPROTO_UDP) ) {
        //    uint16_t sum = in_cksum((unsigned short *)&(quote->ip6_dst), 16);
        //    if (sport != sum) {
        //        cerr << "** IP6 dst in ICMP6 reply quote invalid!" << endl;
        //        sport = dport = 0;
        //    }
        //}
    }
}

uint32_t ICMP4::quoteDst() {
    //if ((type == ICMP_TIMXCEED) and (code == ICMP_TIMXCEED_INTRANS)) {
    //    return quote->ip_dst.s_addr;
    //}
    //return 0;
	if (quote) return ntohl(quote->ip_dst.s_addr);

	return 0;
}

void ICMP::print(char *src, char *dst, int sum) {
    printf(">> ICMP type: %d code: %d from: %s\n", type, code, src);
    printf("\tTS: %lu.%ld\n", tv.tv_sec, (long) tv.tv_usec);
    if (coarse)
      printf("\tRTT: %u ms\n", rtt);
    else
      printf("\tRTT: %u us\n", rtt);
    printf("\tProbe dst: %s\n", dst);
    printf("\tProbe TTL: %d\n", ttl);
    if (ipid) printf("\tReply IPID: %d\n", ipid);
    printf("\tProbe TCP/UDP src/dst port: %d/%d\n", sport, dport);
    if (sum) printf("\tCksum of probe dst: %d\n", sum);
}

void 
ICMP4::print() {
    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_src, src, INET_ADDRSTRLEN);
    char dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(quote->ip_dst), dst, INET_ADDRSTRLEN);
    uint16_t sum = in_cksum((unsigned short *)&(quote->ip_dst), 4);
    ICMP::print(src, dst, sum);
}

void
ICMP6::print() {
    char src[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip_src, src, INET6_ADDRSTRLEN);
    char dst[INET6_ADDRSTRLEN] = "no-quote";
    uint16_t sum = 0;
    if (quote != NULL) {
        inet_ntop(AF_INET6, &(quote->ip6_dst), dst, INET6_ADDRSTRLEN);
        sum = in_cksum((unsigned short *)&(quote->ip6_dst), 16);
    }
    ICMP::print(src, dst, sum);
}

/* trgt, sec, usec, type, code, ttl, hop, rtt, ipid, psize, rsize, rttl, rtos */
void ICMP::write(FILE ** out, uint32_t count, char *src, char *target) {
    if (*out == NULL)
        return;
    fprintf(*out, "%s, %lu, %ld, %d, %d, ",
        target, tv.tv_sec, (long) tv.tv_usec, type, code);
    fprintf(*out, "%d, %s, %d, %u, ",
        ttl, src, rtt, ipid);
    fprintf(*out, "%d, %d, %d, %d, ",
        probesize, replysize, replyttl, replytos);
    fprintf(*out, "%d\n", count);
}

void ICMP4::write(FILE ** out, uint32_t count) {
    if ((sport == 0) and (dport == 0))
        return;
    char src[INET_ADDRSTRLEN];
    char target[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_src, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(quote->ip_dst), target, INET_ADDRSTRLEN);
    ICMP::write(out, count, src, target);
}

void ICMP6::write(FILE ** out, uint32_t count) {
    char src[INET6_ADDRSTRLEN];
    char target[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip_src, src, INET6_ADDRSTRLEN);
    if (((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) or
    (type == ICMP6_DST_UNREACH)) { 
        inet_ntop(AF_INET6, &(quote->ip6_dst.s6_addr), target, INET6_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, &ip_src, target, INET6_ADDRSTRLEN);
    }
    ICMP::write(out, count, src, target);
}

struct in6_addr ICMP6::quoteDst6() {
    if ((type == ICMP6_TIME_EXCEEDED) and (code == ICMP6_TIME_EXCEED_TRANSIT)) {
        return quote->ip6_dst;
    }
}
