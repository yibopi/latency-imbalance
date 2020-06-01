/****************************************************************************
   Program:     $Id: $
   Date:        $Date: $ 
   Description: trace structures
****************************************************************************/
#ifndef TRACE_H
#define TRACE_H

#include "scheduler.h"

/* Payload for IPv6 Yarrp probes */
struct ypayload {
    char id[5];       /* "yrp6" */
    uint8_t ttl;      /* sent TTL */
    uint16_t fudge;   /* make chksum constant */
    uint32_t diff;    /* elapsed time */
};

class Traceroute {
    public:
    Traceroute(YarrpConfig *config);
    virtual ~Traceroute();
    void addTree(Patricia *_tree) {
        tree = _tree;
    }
    void addStats(Stats *_stats) {
        stats = _stats;
    }
    void initHisto(uint8_t);
    void dumpHisto();
    uint32_t elapsed();
    void openOutput(const char *);
    Packet *tracePkt(uint16_t);
    uint16_t regPkt(uint32_t, uint8_t, PKT_TYPE, uint16_t, uint16_t);
    void regIP(uint32_t, uint16_t);
    uint16_t tracePktID(uint32_t);
    virtual void openOutput() {};
    virtual void probe(uint32_t, struct sockaddr_in *, ip_timestamp *) {};
    virtual void probe(uint32_t, uint32_t, ip_timestamp *) {};
    virtual void probe(struct in6_addr, int) {};
	virtual void probe(uint32_t &, uint8_t &) {};

    public:
    int rcvsk_icmp; /* receive (icmp) socket file descriptor */
    int rcvsk_tcp; 
	
    FILE *out;   /* output file stream */
    Patricia *tree;
    Stats *stats;
    YarrpConfig *config;
    vector<TTLHisto *> ttlhisto;
    uint8_t verbose;

	Scheduler *sch;
    double lastTime;
    PKT_TYPE pktType;
    uint8_t ttl;
    uint16_t sport, dport;

    void setPktParam(uint16_t, uint16_t, uint8_t, PKT_TYPE);

    protected:
    uint16_t pktid;
    int sndsock; /* raw socket descriptor */
    int payloadlen;
    int packlen;
    pthread_t recv_thread;
    struct timeval start;
    struct timeval now;
    unordered_map<uint16_t, Packet> pktRepo; 
    pthread_rwlock_t lock;
};

class Traceroute4 : public Traceroute {
    public:
    Traceroute4(YarrpConfig *config);
    virtual ~Traceroute4();
    struct sockaddr_in *getSource() { return &source; }
    void probe(uint32_t, const char *, ip_timestamp *);
    void probe(uint32_t, uint32_t, ip_timestamp *);
    void probe(uint32_t, struct sockaddr_in *, ip_timestamp *);
    void openOutput();

    private:
    void probeUDP(struct sockaddr_in *, ip_timestamp *);
    void probeTCP(struct sockaddr_in *, ip_timestamp *);
    void probeICMP(struct sockaddr_in *, uint16_t, ip_timestamp *);
    struct ip *outip;
    struct ip *outip_icmp;
    struct sockaddr_in source;
};

class Traceroute6 : public Traceroute {
    public:
    Traceroute6(YarrpConfig *config);
    virtual ~Traceroute6();
    struct sockaddr_in6 *getSource() { return &source6; }
    void probe(struct in6_addr, int);
    void probe(void *, struct in6_addr, int);
    void openOutput();

    private:
    void make_transport();
    struct ip6_hdr *outip;
    uint8_t *frame;
    int pcount;
    uint8_t tc = 0; /* traffic class which we always set to 0 */
    uint32_t flow = 0; /* flow label which we always set to 0 */
    struct sockaddr_in6 source6;
    struct ypayload *payload;
};

#endif // TRACE_H
