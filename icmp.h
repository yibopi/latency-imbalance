#ifndef ICMP_H
#define ICMP_H

class ICMP {
    public:
    ICMP();
    virtual void print() {};
    virtual void write(FILE **, uint32_t) {};
    virtual uint32_t getSrc() { return 0; };
    virtual struct in6_addr *getSrc6() { return NULL; };
    virtual uint32_t quoteDst() { return 0; };
    virtual struct in6_addr quoteDst6() {};
    uint8_t quoteTTL() { return ttl; }
    uint32_t getRTT() { return rtt; }
    uint32_t getTTL() { return ttl; }
    uint16_t getSport() { return sport; }
    uint16_t getDport() { return dport; }
    uint16_t getPktid() { return pktid; }
    uint16_t getIpId() { return ipid; }
    uint8_t getType() { return type; }
    void print(char *, char *, int);
    void write(FILE **, uint32_t, char *, char *);
    ip_timestamp *getTs() { return ipts; }

    protected:
    uint32_t rtt;
    uint16_t pktid;
    uint8_t ttl;
    uint8_t type;
    uint8_t code;
    uint16_t sport;
    uint16_t dport;
    uint16_t ipid;
    uint16_t probesize;
    uint16_t replysize;
    uint8_t replyttl;
    uint8_t replytos;
    struct timeval tv;
    bool coarse;
    ip_timestamp *ipts;
};

class ICMP4 : public ICMP {
    public:
    ICMP4(struct ip *, struct icmp *, uint32_t elapsed, bool _coarse);
    uint32_t quoteDst();
    uint32_t getSrc() { return ip_src.s_addr; }
    void print();
    void write(FILE **, uint32_t);

    private:
    struct ip *quote;
    struct in_addr ip_src;
}; 

class ICMP6 : public ICMP {
    public:
    ICMP6(struct ip6_hdr *, struct icmp6_hdr *, struct ypayload *, uint32_t elapsed, bool _coarse);
    struct in6_addr *getSrc6() { return &ip_src; }
    struct in6_addr quoteDst6();
    void print();
    void write(FILE **, uint32_t);

    private:
    struct ip6_hdr *quote;
    struct in6_addr ip_src;
};

#endif // ICMP_H
