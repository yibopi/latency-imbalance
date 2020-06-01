#include "flipr.h"

void
appendHop(vector<Flow> &flows, uint16_t sport, uint16_t dport, Hop h) {
    for (int i = 0; i < flows.size(); i++) {
        if (flows[i].sport == sport && flows[i].dport == dport) {
            flows[i].hops.push_back(h);
            return;
        }
    }
}

void
appendFlow(vector<Flow> &flows, Flow &flow) {
    for (auto &f : flows) {
        if (f.sport == flow.sport && f.dport == flow.dport)
            return;
    }
    flows.push_back(flow);
    return;
}

uint8_t
estTTL(uint8_t ttl) {
	uint8_t maxttl;
	if (ttl < 64) maxttl = 64;
	else if (ttl >= 64 && ttl < 128) maxttl = 128;
	else if (ttl >= 128 && ttl < 192) maxttl = 192;
	else maxttl = 255;

	return maxttl - ttl;
}

void
printFlow(Flow &f) {
    for (auto h : f.hops)
        printf("%d ", h.fwdttl);
    printf("\n");
}
			
void
pathEnumHop(uint32_t id, 
            uint16_t sport, 
            uint16_t dport, 
            Hop h,
            IPState *ipState,
            Scheduler *sch) 
{
    if (ipState->recvbuf.empty()) {
        Flow flow(sport, dport);
        flow.hops.push_back(h);
        ipState->recvbuf.push_back(flow);
    } else {
        if (!ipState->recvbuf[0].updateHop(id, h)) {
            uint32_t pfx = IP2Pfx(id);
            sch->addToBlacklist(pfx);
        }
    }
}

void
procIpOpt(uint32_t id, 
          IPState *ipState, 
          ip_timestamp *ts) 
{
    if (!ts || !ipState) return;

    int i;
    Flow f(0, 0);

    // IP opt format: ip1 ts1 ip2 ts2 ip1 ts3 ip2 ts4
    // printf("id:%lu ", id);
    for (i = 0; i < 8; i++) {
        // printf("%lu ", ntohl(ts->data[i]));
        f.hops.push_back(Hop(ntohl(ts->data[i]), 0));
    }
    // printf("\n");

    bool exist = false;
    for (i = 0; i < ipState->recvbuf.size(); i++) {
        bool equal = true;
        vector<Hop> &hops = ipState->recvbuf[i].hops;
        for (int j = 0; j < hops.size() / 2; j++) {
            if (f.hops[2*j].ip != hops[2*j].ip) 
                equal = false;
        }
        if (equal) { exist = true; break; }
    }

    if (!exist) {
        ipState->recvbuf.push_back(f);
    }

    return;
}

bool
validatePkt(uint32_t ip_dst, 
            uint32_t sport, 
            uint32_t dport,
            Packet *pkt) 
{
    return pkt->targetip == ip_dst
                && pkt->sport == sport
                && pkt->dport == dport;
}

int
countUnqiueAddr(vector<Flow> &flows) {
    unordered_set<uint32_t> uniqueAddr;
    for (auto &f : flows) {
        for (auto &h : f.hops) {
            uniqueAddr.insert(h.ip);
        }
    }
    return uniqueAddr.size();
}

uint32_t
dot2dec(string ip) {
    static in_addr addr;
    assert(inet_aton(ip.c_str(), &addr) == 1);
	return ntohl(addr.s_addr);
}

unordered_map<uint32_t, uint32_t> azureDB = 
{
{dot2dec("10.0.0.6"), dot2dec("52.147.28.91")}, // australia
{dot2dec("10.0.3.4"), dot2dec("52.237.36.63")}, // canada
{dot2dec("10.0.6.4"), dot2dec("168.61.45.80")}, // east-us
{dot2dec("10.0.2.4"), dot2dec("40.89.158.154")}, // france
{dot2dec("10.0.8.4"), dot2dec("104.211.211.71")}, // india
{dot2dec("10.0.1.4"), dot2dec("13.71.128.157")}, //japan
{dot2dec("10.0.4.4"), dot2dec("51.140.75.85")}, //us-south
{dot2dec("10.0.5.4"), dot2dec("52.160.44.109")} // west-us
};

void
parseICMP(Traceroute *trace) 
{
	int len;
    unsigned char buf[PKTSIZE];
    TTLHisto *ttlhisto = NULL;
    uint32_t elapsed = 0;
    uint32_t ip_src, ip_dst;
    uint16_t pktid;
    struct ip *ip = NULL;
    struct icmp *ippayload = NULL;
	ICMP *icmp;
    Packet *packet;
    Scheduler *sch;
    IPState *ipState;
    uint8_t type, replyttl, recvttl;
    uint16_t sport, dport, ipid;

	len = recv(trace->rcvsk_icmp, buf, PKTSIZE, 0);
    if (len == -1) {
        cerr << ">> Listener: read error: " << strerror(errno) << endl;
        return;
    }
	ip = (struct ip *)buf;
	if ((ip->ip_v != IPVERSION) || (ip->ip_p != IPPROTO_ICMP))
		return;

    // ip header
	replyttl = ip->ip_ttl;
    ip_src = ntohl(ip->ip_src.s_addr);

    // exclude addrs like 0.x.x.x
    if ((ip_src >> 24) == 0)
        return;

	ippayload = (struct icmp *)&buf[ip->ip_hl << 2];
	elapsed = trace->elapsed();
	icmp = new ICMP4(ip, ippayload, elapsed, trace->config->coarse);
	if (trace->verbose)
		icmp->print();
	/* Fill mode logic.  If we receive a response from maxttl, fire
	   off tail probes */ 
	//if (trace->config->fillmode) {
	//	if (icmp->getTTL() == trace->config->maxttl) {
	//		trace->stats->fills+=1;
	//		int newtail = trace->config->maxttl + trace->config->fillmode;
	//		for (int j=trace->config->maxttl + 1; j <= newtail; j++) {
	//			trace->probe(icmp->quoteDst(), j); 
	//		}
	//	}
	//}
	// icmp->write(&(trace->out), trace->stats->count);

    // ip header in quote
	ip_dst = icmp->quoteDst();
    recvttl = icmp->getTTL();
    pktid = icmp->getPktid();
    type = icmp->getType();
    sport = icmp->getSport();
    dport = icmp->getDport();
    ipid  = icmp->getIpId();

    sch = trace->sch;

    // added Feb 10
    if (azureDB.count(ip_dst) > 0) {
        ip_dst = azureDB[ip_dst];
    } 

    pthread_rwlock_wrlock(&gLock);

    if (type == ICMP_ECHOREPLY) {
        packet = trace->tracePkt(pktid);
        if (packet && (packet->pktType == TR_ICMP_VAR || packet->pktType == TR_ICMP_FIX)) {
            ip_timestamp *ts = icmp->getTs();
            ip_dst = packet->targetip;
            if (sch->ipStateDB.count(ip_dst) > 0) {
                ipState = &sch->ipStateDB[ip_dst];
                // replyttl in icmp opts cannot be used for estimation
                procIpOpt(ip_src, ipState, ts);

                if (trace->config->debug_mode) {
                    printf("ICMP ECHO RECV: time:%f, to:%lu, from:%lu, sport:%d, dport:%d, ttl:%d, hl:%d\n", 
                        getCurrTime(), (unsigned long)ip_dst, (unsigned long)ip_src, sport, dport, packet->ttl, ip->ip_hl);
                }
            }
        }
    } else if (sch->ipStateDB.count(ip_dst) > 0 && !sch->inBlacklist(ip_dst)) {

        double rttInSec;
        uint32_t pfx = IP2Pfx(ip_dst);
        //ipState = NULL;

        packet = trace->tracePkt(pktid);
        ipState = &sch->ipStateDB[ip_dst];

        if (!packet) {
            // do nothing
        } else if (!validatePkt(ip_dst, sport, dport, packet)) {
            // sch->addToBlacklist(pfx);
        } else if ((rttInSec = getCurrTime() - packet->sndTime) < TIMEOUT) {
            // Note: sport in received packets could differ from sent ones
            Flow flow(sport, dport);
            Hop h(ip_src, packet->ttl);
            h.val = rttInSec * 1000;	
            h.cnt = 1;
    
            if (trace->config->debug_mode) {
                printf("ICMP RECV: time:%f, to:%lu, from:%lu, sport:%d, dport:%d, ipid:%d, ttl:%d, rtt:%f, hl:%d\n", 
                       getCurrTime(), (unsigned long)ip_dst, (unsigned long)ip_src, sport, dport, ipid, packet->ttl, h.val, ip->ip_hl);
            }

            switch (ipState->task) {
                case CHK_RESPONSE:
                case GENERATE_FLOWS:
                    if (ip_dst == ip_src) {
                        flow.hops.push_back(h);
                        flow.rvrttl = MIN(MAX_HOPS, estTTL(replyttl));  
                        appendFlow(ipState->flows, flow);
                    } else {
                        ipState->cnt++;
                        // sch->addToBlacklist(pfx);
                    }
                    break;
                case FIND_LAST_ROUTER:
                    flow.hops.push_back(h);
                    flow.rvrttl = MIN(MAX_HOPS, estTTL(replyttl));
                    flow.fwdttl = h.fwdttl;
                    ipState->recvbuf.push_back(flow);
                    break;
                case PATH_ENUM_E2E:
                    flow.hops.push_back(h);
                    flow.rvrttl = MIN(MAX_HOPS, estTTL(replyttl));  
                    ipState->flows.push_back(flow);
                    break;
                case PATH_HOP_EST:
                case FLOW_ENUM_E2E:
                    appendHop(ipState->flows, sport, dport, h);
                    break;
                case PATH_ENUM_HOP:
                    // update ipid DB
                    sch->updateHistDB(ip_src, ipid);
                case PATH_ENUM_HOP_SIMPLE:
                    h.rvrttl = MIN(MAX_HOPS, estTTL(replyttl));
                    pathEnumHop(ip_dst, sport, dport, h, ipState, sch);
                    break;
                case PERIODIC_PROBE:
                    flow.hops.push_back(h);
                    ipState->flows.push_back(flow);
                    break;
                case ALIAS_RESL_IPID:
                    h.val = ipid;
                    flow.hops.push_back(h);
                    flow.rvrttl = MIN(MAX_HOPS, estTTL(replyttl));
                    ipState->recvbuf.push_back(flow);
                    //if including two different addresses
                    //cout << "numUniqAddr:" << countUnqiueAddr(ipState->recvbuf) 
                    //     << " numProbe:" << ipState->numProbe << endl;
                    if (countUnqiueAddr(ipState->recvbuf) == 2 && ipState->numProbe == 1) {
                        ipState->numProbe = 2;
                        sch->addToQueue(Task(ip_dst, 0));
                    }
                    break;
                case CHK_LB:
                // case ALIAS_RESL_OPTION:
                    flow.hops.push_back(h);
                    flow.rvrttl = MIN(MAX_HOPS, estTTL(replyttl));
                    ipState->recvbuf.push_back(flow);
                    break;
                case ROUTER_LB_TYPE:
                    flow.hops.push_back(h);
                    ipState->recvbuf.push_back(flow);
                    break;
            }
            // record the most recent time
            trace->lastTime = getCurrTime();
        }
    }
    pthread_rwlock_unlock(&gLock);
  
	delete icmp;
    return;
}

void
parseTCP(Traceroute *trace)
{
	int len;
    struct ip *ip = NULL;
    unsigned char buf[PKTSIZE];
    uint32_t ip_src;

	len = recv(trace->rcvsk_tcp, buf, PKTSIZE, 0);
	if (len == -1) {
		cerr << ">> Listener: read error: " << strerror(errno) << endl;
		return;
	}

	ip = (struct ip *)buf;
	if ((ip->ip_v != IPVERSION) or (ip->ip_p != IPPROTO_TCP))
		return;
	
    ip_src = ntohl(ip->ip_src.s_addr);
    
    if ((ip_src >> 24) == 0)
        return;

	uint8_t replyttl;
    uint16_t pktid;
	uint16_t sport, dport;
	uint32_t pfx;
    Packet *packet = NULL;
    IPState *ipState = NULL;

	struct tcphdr *tcp = (struct tcphdr *)&buf[ip->ip_hl << 2];
			
	sport = ntohs(tcp->th_sport);
	dport = ntohs(tcp->th_dport);	
	replyttl = ip->ip_ttl;

	Scheduler *sch = trace->sch;

    pthread_rwlock_wrlock(&gLock);
    pktid = trace->tracePktID(ip_src);
    if (pktid == UINT16_MAX) {
        pfx = IP2Pfx(ip_src);
        sch->addToBlacklist(pfx);
    }
    if (sch->ipStateDB.count(ip_src) != 0 && !sch->inBlacklist(ip_src)) {
        packet = trace->tracePkt(pktid);
        ipState = &sch->ipStateDB[ip_src];
    }
    if (packet && ipState) {
        Hop h(ip_src, packet->ttl);
        double rtt = (getCurrTime() - packet->sndTime) * 1000;	 
        h.val = rtt;	
        h.cnt = 1;
        
        Flow flow(dport, sport);
        flow.hops.push_back(h);
        flow.rvrttl = MIN(MAX_HOPS, estTTL(replyttl));  

        //if (ip_src == 3200372561)
        //    printf("TCP RECV: time:%f, from:%lu, sport:%d, dport:%d, pktid:%d, ttl:%d, rtt:%f\n", 
        //           getCurrTime(), (unsigned long)ip_src, sport, dport, pktid, packet->ttl, rtt);

        switch (ipState->task) {
            case PATH_ENUM_E2E:
                ipState->flows.push_back(flow);
                break;
            case PATH_HOP_EST:
                appendHop(ipState->flows, dport, sport, h);
                break;
            case PATH_ENUM_HOP:
            case PATH_ENUM_HOP_SIMPLE:
                pathEnumHop(ip_src, dport, sport, h, ipState, sch);
                break;
            case PERIODIC_PROBE:
                // NOTE: received packets could have different ports 
                // as the sent packets
                ipState->flows.push_back(flow);
                // record the most recent time
                break;
            case CHK_RESPONSE:
            case GENERATE_FLOWS:
                appendFlow(ipState->flows, flow);
                break;
            case ROUTER_LB_TYPE:
                ipState->recvbuf.push_back(flow);
                break;
        }
        trace->lastTime = getCurrTime();
    }
    pthread_rwlock_unlock(&gLock);
  
    return;
}
    
pthread_rwlock_t gLock;

void*
listener(void *args) {
    fd_set rfds;
    Traceroute *trace = reinterpret_cast < Traceroute * >(args);
    struct timeval timeout;
    uint32_t nullreads = 0;
    int n;
    pthread_rwlock_init(&gLock, NULL);

	while (true) {
        // if (nullreads >= MAXNULLREADS)
        //     break;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

		FD_SET(trace->rcvsk_icmp, &rfds);
		FD_SET(trace->rcvsk_tcp, &rfds);

		int maxsk = max(trace->rcvsk_icmp, trace->rcvsk_tcp);
        n = select(maxsk + 1, &rfds, NULL, NULL, &timeout);
        
		if (n == 0) {
            nullreads++;
            cout << ">> Listener: timeout " << nullreads;
            cout << "/" << MAXNULLREADS << endl;
            continue;
        }
        if (n > 0) {
            nullreads = 0;
	        
			if (FD_ISSET(trace->rcvsk_icmp, &rfds))
				parseICMP(trace);
		
			if (FD_ISSET(trace->rcvsk_tcp, &rfds))
				parseTCP(trace);
        }
    }
    return NULL;
}

void*
listener6(void *args) {
    fd_set rfds;
    Traceroute6 *trace = reinterpret_cast < Traceroute6 * >(args);
    struct timeval timeout;
    unsigned char buf[PKTSIZE];
    uint32_t nullreads = 0;
    int n, len;
    TTLHisto *ttlhisto = NULL;
    uint32_t elapsed = 0;
    struct ip6_hdr *ip = NULL;                /* IPv6 hdr */
    struct icmp6_hdr *ippayload = NULL;       /* ICMP6 hdr */
    struct ip6_hdr *icmpip = NULL;            /* Quoted IPv6 hdr */
    struct ypayload *quotepayload = NULL;     /* Quoted ICMPv6 yrp payload */ 

    while (true) {
        if (nullreads >= MAXNULLREADS)
            break;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(trace->rcvsk_icmp, &rfds);
        n = select(trace->rcvsk_icmp + 1, &rfds, NULL, NULL, &timeout);
        if (n == 0) {
            nullreads++;
            cout << ">> Listener: timeout " << nullreads;
            cout << "/" << MAXNULLREADS << endl;
            continue;
        }
        if (n > 0) {
            nullreads = 0;
            len = recv(trace->rcvsk_icmp, buf, PKTSIZE, 0); 
            if (len == -1) {
                cerr << ">> Listener: read error: " << strerror(errno) << endl;
                continue;
            }
            ip = (struct ip6_hdr *)(buf + ETH_HDRLEN);
            quotepayload = NULL;
            if (ip->ip6_nxt == IPPROTO_ICMPV6) {
                ippayload = (struct icmp6_hdr *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr)];
                if (ippayload->icmp6_type == ICMP6_ECHO_REPLY) {
                    quotepayload = (struct ypayload *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)];
                } else {
                    icmpip = (struct ip6_hdr *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)];
                    if (icmpip->ip6_nxt == IPPROTO_TCP) {
                        quotepayload = (struct ypayload *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)];
                    } else if (icmpip->ip6_nxt == IPPROTO_UDP) {
                        quotepayload = (struct ypayload *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr)];
                    } else if (icmpip->ip6_nxt == IPPROTO_ICMPV6) {
                        quotepayload = (struct ypayload *)&buf[ETH_HDRLEN + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)];
                    } else {
                        continue;
                    }
                }
                elapsed = trace->elapsed();
                if ((ippayload->icmp6_type != ICMP6_ECHO_REQUEST) and strcmp(quotepayload->id, "yrp6") == 0) {
                    ICMP *icmp = new ICMP6(ip, ippayload, quotepayload, elapsed, trace->config->coarse);
                    if (trace->verbose)
                        icmp->print();
                    /* Fill mode logic.   */
                    // if (trace->config->fillmode) {
                    //     if (icmp->getTTL() == trace->config->maxttl) {
                    //         trace->stats->fills+=1;
                    //         int newtail = trace->config->maxttl + trace->config->fillmode;
                    //         for (int j=trace->config->maxttl + 1; j <= newtail; j++) {
                    //             trace->probe(icmp->quoteDst6(), j); 
                    //         }
                    //     }
                    // }
                    icmp->write(&(trace->out), trace->stats->count);
                    /* TTL tree histogram */
                    if (trace->ttlhisto.size() > icmp->quoteTTL()) {
                        ttlhisto = trace->ttlhisto[icmp->quoteTTL()];
                        ttlhisto->add(icmp->getSrc6(), elapsed);
                    }
                    if (trace->verbose) 
                        trace->dumpHisto();
                    delete icmp;
                }
            } 
        }
    }
    return NULL;
}
