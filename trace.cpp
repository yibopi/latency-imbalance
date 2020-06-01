/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "flipr.h"

Traceroute::Traceroute(YarrpConfig *_config) : config(_config), tree(NULL)
{
    verbose = config->verbose;
    pktType = (PKT_TYPE) config->type; 
    // dstport = config->dstport;

	// load all possible /24 blocks
    int cap = config->rate;
	sch = new Scheduler(config->inlist, config->output, cap);

    pktid = 0;

    if (config->ttl_neighborhood)
		initHisto(config->ttl_neighborhood);
    gettimeofday(&start, NULL);
    cout << ">> Traceroute engine started at: " << start.tv_sec << "." << start.tv_usec << endl;
}

Traceroute::~Traceroute() {
    gettimeofday(&start, NULL);
    cout << ">> Traceroute engine stopped at: " << start.tv_sec << "." << start.tv_usec << endl;
    fflush(NULL);
    pthread_cancel(recv_thread);
    //if (out)
    //    fclose(out);
}

uint16_t
Traceroute::regPkt(uint32_t srcip, uint8_t ttl, PKT_TYPE pktType, 
                   uint16_t sport, uint16_t dport) 
{
    //pthread_rwlock_wrlock(&lock);
    pktid = (pktid + 1) % UINT16_MAX;
    pktRepo[pktid] = Packet(srcip, getCurrTime(), ttl, pktType, sport, dport); 
    //pthread_rwlock_unlock(&lock);
    return pktid;
}

void
Traceroute::regIP(uint32_t ip, uint16_t id) {
    //pthread_rwlock_wrlock(&lock);
    sch->ip2id[ip] = id;
    //pthread_rwlock_unlock(&lock);
}

/*
void 
Traceroute::removeIP(uint32_t ip) {
    pthread_rwlock_wrlock(&lock);
    ip2id.erase(ip);
    pthread_rwlock_unlock(&lock);
}
*/

uint16_t
Traceroute::tracePktID(uint32_t ip) {
    int pktid = UINT16_MAX;
    //pthread_rwlock_rdlock(&lock);
    if (sch->ip2id.count(ip) != 0)
        pktid = sch->ip2id[ip];
    //pthread_rwlock_unlock(&lock);
    return pktid; 
}

void
Traceroute::setPktParam(uint16_t _sport, uint16_t _dport,
                        uint8_t _ttl, PKT_TYPE _pktType) {
    sport = _sport;
    dport = _dport;
    ttl = _ttl;
    pktType = _pktType; 
    return;
}

Packet *
Traceroute::tracePkt(uint16_t pktid) 
{
    Packet *packet = NULL;
    //pthread_rwlock_rdlock(&lock);
    if (pktRepo.count(pktid) != 0 && 
        getCurrTime() - pktRepo[pktid].sndTime < TIMEOUT) 
    {
        packet = &pktRepo[pktid];             
    }
    //pthread_rwlock_unlock(&lock);
    return packet;
}

void
Traceroute::initHisto(uint8_t ttl) {
    cout << ">> Init TTL histogram for neighborhood: " << int(ttl) << endl;
    for (int i = 0; i <= ttl; i++) {
        TTLHisto *t = NULL;
        if (config->ipv6)
            t = new TTLHisto6();
        else
            t = new TTLHisto4();
        ttlhisto.push_back(t);
    }
}

void
Traceroute::dumpHisto() {
    if (ttlhisto.size() == 0) 
        return;
    cout << ">> Dumping TTL Histogram:" << endl;
    for (int i = 1; i < ttlhisto.size(); i++) {
        TTLHisto *t = ttlhisto[i];
        cout << "\tTTL: " << i << " ";
        t->dump();
    }
}

uint32_t
Traceroute::elapsed() {
    gettimeofday(&now, NULL);
    if (config->coarse)
        return tsdiff(&now, &start);
    return tsdiffus(&now, &start); 
}

void
Traceroute::openOutput(const char *src) {
    cout << ">> Output: " << config->output << endl;
    out = fopen(config->output, "a");
    fprintf(out, "# yarrp v%s\n", VERSION);
    fprintf(out, "# Started: %s", ctime(&(start.tv_sec)));
    fprintf(out, "# Source: %s\n", src);
    fprintf(out, "# TraceType: %d Count: %d Rate: %u\n", 
            pktType, config->count, config->rate);
    fprintf(out, "# Rand: %d Nbrh: %d Entire: %d BGP: %s Fillmode: %d\n", 
         config->random_scan, config->ttl_neighborhood, 
         config->entire, config->bgpfile, config->fillmode);
    if (config->coarse)
        fprintf(out, "# RTT granularity: ms\n");
    else
        fprintf(out, "# RTT granularity: us\n");
    if (config->inlist) 
        fprintf(out, "# Input IPlist: %s MaxTTL: %d\n", config->inlist, config->maxttl);
    fprintf(out, "# target, sec, usec, type, code, ttl, hop, rtt, ipid, psize, rsize, rttl, rtos, count\n");
}
