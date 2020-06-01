/****************************************************************************
 * Description: Special code for fast, entire Internet-wide IPv4 probing
 *              
****************************************************************************/
#include "flipr.h"

void internet(YarrpConfig *config, Traceroute *trace, Patricia *tree, Stats *stats) {
    uint8_t ttl;
    uint32_t val = 0;
    uint32_t addr = 0;
    TTLHisto *ttlhisto = NULL;
    Status *status = NULL;

    uint32_t host = 1 << 24;
    struct in_addr in;
    char *p = NULL;
    int i;
    uint32_t octets_to_skip[13] = {0,     /* reserved */
                                   6,     /* Army */
                                  10,     /* 1918 */
                                  11,     /* DoD */
                                  22,     /* DISA */
                                  25,     /* UK Defence */
                                  26,     /* DISA */
                                  29,     /* DISA */
                                  30,     /* DISA */
                                  55,     /* DoD */
                                 127,     /* loopback */
                                 214,     /* DoD */
                                 215,     /* DoD */
                               };

    cout << ">> Randomizing permutation key." << endl;
    uint8_t key[KEYLEN] = { 0 };
    if (config->seed)
        permseed(key, config->seed);
    else
        permseed(key);
    struct cperm_t* perm = cperm_create(UINT32_MAX, PERM_MODE_CYCLE, 
                                        PERM_CIPHER_RC5, key, KEYLEN);

    p = (char *) &val;
    while (PERM_END != cperm_next(perm, &val)) {
        addr = val & 0x00FFFFFF;    // pick out 24 bits of network
        ttl = val >> 24;            // use remaining 8 bits of perm as ttl
        /* Probe a host in each /24 that's a function of the /24
           (so it appears somewhat random), but is deterministic,
           and fast to compute */
        host = (p[0] + p[1] + p[2]) & 0xFF;
        addr += (host << 24);               
        if ( (ttl & 0xE0) != 0x0) { // fast check: ttls in [0,31]
          stats->ttl_outside++;
          continue;
        }
#if 1
        /* Only send probe if destination is in BGP table */
        status = (Status *) tree->get(addr);
        if (not status)  {
            stats->bgp_outside++;
            continue;
        }
#else
        if ( (val & 0xE0) == 0xE0) { // multicast, class E
          stats->adr_outside++;
          continue;
        }
        for (i=0;i<13;i++) {
          if ( (val & 0xFF) == octets_to_skip[i]) 
             stats->adr_outside++;
             continue;
        } 
#endif
        ttl++;                   // probe ttls from 1 to 32
#if 1
        if (ttl < config->ttl_neighborhood) {
            ttlhisto = trace->ttlhisto[ttl];
            if (ttlhisto->shouldProbe() == false) {
                stats->nbr_skipped++;
                continue;
            }
            ttlhisto->probed(trace->elapsed());
        }
#endif
        trace->probe(addr, ttl);
        stats->count++;                
        if (stats->count == config->count)
            break;
        /* Every 4096, do this */
        if ( (stats->count & 0xFFF) == 0xFFF ) {
            stats->dump(stderr);
            if (config->rate) {
                /* Calculate sleep time based on scan rate */
                usleep( (1000000 / config->rate) * 4096 );
            }
        }
    }
}
