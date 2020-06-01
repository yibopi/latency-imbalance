#include <flipr.h>

class Stats {
    public:
    Stats() : count(0), to_probe(0), nbr_skipped(0), bgp_skipped(0),
              ttl_outside(0), bgp_outside(0), adr_outside(0), baddst(0),
              fills(0) {
      gettimeofday(&start, NULL);
    };
    void terse() {
      terse(stderr);
    }
    void terse(FILE *out) {
      gettimeofday(&end, NULL);
      float t = (float) tsdiff(&end, &start) / 1000.0;
      //fprintf(out, "# %d/%d (%2.1f%%), NBskip: %d/%d TBAout: %d/%d/%d Bad: %d Fills: %d ",
      //  count, to_probe, (float) count*100.0/to_probe,
      //  nbr_skipped, bgp_skipped, ttl_outside, 
      //  bgp_outside, adr_outside, baddst, fills);
      fprintf(out, " in: %2.3fs (%2.3f p/s)\n",
        t, (float) count / t);
    };
    void dump(FILE *out) {
      gettimeofday(&end, NULL);
      float t = (float) tsdiff(&end, &start) / 1000.0;
      fprintf(out, "# Current TS: %s", ctime(&(end.tv_sec)));  
      fprintf(out, "# Cnt: %d nbr_skip: %d bgp_skip: %d\n",
          count, nbr_skipped, bgp_skipped);
      fprintf(out, "#      ttl_out: %d bgp_out: %d adr_out: %d Bad: %d, Fills: %d\n",
          ttl_outside, bgp_outside, adr_outside, baddst, fills);
      fprintf(out, "# In: %2.3fs (Approx: %2.3f p/sec)\n", 
          t, (float) count / t);
    };
    
    uint32_t count;
    uint32_t to_probe;
    uint32_t nbr_skipped; // b/c already in learned neighborhood 
    uint32_t bgp_skipped; // b/c BGP learned
    uint32_t ttl_outside; // b/c outside range of TTLs we want
    uint32_t bgp_outside; // b/c not in BGP table
    uint32_t adr_outside; // b/c address outside range we want
    uint32_t baddst;      // b/c checksum invalid on destination in reponse
    uint32_t fills;       // extra tail probes past maxttl
   
    struct timeval start;
    struct timeval end;
};
