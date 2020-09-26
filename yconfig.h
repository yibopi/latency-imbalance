class YarrpConfig {
  public:
  YarrpConfig() : rate(2000), scan(false), ttl_neighborhood(0),
    testing(true), entire(false), verbose(0), output(NULL), 
    bgpfile(NULL), inlist(NULL), count(0), debug_mode(false), seed(0),
    dstport(80), maxttl(32), fastmode(false),
    ipv6(false), int_name(NULL), dstmac(NULL), srcmac(NULL),
    coarse(false), fillmode(0), lasthop(false) {};

  void parse_opts(int argc, char **argv); 
  void usage(char *prog);
  unsigned int rate;
  bool scan;
  bool fastmode;
  uint8_t ttl_neighborhood;
  bool testing; /* require -Z flag (and user RTFM) to send any packets */
  bool entire;  /* special mode, with speed as sole emphasis, to scan entire Internet */
  uint8_t verbose;
  char *output;
  char *bgpfile;
  char *inlist;
  uint32_t count;
  bool debug_mode;
  uint8_t maxttl;
  uint32_t seed;
  uint16_t dstport;
  bool ipv6;
  char *int_name;
  uint8_t *dstmac;
  uint8_t *srcmac;
  int type;
  bool coarse;
  int fillmode;
  bool lasthop;
};