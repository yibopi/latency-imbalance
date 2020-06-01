/****************************************************************************
   Program:     $Id: $
   Date:        $Date: $
   Description: yarrp runtime configuration parsing
****************************************************************************/
#include "flipr.h"

static struct option long_options[] = {
    {"bgp", required_argument, NULL, 'b'},
    {"coarse", required_argument, NULL, 'C'},
    {"count", required_argument, NULL, 'c'},
    {"fillmode", required_argument, NULL, 'F'},
    {"srcmac", required_argument, NULL, 'G'},
    {"help", no_argument, NULL, 'h'},
    {"input", required_argument, NULL, 'i'},
    {"interface", required_argument, NULL, 'I'},
    {"debug_mode", no_argument, NULL, 'd'},
    {"dstmac", required_argument, NULL, 'M'},
    {"neighborhood", required_argument, NULL, 'n'},
    {"output", required_argument, NULL, 'o'},
    {"port", required_argument, NULL, 'p'}, 
    {"entire", no_argument, NULL, 'Q'},
    {"rate", required_argument, NULL, 'r'},
    {"sequential", no_argument, NULL, 's'},
    {"seed", required_argument, NULL, 'S'},
    {"type", required_argument, NULL, 't'},
    {"verbose", no_argument, NULL, 'v'},
    {"real", no_argument, NULL, 'Z'},
    {NULL, 0, NULL, 0},
};

uint8_t *read_mac(char *str) {
    uint8_t *mac = (uint8_t *) malloc (6 * sizeof(uint8_t));
    mac[0] = (uint8_t) strtoul(strtok(str, ":"), NULL, 16);
    for (int i=1; i < 6; i++) 
        mac[i] = (uint8_t) strtoul(strtok(NULL, ":"), NULL, 16);
    return mac;
}

void
YarrpConfig::parse_opts(int argc, char **argv) {
    int c, opt_index;
    char *endptr;

    cout << "yarrp v" << VERSION << endl;
    type = TR_TCP_ACK;
    while (-1 != (c = getopt_long(argc, argv, "b:c:CF:G:hi:I:d:M:n:o:p:Qr:sS:t:vZ", long_options, &opt_index))) {
        switch (c) {
        case 'b':
            bgpfile = optarg;
            break;
        case 'C':
            coarse = true;
            break;
        case 'c':
            count = strtol(optarg, &endptr, 10);
            break;
        case 'F':
            fillmode = strtol(optarg, &endptr, 10);
            break;
        case 'i':
            inlist = optarg;
            break;
        case 's':
            random_scan = false;
            break;
        case 'S':
            seed = strtol(optarg, &endptr, 10);
            break;
        case 'Z':
            testing = false;
            break;
        case 'Q':
            entire = true;
            break;
        case 'n':
            ttl_neighborhood = strtol(optarg, &endptr, 10);
            break;
        case 'v':
            verbose++;
            break;
        case 'o':
            output = optarg;
            break;
        case 'p':
            dstport = strtol(optarg, &endptr, 10);
            break;
        case 'd':
            debug_mode = strtol(optarg, &endptr, 10);
            break;
        case 'r':
            rate = strtol(optarg, &endptr, 10);
            break;
        case 'I':
            int_name = optarg;
            break;
        case 'M':
            dstmac = read_mac(optarg);
            break;
        case 'G':
            srcmac = read_mac(optarg);
            break;
        case 't':
            if (strcmp(optarg, "ICMP6") == 0) {
                ipv6 = true;
                type = TR_ICMP6;
            } else if(strcmp(optarg, "UDP6") == 0) {
                ipv6 = true;
                type = TR_UDP6;
            } else if(strcmp(optarg, "TCP6_SYN") == 0) {
                ipv6 = true;
                type = TR_TCP6_SYN;
            } else if(strcmp(optarg, "TCP6_ACK") == 0) {
                ipv6 = true;
                type = TR_TCP6_ACK;
            } else if(strcmp(optarg, "ICMP") == 0) {
                fatal("ICMP4 unsupported.");
            } else if(strcmp(optarg, "UDP") == 0) {
                type = TR_UDP;
            } else if(strcmp(optarg, "TCP_SYN") == 0) {
                type = TR_TCP_SYN;
            }
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }
    /* set default output file, if not set */
    if (not output) {
        output = (char *) malloc(UINT8_MAX);
        snprintf(output, UINT8_MAX, "output.yrp");
    }
    /* set default destination port based on tracetype, if not set */
    if (not dstport) {
        dstport = 80;
        if ( (type == TR_UDP) || (type == TR_UDP6) )
            dstport = 53;
    }
}

void
YarrpConfig::usage(char *prog) {
    cout << "Usage: " << prog << " [OPTIONS] {target specification}" << endl
    << "OPTIONS:" << endl
    << "  -c, --count             Probes to issue (default: unlimited)" << endl
//    << "  -C, --coarse            Coarse ms timestamps (default: us)" << endl
//    << "  -F, --fillmode        Fillmode past maxttl (default: 0)" << endl
    << "  -r, --rate              Scan rate in pps (default: 10)" << endl
    << "  -s, --sequential        Scan sequentially (default: random)" << endl
    << "  -i, --input             Input target file" << endl
    << "  -o, --output            Output file (default: output.yrp)" << endl
    << "  -v, --verbose           verbose (default: off)" << endl
    << "  -m, --mode              Mode" << endl
    << "  -n, --neighborhood      Neighborhood TTL (default: 0)" << endl
    << "  -b, --bgp               BGP table (default: none)" << endl
    << "  -S, --seed              Seed (default: random)" << endl
    << "  -p, --port              Transport dst port (default: 80)" << endl
    << "  -Z, --real              Send probes (default: test mode)" << endl
//    << "  -Q, --entire            Dangerous (default: off)" << endl
    << "  -I, --interface         Network interface (required for IPv6)" << endl
    << "  -M, --dstmac            MAC of gateway router (default: auto)" << endl
    << "  -G, --srcmac            MAC of probing host (default: auto)" << endl
    << "  -t, --type              Type: TCP_SYN, UDP, ICMP6, UDP6, TCP6_SYN, TCP6_ACK (default: TCP_ACK)" << endl
    << "  -h, --help              Show this message" << endl
    << "TARGET SPECIFICATION:" << endl
    << "  A list of one or more CIDR formatted subnets. " << endl
    << "    Example: 192.168.1.0/24" << endl
    << "             2602:306:8b92:b000::/64" << endl
    << endl;
    exit(-1);
}
