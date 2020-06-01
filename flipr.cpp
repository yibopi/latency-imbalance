#include "flipr.h"

void loop(YarrpConfig *config, Traceroute *trace, Patricia *tree, Stats *stats) {
    struct in_addr target;
    struct in6_addr target6;
    uint8_t ttl;
    TTLHisto *ttlhisto = NULL;
    Status *status = NULL;
    char ptarg[INET6_ADDRSTRLEN];
	Graph graph;
    uint32_t addr;
    double prevTime = 0;
    double initTime = getCurrTime();

    // stats->to_probe = iplist->count();
    while (true) {
		vector<Packet> pkts;
        vector<ip_timestamp> option;
        /* Grab next target/ttl pair from permutation */
        if (!config->ipv6) {
            addr = trace->sch->nextAddr(pkts, option);
            if (addr == 0) break;
        }

        /* Only send probe if destination is in BGP table */
        if (config->bgpfile) {
            status = (Status *) tree->get(target.s_addr);
            if (status) {
                /* RB: remove this more complicated skipping logic for IMC
                tree->matchingPrefix(target.s_addr);
                status->print();
                if (status->shouldProbe() == false) {
                    cout << "BGP Skip: " << inet_ntoa(target) << " TTL: " << (int)ttl << endl;
                    stats->bgp_skipped++;
                    continue;
                }
                */
                status->probed(ttl, trace->elapsed());
            } else {
                stats->bgp_outside++;
                continue;
            }
        }
        /* Passed all checks, continue and send probe */
        if (not config->testing) {
            if (config->ipv6)
                trace->probe(target6, ttl);
            else {
                ip_timestamp *ts = NULL;
                for (int i = 0; i < pkts.size(); i++) {
                    ts = (i < option.size()) ? &option[i] : NULL;
                    trace->setPktParam(pkts[i].sport, pkts[i].dport, pkts[i].ttl, pkts[i].pktType);
					// send the probe	
					trace->probe(addr, htonl(pkts[i].targetip), ts);
					stats->count++;

					/* print sending info */
                    if (config->debug_mode) {
                        printf("SEND: time:%f, ip:%lu, sport:%d, dport:%d, ttl:%d, pktType:%d\n", 
                            getCurrTime(), 
                            (unsigned long) pkts[i].targetip, 
                            pkts[i].sport, 
                            pkts[i].dport, 
                            pkts[i].ttl, 
                            pkts[i].pktType);
                    }
				}
			}
        }

        //    stats->terse();
        if (config->rate) {
            /* Calculate sleep time based on scan rate */
            usleep(1000000 / config->rate);
        }
        /* Quit if we've exceeded probe count from command line */
        if (stats->count == config->count)
            break;
    }
}

int 
main(int argc, char **argv) {
    /* Parse options */
    YarrpConfig config = YarrpConfig();
    config.parse_opts(argc, argv);

    /* Setup IPv6, if using (must be done before trace object) */
    if(config.ipv6) {
        if (config.int_name == NULL) 
            fatal("** IPv6 requires specifying an interface");
        if (config.srcmac == NULL || config.dstmac == NULL) {
            LLResolv *ll = new LLResolv();
            ll->gateway();
            ll->mine(config.int_name);
            ll->setSrcMAC(&config.srcmac);
            ll->setDstMAC(&config.dstmac);
        }
        if (config.entire)
            fatal("** Entire Internet mode unsupported for IPv6");
    }

    /* Initialize traceroute engine, if not in test mode */
    Traceroute *trace = NULL;
    if (not config.testing) {
        checkRoot();
        if (config.ipv6) 
            trace = new Traceroute6(&config);
        else
            trace = new Traceroute4(&config);
    }

    /* Init target list (individual IPs, *NOT* subnets) from input file */
    /*
	IPList *iplist = NULL;
    if (config.inlist) {
      if (config.ipv6) 
        iplist = new IPList6(config.maxttl, config.random_scan);
      else
        iplist = new IPList4(config.maxttl, config.random_scan);
      // randomize permutation key
      iplist->setkey(config.seed);
      iplist->read(config.inlist);
    }
	*/

    /* Initialize subnet list and add subnets from args */
    // SubnetList *subnetlist = NULL;
    // if (not config.entire and not config.inlist) {
    //     if (config.random_scan) 
    //         subnetlist = new RandomSubnetList();
    //     else
    //         subnetlist = new SubnetList();
    //     for (int i = optind; i < argc; i++)
    //         subnetlist->add_subnet(argv[i]);
    //     if (0 == subnetlist->count())
    //         config.usage(argv[0]);
    // }

    /* Initialize radix trie, if using */
    Patricia *tree = NULL;
    if (config.bgpfile) {
        if (config.ipv6)
            fatal("Unsupported");
        cout << ">> Populating trie from BGP: " << config.bgpfile << endl;
        tree = new Patricia(32);
        tree->populateStatus(config.bgpfile);
        if (trace)
            trace->addTree(tree);
        cout << ">> Done.  Populated trie from: " << config.bgpfile << endl;
    }
    if (config.entire and not config.bgpfile) 
        fatal("** Entire Internet mode requires BGP table");

    if (config.testing) 
        fatal("** Done (testing mode).");

    /* Begin work */
    cout << ">> Probing begins." << endl;
    Stats *stats = new Stats();
    trace->addStats(stats);
    if (config.inlist) {
        // Normal mode of operation, using individual IPs from input file -i
        loop(&config, trace, tree, stats);
    } else if (not config.entire) {
        /* Normal mode of operation, using subnets from args */
        if (config.ipv6) 
            fatal("Add support for v6 subnets from args!");
        else
            loop(&config, trace, tree, stats);
    } else {
        /* you better really, really, know what you're doing */
        cout << "** Entire Internet fast mode.  Exit now, " << endl;
        cout << "** or forever hold your peas..." << endl;
        sleep(10);
        // internet(&config, trace, tree, stats);
    } 

    /* wait for any outstanding replies */
    cout << ">> Waiting " << SHUTDOWN_WAIT << "s for outstanding replies..." << endl;
    sleep(SHUTDOWN_WAIT);

    /* Finished, cleanup */
	stats->terse();
    //if (config.output and not config.testing)
    //  stats->dump(trace->out);
    //else 
    stats->dump(stdout);
    delete stats;
	if (trace->sch) delete trace->sch;
    delete trace;
    // if (iplist) delete iplist;
    // if (subnetlist) delete subnetlist;
}
