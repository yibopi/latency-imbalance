#include <set>
#include "scheduler.h"
#include "flipr.h"
#include <time.h>
#include <iomanip>
#include <future>

#define NUM_PKT_TYPE 4
#define NUM_REPEAT 6

#define OUT_RVR_PKT_LB -2
#define OUT_FWD_PKT_LB -1
#define OUT_LATENCY 0
#define OUT_FLOW_NO_LB 1
#define OUT_FLOW_LB 2
#define OUT_LB_REGION 3
#define OUT_ALIAS_RESL 4
#define OUT_LAST_HOP_ROUTER 5
#define OUT_HOPS_REVERSE_PATH 6
#define OUT_FINAL_STATE 7
#define OUT_FIREWALL 8

int numRounds = 0;

pthread_rwlock_t ws_lock;

////////////////////////////////////////

Scheduler::Scheduler(char *in, char *out, int _cap) {
    inlist.open(in);
    outlist.open(out);
    outlist << std::fixed << std::setprecision(2);
    cap = _cap; 
    srand(time(NULL));
}

Scheduler::~Scheduler() {
    inlist.close();
    outlist.close();
}

void
Scheduler::updateHistDB(uint32_t &ip, uint16_t &ipid) {
    histDB[ip].ipid = (ipid) ? true : false;
}

/*
void
PfxState::setAlert(bool _alert) {
    pthread_rwlock_wrlock(&lock);
    alert = _alert;
    pthread_rwlock_unlock(&lock);
}

bool
PfxState::isAlert() {
    pthread_rwlock_rdlock(&lock);
    bool ret = alert;
    pthread_rwlock_rdlock(&lock);
    return ret;
}
*/

double getCurrTime() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec + (double) tv.tv_usec / 1000000;
}

void printFlow(vector<Flow> flows) {
	for (auto &f : flows) {
        if (!f.hops.empty()) {
            cout << f.hops.back().ip << " " << f.hops.back().val << endl;
        } else {
            cout << -1.0 << " " << -1.0 << endl;
        }
    }
	printf("\n");
}

bool 
flowCmp(Flow f1, Flow f2) {
	return f1.hops[0].val < f2.hops[0].val;
}

int 
getMinFlow(vector<Flow> &flows, int low, int high) {
	auto it = min_element(flows.begin() + low, flows.begin() + high, flowCmp);
	return distance(flows.begin(), it);
}

int 
getMaxFlow(vector<Flow> &flows, int low, int high) {
	auto it = max_element(flows.begin() + low, flows.begin() + high, flowCmp);
	return distance(flows.begin(), it);
}

pair<uint32_t, uint32_t>
makeOrderedPair(uint32_t &ip1, uint32_t &ip2) {
    return (ip1 < ip2) ? make_pair(ip1, ip2) : make_pair(ip2, ip1);
}

void 
Scheduler::addToQueue(Task task) {
	taskQueue.push(task);
}

Packet 
singlePkt(uint32_t ip, 
          uint16_t sport, 
          uint16_t dport, 
          uint8_t ttl,
          PKT_TYPE pktType)
{
	return Packet(ip, 0, ttl, pktType, sport, dport);
}

uint16_t randPort(uint16_t minPort, uint16_t maxPort) {
	return rand() % (maxPort - minPort) + minPort;
}

bool
isClose(vector<Flow> &flows, int start, int end) {

    if (end <= start) return true;

    int i = getMaxFlow(flows, start, end);
    int j = getMinFlow(flows, start, end);
    return (flows[i].hops.back().val - flows[j].hops.back().val <= MEAS_ERROR);
}

MSG_TYPE 
Scheduler::pathEnumE2E(uint32_t dst, 
                       IPState *ipState, 
                       int numExplr,
                       PKT_TYPE pktType,
                       vector<Packet> &pkts) 
{
	vector<Flow> &flows = ipState->flows;
    uint8_t ttl;
	uint16_t sport, dport;
	int minTrack, maxTrack;
	int i;

	// if the IP becomes mute during probing
	if (ipState->numProbe > numExplr + MAX_PROBES_SENT) {
		ipState->numProbe = 0;
		return NUM_PROBE_EXCEEDED;
	}

    //printf("numFlow:%d, numProbe:%d\n", flows.size(), ipState->numProbe);

	if (flows.size() < numExplr) {
		sport = randPort(MIN_PORT, MAX_PORT);
		dport = randPort(MIN_PORT, MAX_PORT);
        ttl = UINT8_MAX;
	} else if (flows.size() == numExplr) {
		maxTrack = getMaxFlow(flows, 0, numExplr);
		sport = flows[maxTrack].sport;
	    dport = flows[maxTrack].dport;
        ttl   = flows[maxTrack].fwdttl;
	} else if (flows.size() <= numExplr + NUM_REPEAT_E2E) {
		i = getMinFlow(flows, numExplr, flows.size());
		maxTrack = getMaxFlow(flows, 0, numExplr);

        double error = flows[maxTrack].hops.back().val * 0.01;
		if ((double)flows[maxTrack].hops.back().val > (double)flows[i].hops.back().val + error) {
			flows[maxTrack].hops = flows[i].hops;
			flows.erase(flows.begin() + numExplr, flows.end()); 
            maxTrack = getMaxFlow(flows, 0, numExplr);
        }
		// check if the last max rtt is still the maximum
		/*
        i = getMaxFlow(flows, 0, NUM_E2E_EXPLR);
		if (abs(flows[maxTrack].hops.back().val - flows[i].hops.back().val) > MEAS_ERROR) {
			flows.erase(flows.begin() + NUM_E2E_EXPLR, flows.end()); 
            maxTrack = i;
        }
        // check if repeated measurements are close
        if (!isClose(flows, NUM_E2E_EXPLR, flows.size()))
			flows.erase(flows.begin() + NUM_E2E_EXPLR, flows.end()); 
        */

		if (flows.size() < numExplr + NUM_REPEAT_E2E) {
			sport = flows[maxTrack].sport;
			dport = flows[maxTrack].dport;
            ttl   = flows[maxTrack].fwdttl;
		} else {
			minTrack = getMinFlow(flows, 0, numExplr);
			sport = flows[minTrack].sport;
		    dport = flows[minTrack].dport;
            ttl   = flows[minTrack].fwdttl;
		}
	} else if (flows.size() <= numExplr + 2 * NUM_REPEAT_E2E) {
        // check if repeated measurements are close
        //if (!isClose(flows, numExplr + NUM_REPEAT_E2E, flows.size()))
		//	flows.erase(flows.begin() + numExplr + NUM_REPEAT_E2E, flows.end()); 

        if (flows.size() < numExplr + 2 * NUM_REPEAT_E2E) {
            minTrack = getMinFlow(flows, 0, numExplr);
            sport = flows[minTrack].sport;
            dport = flows[minTrack].dport;
            ttl   = flows[minTrack].fwdttl;
        } else {
            int i = getMinFlow(flows, 
                               numExplr + NUM_REPEAT_E2E, 
                               numExplr + 2 * NUM_REPEAT_E2E);
            minTrack = getMinFlow(flows, 0, numExplr);
            if (flows[minTrack].hops.back().val > flows[i].hops.back().val)
                flows[minTrack] = flows[i];
            // put min in the 1st and max in the 2nd position
            swap(flows[0], flows[minTrack]);
            maxTrack = getMaxFlow(flows, 1, numExplr);
            swap(flows[1], flows[maxTrack]);

            ipState->numProbe = 0;
            return PHASE_DONE;
        }
	}
	pkts = {singlePkt(dst, sport, dport, ttl, pktType)};
	ipState->numProbe++;
	return CONTINUE;
}

/*
int avg(vector<int> nums) {
	int sum = 0, n = 0;
	for (auto &h : nums) {
		sum += h; 
		n++;
	}
	return (double)sum / n;
}

void 
processFlow(IPState *state, vector<Flow> flows, int ref, int flowid) {
	int i, j;
	int numFlow = flows.size();
	int index[numFlow] = {0};
	Flow f(state->flows[flowid].sport, state->flows[flowid].dport);

	for (i = 1; i < flows[ref].hops.size(); i++) {
		vector<int> rtts;
		for (j = 0; j < numFlow; j++) {
			if (flows[j].hops[index[j]].ttl == i) {
				rtts.push_back(flows[j].hops[index[j]].val);	
				index[j]++;
			}
		}
		if (rtts.size() < 3) continue;
		sort(rtts.begin(), rtts.end());
		Hop h(flows[ref].hops[i].ip, flows[ref].hops[i].ttl);
		if (rtts.size() >= NUM_PKTLB_EXPLR - 1 && 
			abs(rtts[NUM_PKTLB_EXPLR - 2] - rtts[0]) <= MEAS_ERROR) 
		{
			h.val = avg(rtts);
		} else {
			h.val = rtts[0];
		}
		f.hops.push_back(h);
	}

	state->flows[flowid] = f;
	state->flows.erase(state->flows.begin() + 2, state->flows.end());
}
*/

vector<Packet> 
hopEnumHelper(uint32_t dst, IPState *state, int index, PKT_TYPE pktType) {
	int i;
	int maxttl;
	uint16_t sport, dport;
	vector<Packet> f;

	maxttl = state->flows[index].fwdttl;   
	sport = state->flows[index].sport;
	dport = state->flows[index].dport;
    // printf("index:%d, maxttl:%d\n", index, maxttl);
	for (i = 1; i < maxttl; i++)
		f.push_back(singlePkt(dst, sport, dport, i, pktType));
	f.push_back(singlePkt(dst, sport, dport, maxttl, pktType));

	return f;
}

MSG_TYPE 
mergeFlow(Flow &f1, Flow &f2) {
    Hop h;
    int index, i, j;
    int nhop1, nhop2;
    vector<Hop> hops;

    i = j = 0;
    nhop1 = f1.hops.size();
    nhop2 = f2.hops.size();
    while (i < nhop1 && j < nhop2) {
        if (f1.hops[i].fwdttl == f2.hops[j].fwdttl) {
            if (f1.hops[i].ip != f2.hops[j].ip)
                return DIFF_FWD_FLOW;
            if (f1.hops[i].ip == f2.hops[j].ip 
                    && f1.hops[i].rvrttl != f2.hops[j].rvrttl) 
            {
                return DIFF_RVR_FLOW;
            }
            h = f1.hops[i];
            h.val = min(f1.hops[i].val, f2.hops[j].val);
            h.cnt++;
            i++; j++;
        } else if (f1.hops[i].fwdttl < f2.hops[j].fwdttl) {
            h = f1.hops[i];
            i++;
        } else {
            h = f2.hops[j];
            j++;
        }
        hops.push_back(h);
    }

    if (i == nhop1) { 
        hops.insert(hops.end(), 
                    f2.hops.begin() + j, 
                    f2.hops.end());
    }

    if (j == nhop2) {
        hops.insert(hops.end(), 
                    f1.hops.begin() + i, 
                    f1.hops.end());
    }

    f1.hops = hops;
    return CONTINUE;
}

MSG_TYPE
Scheduler::pathEnumHop(uint32_t dst, 
                       IPState *ipState, 
                       int measTimes,
                       vector<Packet> &pkts) 
{	
    int index;
    MSG_TYPE msgType;
    vector<Flow> &flows = ipState->flows;

    if (ipState->cnt > 0 && !ipState->recvbuf.empty()) {
        Flow f = ipState->recvbuf[0];
        for (index = 0; index < flows.size(); index++) {
            if (flows[index].sport == f.sport &&
                flows[index].dport == f.dport) {
                break;
            }
        }

        if (index == flows.size()) return PROBE_END;

        msgType = mergeFlow(ipState->flows[index], f);
    }
    
    ipState->recvbuf.clear();

	if (ipState->cnt >= measTimes) {
		//processFlow(ipState, flows, ref, flowid);
        ipState->cnt = 0;
		ipState->ptr++;
    }

	if (ipState->ptr >= flows.size()) {
		ipState->ptr = ipState->cnt = 0;
		return PHASE_DONE;
	}

	pkts = hopEnumHelper(dst, ipState, ipState->ptr, TR_UDP);
	ipState->cnt++;

	return CONTINUE;
}

MSG_TYPE 
Scheduler::pathHopEst(uint32_t dst, 
                      IPState *state, 
                      PKT_TYPE pktType, 
                      vector<Packet> &pkts) 
{
	uint8_t sport, dport;
    Flow *flow;
    int numFlow = state->flows.size(); 
    
    flow = &state->flows[state->ptr];

    // cout << flow->hops.size() << " " << (int)flow->maxttl << " " << state->cnt << endl;
    // if (flow->hops.size())
    //     cout << "ttl:" << (int)flow->hops.back().ttl << endl;

    if (flow->hops.size() != 0 && 
        flow->hops.back().fwdttl == flow->fwdttl + state->cnt) 
    {
        flow->fwdttl += state->cnt;
        if (flow->hops.size() == 1) {
           if (flow->hops.back().ip == dst) {
               flow->fwdttl--;
           } else {
               flow->fwdttl++;
           }
        } else if (flow->hops[0].ip == dst) {
            if (flow->hops.back().ip == dst) {
                flow->fwdttl--;
            } else {
                flow->fwdttl++;
                state->ptr++;
            }
        } else {
            if (flow->hops.back().ip == dst) {
                state->ptr++;
            } else {
                flow->fwdttl++;
            }
        }
        state->numProbe = state->cnt = 0;
    }
   
    if (state->numProbe >= NUM_TRIES_PER_HOP) {
        state->numProbe = 0;
        if (flow->hops.size() == 0 || flow->hops[0].ip != dst) {
            state->cnt++;
        } else {
            flow->fwdttl = flow->hops.back().fwdttl;
            state->cnt = 0;
            state->ptr++;
        }
    }
    
    // use state->cnt to count unresponsive hops
    if (state->cnt >= NUM_UNRESPONSIVE_HOPS || 
        flow->fwdttl + state->cnt > MAX_HOPS) 
    {
        state->cnt = state->numProbe = 0;
        state->ptr++;
    }

    if (state->ptr >= numFlow) {
        state->ptr = 0;
        state->cnt = state->numProbe = 0;
        return PHASE_DONE;
    }

    flow = &state->flows[state->ptr];
    pkts = {singlePkt(dst, 
                      flow->sport, 
                      flow->dport, 
                      flow->fwdttl + state->cnt,
                      pktType)};	
    state->numProbe++;
 
    return CONTINUE;
}

void Scheduler::populateTaskQueue() {

	static int ipCount = 0;
	static in_addr addr;
	uint32_t target;
	string line;
    double startTime;

	while (true) {
        if (taskQueue.size() >= cap) break;

        getline(inlist, line);
        if (line.empty()) { return; }

		assert(inet_aton(line.c_str(), &addr) == 1);
		target = ntohl(addr.s_addr);
        
        // lock
        pthread_rwlock_wrlock(&gLock);

		if (inBlacklist(target) > 0) continue;

        if (ipStateDB.count(target) == 0) {
			double startTime = getCurrTime() + ((double)rand() / RAND_MAX) * UDP_FREEZE_TIME;
			ipStateDB[target] = IPState();
            taskQueue.push(Task(target, startTime));
        }

        pthread_rwlock_unlock(&gLock);
        
    	ipCount++;
    	if (ipCount % 1000 == 0)
    		fprintf(stderr, "populateTaskQueue(): Number of IPs probed: %d\n", ipCount);
    }

	return;
}


bool sameFlow(Flow &f1, Flow &f2) {
	int i = 0, j = 0;
	while (i < f1.hops.size() && j < f2.hops.size()) {
		if (f1.hops[i].fwdttl == f2.hops[j].fwdttl) {
			if (f1.hops[i].ip != f2.hops[j].ip) return false;
			i++; j++;
		} else if (f1.hops[i].fwdttl < f2.hops[j].fwdttl) { 
			i++;
		} else { j++; }
	}
	return true;
}

int getFlowRef(vector<Flow> &flows) {
	int i, flowid = 0;
	for (i = 1; i < flows.size(); i++)
		if (flows[i].hops.size() > flows[flowid].hops.size())
			flowid = i;
	return flowid;
}


MSG_TYPE
Scheduler::chkResponse(uint32_t ip, 
                       IPState *ipState, 
                       int numType,
                       PKT_TYPE pktType,
                       vector<Packet> &pkts) 
{
    uint16_t sport, dport;

    // to be modified
    if (ipState->numProbe > 10) {
        ipState->numProbe = ipState->cnt = 0;
        return PROBE_END;
    }

    if (ipState->cnt > ipState->flows.size()) {
        ipState->cnt = 0;
        ipState->flows.clear();
        return NO_RESPONSE;
    }

    if (ipState->cnt < numType) {
    	sport = randPort(MIN_PORT, MAX_PORT);
		dport = randPort(MIN_PORT, MAX_PORT);
        pkts = {singlePkt(ip, sport, dport, UINT8_MAX, pktType)};
    	ipState->cnt++;
        ipState->numProbe++;
        return CONTINUE;
    }

    ipState->cnt = ipState->numProbe = 0;
    ipState->flows.clear();
    return PHASE_DONE;
}

void
logLBReg(uint32_t id, 
         IPState *ipState, 
         int16_t totalRange, 
         vector<LBReg> &lbRegs, 
         ofstream &outlist) 
{
    int rangeE2E = -1;
    vector<Flow> &flows = ipState->flows;
    uint32_t dst = (ipState->lastHopRouter) ? ipState->lastHopRouter : id;

    if (flows.size() == 2 && (!flows[0].hops.empty() && !flows[1].hops.empty()) &&
        flows[0].hops.back().ip == dst && flows[1].hops.back().ip == dst)
    {
        rangeE2E = flows[1].hops.back().val - flows[0].hops.back().val;     
    }
    outlist << fixed << numRounds << " " << id << " " << OUT_LB_REGION << " ";
    outlist << getCurrTime() << " " << rangeE2E << " " << totalRange << " ";
    for (int i = 0; i < lbRegs.size(); i++) {
        outlist << lbRegs[i].start.ip << " " << lbRegs[i].end.ip << " " 
                << lbRegs[i].start.val <<  " " << lbRegs[i].end.val << " "
                << lbRegs[i].link.val << " " << lbRegs[i].link.type << " ";
    }
    outlist << endl;
}

struct ThreadInput {
   ofstream &outlist;
   uint32_t ip;
   vector<Flow> flows;
   ThreadInput(ofstream &out, uint32_t _ip, vector<Flow> f): 
       outlist(out), ip(_ip), flows(f) {}
};

/*
void *procLBRegs(void *in) {
    Graph graph;
	vector<LBReg> lbRegs;
    int16_t totalRange;
    ThreadInput *param = (ThreadInput *)in;

	lbRegs = graph.findLBReg(param->flows);
    totalRange = graph.calcLBRegDiff(param->flows, lbRegs);
    write(param->outlist, param->ip, param->flows, totalRange, lbRegs); 
    delete param;
    pthread_exit(NULL);
}
*/

// MSG_TYPE
// pathEnumE2EVar(uint32_t id, IPState *ipState, vector<Flow> &pkts)
// {
// 	vector<Flow> &flows = ipState->flows;
// 	uint16_t sport, dport;
// 	int minTrack, maxTrack;
// 	int i;

// 	// if the IP becomes mute during probing
// 	if (ipState->numProbe > NUM_FLOWS_E2E + MAX_PROBES_SENT) {
// 		ipState->ptr = ipState->numProbe = 0;
// 		return NUM_PROBE_EXCEEDED;
// 	}

//     // printf("numFlow:%d, numProbe:%d\n", flows.size(), ipState->numProbe);

// 	if (flows.size() <= NUM_FLOWS_E2E + NUM_REPEAT_E2E) {
//    	    // check if repeated measurements are close
//         if (!isClose(flows, NUM_FLOWS_E2E, flows.size()))
// 			flows.erase(flows.begin() + NUM_FLOWS_E2E, flows.end()); 

//         if (flows.size() < NUM_FLOWS_E2E + NUM_REPEAT_E2E) {
//             sport = flows[0].sport;
//             dport = flows[0].dport;
//         } else {
//             sport = flows[1].sport;
//             dport = flows[1].dport;
//         }
// 	} else if (flows.size() <= NUM_FLOWS_E2E + 2 * NUM_REPEAT_E2E) {
//    	    // check if repeated measurements are close
//         if (!isClose(flows, NUM_FLOWS_E2E + NUM_REPEAT_E2E, flows.size()))
// 			flows.erase(flows.begin() + NUM_FLOWS_E2E + NUM_REPEAT_E2E, flows.end()); 

//         if (flows.size() < NUM_FLOWS_E2E + 2 * NUM_REPEAT_E2E) {
// 	        sport = flows[1].sport;
// 	        dport = flows[1].dport;
// 	    } else if (flows.size() == NUM_FLOWS_E2E + 2 * NUM_REPEAT_E2E) {
//             int i = getMinFlow(flows, 
//                                NUM_FLOWS_E2E, 
//                                NUM_FLOWS_E2E + NUM_REPEAT_E2E);
//             flows[0] = flows[i];

//             i = getMinFlow(flows, 
//                            NUM_FLOWS_E2E + NUM_REPEAT_E2E, 
//                            NUM_FLOWS_E2E + 2 * NUM_REPEAT_E2E);
//             flows[1] = flows[i];
            
//             flows.erase(flows.begin() + 2, flows.end());

//             ipState->numProbe = 0;
//             return PHASE_DONE;
//         }
// 	}
// 	pkts = {singlePkt(id, sport, dport, UINT8_MAX)};
// 	ipState->numProbe++;
// 	return CONTINUE;
// }

// MSG_TYPE
// Scheduler::flowEnumE2E(uint32_t id,
//                        IPState *ipState,
//                        vector<Flow> &pkts,
//                        int numFlow)
// {
// 	vector<Flow> &flows = ipState->flows;
// 	uint16_t sport, dport;
// 	int i;

// 	// if the IP becomes mute during probing
// 	if (ipState->numProbe > 300) {
// 		ipState->ptr = ipState->numProbe = 0;
// 		return PHASE_DONE;
// 	}

//     for (i = 0; i < 2; i++) {
//         for (auto &f: ipState->flows) {
//             sport = f.sport;
//             dport = f.dport;
//             pkts.push_back(singlePkt(id, sport, dport, UINT8_MAX));
//         }
//     }

// 	ipState->numProbe++;
// 	return CONTINUE;
// }

// MSG_TYPE
// generateFlows(uint32_t id,
//               IPState *ipState,
//               vector<Flow> &pkts,
//               int numFlow)
// {
//     uint16_t sport, dport;
// 	vector<Flow> &flows = ipState->flows;
    
//     //printf("numFlows:%d, numProbe:%d\n", flows.size(), ipState->numProbe);

// 	// if the IP becomes mute during probing
// 	if (ipState->numProbe > numFlow + MAX_PROBES_SENT) {
// 		ipState->numProbe = 0;
// 		return NUM_PROBE_EXCEEDED;
// 	}

//     if (flows.size() >= numFlow) {
//         if (flows.size() > numFlow) {
//             flows.erase(flows.begin() + numFlow, flows.end());
//         }
//         ipState->numProbe = 0;
//         return PHASE_DONE;
//     }
    	
//     sport = randPort(MIN_PORT, MAX_PORT);
// 	dport = randPort(MIN_PORT, MAX_PORT);
// 	pkts = {singlePkt(id, sport, dport, UINT8_MAX)};
 
//     ipState->numProbe++;

//     return CONTINUE;
// }

// MSG_TYPE
// Scheduler::delayVarRel(IPState *ipState, 
//                        PfxState *state, 
//                        uint32_t &id,
//                        vector<Flow> &pkts, 
//                        PKT_TYPE &pktType)
// {
//     int i;
//     MSG_TYPE msgType;
//     uint32_t pfx = IP2Pfx(id);

//     if (alertDB.count(pfx) > 0) return PROBE_END;

//     if (ipState->task == CHK_RESPONSE) {
//         msgType = chkResponse(id, ipState, pkts, 1);
//         if (msgType == NO_RESPONSE) {
//             // remove from ip2id
//             ip2id.erase(id);
//         } else if (msgType == PHASE_DONE) {
// 			addToQueue(IPTask(id, 0));
// 			ipState->task = PATH_ENUM_E2E;
//         } else if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, UDP_FREEZE_TIME));
//         }
//     } else if (ipState->task == PATH_ENUM_E2E) {
// 		msgType = pathEnumE2E(id, ipState, pkts, 10);
// 		if (msgType == PHASE_DONE) {
// 			ipState->flows[0].hops.clear();
//             ipState->flows[1].hops.clear();    
//             ipState->flows.erase(ipState->flows.begin() + 2, ipState->flows.end());
//             addToQueue(IPTask(id, 0));
//             ipState->task = FLOW_ENUM_E2E;
// 		}
//         if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, UDP_FREEZE_TIME));
//             pktType = TR_UDP;
// 		}
//     /*
//     } else if (ipState->task == GENERATE_FLOWS) {
//         msgType = generateFlows(id, ipState, pkts, 20);
//         if (msgType == PHASE_DONE) {
//             vector<int> rtts, sorted_rtts;
//             for (auto &f : ipState->flows)
//                 rtts.push_back(f.hops.back().val);
//             sorted_rtts = rtts;
//             sort(sorted_rtts.begin(), sorted_rtts.end());
//             int minVal, maxVal, median; 
//             minVal= sorted_rtts[0];
//             maxVal = sorted_rtts.back();
//             median = sorted_rtts[sorted_rtts.size()/2];

//             int medianIndex, minIndex, maxIndex;
//             minIndex = distance(rtts.begin(), find(rtts.begin(), rtts.end(), minVal));
//             maxIndex = distance(rtts.begin(), find(rtts.begin(), rtts.end(), maxVal));
//             medianIndex = distance(rtts.begin(), find(rtts.begin(), rtts.end(), median));

//             vector<Flow> flows;
//             for (i = 0; i < ipState->flows.size(); i++) {
//                 if (i == minIndex || i == maxIndex || i == medianIndex)
//                     flows.push_back(ipState->flows[i]);
//             }
//             ipState->flows = flows;

//             addToQueue(IPTask(id, 0));
//             ipState->task = FLOW_ENUM_E2E;
//         } else if (msgType == CONTINUE) {
//             addToQueue(IPTask(id, UDP_FREEZE_TIME));
//         }
//     */
//     } else if (ipState->task == FLOW_ENUM_E2E) {
//         msgType = flowEnumE2E(id, ipState, pkts, 2);
//         if (msgType == PHASE_DONE) {
//             ipState->flows.clear();
//             msgType = PROBE_END;
//         } else if (msgType == CONTINUE) {
//             for (i = 0; i < 2; i++) {
//                 if (ipState->flows[i].hops.size() > 0) {
//                     outlist << id << " " << i << " " << fixed << getCurrTime() << " ";
//                     for (auto &h : ipState->flows[i].hops)
//                         outlist << h.val << " ";
//                     outlist << endl;
//                     ipState->flows[i].hops.clear();
//                 }
//             }
  
//             addToQueue(IPTask(id, UDP_FREEZE_TIME));
//         }
//     }
        
//     pktType = TR_UDP;
// }

// MSG_TYPE
// Scheduler::endToEndScan(IPState *ipState, 
//                         PfxState *state, 
//                         uint32_t &id, 
//                         vector<Flow> &pkts,
//                         PKT_TYPE &pktType) 
// {
//     int i;
//     uint32_t newid;
//     MSG_TYPE msgType;
    
//     //printf("task:%d\n", ipState->task);

//     if (state->alert) return PROBE_END;

//     if (ipState->task == CHK_RESPONSE) {
//         msgType = chkResponse(id, ipState, pkts, 1);
//         if (msgType == NO_RESPONSE) {
//             newid = MIN(id + 4, IP2Pfx(id) + UINT8_MAX);
//             i = findIPLocPfx(state, newid);
//             if (id - IP2Pfx(id) == UINT8_MAX || i != -1) {
//                 return NO_RESPONSE;
//             }
//             ip2id.erase(id);
//             i = findIPLocPfx(state, id);
//             id = newid;
//             ipState->ptr = 0;
//             state->IPMap[i].first = id - IP2Pfx(id);
//             msgType = chkResponse(id, ipState, pkts, 1);
//         } else if (msgType == PHASE_DONE) {
//             if (ipState->ptr == 0) {
//                 ipState->ptr++;
//                 msgType = chkResponse(id, ipState, pkts, 1);
//             } else {
//                 ipState->ptr = 0;
//                 ipState->task = PATH_ENUM_E2E;
//                 addToQueue(IPTask(id, 0));
//             }
//         }
//         if (msgType == CONTINUE) {
//             if (ipState->ptr == 0) {
// 			    addToQueue(IPTask(id, TCP_FREEZE_TIME));
//                 pktType = TR_TCP_ACK;
//             } else {
// 			    addToQueue(IPTask(id, UDP_FREEZE_TIME));
//                 pktType = TR_UDP;
//             }
//         }
//     } else if (ipState->task == PATH_ENUM_E2E) {
//         if (ipState->ptr == 0) {
// 		    msgType = pathEnumE2E(id, ipState, pkts, NUM_E2E_EXPLR);
//         } else {
// 		    msgType = pathEnumE2E(id, ipState, pkts, NUM_E2E_EXPLR);
//         }
// 		if (msgType == PHASE_DONE) {
// 			int maxRTT = ipState->flows[1].hops.back().val;
//             outlist << id << " " << (int)ipState->ptr << " ";
//             for (int i = 0; i < NUM_E2E_EXPLR; i++)
//                 outlist << (int)ipState->flows[i].hops.back().val << " ";
//             outlist << endl;
//             if (ipState->ptr == 0) {
//                 ipState->ptr++;
//                 ipState->flows.clear(), 
//                 msgType = CONTINUE;
//             } else {
//                 ipState->ptr = 0;
// 			    ipState->flows[0].hops.clear();
//                 ipState->flows[1].hops.clear();    
//                 ipState->flows.erase(ipState->flows.begin() + 2, ipState->flows.end());
//                 addToQueue(IPTask(id, 0));
//                 ipState->task = PATH_HOP_EST;
//             }
// 		}
//         if (msgType == CONTINUE) {
//             if (ipState->ptr == 0) {
// 			    addToQueue(IPTask(id, TCP_FREEZE_TIME));
//                 pktType = TR_TCP_ACK;
//             } else {
// 			    addToQueue(IPTask(id, UDP_FREEZE_TIME));
//                 pktType = TR_UDP;
//             }
// 		}
//     } else if (ipState->task == PATH_HOP_EST) {
// 		msgType = pathHopEst(id, ipState, pkts);
// 		if (msgType == PHASE_DONE) {
//             ipState->flows[0].hops.clear();
//             ipState->flows[1].hops.clear();
// 			addToQueue(IPTask(id, 0));
// 			ipState->task = PATH_ENUM_HOP;
// 		} else if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, UDP_FREEZE_TIME));
// 		}
//         pktType = TR_UDP;
// 	} else if (ipState->task == PATH_ENUM_HOP) {
// 		msgType = pathEnumHop(id, ipState, 5, pkts);
// 		if (msgType == PHASE_DONE) {
// 			addToQueue(IPTask(id, 0));
// 			ipState->task = CHK_LB;
// 		} else if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, UDP_FREEZE_TIME));
// 		}
//         pktType = TR_UDP;
//     } else if (ipState->task == CHK_LB) {
//         //for (int i = 0; i < 2; i++) {
//         //    printf("id:%lu, no:%d ", id, i);
//         //    for (int j = 0; j < ipState->flows[i].hops.size(); j++) {
//         //        printf("%lu ", ipState->flows[i].hops[j].ip);
//         //    }
//         //    printf("\n");
//         //}
//         Graph graph;
//         vector<LBReg> lbRegs;
//         //int16_t totalRange = 1;
//         LINK_TYPE linkType = CMPL_SINGLE_PATH;
//         lbRegs = graph.findLBReg(id, ipState->flows, NULL);
//         //totalRange = graph.calcLBRegDiff(ipState->flows, lbRegs);

//         for (auto lb : lbRegs) {
//             if (isMultiPath(lb)) {
//                 linkType = lb.link.type;
//                 break;
//             } else if (lb.link.type == INCMPL_SINGLE_PATH) {
//                 linkType = lb.link.type;
//             }
//         }
//         outlist << id << " " << 3 << " " << linkType << endl;
//         msgType = PROBE_END;
//     }
//     // To do: remove data from the structure
//     return msgType;
// }

MSG_TYPE
detectLB(uint32_t dst, 
         IPState *ipState, 
         int numFlow, 
         vector<Packet> &pkts) 
{
    if (ipState->ptr > 0 && !ipState->recvbuf.empty()) {
        mergeFlow(ipState->flows[ipState->ptr-1], ipState->recvbuf[0]);
    }

    ipState->recvbuf.clear();

	if (ipState->ptr >= numFlow) {
		ipState->ptr = 0;
		return PHASE_DONE;
	}

	pkts = hopEnumHelper(dst, ipState, ipState->ptr, TR_UDP);
	ipState->ptr++;

	return CONTINUE;
}

#define ALIAS_TEST_EXEMPT 0
#define ALIAS_IN_PROGRESS 1
#define ALIAS_IPID_TEST 2
#define ALIAS_IPOPT_TEST 3
#define ALIAS_TEST_FAILED 4
#define IP_ID_SAME_ROUTER 5
#define IP_ID_DIFF_ROUTER 6
#define IP_OPTION_SAME_ROUTER 7
#define IP_OPTION_DIFF_ROUTER 8

template <typename T>
MSG_TYPE
genProbeSeq(uint32_t id, 
            vector<Flow> &flows, 
            vector<LBReg> &lbRegs,
            T &aliasDB) 
{
    int i, j;
    Flow f;
    Graph graph;
    vector<Flow> fs;

    fs = flows;
    for (auto &lb : lbRegs) {

        // if (lb.link.type != CMPL_MULTI_PATH) continue;

        vector<vector<Hop>> subpaths;

        for (i = 0; i < flows.size(); i++) {
            vector<Hop> subpath;
            bool start = false, end = false;
            for (auto hop : fs[i].hops) {
                if (hop.ip == lb.start.ip)
                    start = true;
                if (hop.ip == lb.end.ip)
                    end = true;
                hop.cnt = i;
                if (start) subpath.push_back(hop);
                if (end) break;
            }

            if (!start || !end) continue;
            if (subpathExist(subpath, subpaths)) continue;
            subpaths.push_back(subpath);
            
            /*
            if (flows[i].hops.size() == 0 || 
                flows[i].hops.back().ip != subpath.front().ip) 
            {
                flows[i].hops.push_back(subpath.front());
                flows[i].hops.push_back(subpath.back());
            } else if (flows[i].hops.back().ip == subpath.front().ip) {
                flows[i].hops.push_back(subpath.back());
            }
            */
        }

        if (subpaths.empty()) continue;
        if (subpaths.size() < 2) {
            // cout << "lbreg:" << id << " " << lb.start.ip << " " << lb.end.ip << endl;
            // cout << "subpath size:" << subpaths.size() << endl;
            for (auto &f : flows) {
                for (auto &h : f.hops) {
                    // cout << h.ip << " " << (int)h.fwdttl << " ";
                }
                // cout << endl;
            }
            continue;
        }

        Hop h1, h2;
        pair<uint32_t, uint32_t> intfpair;
        for (i = 1; i < subpaths[0].size() - 1; i++) {
            for (j = 1; j < subpaths[1].size() - 1; j++) {
                h1 = subpaths[0][i];
                h2 = subpaths[1][j];

                intfpair = makeOrderedPair(h1.ip, h2.ip);
                if (aliasDB.count(intfpair) > 0 && aliasDB[intfpair] >= NUM_ALIAS_RESL)
                    continue;

                // control the number of alias resl
                if (aliasDB.count(intfpair) == 0) {
                    aliasDB[intfpair] = 1;
                } else {
                    aliasDB[intfpair]++;
                }

                h1.val = h2.val = ALIAS_IPID_TEST; 
                f.hops.push_back(h1);
                f.hops.push_back(h2);
                f.hops.push_back(Hop(0, 0));
            }
        }
    }

    if (f.hops.size() == 0) return PROBE_END;
    
    flows.push_back(f);
    return CONTINUE;
}

// MSG_TYPE
// cmmLBReg(uint32_t id, vector<Flow> &flows) 
// {
//     if (flows.size() < 2) return UNKNOWN_PATH;

//     int i;
//     Flow f;
//     Graph graph;
//     vector<Flow> fs;
//     vector<LBReg> lbRegs;

//     // to be modified to accommodate more flows
//     lbRegs = graph.findLBReg(id, flows, NULL);

//     bool multipath = false;
//     for (auto &lb : lbRegs) {
//        if (isMultiPath(lb)) multipath = true; 
//     }
//     if (!multipath) return SINGLE_PATH;

//     /*
//     for (i = 0; i < flows.size(); i++)
//         flows[i].hops.clear();
//     */
//     fs = flows;
//     for (auto &lb : lbRegs) {

//         if (!isMultiPath(lb)) continue;

//         vector<vector<Hop>> subpaths;

//         for (i = 0; i < flows.size(); i++) {
//             vector<Hop> subpath;
//             bool start = false, end = false;
//             for (auto hop : fs[i].hops) {
//                 if (hop.ip == lb.start.ip)
//                     start = true;
//                 if (hop.ip == lb.end.ip)
//                     end = true;
//                 hop.cnt = i;
//                 if (start) subpath.push_back(hop);
//                 if (end) break;
//             }

//             if (!start || !end) continue;
//             if (subpathExist(subpath, subpaths)) continue;
//             subpaths.push_back(subpath);
            
//             /*
//             if (flows[i].hops.size() == 0 || 
//                 flows[i].hops.back().ip != subpath.front().ip) 
//             {
//                 flows[i].hops.push_back(subpath.front());
//                 flows[i].hops.push_back(subpath.back());
//             } else if (flows[i].hops.back().ip == subpath.front().ip) {
//                 flows[i].hops.push_back(subpath.back());
//             }
//             */
//         }

//         if (subpaths.empty()) continue;

//         // check if the lengths of subpaths are equal
//         int len = subpaths[0].back().fwdttl - subpaths[0].front().fwdttl;
//         int type = ALIAS_IPID_TEST;
//         for (i = 1; i < subpaths.size(); i++) {
//             int ttl = subpaths[i].back().fwdttl - subpaths[i].front().fwdttl;
//             if (len != ttl) {
//                 type = ALIAS_RES_DIFF_ROUTER;
//                 break;
//             }
//         }

//         i = 0;
//         bool endOfPath;
//         while (true) {
//             Flow oldf = f;
//             endOfPath = true;
//             for (auto s : subpaths) {
//                 for (auto &h : s) {
//                     if (h.fwdttl - s[0].fwdttl >= i)
//                         endOfPath = false; 
//                     if (h.fwdttl - s[0].fwdttl != i) 
//                         continue;
//                     if (f.hops.empty() || f.hops.back().ip != h.ip) {
//                         h.val = type;
//                         f.hops.push_back(h);
//                     }
//                 }
//             }

//             if (type == ALIAS_IPID_TEST &&
//                 f.hops.size() - oldf.hops.size() == 1) 
//             {
//                 f.hops.back().val = ALIAS_TEST_EXEMPT;
//             }

//             if (endOfPath) break;
//             i++;
//         }

//         // only the first LB region will be monitored
//         f.hops.push_back(Hop(0, 0));
//     }

//     flows.push_back(f);

//     /*
//     outlist << fixed;
//     outlist << 1 << " " << id << " ";
//     for (auto &lb : lbRegs) {
//         if (lb.link.type != CMPL_MULTI_PATH) continue;
//         outlist << lb.start.ip << " " << lb.end.ip << " ";
//     }
//     outlist << endl;
//     */

//     return CONTINUE;
// }

void
setVal(Flow &f, uint32_t ip, int val) {
    for (auto &h : f.hops) {
        if (h.ip == ip) {
            h.rvrttl = val;
        }
    }
}

void
setVal(Flow &f, uint32_t ip1, uint32_t ip2, int val) {
    for (int i = 0; i < f.hops.size() - 1; i++) {
        if ((f.hops[i].ip == ip1 && f.hops[i+1].ip == ip2)
                || (f.hops[i].ip == ip2 && f.hops[i+1].ip == ip1)) 
        {
            f.hops[i].val = f.hops[i+1].val = val;
        }
    }
}

void
setRvrTTL(Flow &dflow, vector<Flow> flows) {
    int i;
    unordered_set<int> s;

    for (auto &f : flows) {
        s.insert(f.hops.back().ip);
    }

    unordered_map<uint32_t, vector<int>> ttls;
    
    for (i = 0; i < flows.size(); i++) {
        Hop &h = flows[i].hops[0];
        ttls[h.ip].push_back(flows[i].rvrttl);
    }

    for (auto it = ttls.begin(); it != ttls.end(); it++) {
        
        if (it->second.size() < 5)
            continue;

        unordered_set<int> s(it->second.begin(), it->second.end());
        if (s.size() == 1) {
            setVal(dflow, it->first, *s.begin());
        }
    }

    return;
}

uint8_t
getRvrTTL(Flow &f, uint32_t ip) {
    for (auto &h : f.hops) {
        if (h.ip == ip)
            return h.rvrttl;  // rvr ttl
    }
    return 0;
}
        
bool
zeroIpId(vector<Flow> &flows, uint32_t &ip) {
    for (auto &f : flows) {
        if (f.hops.back().ip == ip)
            return f.hops.back().val == 0;
    }
    return true;
}


MSG_TYPE
Scheduler::aliasReslIpId(uint32_t id, 
                         IPState *ipState, 
                         vector<Packet> &pkts)
{
    int i, j, index;
    uint16_t sport, dport;
    Flow &dflow = ipState->flows.back();
    int numHop = dflow.hops.size();

    if (ipState->ptr >= dflow.hops.size()) {
        ipState->numProbe = 0;
        ipState->ptr = ipState->cnt = 0;
        return PHASE_DONE;
    }

    if (ipState->numProbe == 2) {
        // cout << "sending the third packet" << endl;
        for (i = 0; i < 3; i++) {
            pkts.push_back(singlePkt(id,
                                    ipState->recvbuf[0].sport,
                                    ipState->recvbuf[0].dport,
                                    ipState->recvbuf[0].hops[0].fwdttl,
                                    TR_UDP));
        }
        ipState->numProbe = 3;
        return NO_ACTION;
    }

    if (ipState->ptr > 0) {
        int type = ALIAS_IPOPT_TEST;
        int minipid = INT_MAX, maxipid = INT_MIN;
        uint32_t ip;

        int cntIpId = 0;
        int numIPs = ipState->ptr - ipState->cnt;

        if (ipState->numProbe == 1 ||
            ipState->recvbuf[0].hops[0].ip != ipState->recvbuf.back().hops[0].ip) {
            // didn't receive responses from both addresses
            // go to IP OPTION
            // cout << "didn't receive the complete sequence" << endl;
        } else {
            ip = ipState->recvbuf[0].hops.back().ip;
            for (i = ipState->cnt; i < ipState->ptr; i++) {
                uint32_t routerip = dflow.hops[i].ip;
                if ((histDB.count(routerip) > 0 && histDB[routerip].ipid) || !zeroIpId(ipState->recvbuf, routerip)) {
                    cntIpId++;
                }
            }
        }

        // if no zeros, determine if ipids are equal
        if (cntIpId == numIPs) {
            type = IP_ID_SAME_ROUTER;
            for (i = 0; i < ipState->recvbuf.size(); i++) {
                Hop h = ipState->recvbuf[i].hops.back();
                if (h.ip == ip) {
                    if ((int)h.val < minipid)
                        minipid = h.val;
                    if ((int)h.val > maxipid) 
                        maxipid = h.val;
                }
            }
            for (i = 0; i < ipState->recvbuf.size(); i++) {
                Hop h = ipState->recvbuf[i].hops.back();
                if (h.ip != ip) {
                    if (h.val < minipid || h.val > maxipid) {
                        type = IP_ID_DIFF_ROUTER;
                        break;
                    }
                }
            }
        // if partial zeros, not from the same router
        } else if (cntIpId > 0) {
            type = IP_ID_DIFF_ROUTER;
        }

        // cout << "cntIpIds:" << cntIpId << " " << numIPs << " " << type << endl;

        // if all zeros, ip option opted in
        for (i = ipState->cnt; i < ipState->ptr; i++)
            dflow.hops[i].val = type;

        // get reverse path length from routers
        // setRvrTTL(dflow, ipState->recvbuf);

        // printFlow(ipState->recvbuf);
    }

    int ptr1 = -1, ptr2 = -1;
    for (i = ipState->ptr; i < numHop; i++) {
        if (dflow.hops[i].val == ALIAS_IPID_TEST) {
            ptr1 = ptr2 = i;
            break;
        }
    }
    if (ptr1 == -1) {
        ipState->numProbe = 0;
        ipState->ptr = ipState->cnt = 0;
        return PHASE_DONE;
    }

    for (i = ptr1+1; i < numHop; i++) {

        if (dflow.hops[i].ip != 0) {
            ptr2 = i;
            continue;
        }

        if (ptr2 - ptr1 > 0) {

            ipState->numProbe = 1;

            //cout << "checking " << ptr1 << " to " << ptr2 << endl;

            // check if all routers have ipid
            bool sendProbe = true;
            for (j = ptr1; j <= ptr2; j++) {
                if (histDB.count(dflow.hops[j].ip) > 0) {
                    sendProbe &= histDB[dflow.hops[j].ip].ipid;
                    // cout << dflow.hops[j].ip << " " << histDB[dflow.hops[j].ip].ipid << " ";
                }
            }
            //cout << " send:" << sendProbe << endl;
            if (!sendProbe) break;

            // send twice to avoid packet loss
            index = dflow.hops[ptr1].cnt;
            sport = ipState->flows[index].sport;
            dport = ipState->flows[index].dport;
            for (j = 0; j < 3; j++) {
                pkts.push_back(singlePkt(id,
                                        sport,
                                        dport,
                                        dflow.hops[ptr1].fwdttl,
                                        TR_UDP));
            }
            for (j = 0; j < 3; j++) {
                index = dflow.hops[ptr2].cnt;
                int srcport = ipState->flows[index].sport;
                int dstport = ipState->flows[index].dport;
                pkts.push_back(singlePkt(id,
                                        srcport,
                                        dstport,
                                        dflow.hops[ptr2].fwdttl,
                                        TR_UDP));
            }

            // change test status for hops
            //for (j = ptr1; j <= ptr2; j++)
            //    dflow.hops[j].val = ALIAS_IN_PROGRESS;

            break;
        }
        ptr1 = ptr2 = i;
    }

    ipState->cnt = ptr1; 
    ipState->ptr = i;

    ipState->recvbuf.clear();
    return CONTINUE;
}

ip_timestamp
assembleOptTs(uint32_t ip1, uint32_t ip2) {
    ip_timestamp ts;

    memset(&ts, 0, sizeof(ip_timestamp));
    ts.ipt_code = IPOPT_TS;
    ts.ipt_len  = 36;
    ts.ipt_ptr  = 4 + 1;
    ts.ipt_flg  = IPOPT_TS_PRESPEC;
    for (int i = 0; i < 2; i++) {
        ts.data[4*i] = htonl(ip1);
        ts.data[4*i+2] = htonl(ip2);
    }
    return ts;
}

MSG_TYPE
aliasReslOpt(uint32_t id, 
             IPState *ipState, 
             vector<Packet> &pkts, 
             vector<ip_timestamp> &opt) 
{
    int i, j;
    Flow &dflow = ipState->flows.back();
    int numHop = dflow.hops.size();

    if (ipState->ptr >= numHop) {
        ipState->ptr = ipState->cnt = 0;
        return PROBE_END;
    }

    if (ipState->ptr > 0) {
        // separate flows
        // vector<Flow> optFlow, ttlFlow;
        // for (auto &f : ipState->recvbuf) {
        //     if (f.hops.size() == 8) {
        //         optFlow.push_back(f);
        //     } else {
        //         ttlFlow.push_back(f);
        //     }
        // }

        // determine rvr path length
        // setRvrTTL(dflow, ttlFlow);

        for (i = 0; i < ipState->recvbuf.size(); i++) {
            int cntZeros = 0;
            vector<Hop> &hops = ipState->recvbuf[i].hops;
            for (j = 0; j < 4; j++) {
                if (hops[2*j+1].ip == 0)
                    cntZeros++;
            }
            uint8_t ttl1 = getRvrTTL(dflow, hops[0].ip);
            uint8_t ttl2 = getRvrTTL(dflow, hops[2].ip);
            // cout << "Zeros:" << cntZeros << " ttl:" << (int)ttl1 << " " << (int)ttl2 << " ";
            if (cntZeros == 0) {
                // cout << "Opt:" << ALIAS_RES_SAME_ROUTER << endl;
                setVal(dflow, hops[0].ip, hops[2].ip, IP_OPTION_SAME_ROUTER);
            } else if (ttl1 == 0 || ttl2 == 0) {
            } else if (cntZeros <= 2 && ttl1 == ttl2) {
                // cout << "Opt:" << ALIAS_RES_SAME_ROUTER << endl;
                setVal(dflow, hops[0].ip, hops[2].ip, IP_OPTION_SAME_ROUTER);
            } else if (ttl1 != ttl2) {
                // cout << "Opt:" << ALIAS_RES_DIFF_ROUTER << endl;
                setVal(dflow, hops[0].ip, hops[2].ip, IP_OPTION_DIFF_ROUTER);
            }
        }
    }

    int index = 0;
    int ptr1;
    ptr1 = -1;
    for (i = ipState->ptr; i < numHop; i++) {
        if (dflow.hops[i].val == ALIAS_IPOPT_TEST) {
            if (ptr1 == -1) {
                ptr1 = i;
            }
        }
            
        if (ptr1 != -1 && dflow.hops[i].ip == 0) {
            vector<Hop> hops;
            for (j = ptr1; j < i; j++)
                hops.push_back(dflow.hops[j]);

            for (j = 1; j < hops.size(); j++) {
                opt.push_back(assembleOptTs(hops[0].ip, hops[j].ip));
                opt.push_back(assembleOptTs(hops[j].ip, hops[0].ip));
                
                pkts.push_back(singlePkt(hops[0].ip, 0, 0, UINT8_MAX, TR_ICMP_FIX));
                pkts.push_back(singlePkt(hops[j].ip, 0, 0, UINT8_MAX, TR_ICMP_FIX));
            }

            // uint16_t sport, dport;
            // for (j = 0; j < hops.size(); j++) {
            //     if (getRvrTTL(dflow, hops[j].ip) != 0) {
            //         continue;
            //     }
            //     for (int k = 0; k < 6; k++) {
            //         sport = ipState->flows[hops[j].cnt].sport;
            //         dport = ipState->flows[hops[j].cnt].dport;
            //         pkts.push_back(singlePkt(id, sport, dport, hops[j].fwdttl, TR_UDP));
            //     }
            // }

            //for (j = ptr1; j < i; j++)
            //    dflow.hops[j].val = ALIAS_IN_PROGRESS;

            break;
        }
    }
    ipState->ptr = i;

    ipState->recvbuf.clear();
    return CONTINUE;
}

// void
// writeToFile(ofstream &outlist, uint32_t id, IPState *ipState) 
// {
//     int i, j;
//     int start = -1;
//     Flow &flow = ipState->flows.back();

//     outlist << id << " " << ipState->minrtt << " " << ipState->maxrtt << " ";

//     for (i = 0; i < flow.hops.size(); i++) {
//         if (start == -1 && flow.hops[i].ip != 0)
//             start = i;
//         if (start != -1 && flow.hops[i].ip == 0) {
//             int startRef = start;
//             outlist << flow.hops[startRef].ip << " " << flow.hops[i-1].ip << " "; 

//             bool diffpath = false, samepath = true;
//             start = -1;
//             for (j = startRef; j < i; j++) {
//                 if (flow.hops[j].val == ALIAS_RES_DIFF_ROUTER) {
//                     outlist << (int)MULTI_PATH << " "; 
//                     diffpath = true;
//                     break;
//                 }
//             }
//             if (diffpath) continue;

//             for (j = startRef; j < i; j++) {
//                 if (flow.hops[j].val != ALIAS_RES_SAME_ROUTER &&
//                     flow.hops[j].val != ALIAS_TEST_EXEMPT) 
//                 {
//                     samepath = false;
//                     break;
//                 }
//             }
//             if (samepath) {
//                 outlist << (int)SINGLE_PATH << " ";    
//                 continue;
//             }
//             outlist << (int)UNKNOWN_PATH << " ";
//         }
//     }

//     outlist << endl;
// }
        
PKT_TYPE
selPktType(int type) {
    if (type == 0) {
        return TR_TCP_ACK; 
    } else if (type == 1) {
        return TR_UDP;
    } else if (type == 2) {
        return TR_ICMP_VAR;
    } else { 
        return TR_ICMP_FIX;
    }
}
        
vector<int>
findUniqPaths(vector<Flow> &flows) {
    int i, j;     
    vector<int> numPaths;
    
    for (i = 0; i < NUM_PKT_TYPE; i++) {
        vector<Flow> subflows(flows.begin() + i * NUM_FLOWS_ENUM,
                              flows.begin() + (i + 1) * NUM_FLOWS_ENUM);
        vector<Flow> container;
        for (j = 0; j < NUM_FLOWS_ENUM; j++) {
            bool exist = false;
            for (auto &f : container) {
                if (sameFlow(f, subflows[j])) {
                    exist = true;
                    break;
                }
            }
            if (!exist) { container.push_back(subflows[j]); }
        }
        numPaths.push_back(container.size());
    }
    return numPaths;
}

// MSG_TYPE
// Scheduler::chkRouterLBType(uint32_t id, 
//                            IPState *ipState, 
//                            vector<Flow> &pkts, 
//                            PKT_TYPE &pktType) 
// {
//     int i;

//     if (ipState->flows.size() <= NUM_PKT_TYPE * NUM_FLOWS_ENUM) 
//         return PROBE_END; 

//     Flow &lastFlow = ipState->flows.back();

//     if (ipState->ptr > 0) {
//         set<uint32_t> nexthops;
//         for (auto &f : ipState->recvbuf) {
//             nexthops.insert(f.hops.back().ip);
//         }
//         lastFlow.hops[ipState->ptr-1].val = nexthops.size();
//     }

//     ipState->recvbuf.clear();

//     if (ipState->ptr >= lastFlow.hops.size()) {
//         outlist << id << " ";
//         vector<int> numPaths = findUniqPaths(ipState->flows); 
//         for (auto &n : numPaths) {
//             outlist << n << " ";
//         }
//         for (auto &h : lastFlow.hops) {
//             outlist << h.ip << " " << (int)h.cnt << " "
//                     << (int)h.numNextHops << " " << h.val << " "; 
//         }
//         outlist << endl;
//         ipState->ptr = 0;
//         return PHASE_DONE; 
//     }

//     uint16_t sport, dport;
//     Hop h = lastFlow.hops[ipState->ptr];
//     sport = ipState->flows[h.val].sport;
//     dport = ipState->flows[h.val].dport;
//     for (i = 0; i < 5; i++) {
//         pkts.push_back(singlePkt(id, sport, dport, h.ttl));
//     }
//     pktType = selPktType(h.cnt);

//     ipState->ptr++;

//     return CONTINUE;
// }

// MSG_TYPE
// Scheduler::pktFeature(IPState *ipState, 
//                       PfxState *state, 
//                       uint32_t id, 
//                       vector<Flow> &pkts, 
//                       PKT_TYPE &pktType)
// {
//     int i, j;
//     uint16_t sport, dport;
//     MSG_TYPE msgType;

//     if (state->alert) return PROBE_END;

//     // printf("task:%d\n", ipState->task);
//     if (ipState->task == CHK_RESPONSE) {
//         uint32_t newid;
//         msgType = chkResponse(id, ipState, pkts, 1);
//         if (msgType == NO_RESPONSE) {
//             // remove from ip2id
//             ip2id.erase(id);

//             newid = MIN(id + 16, IP2Pfx(id) + UINT8_MAX);
//             i = findIPLocPfx(state, newid);
//             if (id - IP2Pfx(id) == UINT8_MAX || i != -1) {
//                 return NO_RESPONSE;
//             }
//             i = findIPLocPfx(state, id);
//             id = newid;
//             state->IPMap[i].first = id - IP2Pfx(id);
//             msgType = chkResponse(id, ipState, pkts, 1);
//         } else if (msgType == PHASE_DONE) {
// 			addToQueue(IPTask(id, 0));
// 			ipState->task = GENERATE_FLOWS;
//         } 
//         if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, TCP_FREEZE_TIME));
//         }
//         pktType = selPktType(ipState->numProbe-1);
//     } else if (ipState->task == GENERATE_FLOWS) {
//         msgType = generateFlows(id, ipState, pkts, NUM_FLOWS_ENUM);
//         if (msgType == PHASE_DONE) {
//             for (auto &f : ipState->flows)
//                 f.hops.clear();
//             addToQueue(IPTask(id, 0));
//             ipState->task = PATH_HOP_EST;
//         } else if (msgType == CONTINUE) {
//             addToQueue(IPTask(id, TCP_FREEZE_TIME));
//         }
//         pktType = TR_TCP_ACK;
//    	} else if (ipState->task == PATH_HOP_EST) {
// 		msgType = pathHopEst(id, ipState, pkts);
// 		if (msgType == PHASE_DONE) {
//             vector<Flow> &flows = ipState->flows; 
//             for (auto &f : flows)
//                 f.hops.clear();
//             vector<Flow> copy(flows.begin(), flows.end());
//             for (i = 0; i < NUM_PKT_TYPE-1; i++) {
//                 flows.insert(flows.end(), copy.begin(), copy.end());
//             }
// 			addToQueue(IPTask(id, 0));
// 			ipState->task = PATH_ENUM_HOP;
// 		} else if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, TCP_FREEZE_TIME));
// 		}
//         pktType = TR_TCP_ACK;
// 	} else if (ipState->task == PATH_ENUM_HOP) {
// 		msgType = detectLB(id, ipState, NUM_PKT_TYPE * NUM_FLOWS_ENUM, pkts);
//         if (msgType == PHASE_DONE) {
//             for (i = 0; i < NUM_PKT_TYPE; i++) {
//                 vector<Flow> flows(ipState->flows.begin() + i * NUM_FLOWS_ENUM,
//                                    ipState->flows.begin() + (i + 1) * NUM_FLOWS_ENUM);
//                 Graph g;
//                 Flow f = g.findLBRouter(id, flows);
//                 for (auto &h : f.hops) {
//                     h.cnt = i;
//                     h.val += i * NUM_FLOWS_ENUM;
//                 }
//                 if (ipState->flows.size() <= NUM_PKT_TYPE * NUM_FLOWS_ENUM) {
//                     ipState->flows.push_back(f);
//                 } else {
//                     Flow &lastFlow = ipState->flows.back();
//                     lastFlow.hops.insert(lastFlow.hops.end(), f.hops.begin(), f.hops.end());
//                 }
//             }
//             ipState->ptr = 0;
//             addToQueue(IPTask(id, 0));
//             ipState->task = ROUTER_LB_TYPE;
// 		} else if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, TCP_FREEZE_TIME));
// 		}
//         pktType = selPktType((ipState->ptr - 1) / NUM_FLOWS_ENUM);
//     } else if (ipState->task == ROUTER_LB_TYPE) {
//         msgType = chkRouterLBType(id, ipState, pkts, pktType);
//         if (msgType == PHASE_DONE) {
//             ipState->flows.clear();
//             msgType = PROBE_END;
//         } else if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, TCP_FREEZE_TIME));
//         }
//     }

//     return msgType;
// }

// MSG_TYPE
// Scheduler::periodicScan(IPState *ipState, 
//                         PfxState *state, 
//                         uint32_t &id, 
//                         vector<Flow> &pkts, 
//                         PKT_TYPE &pktType,
//                         vector<ip_timestamp> &opt)
// {
//     int i, j;
//     uint16_t sport, dport;
//     MSG_TYPE msgType;

//     if (state->alert) return PROBE_END;

//     if (ipState->task == CHK_RESPONSE) {
//         uint32_t newid;
//         msgType = chkResponse(id, ipState, pkts, 1);
//         if (msgType == NO_RESPONSE) {
//             newid = MIN(id + 16, IP2Pfx(id) + UINT8_MAX);
//             i = findIPLocPfx(state, newid);
//             if (id - IP2Pfx(id) == UINT8_MAX || i != -1) {
//                 return NO_RESPONSE;
//             }
//             i = findIPLocPfx(state, id);
//             id = newid;
//             state->IPMap[i].first = id - IP2Pfx(id);
//             msgType = chkResponse(id, ipState, pkts, 1);
//         } else if (msgType == PHASE_DONE) {
// 			addToQueue(IPTask(id, 0));
// 			ipState->task = GENERATE_FLOWS;
//         } 
//         if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, TCP_FREEZE_TIME));
//         }
//         pktType = TR_TCP_ACK;
//     } else if (ipState->task == GENERATE_FLOWS) {
// 		msgType = pathEnumE2E(id, ipState, pkts, NUM_E2E_EXPLR);
//         if (msgType == PHASE_DONE) {
//             vector<Flow> &flows = ipState->flows;
// 			ipState->minrtt = ipState->flows[0].hops.back().val;
// 			ipState->maxrtt = ipState->flows[1].hops.back().val;
            
//             // remove extra flows
//             flows.erase(flows.begin() + NUM_FLOWS_ENUM, flows.end());
//             for (auto &f : flows)
//                 f.hops.clear();

//             addToQueue(IPTask(id, 0));
//             ipState->task = PATH_HOP_EST;
//         } else if (msgType == CONTINUE) {
//             addToQueue(IPTask(id, TCP_FREEZE_TIME));
//         }
//         pktType = TR_TCP_ACK;
//    	} else if (ipState->task == PATH_HOP_EST) {
// 		msgType = pathHopEst(id, ipState, pkts);
// 		if (msgType == PHASE_DONE) {
//             for (i = 0; i < NUM_FLOWS_ENUM; i++) { 
//                 ipState->flows[i].hops.clear();
//             }
// 			addToQueue(IPTask(id, 0));
// 			ipState->task = PATH_ENUM_HOP;
// 		} else if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, TCP_FREEZE_TIME));
// 		}
//         pktType = TR_TCP_ACK;
// 	} else if (ipState->task == PATH_ENUM_HOP) {
// 		msgType = detectLB(id, ipState, NUM_FLOWS_ENUM, pkts);
//         if (msgType == PHASE_DONE) {
//             MSG_TYPE msg = cmmLBReg(id, ipState->flows);
//             if (msg == SINGLE_PATH || msg == UNKNOWN_PATH) {
//                 outlist << fixed;
//                 outlist << id << " " << ipState->minrtt << " " 
//                         << ipState->maxrtt << " " << msg << endl;
//                 msgType = PROBE_END;
//             } else {
//                 addToQueue(IPTask(id, 0));
//                 ipState->task = ALIAS_RESL_IPID;
//             }
// 		} else if (msgType == CONTINUE) {
// 			addToQueue(IPTask(id, TCP_FREEZE_TIME));
// 		}
//         pktType = TR_TCP_ACK;
//     } else if (ipState->task == ALIAS_RESL_IPID) {
//         msgType = aliasReslIpId(id, ipState, pkts);
//         if (msgType == PHASE_DONE) {
//             addToQueue(IPTask(id, 0));
//             ipState->task = ALIAS_RESL_OPTION; 
//         } else if (msgType == CONTINUE) {
//             addToQueue(IPTask(id, TCP_FREEZE_TIME));
//         }
//         pktType = TR_TCP_ACK;
//     } else if (ipState->task == ALIAS_RESL_OPTION) {
//         msgType = aliasReslOpt(id, ipState, pkts, opt);
//         if (msgType == CONTINUE) {
//             addToQueue(IPTask(id, TCP_FREEZE_TIME));
//         } else {
//             writeToFile(outlist, id, ipState);
//             msgType = PROBE_END;
//         }
//         pktType = TR_ICMP_FIX;
//     } else if (ipState->task == PERIODIC_PROBE) {
//         // write into file
//         vector<Flow> &flows = ipState->flows;
//         if (flows.size() > NUM_FLOWS_ENUM) {
//             for (i = NUM_FLOWS_ENUM; i < flows.size(); i++) {
//                 outlist << fixed;
//                 outlist << 2 << " " << getCurrTime() << " " << id << " " 
//                         << flows[i].sport << " " << flows[i].dport << " " 
//                         << flows[i].hops.back().ip << " "
//                         << flows[i].hops.back().val << endl; 
//             }
//             flows.erase(flows.begin() + NUM_FLOWS_ENUM, flows.end());
//         }

//         ipState->ptr %= NUM_FLOWS_ENUM;

//         Flow *f;
//         for (; ipState->ptr < NUM_FLOWS_ENUM; ipState->ptr++) { 
//             f = &ipState->flows[ipState->ptr];
//             if (f->hops.size() != 0) {
//                 sport = f->sport;
//                 dport = f->dport;
//                 for (j = 0; j < f->hops.size(); j++)
//                     pkts.push_back(singlePkt(id, sport, dport, f->hops[j].ttl));
//                 ipState->ptr++;
//                 break;
//             }
//         }

//         msgType = CONTINUE;
//         addToQueue(IPTask(id, TCP_FREEZE_TIME));
//         pktType = TR_TCP_ACK;
//     }

//     return msgType;
// }

void logRes(uint32_t id, IPState *ipState, int type, ofstream &outlist) {

    pthread_rwlock_rdlock(&ws_lock);

    // new
    outlist << fixed << numRounds << " " << id << " " << type << " " << getCurrTime() << " ";

    switch (type) {
        case OUT_FWD_PKT_LB:
        case OUT_RVR_PKT_LB:
            break;
        case OUT_LATENCY:
            for (int i = 0; i < NUM_EXPLR_E2E + 2 * NUM_REPEAT_E2E; i++) {
                outlist << ipState->flows[i].hops.back().val << " ";
            }
            break;
        case OUT_FLOW_NO_LB:
        case OUT_FLOW_LB:
            for (auto &f : ipState->flows) {
                for (auto &h : f.hops) {
                    outlist << h.ip << " " << (int)h.fwdttl << " " 
                            << (int)h.rvrttl << " " << h.val << " ";
                }
            }
            break;
        case OUT_ALIAS_RESL:
            for (auto &h : ipState->flows.back().hops) {
                outlist << h.ip << " " << (int)h.val << " ";
            }
            break;
        case OUT_HOPS_REVERSE_PATH:
            for (int i = 0; i < NUM_EXPLR_E2E; i++) {
                outlist << (int)ipState->flows[i].rvrttl << " ";
            }
            break;
        case OUT_LAST_HOP_ROUTER:
            outlist << ipState->lastHopRouter;
            break;
        case OUT_FIREWALL:
            outlist << ipState->cnt;
            break;
    }

    outlist << "\n";

    pthread_rwlock_unlock(&ws_lock);
}

bool
Scheduler::inBlacklist(uint32_t &id) {
    return blacklist.count(IP2Pfx(id));
}

void
Scheduler::addToBlacklist(uint32_t &id) {
    blacklist.insert(id);
}

MSG_TYPE
Scheduler::findLastRouter(uint32_t id, 
                          IPState *ipState, 
                          PKT_TYPE pktType,
                          vector<Packet> &pkts) 
{
    uint16_t sport, dport;
    vector<Flow> &flows = ipState->flows;
    vector<Flow> &recvbuf = ipState->recvbuf;
    const int numNeighExplr = 3;

    // [0, numNeighExplr] has numNeighExplr + 1 elements
    if (ipState->numProbe >= MAX_HOPS + NUM_EXPLR_E2E * (numNeighExplr + 1)) {
        ipState->numProbe = ipState->cnt = ipState->ptr = 0;
        return PROBE_END;
    }

    bool routerFound = false;
    uint32_t routerip = 0;

    if (recvbuf.size() != 0) {
        routerip = recvbuf.back().hops.back().ip;
    }

    if (flows.size() == 0 && recvbuf.size() != 0) {

        // check if router has been probed
        if (ipState->lastHopRouter == 0)
            ipState->lastHopRouter = routerip;

        if (histDB[routerip].probed) {
            return PROBE_END;
        }

        flows.push_back(recvbuf.back());

    } else if (flows.size() != 0 && !ipState->found) {
        if (recvbuf.size() == 0 || (routerip && ipState->lastHopRouter != routerip)) {
            ipState->found = routerFound = true;
            flows.back().fwdttl = ipState->ptr + 2;
            // ptr is the index of next flow
            ipState->ptr = 1; 
        }
    } else {
         // add recvbuf to flows
        for (auto &f : ipState->recvbuf) {
            Flow &flow = flows[ipState->ptr];
            if (f.sport == flow.sport 
                    && f.dport == flow.dport
                    && f.hops.back().ip == ipState->lastHopRouter) 
            {
                flow = f;
                routerFound = true;
                ipState->ptr++;
                break;
            }
        }
    }

    recvbuf.clear();

    //printFlow(flows);
    //cout << ipState->ptr << " " << ipState->cnt << " " << routerFound << " " << ipState->numProbe << endl;

    if (!ipState->found) {
        if (ipState->ptr == 0) {
            return PROBE_END;
        }

        if (flows.size() == 0) {
            sport = randPort(MIN_PORT, MAX_PORT);
            dport = randPort(MIN_PORT, MAX_PORT);
        } else {
            sport = flows.back().sport;
            dport = flows.back().dport;
        }

        pkts = {singlePkt(id, sport, dport, ipState->ptr, pktType)};
        ipState->ptr--;

        ipState->numProbe++;
        return CONTINUE;
    } else if (ipState->ptr < NUM_EXPLR_E2E) {

        if (!routerFound && ipState->cnt < numNeighExplr) {
            sport = flows.back().sport;
            dport = flows.back().dport;
            ipState->cnt++;
        } else {
            sport = randPort(MIN_PORT, MAX_PORT);
            dport = randPort(MIN_PORT, MAX_PORT);       
            ipState->cnt = 0;     
        }

        uint8_t ttl = ipState->flows[0].fwdttl;
        if (ipState->cnt == 0) {
            pkts = {singlePkt(id, sport, dport, ttl, pktType)};
        } else {
            pkts.push_back(singlePkt(id, sport, dport, ttl + ipState->cnt, pktType));
            pkts.push_back(singlePkt(id, sport, dport, ttl - ipState->cnt, pktType));
        }

        if (flows.size() > ipState->ptr) {
            flows[ipState->ptr].sport = sport;
            flows[ipState->ptr].dport = dport;
        } else {
            flows.push_back(Flow(sport, dport));
        }

        ipState->numProbe++;
        return CONTINUE;
    }

    recvbuf.clear();
    flows.erase(flows.begin() + NUM_EXPLR_E2E, flows.end());
    ipState->numProbe = ipState->cnt = ipState->ptr = 0;
    return PHASE_DONE;
}

// template <typename T>
// void updateAliasDB(IPState *ipState, T &aliasDB) {
//     int i = 0;
//     pair<uint32_t, uint32_t> intfpair;
//     vector<Hop> &hops = ipState->flows.back().hops;
//     while (i < hops.size()) {

//         if (hops[i].ip == 0) {
//             i++;
//         } else {
//             intfpair = makeOrderedPair(hops[i].ip, hops[i + 1].ip);
//             if (aliasDB.count(intfpair) == 0) {
//                 aliasDB[intfpair] = 0;
//             } else {
//                 aliasDB[intfpair]++;
//             }
//             i += 2;
//         }
//     }
// }

MSG_TYPE
Scheduler::LBRegScan(IPState *ipState, 
                     uint32_t &id, 
                     vector<Packet> &pkts,
                     vector<ip_timestamp> &opt)
{
    MSG_TYPE msgType;
    double currTime = getCurrTime();

    if (inBlacklist(id)) { 
        return PROBE_END;
    }

    // cout << "task:" << (int)ipState->task << endl;

    // ipState->task = UPDATE_MAP;
    if (ipState->task == CHK_RESPONSE) {
        int i;
        uint32_t newid;

        msgType = chkResponse(id, ipState, 1, TR_UDP, pkts);

        if (msgType == NO_RESPONSE) {

            if (id - IP2Pfx(id) == UINT8_MAX) {

                // log results
                async(std::launch::async, logRes, id, ipState, OUT_FIREWALL, std::ref(outlist));

                ipState->cnt = 0;
                ipState->ptr = MAX_HOPS;
                ipState->task = FIND_LAST_ROUTER;
                addToQueue(Task(id, currTime));
                return PHASE_DONE;
            }

            newid = MIN(id + 1, IP2Pfx(id) + UINT8_MAX);

            // update key
            ipStateDB.insert({newid, *ipState});
            ipState = &ipStateDB[newid];
            ipStateDB.erase(id);
            id = newid;
            
            // send probes to new id
            msgType = chkResponse(id, ipState, 1, TR_UDP, pkts);

        } else if (msgType == PHASE_DONE) {
			addToQueue(Task(id, currTime));
			ipState->task = PATH_ENUM_E2E;
        } 
        if (msgType == CONTINUE) {
			addToQueue(Task(id, currTime + UDP_FREEZE_TIME));
        }
    } else if (ipState->task == FIND_LAST_ROUTER) {
        msgType = findLastRouter(id, ipState, TR_UDP, pkts);

        if (msgType == PHASE_DONE) {
            ipState->task = PATH_ENUM_E2E;

            // log results
            async(std::launch::async, logRes, id, ipState, OUT_LAST_HOP_ROUTER, std::ref(outlist));

            addToQueue(Task(id, currTime));
        } else if (msgType == CONTINUE) {
            addToQueue(Task(id, currTime + UDP_FREEZE_TIME));
        }
    } else if (ipState->task == PATH_ENUM_E2E) {
		msgType = pathEnumE2E(id, ipState, NUM_EXPLR_E2E, TR_UDP, pkts);
		if (msgType == PHASE_DONE) {
			// go to next stage
			int minRTT = ipState->flows[0].hops.back().val;
			int maxRTT = ipState->flows[1].hops.back().val;

            async(std::launch::async, logRes, id, ipState, OUT_LATENCY, std::ref(outlist));
            // async(std::launch::async, logRes, id, ipState, OUT_HOPS_REVERSE_PATH, std::ref(outlist));

            /* measure addresses with large latency imbalance and one-fifth addresses with almost no latency imbalance */
            bool randSel = (rand() % 100 < 20);
            bool largeDiff = ((maxRTT - minRTT) >= RANGE_THRES);

			if (largeDiff || randSel) {
                ipState->flows[0].hops.clear();
                ipState->flows[1].hops.clear();
                ipState->flows.erase(ipState->flows.begin() + 2, ipState->flows.end());
				
                ipState->task = (largeDiff) ? PATH_HOP_EST : PATH_ENUM_HOP_SIMPLE;
				
                if (largeDiff && ipState->lastHopRouter) {
                    ipState->task = PATH_ENUM_HOP;
                } else if (largeDiff && !ipState->lastHopRouter) {
                    // initialize fwdttl to rvrttl
                    for (auto &f : ipState->flows) {
                        f.fwdttl = f.rvrttl;
                    }
                    ipState->task = PATH_HOP_EST;
                } else {
                    ipState->task = PATH_ENUM_HOP_SIMPLE;
                }
                
                addToQueue(Task(id, currTime));
            } else {
                ipState->flows.clear();
                msgType = PROBE_END;
			}
		} else if (msgType == CONTINUE) {
			addToQueue(Task(id, currTime + UDP_FREEZE_TIME));
		}
	} else if (ipState->task == PATH_HOP_EST) {

		msgType = pathHopEst(id, ipState, TR_UDP, pkts);

		if (msgType == PHASE_DONE) {
            ipState->flows[0].hops.clear();
            ipState->flows[1].hops.clear();

            ipState->task = PATH_ENUM_HOP;
			addToQueue(Task(id, currTime));
		} else if (msgType == CONTINUE) {
			addToQueue(Task(id, currTime + UDP_FREEZE_TIME));
		}
    } else if (ipState->task == PATH_ENUM_HOP_SIMPLE) {
		msgType = pathEnumHop(id, ipState, 1, pkts);
        if (msgType == PHASE_DONE) {
            async(std::launch::async, logRes, id, ipState, OUT_FLOW_NO_LB, std::ref(outlist));            
            msgType = PROBE_END;
        } else if (msgType == CONTINUE) {
			addToQueue(Task(id, currTime + UDP_FREEZE_TIME));
        }
	} else if (ipState->task == PATH_ENUM_HOP) {
		msgType = pathEnumHop(id, ipState, 6, pkts);
        if (msgType == DIFF_FWD_FLOW) {
            // per-packet load balancer
            async(std::launch::async, logRes, id, ipState, OUT_FWD_PKT_LB, std::ref(outlist));
            msgType = PROBE_END;
        } else if (msgType == DIFF_RVR_FLOW) {
            async(std::launch::async, logRes, id, ipState, OUT_RVR_PKT_LB, std::ref(outlist));
            msgType = PROBE_END;
        } else if (msgType == PHASE_DONE) {
            // write flows to files
            async(std::launch::async, logRes, id, ipState, OUT_FLOW_LB, std::ref(outlist));
			msgType = PROBE_END;
		} else if (msgType == CONTINUE) {
			addToQueue(Task(id, currTime + UDP_FREEZE_TIME));
        }
    }

    return msgType;
}

bool
endOfProbe(MSG_TYPE msgType) {
    if (msgType == NUM_PROBE_EXCEEDED ||
        msgType == PROBE_END) 
    {
        return true;    
    }
    return false;
}

uint32_t
Scheduler::nextAddr(vector<Packet> &pkts, 
                    vector<ip_timestamp> &opt) 
{
    int i;
    Task task;
	IPState *ipState;
    MSG_TYPE msgType;

    populateTaskQueue();

	while (taskQueue.empty()) {
		sleep(TIMEOUT);
		return 0;
	}

    while (true) {
        task = taskQueue.top();

        if (getCurrTime() >= task.startTime)
            break;

        sleep(1.0/1000);
    }

    taskQueue.pop();

    pthread_rwlock_wrlock(&gLock);
    ipState = &ipStateDB[task.id];

    msgType = LBRegScan(ipState, task.id, pkts, opt);

    if (endOfProbe(msgType)) {
        /* log the final state */
        // outlist << fixed << numRounds << " " << task.id << " " << OUT_FINAL_STATE << " " 
        //         << getCurrTime() << " " << (int)ipState->task << " " << msgType << endl; 

        if (ipState->lastHopRouter) {
            histDB[ipState->lastHopRouter].probed = true;
        }

        /* when TCP_ACKs are used, remove the task when done */
        ip2id.erase(task.id);
        
        /* remove the task from the database when done */
        ipStateDB.erase(task.id);
   }

    pthread_rwlock_unlock(&gLock);

	return task.id;
}

uint32_t IP2Pfx(uint32_t ip) {
	return (ip >> 8) << 8;
}
