#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "graph.h"
#include <netinet/ip.h>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <algorithm>
#include <iterator>
#include <fstream>

using namespace std;

#define TCP_FREEZE_TIME 3
#define ICMP_FREEZE_TIME 1
#define UDP_FREEZE_TIME_SHORT 0.2
#define UDP_FREEZE_TIME_LONG 3
#define TIMEOUT MIN(TCP_FREEZE_TIME, MIN(UDP_FREEZE_TIME_LONG, ICMP_FREEZE_TIME))

#define NUM_EXPLR_E2E 5 // std: 30
#define NUM_REPEAT_E2E 6 // std: 6
#define MAX_PROBES_SENT 90 // NUM_EXPLR_E2E + 10 * NUM_REPEAT_E2E
#define NUM_PKTLB_EXPLR 6  // std: 6
#define NUM_ALIAS_RESL 3   // 1000

// Port number
#define MIN_PORT 49152
#define MAX_PORT UINT16_MAX

#define NUM_FLOWS_E2E 2
#define RANGE_THRES 0 // 6ms
#define MEAS_ERROR 5 // 5ms
#define MAX_HOPS 30
#define NUM_TRIES_PER_HOP 3
#define NUM_UNRESPONSIVE_HOPS 3

//extern pthread_rwlock_t mapLock;
//pthread_rwlock_t mapLock;
//pthread_rwlock_init(mapLock);

// IP level
typedef enum {
    CHK_RESPONSE, 
    FIND_LAST_ROUTER,
    PATH_ENUM_E2E, 
    PATH_HOP_EST, 
    PATH_ENUM_HOP, 
    PATH_ENUM_HOP_SIMPLE, 
    CHK_LB, 
    UPDATE_MAP, 
    GENERATE_FLOWS, 
    PERIODIC_PROBE, 
    FLOW_ENUM_E2E, 
    ALIAS_RESL_IPID, 
    ALIAS_RESL_OPTION, 
    ROUTER_LB_TYPE
} TASK_TYPE;

// Packet type
typedef enum {
    TR_ICMP6, 
    TR_ICMP_VAR, 
    TR_ICMP_FIX, 
    TR_UDP6, 
    TR_UDP, 
    TR_TCP6_SYN, 
    TR_TCP_SYN, 
    TR_TCP6_ACK, 
    TR_TCP_ACK, 
    TR_TCP_RST
} PKT_TYPE;

struct Packet {
    uint32_t targetip;
    double sndTime;
    uint8_t ttl;
    PKT_TYPE pktType;
    uint16_t sport, dport;
    Packet(uint32_t _ip, double _time, 
            uint8_t _ttl, PKT_TYPE _pktType, 
            uint16_t _sport, uint16_t _dport): 
            targetip(_ip), sndTime(_time), ttl(_ttl), 
            pktType(_pktType), sport(_sport), dport(_dport) {};
    Packet(): targetip(0), sndTime(0), ttl(0), pktType(TR_TCP_ACK), sport(0), dport(0) {};
};

static const char *Tr_Type_String[] = {
    "ICMP6", 
    "ICMP", 
    "UDP6", 
    "UDP",
	"TCP6_SYN", 
    "TCP_SYN", 
    "TCP6_ACK",
    "TCP_ACK"
};

// error type
typedef enum {
    NUM_PROBE_EXCEEDED, 
    PKT_LB_DETECTED, 
    DIFF_FWD_FLOW,
    DIFF_RVR_FLOW, 
    NO_RESPONSE, 
    CONTINUE,
    PHASE_DONE, 
    PROBE_END,
    MULTI_PATH, 
    SINGLE_PATH, 
    UNKNOWN_PATH,
    NO_ACTION
} MSG_TYPE;

// mode
typedef enum {
    LBREG_SCAN,
    E2E_SCAN, 
    DELAY_VAR_REL, 
    PERIODIC_SCAN, 
    PKT_FEATURE
} SCAN_MODE;

/*
template <typename T1, typename T2>
class Unordered_map {
public:
    int count(T1 &v) {
        pthread_rwlock_rdlock(&lock);
        int ret = m.count(v);
        pthread_rwlock_unlock(&lock);
        return ret;
    }

    T2& operator[] (T1 &key) {
        pthread_rwlock_wrlock(&lock);
        T2& value = m[key]; 
        pthread_rwlock_unlock(&lock);
        return value;
    }
private:
    pthread_rwlock_t lock;
    unordered_map<T1, T2> m;
};
*/

// Tasks should be above the IP level; otherwise, hard to make sure packets are sent in order
struct Task {
	uint32_t id;
	double startTime;
	Task(): id(0), startTime(0) {}
	Task(uint32_t ip, double time): id(ip), startTime(time) {}
};

struct IPState {
    uint8_t task;
	uint16_t ptr, cnt;
	uint16_t numProbe;
    uint32_t lastHopRouter;
    vector<Flow> recvbuf, flows;
    string output;

	IPState(): task(CHK_RESPONSE), 
               ptr(0),
               cnt(0),
               numProbe(0),
               lastHopRouter(0) {}
};

class Scheduler {
public:
	Scheduler(char *in, char *out, int _cap, bool lasthop, bool scan, bool fastmode);
    ~Scheduler();

    SCAN_MODE mode;
	uint32_t nextAddr(vector<Packet> &, vector<ip_timestamp> &);
	
    // funcs implementing a specific task
    MSG_TYPE pathEnumE2E(uint32_t, IPState *, int, PKT_TYPE, vector<Packet> &);
	MSG_TYPE pathHopEst(uint32_t, IPState *, PKT_TYPE, vector<Packet> &);
	MSG_TYPE pathEnumHop(uint32_t, IPState *, int, vector<Packet> &);
    // MSG_TYPE flowEnumE2E(uint32_t, IPState *, vector<Flow> &, int);
    MSG_TYPE findLastRouter(uint32_t, IPState *, PKT_TYPE, vector<Packet> &); 
	
    // auxilary functions
    bool pathDecouple(uint32_t, IPState *, Graph &, vector<Flow> &);
	void addToQueue(Task);
    void populateTaskQueue();

    MSG_TYPE chkResponse(uint32_t, IPState *, int, PKT_TYPE, vector<Packet> &);
    MSG_TYPE aliasReslIpId(uint32_t, IPState *, vector<Packet> &);

    //MSG_TYPE pktFeature(IPState *, PfxState *, uint32_t, vector<Flow> &, PKT_TYPE &);
    MSG_TYPE LBRegScan(IPState *, uint32_t &, vector<Packet> &, vector<ip_timestamp> &);
    //MSG_TYPE endToEndScan(IPState *, PfxState *, uint32_t &, vector<Flow> &, PKT_TYPE &);
    //MSG_TYPE periodicScan(IPState *, PfxState *, uint32_t &, vector<Flow> &, 
    //                      PKT_TYPE &, vector<ip_timestamp> &);
    MSG_TYPE chkRouterLBType(uint32_t, IPState *, vector<Flow> &, PKT_TYPE &);
    //MSG_TYPE delayVarRel(IPState *, PfxState *, uint32_t &, vector<Flow> &, PKT_TYPE &);

	unordered_map<uint32_t, IPState> ipStateDB;
    unordered_map<uint32_t, uint16_t> ip2id;

    bool lasthop, scan, fastmode;
    char *input;
    ofstream outlist;

    bool inBlacklist(uint32_t &);
    void addToBlacklist(uint32_t &);
    void updateHistDB(uint32_t &, uint16_t &);

private:
    int cap;

    unordered_set<uint32_t> blacklist;

    class TaskCmp {
      public:
        bool operator()(Task &t1, Task &t2) {
            return t1.startTime > t2.startTime;
        }
    };

    priority_queue<Task, vector<Task>, TaskCmp> taskQueue;

    struct pair_hash {
        inline std::size_t operator()(const std::pair<int, int> &v) const {
            return v.first * 31 + v.second;
        }
    };
    unordered_map<pair<uint32_t, uint32_t>, int, pair_hash> aliasDB;

    struct Status {
        bool ipid;
        bool probed;
        // ttl is not stored because of dynamic topo
        Status(): ipid(true), probed(false) {}
    };
    unordered_map<uint32_t, Status> histDB;
};

uint32_t IP2Pfx(uint32_t ip);
double getCurrTime();

#endif //
