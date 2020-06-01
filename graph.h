#ifndef GRAPH_H
#define GRAPH_H

#include <vector>
#include <stdint.h>
#include <cstddef>
#include <string.h>
#include <pthread.h>
#include <fstream>

#define NUM_FLOWS_ENUM 2

typedef enum {NO_LB_ANALYSIS, LB_ANALYSIS} ANAL_MODE;

using namespace std;

enum LINK_TYPE {
    CMPL_SINGLE_PATH, 
    INCMPL_SINGLE_PATH,  
    CMPL_MULTI_PATH, 
    INCMPL_MULTI_PATH,
    DIRECT_LINK, 
    INDIRECT_LINK
}; 

/*
template <typename T>
class Vector {
public:

    Vector() {
        pthread_rwlock_init(&lock, NULL);
    }

    typedef typename vector<T>::iterator iterator;

    void push_back(T v) {
        pthread_rwlock_wrlock(&lock);
        vec.push_back(v);
        pthread_rwlock_unlock(&lock);
    }

    T& operator[] (int index) {
        pthread_rwlock_rdlock(&lock);
        T& ret = vec[index];
        pthread_rwlock_unlock(&lock);
        return ret;
    }

    size_t size() {
        pthread_rwlock_rdlock(&lock);
        size_t s = vec.size();
        pthread_rwlock_unlock(&lock);
        return s;
    }

    iterator begin() {
        pthread_rwlock_rdlock(&lock);
        iterator it = vec.begin();
        pthread_rwlock_unlock(&lock);
        return it;
    }

    iterator end() {
        pthread_rwlock_rdlock(&lock);
        iterator it = vec.end();
        pthread_rwlock_unlock(&lock);
        return it;
    }

    void erase(iterator iter) {
        pthread_rwlock_rdlock(&lock);
        vec.erase(iter);
        pthread_rwlock_unlock(&lock);
    }

    T& back() {
        pthread_rwlock_rdlock(&lock);
        T& ret = vec.back();
        pthread_rwlock_unlock(&lock);
        return ret;
    }

    void insert(iterator pos, T& v) {
        pthread_rwlock_wrlock(&lock);
        vec.insert(pos, v);
        pthread_rwlock_unlock(&lock);
    }

    void insert(iterator pos, iterator t1, iterator t2) {
        pthread_rwlock_wrlock(&lock);
        vec.insert(pos, t1, t2);
        pthread_rwlock_unlock(&lock);
    }

    void clear() {
        pthread_rwlock_wrlock(&lock);
        vec.clear();
        pthread_rwlock_unlock(&lock);
    }

    void erase(iterator it1, iterator it2) {
        pthread_rwlock_wrlock(&lock);
        vec.erase(it1, it2);
        pthread_rwlock_unlock(&lock);
    }

private:
    pthread_rwlock_t lock;
    vector<T> vec;
};
*/

struct Hop {
    uint8_t cnt;
	uint8_t fwdttl; // fwdttl by default
    uint8_t rvrttl;
	float val;
	uint32_t ip;
	Hop(uint32_t _ip, uint8_t _ttl): ip(_ip), fwdttl(_ttl), val(0), cnt(0) {}
	Hop(): ip(0), fwdttl(UINT8_MAX), val(0), cnt(0) {}
};

struct Flow {
	uint16_t sport;
	uint16_t dport;
    uint8_t fwdttl, rvrttl;
	vector<Hop> hops;
	bool updateHop(uint32_t dst, Hop h);
    Flow() : sport(0), dport(0), fwdttl(UINT8_MAX), rvrttl(UINT8_MAX) {}
	Flow(uint16_t s, uint16_t d): sport(s), dport(d), fwdttl(UINT8_MAX), rvrttl(UINT8_MAX) {}
};

struct Link {
    float val; // use this val...
	LINK_TYPE type;
    Link() {};
    Link(LINK_TYPE _type, int _val): type(_type), val(_val) {}
};

struct Node {
    uint8_t indegree;
 	Hop hop;
	vector<Link> links;
	vector<Node *> nextHops;
    uint8_t ttls[NUM_FLOWS_ENUM];
	Node(Hop h) : hop(h), indegree(0) {
        memset(ttls, 0, NUM_FLOWS_ENUM); 
    }
};

struct LBReg {
	Hop start, end;
	Link link;
	LBReg(Hop s, Hop e, LINK_TYPE type): start(s), end(e) {
        link.type = type;
        link.val = INT16_MAX;
    }
};

class Graph {
public:
	Graph() { root = NULL; }
	~Graph();

	vector<LBReg> findLBReg(uint32_t, vector<Flow> &, ofstream *);
    Node *addHop(Node *, int, Hop &);
    Node *findNodeInGraph(uint32_t, Node *);
    double calcLBRegDiff(vector<Flow> &, vector<LBReg> &);
    void buildGraph(uint32_t, vector<Flow> );
    Flow findLBRouter(uint32_t, vector<Flow> &);
	void updateGraph(vector<LBReg> &);
    void printGraph(uint32_t, ostream *);

private:
	Node *root;
};

bool isMultiPath(LBReg &);
vector<vector<Hop>> findUniqPaths(vector<Flow> &, uint32_t, uint32_t);
bool subpathExist(vector<Hop> &, vector<vector<Hop>> &);

#endif
