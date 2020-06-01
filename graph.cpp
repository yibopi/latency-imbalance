#include "graph.h"
#include "scheduler.h"
#include <cmath>
#include <set>
#include <queue>
#include <unordered_map>
#include <iostream>

int sameHop(Flow &f, Hop &hop, int start, bool &hopJump) {
	for (int i = start; i < f.hops.size(); i++) {
        if (i - start != f.hops[i].fwdttl - f.hops[start].fwdttl)
            hopJump = true;
		if (hop.ip == f.hops[i].ip)
			return i;
	}
	return -1;
}

bool
Flow::updateHop(uint32_t dst, Hop h) {
	int i;
	for (i = hops.size() - 1; i >= 0; i--) {
        if (hops[i].ip == dst) {
            break;
        }
        if (hops[i].ip == h.ip) {
            // some routers reply with rotating interfaces
            if (i !=  hops.size() - 1)
                return false;
            hops[i].fwdttl = min(hops[i].fwdttl, h.fwdttl);
            break;
        }
        if (hops[i].fwdttl < h.fwdttl) {
			hops.insert(hops.begin() + i + 1, h);
			break;
		}
	}
	if (i < 0) hops.insert(hops.begin(), h);
    return true;
}

int 
getHopPos(Flow &f, Hop &h)
{
	for (int i = 0; i < f.hops.size(); i++)
		if (f.hops[i].ip == h.ip) return i;
    return -1;
}

bool hasHopJump(Flow &f, int start, int i, int dir) 
{
    if (i == start) return false;
    if (f.hops[i].fwdttl - f.hops[i - dir].fwdttl != dir)
        return true;
    return false;
}

pair<Hop, Hop>
selHop(vector<Flow> &flows, Hop start, Hop end, int dir)
{
    int i, j, k;
    int idx1, idx2, idx3, idx4;
    bool hopJump;
    vector<int> counts;
    vector<pair<int, int>> indices;

    idx1 = getHopPos(flows[0], start);
    idx2 = getHopPos(flows[1], start);
    idx3 = getHopPos(flows[0], end);
    idx4 = getHopPos(flows[1], end);

    if (idx1 == -1 || idx2 == -1 || idx3 == -1 || idx4 == -1)
        return make_pair(Hop(), Hop()); 

    k = idx2;
    hopJump = false;
    for (i = idx1; i != idx3 + dir; i += dir) {
        for (j = k; j != idx4 + dir; j += dir) {
            hopJump = hasHopJump(flows[0], idx1, i, dir) || hasHopJump(flows[1], idx2, j, dir); 
            if (hopJump) break;
            if (flows[0].hops[i].ip == flows[1].hops[j].ip) {
                if (flows[0].hops[i].cnt > 0 && flows[1].hops[j].cnt > 0) {
                //    found = true;
                //    flowInd1 = i;
                //    flowInd2 = j;
                    counts.push_back(min(flows[0].hops[i].cnt, flows[1].hops[j].cnt));
                    indices.push_back(make_pair(i, j));
                }
                k = j + dir;
            }
        }
        if (hopJump) break;
    }

    if (counts.empty())
        return make_pair(Hop(), Hop()); 

    int maxIndex = distance(counts.begin(), max_element(counts.begin(), counts.end()));
    int ind1 = indices[maxIndex].first;
    int ind2 = indices[maxIndex].second;

    return make_pair(flows[0].hops[ind1], flows[1].hops[ind2]);
}

bool isMultiPath(LBReg &lbReg) {
    return (lbReg.link.type == CMPL_MULTI_PATH || 
            lbReg.link.type == INCMPL_MULTI_PATH);
}

double
LBRegDiffHelper(vector<Flow> &flows, vector<LBReg> &lbRegs, int ind1, int ind2) 
{
    int i, j;
    Hop start, mid1, mid2, end;

    mid1 = lbRegs[ind1].start;
    if (ind1 == 0 || isMultiPath(lbRegs[ind1-1])) {
        start = mid1; 
    } else {
        start = lbRegs[ind1-1].start;
    }

    mid2 = lbRegs[ind2].end;
    if (ind2 == lbRegs.size() - 1 || isMultiPath(lbRegs[ind2+1])) {
        end = mid2;
    } else {
        end = lbRegs[ind2+1].end;
    }

    pair<Hop, Hop> p1 = selHop(flows, mid1, start, -1);
    pair<Hop, Hop> p2 = selHop(flows, mid2, end, 1);

    if (p1.first.cnt == 0 || p1.second.cnt == 0 || 
        p2.first.cnt == 0 || p2.second.cnt == 0) {
        return -1;
    }

    return (p2.second.val - p1.second.val) - (p2.first.val - p1.first.val);
}

double
Graph::calcLBRegDiff(vector<Flow> &flows, vector<LBReg> &lbRegs)
{
	int i;
    int firstLB = -1, lastLB = -1;

	for (i = 0; i < lbRegs.size(); i++) {

		//if (lbRegs[i].link.type == INCMPL_SINGLE_PATH ||
        //    lbRegs[i].link.type == CMPL_SINGLE_PATH) 
        //    continue;
        
        if (firstLB == -1) firstLB = i;
        lastLB = i;

        lbRegs[i].link.val = LBRegDiffHelper(flows, lbRegs, i, i);
    }

    if (firstLB != -1 && lastLB != -1)
        return LBRegDiffHelper(flows, lbRegs, firstLB, lastLB);

	return -1;
}

void
Graph::printGraph(uint32_t id, ostream *out) {

    if (!out || !root) return;

    queue<pair<Node *, int>> q;
    q.push(make_pair(root, 0));
    unordered_map<uint32_t, bool> visited;
    
    *out << fixed << getCurrTime() << " " << id << " " << "2" << " ";
    while (!q.empty()) {
        Node *n = q.front().first;
        int level = q.front().second;
        q.pop();

        if (visited.count(n->hop.ip) == 0) {
            *out << n->hop.ip << " " << (int)n->hop.fwdttl << " "; 
            //printf("level:%d, ip:%lu ttls:", level, n->hop.ip);
            //for (int i = 0; i < NUM_FLOWS_ENUM; i++)
            //    printf("%d ", n->ttls[i]);
            //printf("indegree:%d\n", n->indegree);
            visited[n->hop.ip] = 1;

            //printf("Link: ");
            //for (auto &link : n->links) {
            //    printf("%d ", link.type);
            //}
            //printf("\n");
        }
        for (auto &h : n->nextHops) {
            q.push(make_pair(h, level + 1)); 
        }
    }
    *out << endl;
}

Node *
Graph::addHop(Node *curr, int flowid, Hop &h) {
    Node *node;

    node = findNodeInGraph(h.ip, root);
    if (!node) {
        node = new Node(h);
        curr->nextHops.push_back(node); 
    } else {
        if (h.val < node->hop.val) {
            node->hop.val = h.val;
            node->hop.cnt = h.cnt;
        } else if (h.val == node->hop.val) {
            node->hop.cnt = max(node->hop.cnt, h.cnt);
        }

        // curr: curr node
        // node: next node
        if (curr->hop.ip == node->hop.ip) 
            return curr;
        if (findNodeInGraph(curr->hop.ip, node))
            return NULL;

        vector<Node *>::iterator it;
        it = find(curr->nextHops.begin(), curr->nextHops.end(), node);
        if (it == curr->nextHops.end()) {
            curr->nextHops.push_back(node);
        } else {
            int index = distance(curr->nextHops.begin(), it);
            if (h.fwdttl - curr->hop.fwdttl == 1 && 
                    curr->links[index].type == INDIRECT_LINK) 
            {
                curr->links[index].type = DIRECT_LINK;
                curr->links[index].val  = flowid;
            }
            node->ttls[flowid] = h.fwdttl;
            return node;
        }
    }
    node->ttls[flowid] = h.fwdttl;
    if (h.fwdttl - curr->hop.fwdttl == 1) {
        curr->links.push_back(Link(DIRECT_LINK, flowid));
    } else {
        curr->links.push_back(Link(INDIRECT_LINK, flowid));
    }
    return node;
}

/*
vector<Flow>
enumPath(Node *t, uint32_t dst, unordered_map<uint32_t, bool> &v) {

    Flow f;
    vector<Flow> paths, subpaths;

    v[t->hop.ip] = true;
    f.hops.push_back(Hop(t->hop.ip, t->hop.ttl));

    if (t->hop.ip == dst) {
        paths.push_back(f);
    } else {
        for (auto &n : t->nextHops) {
            if (v.count(t->hop.ip) == 0 || !v[t->hop.ip]) {
                subpaths = enumPath(n, dst, v);
                insert(paths.end(), subpaths.begin(), subpaths.end());
            }
        }
    }

    f.hops.pop_back();
    v[t->hop.ip] = false;

    return paths;
}
*/

bool
subpathExist(vector<Hop> &subpath, vector<vector<Hop>> &subpaths) {
    bool same;
    for (auto &s : subpaths) {
        if (subpath.size() != s.size()) continue;
        same = true;
        for (int i = 0; i < subpath.size(); i++) {
            if (subpath[i].ip != s[i].ip) {
                same = false;
                break;
            }
        }
        if (same) return true;
    }
    return false;
}

vector<vector<Hop>> 
findUniqPaths(vector<Flow> &flows, uint32_t src, uint32_t dst) {
    int i;
    vector<vector<Hop>> subpaths;
    
    for (i = 0; i < flows.size(); i++) {
        vector<Hop> subpath;
        bool start = false, end = false;
        for (auto hop : flows[i].hops) {
            if (hop.ip == src)
                start = true;
            if (hop.ip == dst)
                end = true;
            hop.cnt = i;
            if (start) subpath.push_back(hop);
            if (end) break;
        }

        if (!start || !end) continue;
        if (subpathExist(subpath, subpaths)) continue;
        subpaths.push_back(subpath);
    }

    return subpaths;
}

void
pruneIndirectLinks(Node *t, vector<Flow> flows, unordered_map<uint32_t, bool> &visited) {

    if (!t || t->nextHops.empty() || visited.count(t->hop.ip))
        return;

    visited[t->hop.ip] = true;

    int i, j;
    vector<int> sel;

    for (i = 0; i < t->links.size(); i++) {
        if (t->links[i].type == INDIRECT_LINK) {
            vector<int> target;
            int index = t->links[i].val;
            int ttldiff = t->nextHops[i]->ttls[index] - t->ttls[index];
            for (j = 0; j < NUM_FLOWS_ENUM; j++) {
                if (t->nextHops[i]->ttls[j] - t->ttls[j] == ttldiff) { 
                    target.push_back(j);
                }
            }
            vector<Flow> targetFlows;
            vector<vector<Hop>> paths; 

            for (auto j : target) 
                targetFlows.push_back(flows[j]);
            paths = findUniqPaths(targetFlows, t->hop.ip, t->nextHops[i]->hop.ip);

            if (paths.size() > 1) {
                sel.push_back(i);
            }
        }
    }

    for (i = sel.size() - 1; i >= 0; i--) {
        t->links.erase(t->links.begin() + sel[i]);
        t->nextHops.erase(t->nextHops.begin() + sel[i]);
    }

    for (i = 0; i < t->nextHops.size(); i++) {
        t->nextHops[i]->indegree++;
        pruneIndirectLinks(t->nextHops[i], flows, visited);
    }
}

/*
void
pruneDanglingBranch(uint32_t dst, Node *t) {
    if (t->nextHops.empty()) { return; }
    vector<Node *> nextHops = t->nextHops;
    ptrdiff_t pos; 
    for (auto &n : nextHops) {
        if (n->nextHops.empty() && n->hop.ip != dst) {
            pos = find(t->nextHops.begin(), t->nextHops.end(), n) - t->nextHops.begin();
            t->nextHops.erase(it);
            t->links.erase();
            free(n);
        }
    }

    for (auto &n : t->nextHops) {
        pruneDanglingBranch(dst, n);
    }
}
*/

int
countEnds(Node *t, unordered_map<uint32_t, bool> &visited) {
    int i, count = 0;

    if (visited.count(t->hop.ip)) { return 0; }

    visited[t->hop.ip] = true;

    if (t->nextHops.empty()) { return 1; } 

    for (i = 0; i < t->nextHops.size(); i++)
        count += countEnds(t->nextHops[i], visited);

    return count;
}

void
pruneMultipleEnds(Node *t, 
                  uint32_t dst, 
                  set<Node *> &deletedNodes, 
                  unordered_map<uint32_t, bool> &visited) 
{
    int i;

    if (!t || visited.count(t->hop.ip) || t->nextHops.empty()) { return; }

    visited[t->hop.ip] = true;

    for (i = 0; i < t->nextHops.size(); i++) {
        Node *node = t->nextHops[i];
        if (node->nextHops.empty() && node->hop.ip != dst) {
            deletedNodes.insert(node);
            t->links.erase(t->links.begin() + i);
            t->nextHops.erase(t->nextHops.begin() + i);
        } else {
            pruneMultipleEnds(node, dst, deletedNodes, visited);
        }
    }
}

void
calcIndegree(Node *t, unordered_map<uint32_t, bool> &visited) {

    if (!t || t->nextHops.empty() || visited.count(t->hop.ip))
        return;

    visited[t->hop.ip] = true;

    int i;

    for (i = 0; i < t->nextHops.size(); i++) {
        t->nextHops[i]->indegree++;
        calcIndegree(t->nextHops[i], visited);
    }
}



void
Graph::buildGraph(uint32_t dst, vector<Flow> flows) {
    int i, j;
    Node *curr;
    unordered_map<uint32_t, bool> visited;

    // add destination
    Hop endHop(dst, UINT8_MAX);
    // for not being considered as no measurements
    endHop.cnt = 6;
    endHop.val = UINT16_MAX;
    for (auto &f : flows) {
        if (f.hops.size() > 0 && f.hops.back().ip == dst)
            continue;
        f.hops.insert(f.hops.end(), endHop);
    }

    // Construct the graph
    for (i = 0; i < flows.size(); i++) {
        if (flows[i].hops.empty()) continue;
        if (!root) {
            root = new Node(flows[i].hops[0]);
            curr = root;
        } else {
            curr = findNodeInGraph(flows[i].hops[0].ip, root);
            if (!curr) { continue; } 
        }
        for (j = 1; j < flows[i].hops.size(); j++) {
            curr = addHop(curr, i, flows[i].hops[j]);
            if (curr == NULL) break;
        }
    }

    // printGraph(dst, &std::cout);

    calcIndegree(root, visited);

    // pruneIndirectLinks(root, flows, visited);
    
    /*
    uint32_t lasthop = 0;
    for (auto &f : flows) {
        if (f.hops.back().ip == dst)
            lasthop = dst;
    }
    if (lasthop == 0) {
        int hopcount = 0;
        for (i = 0; i < flows.size(); i++) {
            if (hopcount <= flows[i].hops.back().ttl) {
                hopcount = flows[i].hops.back().ttl;
                lasthop = flows[i].hops.back().ip; 
            }
        }
    }

    set<Node *> newNodes, totalNodes;

    do {
        visited.clear();
        newNodes.clear();
        pruneMultipleEnds(root, lasthop, newNodes, visited);
        totalNodes.insert(newNodes.begin(), newNodes.end());
    } while (!newNodes.empty());

    for (auto &node : totalNodes)
        delete node;
    */

    // printGraph(dst, &std::cout);
}

vector<LBReg> 
Graph::findLBReg(uint32_t dst, vector<Flow> &flows, ofstream *outlist) {
    int i, j;
    vector<LBReg> lbRegs;

    buildGraph(dst, flows);
    
    // printGraph(dst, outlist);

    //printf("after pruning\n");
    //g.printGraph();

    // if a graph has multiple ends, no bottleneck point can be
    // determined. Thus, no second LB reg is identifiable.
    //unordered_map<uint32_t, bool> visited;
    //int numEnds = countEnds(g.getRoot(), visited);

    //printf("numEnds:%d\n", numEnds);

    /* find LB regions */
    queue<Node *> q; 
    set<Node *> boundaryIPs;
    Node *u;
    bool hopJump = false;
    LINK_TYPE linkType;
    Node *singlePathStart, *multiPathStart;

#define SINGLE_PATH 0
#define MULTI_PATH 1
#define UNKNOWN -1

    int lbType = UNKNOWN;
    singlePathStart = multiPathStart = NULL;
    // enqueue vertices with indegree 0
    if (root) {
        q.push(root);
        boundaryIPs.insert(root);
    }

    while (!q.empty()) {

        /*
        queue<Node *> p = q; 
        printf("queue:");
        while (!p.empty()) {
            Node *w = p.front();
            p.pop();
            printf("%lu ", w->hop.ip);
        }
        printf(" set: ");
        for (set<Node *>::iterator it = boundaryIPs.begin(); it != boundaryIPs.end(); it++) {
            printf("%lu ", (*it)->hop.ip);
        }
        printf("\n");
        */

        u = q.front();
        q.pop();
        boundaryIPs.erase(boundaryIPs.find(u));

        if (lbType == UNKNOWN && u->nextHops.size() == 1) {
            lbType = SINGLE_PATH;
            singlePathStart = u;
        }
        if (u->nextHops.size() > 1) {
            if (lbType == SINGLE_PATH) {
                linkType = (hopJump) ? INCMPL_SINGLE_PATH : CMPL_SINGLE_PATH;
                lbRegs.push_back(LBReg(singlePathStart->hop, u->hop, linkType));
                lbType = UNKNOWN;
                hopJump = false;
            }
            if (lbType == UNKNOWN) {
                multiPathStart = u;
            }
            lbType = MULTI_PATH;
        }

        for (i = 0; i < u->nextHops.size(); i++) {
            Node *n = u->nextHops[i];
            boundaryIPs.insert(n);
            if (--n->indegree == 0)
                q.push(n);
            if (u->links[i].type == INDIRECT_LINK)
                hopJump = true;
        }

        if (boundaryIPs.size() == 1) {
            if (lbType == MULTI_PATH) {
                linkType = (hopJump) ? INCMPL_MULTI_PATH : CMPL_MULTI_PATH;            
			    lbRegs.push_back(LBReg(multiPathStart->hop, (*boundaryIPs.begin())->hop, linkType));
                lbType = UNKNOWN;
                hopJump = false;
            }
        }
    }
    if (singlePathStart != u && lbType == SINGLE_PATH) {
        linkType = (hopJump) ? INCMPL_SINGLE_PATH : CMPL_SINGLE_PATH;            
        lbRegs.push_back(LBReg(singlePathStart->hop, u->hop, linkType));
    }

    return lbRegs;
}

/*
vector<LBReg> Graph::findLBReg(vector<Flow> &flows, int16_t &totalRange, ANAL_MODE mode) {
	int i = 0, j = 0;
    Flow &f1 = flows[0];
    Flow &f2 = flows[1];
	vector<LBReg> LBRegs;

    if (f1.hops.size() == 0 || f2.hops.size() == 0) return LBRegs;

    bool cmmLastHop, hopJump = false;
	Hop firstCmmHop = f1.hops[0], lastCmmHop = firstCmmHop;
	while (i < f1.hops.size() && j < f2.hops.size()) {
		if (f1.hops[i].ip == f2.hops[j].ip) {
			lastCmmHop = f1.hops[i];
            lastCmmHop.val = (f1.hops[i].val + f2.hops[j].val) / 2;
            hopJump = hopJump || (hasHopJump(f1, 0, i, 1) || hasHopJump(f2, 0, j, 1));
            cmmLastHop = true;
			i++; j++;
		} else {
            cmmLastHop = false;
			if (firstCmmHop.ip != lastCmmHop.ip) {
                if (hopJump) { 
				    LBRegs.push_back(LBReg(firstCmmHop, lastCmmHop, INCMPL_SINGLE_PATH));
                } else {
				    LBRegs.push_back(LBReg(firstCmmHop, lastCmmHop, CMPL_SINGLE_PATH));
                }
            }
            
            hopJump = false;
			for (; i < f1.hops.size(); i++) {
                hopJump = hopJump || (hasHopJump(f1, 0, i, 1) || hasHopJump(f2, 0, j, 1));
				int k = sameHop(f2, f1.hops[i], j, hopJump);
				if (k != -1) {
					j = k; 
                    Hop nextCmmHop = f2.hops[j];
                    nextCmmHop.val = (f1.hops[i].val + f2.hops[j].val) / 2;

                    if (hopJump) {
					    LBRegs.push_back(LBReg(lastCmmHop, nextCmmHop, INCMPL_MULTI_PATH));
                    } else {
					    LBRegs.push_back(LBReg(lastCmmHop, nextCmmHop, CMPL_MULTI_PATH));
                    }

					firstCmmHop = lastCmmHop = nextCmmHop;
                    hopJump = false;
                    cmmLastHop = true;
					break;
				}
			}
		}
	}
	if (firstCmmHop.ip != lastCmmHop.ip && cmmLastHop) {
        if (hopJump) { 
		    LBRegs.push_back(LBReg(firstCmmHop, lastCmmHop, INCMPL_SINGLE_PATH));
        } else {
			LBRegs.push_back(LBReg(firstCmmHop, lastCmmHop, CMPL_SINGLE_PATH));
        }
    }
	
    if (mode == LB_ANALYSIS)
        totalRange = calcLBRegDiff(flows, LBRegs);
    // check if ranges at different LBRegs sum up to total
    //int sum = 0;
    //for (i = 0; i < LBRegs.size(); i++) {
    //    sum += isMultiPath(LBRegs[i]) ? LBRegs[i].link.val : 0;
    //}
    //if (abs(sum - lbRegRangeTotal) <= MEAS_ERROR)
    //    return LBRegs;

    //LBRegs.clear();
    return LBRegs; 
}
*/

Node *
findNodeHelper(uint32_t ip, Node *root, unordered_map<uint32_t, bool> &v) {
    
    if (!root || v.count(root->hop.ip)) 
        return NULL;

    v[root->hop.ip] = true;

	if (root->hop.ip == ip)
		return root;

	for (auto &next : root->nextHops) {
		Node *target = findNodeHelper(ip, next, v);
		if (target) return target;
	}

	return NULL;
}

Node *
Graph::findNodeInGraph(uint32_t ip, Node *root) {
    unordered_map<uint32_t, bool> visited;
    return findNodeHelper(ip, root, visited);
}

void Graph::updateGraph(vector<LBReg> &lbRegs) {
	Node *start = findNodeInGraph(lbRegs[0].start.ip, root);

	Node *node = start, *next;
	bool exist;

    if (!node) {
        next = new Node(lbRegs[0].start);
        root->nextHops.push_back(next);
        root->links.push_back(Link(INCMPL_SINGLE_PATH, 0));
        node = next;
    }
	for (int i = 0; i < lbRegs.size(); i++) {
		exist = false;
		for (int j = 0; j < node->nextHops.size(); j++) {
			next = node->nextHops[j];
			if (next->hop.ip == lbRegs[i].end.ip) {
				if (isMultiPath(lbRegs[i])) { 
					node->links[j].type = lbRegs[i].link.type;
                    if(abs(node->links[j].val) > abs(lbRegs[i].link.val)) {
                        node->links[j].val = lbRegs[i].link.val;
                    }
                }
				node = next;
				exist = true;
				break;
			}
		}
		if (!exist) {
			next = findNodeInGraph(lbRegs[i].end.ip, root);
			if (!next) next = new Node(lbRegs[i].end);
			node->nextHops.push_back(next);
			node->links.push_back(lbRegs[i].link);
			node = next;
		}
	}
	return;
}

// Flow
// findLBRouterHelper(Node *t, 
//                    vector<Flow> &flows, 
//                    unordered_map<Node *, bool> &visited)
// {
//     int i;
//     Flow routers;

//     if (visited.count(t)) return routers; 

//     visited[t] = true;

//     if (t->nextHops.size() > 1) {
//         for (i = 0; i < NUM_FLOWS_ENUM; i++) {
//             if (t->ttls[i] != 0) {
//                 Hop h(t->hop.ip, t->ttls[i]);
//                 h.val = i;
//                 h.numNextHops = t->nextHops.size();
//                 routers.hops.push_back(h);
//                 break;
//             }
//         }
//     }

//     for (auto &next : t->nextHops) {
//         Flow f = findLBRouterHelper(next, flows, visited);
//         routers.hops.insert(routers.hops.end(), f.hops.begin(), f.hops.end());
//     }

//     return routers;
// }

// Flow
// Graph::findLBRouter(uint32_t id, vector<Flow> &flows) {
//     buildGraph(id, flows);    
//     //printGraph();
//     unordered_map<Node *, bool> visited;
//     return findLBRouterHelper(root, flows, visited);
// }

void 
freeGraph(Node *t, unordered_map<Node *, bool> &visited) 
{
    int i;

    if (!t || visited.count(t)) return;

    visited[t] = true;

	for (auto &next : t->nextHops) {
		freeGraph(next, visited);
    }

	delete t;
    return;
}

Graph::~Graph() {
    unordered_map<Node *, bool> visited;
	freeGraph(root, visited);
}
