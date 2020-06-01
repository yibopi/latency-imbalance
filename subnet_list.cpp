/****************************************************************************
   Program:     $Id: $
   Date:        $Date: $
   Description: subnet list
****************************************************************************/
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <string>
#include <list>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>

#include "subnet_list.h"

using namespace std;

SubnetList::SubnetList() {
    addr_count = 0;
    current_twentyfour = 0;
    current_ttl = 1;
};

SubnetList::~SubnetList() {
};

void            
SubnetList::add_subnet(string s) {
    Subnet subnet = Subnet(s);
    subnets.push_back(subnet);
    current_subnet = subnets.begin();
    addr_count += subnet.count();
}

void
SubnetList::add_subnet(uint32_t addr, uint8_t prefix) {
    Subnet subnet = Subnet(addr, prefix);
    subnets.push_back(subnet);
    addr_count += subnet.count();
}

uint32_t
SubnetList::next_address(struct in_addr *in, uint8_t * ttl) {
    if (current_subnet == subnets.end()) {
        return 0;
    }
    in->s_addr = htonl((*current_subnet).first() + (current_twentyfour << 8) + getHost(0));
    *ttl = current_ttl;
    if (++current_ttl > 32) {
        current_ttl = 1;
        current_twentyfour += 1;
    }
    if (current_twentyfour >= (*current_subnet).count() >> 5) {
        current_twentyfour = 0;
        current_subnet++;
    }
    return 1;
}

uint32_t
SubnetList::count() {
    return addr_count;
}

bool
SubnetList::exists(uint32_t addr) {
    list < Subnet >::iterator iter = subnets.begin();
    while (iter != subnets.end()) {
        if ((*iter).exists(addr)) {
            return true;
        }
        iter++;
    }
    return false;
}

uint16_t        
SubnetList::getHost(uint8_t * addr) {
    return 1;
}
