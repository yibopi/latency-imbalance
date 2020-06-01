/****************************************************************************
   Program:     $Id: $
   Date:        $Date: $
   Description: random subnet list
****************************************************************************/
#include "flipr.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <cperm.h>

#include "random_list.h"


RandomSubnetList::RandomSubnetList():SubnetList() {
    seeded = false;
    perm = NULL;
}

RandomSubnetList::~RandomSubnetList() {
    if (perm)
        cperm_destroy(perm);
}

void            
RandomSubnetList::seed() {
    uint8_t buffer[16];
    PermMode mode = PERM_MODE_CYCLE;

    /*
     * Switch to libperm's prefix mode if the total number of hosts to scan
     * is less than 50000. This number is completely arbitrary. The choice is
     * a time/space tradeoff. More testing should be done to select the right
     * switchover point.
     */
    if (addr_count < 500000) {
        //printf("Switching to prefix mode.\n");
        mode = PERM_MODE_PREFIX;
    }
    perm = cperm_create(addr_count, mode, PERM_CIPHER_RC5, buffer, 16);
    if (!perm) {
        printf("Failed to initialize permutation of size %u. Code: %d\n", addr_count, cperm_get_last_error());
        exit(1);
    }
    seeded = true;
}

uint32_t        
RandomSubnetList::next_address(struct in_addr *in, uint8_t * ttl) {
    list < Subnet >::iterator iter;
    uint32_t next, subnet_count, current = 0;
    uint32_t addr, offset;

    if (!seeded)
        seed();

    if (PERM_END == cperm_next(perm, &next))
        return 0;

    for (iter = subnets.begin(); iter != subnets.end(); iter++) {
        subnet_count = (*iter).count();
        if (next >= current && next < current + subnet_count) {
            offset = next - current;
            *ttl = (offset & 0x1f) + 1;
            //uint32_t net = offset >> 5;
            //printf("Offset %02x TTL: %02x Net: %02x\n", offset, *ttl, net);
            //addr = (*iter).first() + (net << 8);
            addr = (*iter).first() + (offset << 3);
            addr = addr & 0xffffff00;
            addr += getHost((uint8_t *) & addr);
            in->s_addr = htonl(addr);
        }
        current += subnet_count;
    }
    return 1;
}

uint16_t        
RandomSubnetList::getHost(uint8_t * addr) {
    uint16_t sum = addr[0] + addr[1] + addr[2] + addr[3] + 127;
    return sum & 0xff;
}
