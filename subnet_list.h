/****************************************************************************
   Program:     $Id: $
   Date:        $Date: $
   Description: subnet list 
****************************************************************************/

#ifndef SUBNET_LIST_H
#define SUBNET_LIST_H
#include <stdint.h>
#include <pthread.h>
#include <string>
#include <list>

#include "subnet.h"

using namespace std;

class SubnetList {
	public:
		SubnetList();
		virtual ~SubnetList();

		virtual void add_subnet(string s);
		virtual void add_subnet(uint32_t addr, uint8_t prefix);
		void normalize();

		bool exists(uint32_t addr);

        virtual uint32_t next_address(struct in_addr *in, uint8_t *ttl);
        uint32_t next_address(struct in6_addr *in, uint8_t *ttl) { return 0; };

		uint32_t count();

	protected:
		list<Subnet> subnets;
		uint32_t addr_count;

        uint16_t getHost(uint8_t *addr);
		bool restricted_address(Subnet& subnet);
		bool restricted_address(uint32_t min, uint32_t max);
    private:
        list<Subnet>::iterator current_subnet;
        uint32_t current_twentyfour; 
        uint8_t current_ttl; 
};

#endif /* SUBNET_LIST_H */
