/****************************************************************************
   Program:     $Id: yarrp.h 40 2016-01-02 18:54:39Z rbeverly $
   Date:        $Date: 2016-01-02 10:54:39 -0800 (Sat, 02 Jan 2016) $
   Description: yarrp header
****************************************************************************/

#if HAVE_CONFIG_H
  #include "config.h"
#endif

#ifndef _YRP_H_
#define _YRP_H_

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#ifndef __FAVOR_BSD
  #define  __FAVOR_BSD
#endif
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#ifdef _LINUX
  #include <linux/if_packet.h>
#endif
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <net/if.h>

#ifdef HAVE_NETINET_IP_VAR_H
  #include <netinet/ip_var.h>
#endif
#ifdef HAVE_NETINET_UDP_VAR_H
  #include <netinet/udp_var.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDINT_H
 #include <stdint.h>
#endif
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>

#ifdef HAVE_PTHREAD
 #include <pthread.h>
#endif

#include <iostream>
#include <vector>

#include "cperm.h" 

#define func() do {if (DEBUG) fprintf(stdout,"\t>> %s:%s():%d\n",__FILE__,__FUNCTION__,__LINE__); } while (0)
#define warn(x...) do {fprintf(stderr,"*** Warn: "); fprintf(stderr,x); fprintf(stderr,"\n");} while (0)
#define fatal(x...) do {fprintf(stderr,"*** Fatal: "); fprintf(stderr,x); fprintf(stderr,"\n"); exit(-1);} while (0)
#define debug(level,x...) do {if (verbose >= level) {printf(x);} } while (0)
#define PKTSIZE 1500
#define MAXNULLREADS 10
#define SHUTDOWN_WAIT 10
//#define SHUTDOWN_WAIT 300
#define KEYLEN 16
#ifndef UINT8_MAX
 #define UINT8_MAX (255)
 #define UINT16_MAX (65535)
 #define UINT32_MAX (4294967295U)
#endif
#define ETH_HDRLEN 14

unsigned short in_cksum(unsigned short *addr, int len);
int infer_my_ip(struct sockaddr_in *mei);
int infer_my_ip6(struct sockaddr_in6 *mei6);
int raw_sock(struct sockaddr_in *sin_orig);
int raw_sock6(struct sockaddr_in6 *sin6_orig);
u_short p_cksum(struct ip *ip, u_short *data, int len);
u_short p_cksum(struct ip6_hdr *ip, u_short *data, int len);
unsigned short compute_data(unsigned short start_cksum, unsigned short target_cksum);
void print_binary(const unsigned char *buf, int len, int brk, int tabs);
void *listener(void *args);
void *listener6(void *args);
uint32_t tsdiff(struct timeval *end, struct timeval *begin);
uint32_t tsdiffus(struct timeval *end, struct timeval *begin);
uint8_t randuint8();
bool checkRoot();
double decayprob(double t, uint32_t range);
double decayprob(int32_t t, uint32_t range);
double zrand();
void permseed(uint8_t *);
void permseed(uint8_t *, uint32_t);

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
extern pthread_rwlock_t gLock;

#include "yconfig.h"
#include "patricia.h"
#include "mac.h"
#include "stats.h"
#include "status.h"
#include "ttlhisto.h"
// #include "subnet_list.h"
// #include "random_list.h"
#include "trace.h"
#include "icmp.h"

void internet(YarrpConfig *config, Traceroute *trace, Patricia *tree, Stats *stats);

using namespace std;

#endif  /* _YRP_H_ */
