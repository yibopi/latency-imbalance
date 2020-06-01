#include "flipr.h"
#include "random_list.h"

IPList::IPList(uint8_t _maxttl, bool _rand) {
  perm = NULL;
  permsize = 0;
  maxttl = _maxttl;
  ttlbits = log2(maxttl);
  ttlmask = 0xffffffff >> (32 - ttlbits);
  rand = _rand;
  memset(key, 0, KEYLEN);
  //std::cout << ">> MAXTTL: " << int(maxttl) << " TTLBits: " << int(ttlbits) << std::endl;
  //printf("ttlmask: %02x\n", ttlmask);
}

void IPList::setkey(int seed) {
    cout << ">> Randomizing permutation key (seed: " << seed << ")." << endl;
    if (seed)
      permseed(key, seed);
    else
      permseed(key);
}

IPList4::~IPList4() {
  targets.clear();
  cperm_destroy(perm);
}

IPList6::~IPList6() {
  targets.clear();
  cperm_destroy(perm);
}

/* seed */
void IPList4::seed() {
  PermMode mode = PERM_MODE_CYCLE;
  assert(targets.size() > 0);
  permsize = targets.size() * maxttl;
  if (permsize < 500000) 
    mode = PERM_MODE_PREFIX;
  perm = cperm_create(permsize, mode, PERM_CIPHER_RC5, key, 16);
  assert(perm);
}

void IPList6::seed() {
  PermMode mode = PERM_MODE_PREFIX;
  assert(targets.size() > 0);
  permsize = targets.size() * maxttl;
  if (permsize < 500000) 
    mode = PERM_MODE_PREFIX;
  perm = cperm_create(permsize, mode, PERM_CIPHER_SPECK, key, 8);
  assert(perm);
}

/* log_2(x) lookup table */
uint8_t IPList::log2(uint8_t x) {
  if (x == 64)
    return 6;
  else if (x == 32)
    return 5;
  else if (x == 16)
    return 4;
  else if (x == 8)
    return 3;
  else if (x == 4)
    return 2;
  else if (x == 2)
    return 1;
  else
    assert(false);
}


uint32_t IPList4::next_address(struct in_addr *in, uint8_t * ttl) {
  if (rand) 
    return next_address_rand(in, ttl);
  else
    return next_address_seq(in, ttl);
}

/* sequential next address */
uint32_t IPList4::next_address_seq(struct in_addr *in, uint8_t * ttl) {
  static std::vector<uint32_t>::iterator iter = targets.begin();
  static uint32_t last_addr = *iter;
  static uint8_t  last_ttl = 0;

  if (last_ttl + 1 > maxttl) {
    iter++;
    if (iter == targets.end())
      return 0;
    last_ttl = 0;
    last_addr = *(iter);
  }
  last_ttl+=1;
  *ttl = last_ttl;
  in->s_addr = last_addr;
  return 1;
}

/* random next address */
uint32_t IPList4::next_address_rand(struct in_addr *in, uint8_t * ttl) {
  static uint32_t next = 0;

  if (permsize == 0)
    seed();

  if (PERM_END == cperm_next(perm, &next))
    return 0;

  in->s_addr = targets[next >> ttlbits];
  *ttl = (next & ttlmask)  + 1;
  return 1;
}

/* Read list of input IPs */
void IPList4::read(char *in) {
  std::ifstream inlist(in);
  std::string line;
  struct in_addr addr;
  while (getline(inlist, line)) {
    assert(inet_aton(line.c_str(), &addr) == 1);
    targets.push_back(addr.s_addr);
  }
  if (permsize == 0)
    seed();
  std::cout << ">> Populated target list: " << targets.size() << std::endl;
}

uint32_t IPList6::next_address(struct in6_addr *in, uint8_t * ttl) {
  if (rand) 
    return next_address_rand(in, ttl);
  else
    return next_address_seq(in, ttl);
}

/* sequential next address */
uint32_t IPList6::next_address_seq(struct in6_addr *in, uint8_t * ttl) {
  static std::vector<struct in6_addr>::iterator iter = targets.begin();
  static struct in6_addr last_addr = *iter;
  static uint8_t  last_ttl = 0;
  int i;

  if (last_ttl + 1 > maxttl) {
    iter++;
    if (iter == targets.end())
      return 0;
    last_ttl = 0;
    last_addr = *(iter);
  }
  last_ttl+=1;
  *ttl = last_ttl;
  for(i = 0; i < 16; i++)
    in->s6_addr[i] = last_addr.s6_addr[i];
  return 1;
}


/* random next address */
uint32_t IPList6::next_address_rand(struct in6_addr *in, uint8_t * ttl) {
  static uint32_t next = 0;

  if (permsize == 0)
    seed();

  if (PERM_END == cperm_next(perm, &next))
    return 0;

  *in = targets[next >> ttlbits];
  *ttl = (next & ttlmask)  + 1;
  return 1;
}

/* Read list of input IPs */
void IPList6::read(char *in) {
  std::ifstream inlist(in);
  std::string line;
  struct in6_addr addr;
  while (getline(inlist, line)) {
    assert(inet_pton(AF_INET6, line.c_str(), &addr) == 1);
    targets.push_back(addr);
  }  
  if (permsize == 0)
    seed();
  std::cout << ">> Populated target list: " << targets.size() << std::endl;
}

