#ifndef RENESIS_H
#define RENESIS_H

#include "miner.h"

extern int renesis_test(unsigned char *pdata, const unsigned char *ptarget,
			uint32_t nonce);
extern void renesis_regenhash(struct work *work);

#endif /* RENESIS_H */
