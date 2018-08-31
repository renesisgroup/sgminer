/* Renesis By DrZeck*/

#include "config.h"
#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#include "sph/sph_skein.h"
#include "sph/sph_keccak.h"
#include "sph/sph_simd.h"
#include "sph/sph_shavite.h"
#include "sph/sph_jh.h"
#include "sph/sph_cubehash.h"
#include "sph/sph_fugue.h"
#include "sph/sph_gost.h"


typedef struct {
	
    sph_skein512_context    skein1;
    sph_keccak512_context   keccak1;
    sph_simd512_context     simd1;
    sph_shavite512_context  shavite1;
    sph_jh512_context       jh1;
    sph_cubehash512_context cubehash1;
    sph_fugue512_context    fugue1;
    sph_gost512_context	    gost1;
	
}   Xhash_context_holder;

static Xhash_context_holder base_contexts;

static void init_Xhash_contexts()
{
    sph_skein512_init(&base_contexts.skein1);
    sph_keccak512_init(&base_contexts.keccak1);
    sph_simd512_init(&base_contexts.simd1);
    sph_shavite512_init(&base_contexts.shavite1);
    sph_jh512_init(&base_contexts.jh1);
    sph_cubehash512_init(&base_contexts.cubehash1);
    sph_fugue512_init(&base_contexts.fugue1);
    sph_gost512_init(&base_contexts.gost1);
}

static inline void xhash(void *state, const void *input)
{
    init_Xhash_contexts();

    Xhash_context_holder ctx;

    uint32_t hashA[16];

    memcpy(&ctx, &base_contexts, sizeof(base_contexts));

    sph_skein512(&ctx.skein1, input, 80);
    sph_skein512_close(&ctx.skein1, hashA);
	
	sph_keccak512(&ctx.keccak1, hashA, 64);
    sph_keccak512_close(&ctx.keccak1, hashA);
	
	sph_simd512(&ctx.simd1, hashA, 64);
    sph_simd512_close(&ctx.simd1, hashA);
	
	sph_shavite512(&ctx.shavite1, hashA, 64);
    sph_shavite512_close(&ctx.shavite1, hashA);
	
	sph_jh512(&ctx.jh1, hashA, 64);
	sph_jh512_close(&ctx.jh1, hashA);

    sph_cubehash512(&ctx.cubehash1, hashA, 64);
    sph_cubehash512_close(&ctx.cubehash1, hashA);

    sph_fugue512(&ctx.fugue1, hashA, 64);
    sph_fugue512_close(&ctx.fugue1, hashA);
    
    sph_gost512(&ctx.gost1, hashA, 64);
    sph_gost512_close(&ctx.gost1, hashA);

    memcpy(state, hashA, 32);
}

static const uint32_t diff1targ = 0x0000ffff;

int renesis_test(unsigned char *pdata, const unsigned char *ptarget, uint32_t nonce)
{
	uint32_t tmp_hash7, Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	uint32_t data[20], ohash[8];

	be32enc_vect(data, (const uint32_t *)pdata, 19);
	data[19] = htobe32(nonce);
	xhash(ohash, data);
	tmp_hash7 = be32toh(ohash[7]);

	applog(LOG_DEBUG, "htarget %08lx diff1 %08lx hash %08lx",
				(long unsigned int)Htarg,
				(long unsigned int)diff1targ,
				(long unsigned int)tmp_hash7);
	if (tmp_hash7 > diff1targ)
		return -1;
	if (tmp_hash7 > Htarg)
		return 0;
	return 1;
}

void renesis_regenhash(struct work *work)
{
        uint32_t data[20];
        uint32_t *nonce = (uint32_t *)(work->data + 76);
        uint32_t *ohash = (uint32_t *)(work->hash);

        be32enc_vect(data, (const uint32_t *)work->data, 19);
        data[19] = htobe32(*nonce);
        xhash(ohash, data);
}

bool scanhash_renesis(struct thr_info *thr, const unsigned char __maybe_unused *pmidstate,
		     unsigned char *pdata, unsigned char __maybe_unused *phash1,
		     unsigned char __maybe_unused *phash, const unsigned char *ptarget,
		     uint32_t max_nonce, uint32_t *last_nonce, uint32_t n)
{
	uint32_t *nonce = (uint32_t *)(pdata + 76);
	uint32_t data[20];
	uint32_t tmp_hash7;
	uint32_t Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	bool ret = false;

	be32enc_vect(data, (const uint32_t *)pdata, 19);

	while(1) {
		uint32_t ostate[8];

		*nonce = ++n;
		data[19] = (n);
		xhash(ostate, data);
		tmp_hash7 = (ostate[7]);

		applog(LOG_INFO, "data7 %08lx",
					(long unsigned int)data[7]);

		if (unlikely(tmp_hash7 <= Htarg)) {
			((uint32_t *)pdata)[19] = htobe32(n);
			*last_nonce = n;
			ret = true;
			break;
		}

		if (unlikely((n >= max_nonce) || thr->work_restart)) {
			*last_nonce = n;
			break;
		}
	}

	return ret;
}



