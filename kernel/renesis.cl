/* Renesis By DrZeck */

#ifndef RENESIS_CL
#define RENESIS_CL

#if __ENDIAN_LITTLE__
#define SPH_LITTLE_ENDIAN 1
#else
#define SPH_BIG_ENDIAN 1
#endif

#define SPH_UPTR sph_u64

typedef unsigned int sph_u32;
typedef int sph_s32;
#ifndef __OPENCL_VERSION__
typedef unsigned long long sph_u64;
typedef long long sph_s64;
#else
typedef unsigned long sph_u64;
typedef long sph_s64;
#endif

#define SPH_64 1
#define SPH_64_TRUE 1

#define SPH_C32(x)    ((sph_u32)(x ## U))
#define SPH_T32(x)    ((x) & SPH_C32(0xFFFFFFFF))
#define SPH_ROTL32(x, n)   SPH_T32(((x) << (n)) | ((x) >> (32 - (n))))
#define SPH_ROTR32(x, n)   SPH_ROTL32(x, (32 - (n)))

#define SPH_C64(x)    ((sph_u64)(x ## UL))
#define SPH_T64(x)    ((x) & SPH_C64(0xFFFFFFFFFFFFFFFF))
#define SPH_ROTL64(x, n)   SPH_T64(((x) << (n)) | ((x) >> (64 - (n))))
#define SPH_ROTR64(x, n)   SPH_ROTL64(x, (64 - (n)))

#define SPH_KECCAK_64 1
#define SPH_JH_64 1
#define SPH_SIMD_NOCOPY 0
#define SPH_KECCAK_NOCOPY 0
#define SPH_CUBEHASH_UNROLL 0
#define SPH_KECCAK_UNROLL   0

#include "skein.cl"
#include "keccak.cl"
#include "simd.cl"
#include "shavite.cl"
#include "jh.cl"
#include "cubehash.cl"
#include "fugue.cl"
#include "streebog.cl"

#define SWAP4(x) as_uint(as_uchar4(x).wzyx)
#define SWAP8(x) as_ulong(as_uchar8(x).s76543210)

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global unsigned char* block, volatile __global uint* output, const ulong target)
{
  uint gid = get_global_id(0);
  union {
    unsigned char h1[64];
    uint h4[16];
    ulong h8[8];
  } hash;

  __local sph_u32 AES0[256], AES1[256], AES2[256], AES3[256];
  int init = get_local_id(0);
  int step = get_local_size(0);
  for (int i = init; i < 256; i += step)
  
  {
    AES0[i] = AES0_C[i];
    AES1[i] = AES1_C[i];
    AES2[i] = AES2_C[i];
    AES3[i] = AES3_C[i];
  }
  
  barrier(CLK_LOCAL_MEM_FENCE);

	// skein
  {
    sph_u64 h0 = SPH_C64(0x4903ADFF749C51CE), 
			h1 = SPH_C64(0x0D95DE399746DF03), 
			h2 = SPH_C64(0x8FD1934127C79BCE), 
			h3 = SPH_C64(0x9A255629FF352CB1), 
			h4 = SPH_C64(0x5DB62599DF6CA7B0), 
			h5 = SPH_C64(0xEABE394CA9D5C3F4), 
			h6 = SPH_C64(0x991112C71A75B523), 
			h7 = SPH_C64(0xAE18A40B660FCC33);
			
    sph_u64 m0, m1, m2, m3, m4, m5, m6, m7;
    sph_u64 bcount = 0;

    m0 = (block[0]);
    m1 = (block[1]);
    m2 = (block[2]);
    m3 = (block[3]);
    m4 = (block[4]);
    m5 = (block[5]);
    m6 = (block[6]);
    m7 = (block[7]);
	
    UBI_BIG(480, 64);
	
    bcount = 0;
	
    m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = 0;
	
    UBI_BIG(510, 8);
	
    hash.h8[0] = (h0);
    hash.h8[1] = (h1);
    hash.h8[2] = (h2);
    hash.h8[3] = (h3);
    hash.h8[4] = (h4);
    hash.h8[5] = (h5);
    hash.h8[6] = (h6);
    hash.h8[7] = (h7);
  }
	// keccak
  {
    sph_u64 a00 = 0, a01 = 0, a02 = 0, a03 = 0, a04 = 0;
    sph_u64 a10 = 0, a11 = 0, a12 = 0, a13 = 0, a14 = 0;
    sph_u64 a20 = 0, a21 = 0, a22 = 0, a23 = 0, a24 = 0;
    sph_u64 a30 = 0, a31 = 0, a32 = 0, a33 = 0, a34 = 0;
    sph_u64 a40 = 0, a41 = 0, a42 = 0, a43 = 0, a44 = 0;

    a10 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a20 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a31 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a22 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a23 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a04 = SPH_C64(0xFFFFFFFFFFFFFFFF);

    a00 ^= SWAP8(hash.h8[0]);
    a10 ^= SWAP8(hash.h8[1]);
    a20 ^= SWAP8(hash.h8[2]);
    a30 ^= SWAP8(hash.h8[3]);
    a40 ^= SWAP8(hash.h8[4]);
    a01 ^= SWAP8(hash.h8[5]);
    a11 ^= SWAP8(hash.h8[6]);
    a21 ^= SWAP8(hash.h8[7]);
    a31 ^= 0x8000000000000001;
	
    KECCAK_F_1600;
	    
    a10 = ~a10;
    a20 = ~a20;

    hash.h8[0] = SWAP8(a00);
    hash.h8[1] = SWAP8(a10);
    hash.h8[2] = SWAP8(a20);
    hash.h8[3] = SWAP8(a30);
    hash.h8[4] = SWAP8(a40);
    hash.h8[5] = SWAP8(a01);
    hash.h8[6] = SWAP8(a11);
    hash.h8[7] = SWAP8(a21);
  }
	// simd
  {
    s32 q[256];
    unsigned char x[128];
    for(unsigned int i = 0; i < 64; i++)
    x[i] = hash.h1[i];
    for(unsigned int i = 64; i < 128; i++)
    x[i] = 0;

    u32 A0 = C32(0x0BA16B95), A1 = C32(0x72F999AD), A2 = C32(0x9FECC2AE), A3 = C32(0xBA3264FC), A4 = C32(0x5E894929), A5 = C32(0x8E9F30E5), A6 = C32(0x2F1DAA37), A7 = C32(0xF0F2C558);
    u32 B0 = C32(0xAC506643), B1 = C32(0xA90635A5), B2 = C32(0xE25B878B), B3 = C32(0xAAB7878F), B4 = C32(0x88817F7A), B5 = C32(0x0A02892B), B6 = C32(0x559A7550), B7 = C32(0x598F657E);
    u32 C0 = C32(0x7EEF60A1), C1 = C32(0x6B70E3E8), C2 = C32(0x9C1714D1), C3 = C32(0xB958E2A8), C4 = C32(0xAB02675E), C5 = C32(0xED1C014F), C6 = C32(0xCD8D65BB), C7 = C32(0xFDB7A257);
    u32 D0 = C32(0x09254899), D1 = C32(0xD699C7BC), D2 = C32(0x9019B6DC), D3 = C32(0x2B9022E4), D4 = C32(0x8FA14956), D5 = C32(0x21BF9BD3), D6 = C32(0xB94D0943), D7 = C32(0x6FFDDC22);

    FFT256(0, 1, 0, ll1);
    for (int i = 0; i < 256; i ++) {
      s32 tq;

      tq = q[i] + yoff_b_n[i];
      tq = REDS2(tq);
      tq = REDS1(tq);
      tq = REDS1(tq);
      q[i] = (tq <= 128 ? tq : tq - 257);
    }

    A0 ^= hash.h4[0];
    A1 ^= hash.h4[1];
    A2 ^= hash.h4[2];
    A3 ^= hash.h4[3];
    A4 ^= hash.h4[4];
    A5 ^= hash.h4[5];
    A6 ^= hash.h4[6];
    A7 ^= hash.h4[7];
    B0 ^= hash.h4[8];
    B1 ^= hash.h4[9];
    B2 ^= hash.h4[10];
    B3 ^= hash.h4[11];
    B4 ^= hash.h4[12];
    B5 ^= hash.h4[13];
    B6 ^= hash.h4[14];
    B7 ^= hash.h4[15];

    ONE_ROUND_BIG(0_, 0,  3, 23, 17, 27);
    ONE_ROUND_BIG(1_, 1, 28, 19, 22,  7);
    ONE_ROUND_BIG(2_, 2, 29,  9, 15,  5);
    ONE_ROUND_BIG(3_, 3,  4, 13, 10, 25);

    STEP_BIG(
      C32(0x0BA16B95), C32(0x72F999AD), C32(0x9FECC2AE), C32(0xBA3264FC),
      C32(0x5E894929), C32(0x8E9F30E5), C32(0x2F1DAA37), C32(0xF0F2C558),
      IF,  4, 13, PP8_4_);
    STEP_BIG(
      C32(0xAC506643), C32(0xA90635A5), C32(0xE25B878B), C32(0xAAB7878F),
      C32(0x88817F7A), C32(0x0A02892B), C32(0x559A7550), C32(0x598F657E),
      IF, 13, 10, PP8_5_);
    STEP_BIG(
      C32(0x7EEF60A1), C32(0x6B70E3E8), C32(0x9C1714D1), C32(0xB958E2A8),
      C32(0xAB02675E), C32(0xED1C014F), C32(0xCD8D65BB), C32(0xFDB7A257),
      IF, 10, 25, PP8_6_);
    STEP_BIG(
      C32(0x09254899), C32(0xD699C7BC), C32(0x9019B6DC), C32(0x2B9022E4),
      C32(0x8FA14956), C32(0x21BF9BD3), C32(0xB94D0943), C32(0x6FFDDC22),
      IF, 25,  4, PP8_0_);

    u32 COPY_A0 = A0, COPY_A1 = A1, COPY_A2 = A2, COPY_A3 = A3, COPY_A4 = A4, COPY_A5 = A5, COPY_A6 = A6, COPY_A7 = A7;
    u32 COPY_B0 = B0, COPY_B1 = B1, COPY_B2 = B2, COPY_B3 = B3, COPY_B4 = B4, COPY_B5 = B5, COPY_B6 = B6, COPY_B7 = B7;
    u32 COPY_C0 = C0, COPY_C1 = C1, COPY_C2 = C2, COPY_C3 = C3, COPY_C4 = C4, COPY_C5 = C5, COPY_C6 = C6, COPY_C7 = C7;
    u32 COPY_D0 = D0, COPY_D1 = D1, COPY_D2 = D2, COPY_D3 = D3, COPY_D4 = D4, COPY_D5 = D5, COPY_D6 = D6, COPY_D7 = D7;

    #define q SIMD_Q

    A0 ^= 0x200;

    ONE_ROUND_BIG(0_, 0,  3, 23, 17, 27);
    ONE_ROUND_BIG(1_, 1, 28, 19, 22,  7);
    ONE_ROUND_BIG(2_, 2, 29,  9, 15,  5);
    ONE_ROUND_BIG(3_, 3,  4, 13, 10, 25);
    STEP_BIG(
      COPY_A0, COPY_A1, COPY_A2, COPY_A3,
      COPY_A4, COPY_A5, COPY_A6, COPY_A7,
      IF,  4, 13, PP8_4_);
    STEP_BIG(
      COPY_B0, COPY_B1, COPY_B2, COPY_B3,
      COPY_B4, COPY_B5, COPY_B6, COPY_B7,
      IF, 13, 10, PP8_5_);
    STEP_BIG(
      COPY_C0, COPY_C1, COPY_C2, COPY_C3,
      COPY_C4, COPY_C5, COPY_C6, COPY_C7,
      IF, 10, 25, PP8_6_);
    STEP_BIG(
      COPY_D0, COPY_D1, COPY_D2, COPY_D3,
      COPY_D4, COPY_D5, COPY_D6, COPY_D7,
      IF, 25,  4, PP8_0_);
    #undef q

    hash.h4[0] = A0;
    hash.h4[1] = A1;
    hash.h4[2] = A2;
    hash.h4[3] = A3;
    hash.h4[4] = A4;
    hash.h4[5] = A5;
    hash.h4[6] = A6;
    hash.h4[7] = A7;
    hash.h4[8] = B0;
    hash.h4[9] = B1;
    hash.h4[10] = B2;
    hash.h4[11] = B3;
    hash.h4[12] = B4;
    hash.h4[13] = B5;
    hash.h4[14] = B6;
    hash.h4[15] = B7;
  }
	// shavite
  {
    sph_u32 h0 = SPH_C32(0x72FCCDD8), h1 = SPH_C32(0x79CA4727), h2 = SPH_C32(0x128A077B), h3 = SPH_C32(0x40D55AEC);
    sph_u32 h4 = SPH_C32(0xD1901A06), h5 = SPH_C32(0x430AE307), h6 = SPH_C32(0xB29F5CD1), h7 = SPH_C32(0xDF07FBFC);
    sph_u32 h8 = SPH_C32(0x8E45D73D), h9 = SPH_C32(0x681AB538), hA = SPH_C32(0xBDE86578), hB = SPH_C32(0xDD577E47);
    sph_u32 hC = SPH_C32(0xE275EADE), hD = SPH_C32(0x502D9FCD), hE = SPH_C32(0xB9357178), hF = SPH_C32(0x022A4B9A);

    // state
    sph_u32 rk00, rk01, rk02, rk03, rk04, rk05, rk06, rk07;
    sph_u32 rk08, rk09, rk0A, rk0B, rk0C, rk0D, rk0E, rk0F;
    sph_u32 rk10, rk11, rk12, rk13, rk14, rk15, rk16, rk17;
    sph_u32 rk18, rk19, rk1A, rk1B, rk1C, rk1D, rk1E, rk1F;

    sph_u32 sc_count0 = (64 << 3), sc_count1 = 0, sc_count2 = 0, sc_count3 = 0;

    rk00 = hash.h4[0];
    rk01 = hash.h4[1];
    rk02 = hash.h4[2];
    rk03 = hash.h4[3];
    rk04 = hash.h4[4];
    rk05 = hash.h4[5];
    rk06 = hash.h4[6];
    rk07 = hash.h4[7];
    rk08 = hash.h4[8];
    rk09 = hash.h4[9];
    rk0A = hash.h4[10];
    rk0B = hash.h4[11];
    rk0C = hash.h4[12];
    rk0D = hash.h4[13];
    rk0E = hash.h4[14];
    rk0F = hash.h4[15];
    rk10 = 0x80;
    rk11 = rk12 = rk13 = rk14 = rk15 = rk16 = rk17 = rk18 = rk19 = rk1A = 0;
    rk1B = 0x2000000;
    rk1C = rk1D = rk1E = 0;
    rk1F = 0x2000000;

    c512(buf);

    hash.h4[0] = h0;
    hash.h4[1] = h1;
    hash.h4[2] = h2;
    hash.h4[3] = h3;
    hash.h4[4] = h4;
    hash.h4[5] = h5;
    hash.h4[6] = h6;
    hash.h4[7] = h7;
    hash.h4[8] = h8;
    hash.h4[9] = h9;
    hash.h4[10] = hA;
    hash.h4[11] = hB;
    hash.h4[12] = hC;
    hash.h4[13] = hD;
    hash.h4[14] = hE;
    hash.h4[15] = hF;
  }
	// jh
  {
  sph_u64 h0h = C64e(0x6fd14b963e00aa17), h0l = C64e(0x636a2e057a15d543), h1h = C64e(0x8a225e8d0c97ef0b), h1l = C64e(0xe9341259f2b3c361), h2h = C64e(0x891da0c1536f801e), h2l = C64e(0x2aa9056bea2b6d80), h3h = C64e(0x588eccdb2075baa6), h3l = C64e(0xa90f3a76baf83bf7);
  sph_u64 h4h = C64e(0x0169e60541e34a69), h4l = C64e(0x46b58a8e2e6fe65a), h5h = C64e(0x1047a7d0c1843c24), h5l = C64e(0x3b6e71b12d5ac199), h6h = C64e(0xcf57f6ec9db1f856), h6l = C64e(0xa706887c5716b156), h7h = C64e(0xe3c2fcdfe68517fb), h7l = C64e(0x545a4678cc8cdd4b);
  sph_u64 tmp;
  
  for(int i = 0; i < 8; ++i) hash.h8[i] = SWAP8(hash.h8[i]);
  
  for(int i = 0; i < 2; i++)
  {
  if (i == 0)
  {
    h0h ^= (hash.h8[0]);
    h0l ^= (hash.h8[1]);
    h1h ^= (hash.h8[2]);
    h1l ^= (hash.h8[3]);
    h2h ^= (hash.h8[4]);
    h2l ^= (hash.h8[5]);
    h3h ^= (hash.h8[6]);
    h3l ^= (hash.h8[7]);
  }
  else if(i == 1)
  {
    h4h ^= (hash.h8[0]);
    h4l ^= (hash.h8[1]);
    h5h ^= (hash.h8[2]);
    h5l ^= (hash.h8[3]);
    h6h ^= (hash.h8[4]);
    h6l ^= (hash.h8[5]);
    h7h ^= (hash.h8[6]);
    h7l ^= (hash.h8[7]);

    h0h ^= 0x80;
    h3l ^= 0x2000000000000;
  }
  E8;
  }
  h4h ^= 0x80;
  h7l ^= 0x2000000000000;

  hash.h8[0] = (h4h);
  hash.h8[1] = (h4l);
  hash.h8[2] = (h5h);
  hash.h8[3] = (h5l);
  hash.h8[4] = (h6h);
  hash.h8[5] = (h6l);
  hash.h8[6] = (h7h);
  hash.h8[7] = (h7l);
  }
	// cubehash
  {
    sph_u32 x0 = SPH_C32(0x2AEA2A61), x1 = SPH_C32(0x50F494D4), x2 = SPH_C32(0x2D538B8B), x3 = SPH_C32(0x4167D83E);
    sph_u32 x4 = SPH_C32(0x3FEE2313), x5 = SPH_C32(0xC701CF8C), x6 = SPH_C32(0xCC39968E), x7 = SPH_C32(0x50AC5695);
    sph_u32 x8 = SPH_C32(0x4D42C787), x9 = SPH_C32(0xA647A8B3), xa = SPH_C32(0x97CF0BEF), xb = SPH_C32(0x825B4537);
    sph_u32 xc = SPH_C32(0xEEF864D2), xd = SPH_C32(0xF22090C4), xe = SPH_C32(0xD0E5CD33), xf = SPH_C32(0xA23911AE);
    sph_u32 xg = SPH_C32(0xFCD398D9), xh = SPH_C32(0x148FE485), xi = SPH_C32(0x1B017BEF), xj = SPH_C32(0xB6444532);
    sph_u32 xk = SPH_C32(0x6A536159), xl = SPH_C32(0x2FF5781C), xm = SPH_C32(0x91FA7934), xn = SPH_C32(0x0DBADEA9);
    sph_u32 xo = SPH_C32(0xD65C8A2B), xp = SPH_C32(0xA5A70E75), xq = SPH_C32(0xB1C62456), xr = SPH_C32(0xBC796576);
    sph_u32 xs = SPH_C32(0x1921C8F7), xt = SPH_C32(0xE7989AF1), xu = SPH_C32(0x7795D246), xv = SPH_C32(0xD43E3B44);

    x0 ^= SWAP4(hash.h4[1]);
    x1 ^= SWAP4(hash.h4[0]);
    x2 ^= SWAP4(hash.h4[3]);
    x3 ^= SWAP4(hash.h4[2]);
    x4 ^= SWAP4(hash.h4[5]);
    x5 ^= SWAP4(hash.h4[4]);
    x6 ^= SWAP4(hash.h4[7]);
    x7 ^= SWAP4(hash.h4[6]);

    for (int i = 0; i < 13; i ++) {
	
      SIXTEEN_ROUNDS;

      if (i == 0) {
        x0 ^= SWAP4(hash.h4[9]);
        x1 ^= SWAP4(hash.h4[8]);
        x2 ^= SWAP4(hash.h4[11]);
        x3 ^= SWAP4(hash.h4[10]);
        x4 ^= SWAP4(hash.h4[13]);
        x5 ^= SWAP4(hash.h4[12]);
        x6 ^= SWAP4(hash.h4[15]);
        x7 ^= SWAP4(hash.h4[14]);
      } else if(i == 1) {
        x0 ^= 0x80;
      } else if (i == 2) {
        xv ^= SPH_C32(1);
      }
    }

    hash.h4[0] = x0;
    hash.h4[1] = x1;
    hash.h4[2] = x2;
    hash.h4[3] = x3;
    hash.h4[4] = x4;
    hash.h4[5] = x5;
    hash.h4[6] = x6;
    hash.h4[7] = x7;
    hash.h4[8] = x8;
    hash.h4[9] = x9;
    hash.h4[10] = xa;
    hash.h4[11] = xb;
    hash.h4[12] = xc;
    hash.h4[13] = xd;
    hash.h4[14] = xe;
    hash.h4[15] = xf;
  }
	// fugue
  {
    
  __local sph_u32 mixtab0[256], mixtab1[256], mixtab2[256], mixtab3[256];
  int init = get_local_id(0);
  int step = get_local_size(0);
  for (int i = init; i < 256; i += step)
  {
    mixtab0[i] = mixtab0_c[i];
    mixtab1[i] = mixtab1_c[i];
    mixtab2[i] = mixtab2_c[i];
    mixtab3[i] = mixtab3_c[i];
  }
    sph_u32 S00, S01, S02, S03, S04, S05, S06, S07, S08, S09;
    sph_u32 S10, S11, S12, S13, S14, S15, S16, S17, S18, S19;
    sph_u32 S20, S21, S22, S23, S24, S25, S26, S27, S28, S29;
    sph_u32 S30, S31, S32, S33, S34, S35;

    ulong fc_bit_count = (sph_u64) 64 << 3;

    S00 = S01 = S02 = S03 = S04 = S05 = S06 = S07 = S08 = S09 = S10 = S11 = S12 = S13 = S14 = S15 = S16 = S17 = S18 = S19 = 0;
    S20 = SPH_C32(0x8807a57e); S21 = SPH_C32(0xe616af75); S22 = SPH_C32(0xc5d3e4db); S23 = SPH_C32(0xac9ab027);
    S24 = SPH_C32(0xd915f117); S25 = SPH_C32(0xb6eecc54); S26 = SPH_C32(0x06e8020b); S27 = SPH_C32(0x4a92efd1);
    S28 = SPH_C32(0xaac6e2c9); S29 = SPH_C32(0xddb21398); S30 = SPH_C32(0xcae65838); S31 = SPH_C32(0x437f203f);
    S32 = SPH_C32(0x25ea78e7); S33 = SPH_C32(0x951fddd6); S34 = SPH_C32(0xda6ed11d); S35 = SPH_C32(0xe13e3567);

    FUGUE512_3((hash.h4[0x0]), (hash.h4[0x1]), (hash.h4[0x2]));
    FUGUE512_3((hash.h4[0x3]), (hash.h4[0x4]), (hash.h4[0x5]));
    FUGUE512_3((hash.h4[0x6]), (hash.h4[0x7]), (hash.h4[0x8]));
    FUGUE512_3((hash.h4[0x9]), (hash.h4[0xA]), (hash.h4[0xB]));
    FUGUE512_3((hash.h4[0xC]), (hash.h4[0xD]), (hash.h4[0xE]));
    FUGUE512_3((hash.h4[0xF]), as_uint2(fc_bit_count).y, as_uint2(fc_bit_count).x);

    // apply round shift if necessary
	
    int i;

    for (i = 0; i < 32; i ++) {
        ROR3;
        CMIX36(S00, S01, S02, S04, S05, S06, S18, S19, S20);
        SMIX(S00, S01, S02, S03);
    }
    for (i = 0; i < 13; i ++) {
        S04 ^= S00;
        S09 ^= S00;
        S18 ^= S00;
        S27 ^= S00;
        ROR9;
        SMIX(S00, S01, S02, S03);
        S04 ^= S00;
        S10 ^= S00;
        S18 ^= S00;
        S27 ^= S00;
        ROR9;
        SMIX(S00, S01, S02, S03);
        S04 ^= S00;
        S10 ^= S00;
        S19 ^= S00;
        S27 ^= S00;
        ROR9;
        SMIX(S00, S01, S02, S03);
        S04 ^= S00;
        S10 ^= S00;
        S19 ^= S00;
        S28 ^= S00;
        ROR8;
        SMIX(S00, S01, S02, S03);
    }
    S04 ^= S00;
    S09 ^= S00;
    S18 ^= S00;
    S27 ^= S00;

    hash.h4[0] = SWAP4(S01);
    hash.h4[1] = SWAP4(S02);
    hash.h4[2] = SWAP4(S03);
    hash.h4[3] = SWAP4(S04);
    hash.h4[4] = SWAP4(S09);
    hash.h4[5] = SWAP4(S10);
    hash.h4[6] = SWAP4(S11);
    hash.h4[7] = SWAP4(S12);
    hash.h4[8] = SWAP4(S18);
    hash.h4[9] = SWAP4(S19);
    hash.h4[10] = SWAP4(S20);
    hash.h4[11] = SWAP4(S21);
    hash.h4[12] = SWAP4(S27);
    hash.h4[13] = SWAP4(S28);
    hash.h4[14] = SWAP4(S29);
    hash.h4[15] = SWAP4(S30);

  }
	// gost
  {
  __local sph_u64 lT[8][256];

  for(int i=0; i<8; i++) {
    for(int j=0; j<256; j++) lT[i][j] = T[i][j];
  }

  __local unsigned char lCC[12][64];
  __local void*    vCC[12];
  __local sph_u64* sCC[12];

  for(int i=0; i<12; i++) {
    for(int j=0; j<64; j++) lCC[i][j] = CC[i][j];
  }

  for(int i=0; i<12; i++) {
    vCC[i] = lCC[i];
  }
  for(int i=0; i<12; i++) {
    sCC[i] = vCC[i];
  }

  sph_u64 message[8];
  
  message[0] = (hash.h8[0]);
  message[1] = (hash.h8[1]);
  message[2] = (hash.h8[2]);
  message[3] = (hash.h8[3]);
  message[4] = (hash.h8[4]);
  message[5] = (hash.h8[5]);
  message[6] = (hash.h8[6]);
  message[7] = (hash.h8[7]);

  sph_u64 out[8];
  sph_u64 len = 512;
  
  GOST_HASH_512(message, len, out);

#if 0
  hash.h8[0] = (out[0]);
  hash.h8[1] = (out[1]);
  hash.h8[2] = (out[2]);
  hash.h8[3] = (out[3]);
  hash.h8[4] = (out[4]);
  hash.h8[5] = (out[5]);
  hash.h8[6] = (out[6]);
  hash.h8[7] = (out[7]);
#endif

  if (out[3] <= target)
    output[atomic_inc(output+0xFF)] = gid;
  }
}

#endif // RENESIS_CL  