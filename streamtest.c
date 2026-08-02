// Stream-window tester: for (scheme, seed), generate PRNG stream, take 16-byte
// windows, derive m/44'/60'/0'/0/0 ETH address, test membership in victim set.
// Usage: streamtest <scheme> <seed> <kmax> <victims.bin>
// victims.bin: sorted concatenated 20-byte addresses.
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pbkdf2.h"
#include "hmac.h"
#include "sha2.h"
#include "sha3.h"
#include <secp256k1.h>
#include "ripemd160.h"
#include "bip39_english.h"

static secp256k1_context* SECP;

static const uint32_t N32 = 0xFFFFFFFF;
// secp256k1 order
static const uint8_t ORDER[32] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
  0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

/* ---------- PRNG streams (byte-oriented, pull model) ---------- */
typedef struct {
    int scheme;            // 0 MT-BE,1 MT-LE,2 MT-LOW,3 MT-HIGH,4 GLIBC-BE,5 GLIBC-LE,6 JAVA,7 LCG-LE,8 LCG-BE
    uint32_t mt[624]; int mti; uint32_t cur; int curpos;
    int32_t gr[34]; int gf, gb;
    uint64_t js, ls;       // java state / lcg state
    uint32_t jcur; int jpos;
    uint64_t jbuf; int jbufn; // java nextBytes leftover
} prng_t;

static void mt_init(prng_t*p, uint32_t s){
    p->mt[0]=s;
    for(int i=1;i<624;i++) p->mt[i]=(1812433253u*(p->mt[i-1]^(p->mt[i-1]>>30))+i);
    p->mti=624;
}
static uint32_t mt_u32(prng_t*p){
    if(p->mti>=624){
        for(int i=0;i<624;i++){
            uint32_t y=(p->mt[i]&0x80000000u)|(p->mt[(i+1)%624]&0x7fffffffu);
            p->mt[i]=p->mt[(i+397)%624]^(y>>1)^((y&1)?0x9908b0dfu:0);
        }
        p->mti=0;
    }
    uint32_t y=p->mt[p->mti++];
    y^=y>>11; y^=(y<<7)&0x9d2c5680u; y^=(y<<15)&0xefc60000u; y^=y>>18;
    return y;
}
static void ginit(prng_t*p, uint32_t s){
    if(s==0)s=1;
    p->gr[0]=s&0x7fffffff;
    for(int i=1;i<31;i++) p->gr[i]=(int32_t)(((int64_t)16807*p->gr[i-1])%2147483647);
    for(int i=31;i<34;i++) p->gr[i]=p->gr[i-31];
    p->gf=3; p->gb=0;
    for(int i=0;i<310;i++){ int32_t v=p->gr[p->gf]+p->gr[p->gb]; p->gr[p->gf]=v; p->gf=(p->gf+1)%34; p->gb=(p->gb+1)%34; }
}
static inline int32_t grand(prng_t*p){
    int32_t v=p->gr[p->gf]+p->gr[p->gb]; p->gr[p->gf]=v; int32_t o=(v>>1)&0x7fffffff;
    p->gf=(p->gf+1)%34; p->gb=(p->gb+1)%34; return o;
}

static void prng_init(prng_t*p, int scheme, uint32_t seed){
    memset(p,0,sizeof(*p)); p->scheme=scheme;
    switch(scheme){
        case 0: case 1: case 2: case 3: mt_init(p,seed); p->curpos=4; break;
        case 4: case 5: ginit(p,seed); p->curpos=4; break;
        case 6: p->js=(seed^0x5DEECE66Du)&((1ULL<<48)-1); p->jbufn=0; break;
        case 7: case 8: p->ls=seed; p->curpos=4; break;
    }
}
static uint32_t java_next32(prng_t*p){
    p->js=(p->js*0x5DEECE66Du+0xBu)&((1ULL<<48)-1);
    return (uint32_t)(p->js>>16);
}
static uint8_t prng_byte(prng_t*p){
    switch(p->scheme){
        case 0: case 1: case 2: case 3: {
            if(p->curpos>=4){ p->cur=mt_u32(p); p->curpos=0; }
            uint8_t b;
            if(p->scheme==0){ b=(p->cur>>(24-8*p->curpos))&0xff; }
            else if(p->scheme==1){ b=(p->cur>>(8*p->curpos))&0xff; }
            else if(p->scheme==2){ b=p->cur&0xff; p->curpos=3; }   // LOW: whole word per byte
            else { b=(p->cur>>24)&0xff; p->curpos=3; }             // HIGH
            p->curpos++;
            return b;
        }
        case 4: case 5: {
            if(p->curpos>=4){ p->cur=(uint32_t)grand(p); p->curpos=0; }
            uint8_t b = (p->scheme==4) ? (p->cur>>(24-8*p->curpos))&0xff : (p->cur>>(8*p->curpos))&0xff;
            p->curpos++;
            return b;
        }
        case 6: { // java nextBytes: 4 bytes BE per next(32)
            if(p->jbufn==0){ p->jbuf=java_next32(p); p->jbufn=4; }
            uint8_t b=(p->jbuf>>(8*(p->jbufn-1)))&0xff; p->jbufn--;
            return b;
        }
        case 7: case 8: {
            if(p->curpos>=4){ p->ls=(1664525u*p->ls+1013904223u); p->cur=(uint32_t)p->ls; p->curpos=0; }
            uint8_t b = (p->scheme==7) ? (p->cur>>(8*p->curpos))&0xff : (p->cur>>(24-8*p->curpos))&0xff;
            p->curpos++;
            return b;
        }
    }
    return 0;
}

/* ---------- BIP39 (english) ---------- */
static void entropy_to_mnemonic(const uint8_t*ent, char*out){
    uint8_t csfull[32]; sha256_Raw(ent,16,csfull);
    uint32_t bits[6]; // 132 bits: use byte ops instead
    // build 11-bit indices
    int bitpos=0; out[0]=0;
    for(int w=0; w<12; w++){
        int idx=0;
        for(int b=0;b<11;b++){
            int bytei, biti, v;
            if(bitpos<128){ bytei=bitpos/8; biti=7-(bitpos%8); v=(ent[bytei]>>biti)&1; }
            else { int cp=bitpos-128; bytei=cp/8; biti=7-(cp%8); v=(csfull[bytei]>>biti)&1; }
            idx=(idx<<1)|v; bitpos++;
        }
        const char* word = wordlist[idx];
        strcat(out, word);
        if(w<11) strcat(out, " ");
        (void)bits;
    }
}

/* ---------- BIP32 CKDpriv + eth addr ---------- */
static void hmac512(const uint8_t*key,int klen,const uint8_t*data,int dlen,uint8_t*out){
    HMAC_SHA512_CTX ctx; hmac_sha512_Init(&ctx,key,klen); hmac_sha512_Update(&ctx,data,dlen); hmac_sha512_Final(&ctx,out);
}
static int ckd(uint8_t*k, uint8_t*chain, uint32_t idx){
    uint8_t data[37]; int dlen;
    if(idx&0x80000000u){ data[0]=0; memcpy(data+1,k,32); dlen=33; }
    else {
        secp256k1_pubkey pub;
        secp256k1_ec_pubkey_create(SECP,&pub,k);
        size_t l=33; secp256k1_ec_pubkey_serialize(SECP,data,&l,&pub,SECP256K1_EC_COMPRESSED);
        dlen=33;
    }
    memcpy(data+dlen,&((uint8_t[]){(idx>>24)&0xff,(idx>>16)&0xff,(idx>>8)&0xff,idx&0xff}),4); dlen+=4;
    uint8_t I[64]; hmac512(chain,32,data,dlen,I);
    if(!secp256k1_ec_seckey_verify(SECP,I)) return -1;
    if(!secp256k1_ec_seckey_tweak_add(SECP,k,I)) return -1;
    memcpy(chain,I+32,32);
    return 0;
}
static void eth_addr(const uint8_t*priv, uint8_t*out20){
    secp256k1_pubkey pub; secp256k1_ec_pubkey_create(SECP,&pub,priv);
    uint8_t ser[65]; size_t l=65; secp256k1_ec_pubkey_serialize(SECP,ser,&l,&pub,SECP256K1_EC_UNCOMPRESSED);
    uint8_t h[32]; keccak_256(ser+1,64,h);
    memcpy(out20,h+12,20);
}
static void btc_hash160(const uint8_t*priv, uint8_t*out20){
    secp256k1_pubkey pub; secp256k1_ec_pubkey_create(SECP,&pub,priv);
    uint8_t ser[33]; size_t l=33; secp256k1_ec_pubkey_serialize(SECP,ser,&l,&pub,SECP256K1_EC_COMPRESSED);
    uint8_t h[32]; sha256_Raw(ser,33,h);
    ripemd160(h,32,out20);
}

/* ---------- victim set ---------- */
static uint8_t* victims; static size_t nvict;
static int cmp20(const void*a,const void*b){ return memcmp(a,b,20); }
static int is_victim(const uint8_t*a){
    return bsearch(a,victims,nvict,20,cmp20)!=NULL;
}

int main(int argc,char**argv){
    if(argc<5){ fprintf(stderr,"usage: %s scheme seed kmax victims.bin\n",argv[0]); return 2; }
    SECP = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int scheme=atoi(argv[1]); uint32_t seed=(uint32_t)strtoul(argv[2],0,0);
    long kmax=atol(argv[3]);
    int mode = argc>5 ? atoi(argv[5]) : 0;  // 0=ETH m/44'/60', 1=BTC m/44'/0'
    FILE*f=fopen(argv[4],"rb"); if(!f){ fprintf(stderr,"cannot open %s\n",argv[4]); return 2; } fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    nvict=sz/20; victims=malloc(sz); fread(victims,20,nvict,f); fclose(f);
    qsort(victims,nvict,20,cmp20);

    prng_t p; prng_init(&p,scheme,seed);
    uint8_t ent[16]; char mn[512]; uint8_t seed64[64], I[64];
    uint8_t k[32], chain[32], addr[20];
    for(long w=0; w<=kmax; w++){
        for(int i=0;i<16;i++) ent[i]=prng_byte(&p);
        entropy_to_mnemonic(ent,mn);
        pbkdf2_hmac_sha512((const uint8_t*)mn,strlen(mn),(const uint8_t*)"mnemonic",8,2048,seed64,64);
        hmac512((const uint8_t*)"Bitcoin seed",12,seed64,64,I);
        memcpy(k,I,32); memcpy(chain,I+32,32);
        const uint32_t H=0x80000000u;
        uint32_t path[5]={44+H,(mode==1?0u:60u)+H,0+H,0,0};
        for(int i=0;i<5;i++) ckd(k,chain,path[i]);
        if(mode==1) btc_hash160(k,addr); else eth_addr(k,addr);
        if(is_victim(addr)){
            printf("HIT scheme=%d seed=%u window=%ld ent=",scheme,seed,w);
            for(int i=0;i<16;i++) printf("%02x",ent[i]);
            printf(" addr=0x"); for(int i=0;i<20;i++) printf("%02x",addr[i]);
            printf("\n"); fflush(stdout);
        }
    }
    return 0;
}
