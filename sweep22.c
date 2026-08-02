// Full 2^32 seed sweep, 22-bit fingerprint filter (bytes 71 23 + top6(byte2)=0)
// Schemes: MT19937(init_genrand) BE/LE, glibc TYPE_3 srand BE/LE, JavaRandom nextBytes.
// Output TSV: scheme \t seed \t entropy16_hex (first 16 bytes of stream)
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static uint32_t mt[624]; static int mti; // per-thread via TLS
static __thread uint32_t t_mt[624];

static inline void mt_init(uint32_t s){
    t_mt[0]=s;
    for(int i=1;i<624;i++) t_mt[i]=(1812433253u*(t_mt[i-1]^(t_mt[i-1]>>30))+i);
}
static inline void mt_twist(void){
    for(int i=0;i<624;i++){
        uint32_t y=(t_mt[i]&0x80000000u)|(t_mt[(i+1)%624]&0x7fffffffu);
        t_mt[i]=t_mt[(i+397)%624]^(y>>1)^((y&1)?0x9908b0dfu:0);
    }
    mti=0;
}
static inline uint32_t mt_u32(void){
    if(mti>=624) mt_twist();
    uint32_t y=t_mt[mti++];
    y^=y>>11; y^=(y<<7)&0x9d2c5680u; y^=(y<<15)&0xefc60000u; y^=y>>18;
    return y;
}

// glibc per-thread
static __thread int32_t gr[34]; static __thread int gf,gb;
static void ginit(uint32_t s){
    if(s==0)s=1;
    gr[0]=s&0x7fffffff;
    for(int i=1;i<31;i++) gr[i]=(int32_t)(((int64_t)16807*gr[i-1])%2147483647);
    for(int i=31;i<34;i++) gr[i]=gr[i-31];
    gf=3; gb=0;
    for(int i=0;i<310;i++){ int32_t v=gr[gf]+gr[gb]; gr[gf]=v; gf=(gf+1)%34; gb=(gb+1)%34; }
}
static inline int32_t grand(void){
    int32_t v=gr[gf]+gr[gb]; gr[gf]=v; int32_t o=(v>>1)&0x7fffffff;
    gf=(gf+1)%34; gb=(gb+1)%34; return o;
}

// Java Random per-thread
static __thread uint64_t js;
static inline void jinit(uint64_t s){ js=(s^0x5DEECE66Du)&((1UL<<48)-1); }
static inline uint32_t jn32(void){ js=(js*0x5DEECE66Du+0xBu)&((1UL<<48)-1); return (uint32_t)(js>>16); }

static FILE* out;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static inline int fp22(uint8_t b0,uint8_t b1,uint8_t b2){
    return b0==0x71 && b1==0x23 && (b2>>2)==0;
}

static void emit(const char* scheme, uint32_t seed, const uint8_t* e16){
    pthread_mutex_lock(&lock);
    fprintf(out,"%s\t%u\t",scheme,seed);
    for(int i=0;i<16;i++) fprintf(out,"%02x",e16[i]);
    fprintf(out,"\n");
    pthread_mutex_unlock(&lock);
}

typedef struct { uint32_t lo, hi; } range_t;

static void* worker(void* arg){
    range_t r = *(range_t*)arg;
    uint8_t e[16];
    for(uint32_t s=r.lo;;s++){
        // MT19937
        mt_init(s); mti=624;
        uint32_t w0=mt_u32();
        uint8_t be0=w0>>24, be1=w0>>16, be2=w0>>8;
        uint8_t le0=w0&0xff, le1=(w0>>8)&0xff, le2=(w0>>16)&0xff;
        int mbe=fp22(be0,be1,be2), mle=fp22(le0,le1,le2);
        int mlb = le0==0x71; // low-byte extraction: byte0 = w0&0xff
        int mhb = be0==0x71; // high-byte extraction: byte0 = w0>>24
        if(mbe||mle){
            uint32_t w1=mt_u32(),w2=mt_u32(),w3=mt_u32();
            if(mbe){ uint32_t w[4]={w0,w1,w2,w3};
                for(int i=0;i<4;i++){e[4*i]=w[i]>>24;e[4*i+1]=w[i]>>16;e[4*i+2]=w[i]>>8;e[4*i+3]=w[i];}
                emit("MT32-BE",s,e); }
            if(mle){ uint32_t w[4]={w0,w1,w2,w3};
                for(int i=0;i<4;i++){e[4*i]=w[i]&0xff;e[4*i+1]=(w[i]>>8)&0xff;e[4*i+2]=(w[i]>>16)&0xff;e[4*i+3]=w[i]>>24;}
                emit("MT32-LE",s,e); }
        }
        if(mlb||mhb){ // per-byte extraction: one u32 per entropy byte (wallet-core WASM style)
            uint32_t ws[16]; ws[0]=w0;
            for(int i=1;i<16;i++) ws[i]=mt_u32();
            if(mlb){ for(int i=0;i<16;i++) e[i]=ws[i]&0xff;
                if(e[1]==0x23 && (e[2]>>2)==0) emit("MT32-LOWBYTE",s,e); }
            if(mhb){ for(int i=0;i<16;i++) e[i]=ws[i]>>24;
                if(e[1]==0x23 && (e[2]>>2)==0) emit("MT32-HIGHBYTE",s,e); }
        }
        // glibc
        ginit(s); int32_t g0=grand();
        uint8_t gb0=g0>>24,gb1=g0>>16,gb2=g0>>8;
        uint8_t gl0=g0&0xff,gl1=(g0>>8)&0xff,gl2=(g0>>16)&0xff;
        int gbe=fp22(gb0,gb1,gb2), gle=fp22(gl0,gl1,gl2);
        if(gbe||gle){
            int32_t g1=grand(),g2=grand(),g3=grand(),g4=grand(); // 31-bit chunks; pack BE/LE 4x31-> bytes as produced sequentially (common: take low byte each call) — we emit BOTH packings
            int32_t gs[5]={g0,g1,g2,g3,g4};
            if(gbe){ for(int i=0;i<4;i++){e[4*i]=gs[i]>>24;e[4*i+1]=gs[i]>>16;e[4*i+2]=gs[i]>>8;e[4*i+3]=gs[i];} emit("GLIBC-BE",s,e); }
            if(gle){ for(int i=0;i<4;i++){e[4*i]=gs[i]&0xff;e[4*i+1]=(gs[i]>>8)&0xff;e[4*i+2]=(gs[i]>>16)&0xff;e[4*i+3]=gs[i]>>24;} emit("GLIBC-LE",s,e); }
        }
        // Java Random: nextBytes fills from successive next(32), 4 bytes BE per int
        jinit(s); uint32_t j0=jn32();
        if(fp22(j0>>24,(j0>>16)&0xff,(j0>>8)&0xff)){
            uint32_t jw[4]={j0,jn32(),jn32(),jn32()};
            for(int i=0;i<4;i++){e[4*i]=jw[i]>>24;e[4*i+1]=jw[i]>>16;e[4*i+2]=jw[i]>>8;e[4*i+3]=jw[i];}
            emit("JAVA-RANDOM",s,e);
        }
        if(s==r.hi) break;
    }
    return NULL;
}

int main(int argc,char**argv){
    out = fopen("candidates.tsv","w");
    int NT=8;
    pthread_t th[8]; range_t rs[8];
    uint64_t total=0x100000000ULL, chunk=total/NT;
    for(int i=0;i<NT;i++){ rs[i].lo=i*chunk; rs[i].hi=(i==NT-1)?0xffffffffu:(uint32_t)((i+1)*chunk-1); }
    for(int i=0;i<NT;i++) pthread_create(&th[i],NULL,worker,&rs[i]);
    for(int i=0;i<NT;i++) pthread_join(th[i],NULL);
    fclose(out);
    return 0;
}
