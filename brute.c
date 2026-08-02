// Brute-force: which fresh-state seed makes first PRNG bytes == 0x71 0x23 ?
// Covers: MT19937 (init_genrand) small seeds + Unix-second timestamps 2008..2024,
//         Java Random small seeds, glibc srand small + timestamps.
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define FP0 0x71
#define FP1 0x23

/* ---- MT19937 reference ---- */
static uint32_t mt[624];
static void mt_init(uint32_t s){
    mt[0]=s;
    for(int i=1;i<624;i++) mt[i]=(1812433253u*(mt[i-1]^(mt[i-1]>>30))+i);
}
static uint32_t mt_first(void){ // full twist then temper of slot 0
    for(int i=0;i<624;i++){
        uint32_t y=(mt[i]&0x80000000u)|(mt[(i+1)%624]&0x7fffffffu);
        mt[i]=mt[(i+397)%624]^(y>>1)^((y&1)?0x9908b0dfu:0);
    }
    uint32_t y=mt[0];
    y^=y>>11; y^=(y<<7)&0x9d2c5680u; y^=(y<<15)&0xefc60000u; y^=y>>18;
    return y;
}

/* ---- Java Random nextBytes first 2 bytes: need first next(32) -> bytes 3,2 of int ---- */
static uint64_t jseed;
static void jinit(uint64_t s){ jseed=(s^0x5DEECE66Du)&((1uL<<48)-1); }
static uint32_t jnext32(void){ jseed=(jseed*0x5DEECE66Du+0xBu)&((1uL<<48)-1); return (uint32_t)(jseed>>(48-32)); }

/* ---- glibc TYPE_3 ---- */
static int32_t gr[34]; static int gf,gb;
static void ginit(uint32_t s){
    if(s==0)s=1;
    gr[0]=s&0x7fffffff;
    for(int i=1;i<31;i++) gr[i]=(int32_t)(((int64_t)16807*gr[i-1])%2147483647);
    for(int i=31;i<34;i++) gr[i]=gr[i-31];
    gf=3; gb=0;
    for(int i=0;i<310;i++){ int32_t v=gr[gf]+gr[gb]; gr[gf]=v; gf=(gf+1)%34; gb=(gb+1)%34; }
}
static int32_t grand(void){
    int32_t v=gr[gf]+gr[gb]; gr[gf]=v; int32_t o=(v>>1)&0x7fffffff;
    gf=(gf+1)%34; gb=(gb+1)%34; return o;
}

int main(void){
    long hits=0;

    // MT small seeds
    for(uint32_t s=0;s<=2000000;s++){
        mt_init(s); uint32_t v=mt_first();
        uint8_t be[4]={v>>24,v>>16,v>>8,v};
        uint8_t le[4]={v,v>>8,v>>16,v>>24};
        if(be[0]==FP0&&be[1]==FP1){printf("MT seed=%u u32=%08x BE\n",s,v);hits++;}
        if(le[0]==FP0&&le[1]==FP1){printf("MT seed=%u u32=%08x LE\n",s,v);hits++;}
        if(hits>40)goto done_mt;
    }
done_mt:
    printf("-- MT small done hits=%ld\n",hits);

    // MT seeded with unix seconds 2008-01-01 .. 2024-06-01
    hits=0;
    for(uint32_t s=1199145600;s<=1717200000;s++){
        mt_init(s); uint32_t v=mt_first();
        uint8_t be[4]={v>>24,v>>16,v>>8,v};
        uint8_t le[4]={v,v>>8,v>>16,v>>24};
        if(be[0]==FP0&&be[1]==FP1){printf("MT ts=%u u32=%08x BE\n",s,v);if(++hits>60)goto done_ts;}
        if(le[0]==FP0&&le[1]==FP1){printf("MT ts=%u u32=%08x LE\n",s,v);if(++hits>60)goto done_ts;}
    }
done_ts:
    printf("-- MT timestamps done hits=%ld\n",hits);

    // Java Random small seeds 0..100M (nextBytes first two bytes = top 2 bytes of first next(32))
    hits=0;
    for(uint64_t s=0;s<=100000000;s++){
        jinit(s); uint32_t v=jnext32();
        if((v>>24)==FP0 && ((v>>16)&0xff)==FP1){ printf("JavaRandom seed=%llu\n",(unsigned long long)s); if(++hits>40)break; }
    }
    printf("-- JavaRandom small done hits=%ld\n",hits);

    // glibc small + timestamps
    hits=0;
    for(uint32_t s=0;s<=2000000;s++){
        ginit(s); int32_t v=grand();
        uint8_t be[4]={v>>24,v>>16,v>>8,v};
        uint8_t le[4]={v,v>>8,v>>16,v>>24};
        if(be[0]==FP0&&be[1]==FP1){printf("glibc seed=%u BE\n",s);if(++hits>40)goto done_g;}
        if(le[0]==FP0&&le[1]==FP1){printf("glibc seed=%u LE\n",s);if(++hits>40)goto done_g;}
    }
done_g:
    printf("-- glibc small done hits=%ld\n",hits);
    hits=0;
    for(uint32_t s=1199145600;s<=1717200000;s++){
        ginit(s); int32_t v=grand();
        uint8_t be[4]={v>>24,v>>16,v>>8,v};
        if(be[0]==FP0&&be[1]==FP1){printf("glibc ts=%u BE\n",s);if(++hits>40)break;}
    }
    printf("-- glibc ts done hits=%ld\n",hits);
    return 0;
}
