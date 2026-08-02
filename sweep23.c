// sweep23.c — full 2^32 seed space × 14 PRNG schemes, 22-bit prefix filter (71 23 00-03)
// Usage: sweep23 <start> <end> <outfile>   (ranged, process-sharded)
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static uint32_t MT[624];
static inline void mt_init(uint32_t s){
    MT[0]=s;
    for(int i=1;i<624;i++) MT[i]=(1812433253u*(MT[i-1]^(MT[i-1]>>30))+i);
}
static inline void mt_twist(void){
    for(int i=0;i<624;i++){
        uint32_t y=(MT[i]&0x80000000u)|(MT[(i+1)%624]&0x7fffffffu);
        MT[i]=MT[(i+397)%624]^(y>>1)^((y&1)?0x9908b0dfu:0);
    }
}
static inline uint32_t temper(uint32_t y){
    y^=y>>11; y^=(y<<7)&0x9d2c5680u; y^=(y<<15)&0xefc60000u; y^=y>>18; return y;
}

static int32_t GR[34]; static int GF, GB;
static void ginit(uint32_t s){
    if(s==0)s=1;
    GR[0]=s&0x7fffffff;
    for(int i=1;i<31;i++) GR[i]=(int32_t)(((int64_t)16807*GR[i-1])%2147483647);
    for(int i=31;i<34;i++) GR[i]=GR[i-31];
    GF=3; GB=0;
    for(int i=0;i<310;i++){ int32_t v=GR[GF]+GR[GB]; GR[GF]=v; GF=(GF+1)%34; GB=(GB+1)%34; }
}
static inline int32_t grand(void){
    int32_t v=GR[GF]+GR[GB]; GR[GF]=v; int32_t o=(v>>1)&0x7fffffff;
    GF=(GF+1)%34; GB=(GB+1)%34; return o;
}

static inline uint32_t mulberry32(uint32_t*a){
    *a = (*a + 0x6D2B79F5u);
    uint32_t t=*a;
    t=(t^(t>>15))*(t|1);
    t=(t + (((t^(t>>7))*(t|61))^t));
    return t^(t>>14);
}
static inline uint32_t xorshift32(uint32_t*x){
    uint32_t v=*x; if(!v)v=0x9E3779B9u;
    v^=v<<13; v^=v>>17; v^=v<<5; *x=v; return v;
}
static inline uint32_t posixr(uint32_t*s){
    *s = (*s*1103515245u+12345u)&0x7fffffffu;
    return (*s>>16)&0x7fff;
}

/* .NET System.Random */
static int dn_seedArray[56]; static int dn_i1, dn_i2;
static void dn_init(int seed){
    const int MBIG=2147483647, MSEED=161803398;
    int sub = seed==-2147483648?2147483647:abs(seed);
    int mj = MSEED - sub; if(mj<0) mj+=MBIG; // %MBIG with positive
    dn_seedArray[55]=mj; int mk=1;
    for(int i=1;i<55;i++){
        int ii=(21*i)%55;
        dn_seedArray[ii]=mk;
        mk=mj-mk; if(mk<0)mk+=MBIG;
        mj=dn_seedArray[ii];
    }
    for(int k=0;k<4;k++)
        for(int i=1;i<56;i++){
            dn_seedArray[i]-=dn_seedArray[1+(i+30)%55];
            if(dn_seedArray[i]<0)dn_seedArray[i]+=MBIG;
        }
    dn_i1=0; dn_i2=21;
}
static inline int dn_next(void){
    if(++dn_i1>=56)dn_i1=1;
    if(++dn_i2>=56)dn_i2=1;
    int r=dn_seedArray[dn_i1]-dn_seedArray[dn_i2];
    if(r<0)r+=2147483647;
    dn_seedArray[dn_i1]=r; return r;
}

/* ARC4 keyed by decimal string of seed */
static uint8_t AS[256]; static int AI, AJ;
static void arc4_init(uint32_t seed){
    char key[12]; int kl=snprintf(key,12,"%u",seed);
    for(int i=0;i<256;i++)AS[i]=i;
    int j=0;
    for(int i=0;i<256;i++){ j=(j+AS[i]+(uint8_t)key[i%kl])&0xff; uint8_t t=AS[i];AS[i]=AS[j];AS[j]=t; }
    AI=AJ=0;
}
static inline uint8_t arc4_next(void){
    AI=(AI+1)&0xff; AJ=(AJ+AS[AI])&0xff;
    uint8_t t=AS[AI];AS[AI]=AS[AJ];AS[AJ]=t;
    return AS[(AS[AI]+AS[AJ])&0xff];
}

/* Alea (seedrandom) keyed by decimal string */
static double al_s0, al_s1, al_s2, al_c;
static double al_mash_n;
static double al_mash(const char*data){
    for(const char*p=data;*p;p++){
        al_mash_n += (unsigned char)*p;
        double h = 0.02519603282416938 * al_mash_n;
        al_mash_n = (double)(uint32_t)h;
        h -= al_mash_n;
        h *= al_mash_n;
        al_mash_n = (double)(uint32_t)h;
        h -= al_mash_n;
        al_mash_n += (double)(uint32_t)(h * 4294967296.0);
        al_mash_n = (double)(uint32_t)al_mash_n;  // JS >>> 0 truncation
    }
    return al_mash_n * 2.3283064365386963e-10;
}
static void alea_init(uint32_t seed){
    char key[12]; snprintf(key,12,"%u",seed);
    al_mash_n = 0xefc8249d;
    al_s0=al_mash(" "); al_s1=al_mash(" "); al_s2=al_mash(" "); al_c=1;
    al_s0-=al_mash(key); if(al_s0<0)al_s0+=1;
    al_s1-=al_mash(key); if(al_s1<0)al_s1+=1;
    al_s2-=al_mash(key); if(al_s2<0)al_s2+=1;
}
static inline double alea_next(void){
    double t = 2091639.0*al_s0 + al_c*2.3283064365386963e-10;
    al_s0=al_s1; al_s1=al_s2;
    al_c=(double)(uint32_t)t;
    al_s2=t-al_c;
    return al_s2;
}

static inline int prefix2(const uint8_t*b){ return b[0]==0x71 && b[1]==0x23 && b[2]<4; }

int main(int argc,char**argv){
    uint32_t start=(uint32_t)strtoul(argv[1],0,0), end=(uint32_t)strtoul(argv[2],0,0);
    FILE*out=fopen(argv[3],"w");
    uint8_t b[16];
    for(uint32_t s=start;s<end;s++){
        // MT variants
        mt_init(s); mt_twist();
        uint32_t w0=temper(MT[0]),w1=temper(MT[1]),w2=temper(MT[2]),w3=temper(MT[3]);
        uint32_t ws[4]={w0,w1,w2,w3};
        for(int i=0;i<4;i++){ uint32_t w=ws[i]; b[i*4]=w>>24; b[i*4+1]=w>>16; b[i*4+2]=w>>8; b[i*4+3]=w; }
        if(prefix2(b)) fprintf(out,"MT32-BE\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        for(int i=0;i<4;i++){ uint32_t w=ws[i]; b[i*4]=w; b[i*4+1]=w>>8; b[i*4+2]=w>>16; b[i*4+3]=w>>24; }
        if(prefix2(b)) fprintf(out,"MT32-LE\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        for(int i=0;i<16;i++) b[i]=ws[i/4]>>((i%4)*8), b[i]=b[i]; // placeholder
        for(int i=0;i<16;i++) b[i]=(ws[i%4]&0xff);
        if(prefix2(b)) fprintf(out,"MT32-LOWBYTE\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        for(int i=0;i<16;i++) b[i]=(ws[i%4]>>24)&0xff;
        if(prefix2(b)) fprintf(out,"MT32-HIGHBYTE\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        // glibc
        ginit(s);
        for(int i=0;i<4;i++){ uint32_t w=(uint32_t)grand(); b[i*4]=w>>24; b[i*4+1]=w>>16; b[i*4+2]=w>>8; b[i*4+3]=w; }
        if(prefix2(b)) fprintf(out,"GLIBC-BE\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        ginit(s);
        for(int i=0;i<4;i++){ uint32_t w=(uint32_t)grand(); b[i*4]=w; b[i*4+1]=w>>8; b[i*4+2]=w>>16; b[i*4+3]=w>>24; }
        if(prefix2(b)) fprintf(out,"GLIBC-LE\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        // java
        uint64_t js=(s^0x5DEECE66Du)&((1ULL<<48)-1);
        for(int i=0;i<4;i++){ js=(js*0x5DEECE66Du+0xBu)&((1ULL<<48)-1); uint32_t w=js>>16; b[i*4]=w>>24; b[i*4+1]=w>>16; b[i*4+2]=w>>8; b[i*4+3]=w; }
        if(prefix2(b)) fprintf(out,"JAVA-RANDOM\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        // mulberry32 floor*256
        uint32_t ms=s;
        for(int i=0;i<16;i++){ b[i]=(uint8_t)(mulberry32(&ms)/16777216u); } // floor(rnd*256): rnd=u32/2^32 → *256 = u32>>24
        if(prefix2(b)) fprintf(out,"MULBERRY32\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        // xorshift32 floor*256
        uint32_t xs=s;
        for(int i=0;i<16;i++){ b[i]=(uint8_t)(xorshift32(&xs)>>24); }
        if(prefix2(b)) fprintf(out,"XORSHIFT32\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        // posix floor*256 (r in [0,32767] → *256/32768 = r>>7)
        uint32_t ps=s;
        for(int i=0;i<16;i++){ b[i]=(uint8_t)(posixr(&ps)>>7); }
        if(prefix2(b)) fprintf(out,"POSIX-F256\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        // posix raw &0xff
        ps=s;
        for(int i=0;i<16;i++){ b[i]=(uint8_t)(posixr(&ps)&0xff); }
        if(prefix2(b)) fprintf(out,"POSIX-RAW\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        // dotnet floor*256
        dn_init((int)s);
        for(int i=0;i<16;i++){ b[i]=(uint8_t)((uint32_t)dn_next()>>23); } // r/MBIG*256: r<2^31 → r>>23 gives 0..255
        if(prefix2(b)) fprintf(out,"DOTNET\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        // arc4 bytes
        arc4_init(s);
        for(int i=0;i<16;i++) b[i]=arc4_next();
        if(prefix2(b)) fprintf(out,"ARC4\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        // alea floor*256
        alea_init(s);
        for(int i=0;i<16;i++){ double r=alea_next(); b[i]=(uint8_t)(r*256.0); }
        if(prefix2(b)) fprintf(out,"ALEA\t%u\t%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",s,b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
    }
    fclose(out);
    return 0;
}
