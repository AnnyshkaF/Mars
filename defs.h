#include <stdlib.h>

#define rotr(x,n) _lrotr(x,n)
#define rotl(x,n) _lrotl(x,n)

#define S0(a) s_box[a & 0xff]				//255 - 0xff - low 8 bits
#define S1(a) s_box[(a & 0xff) + 256]		//255 - 0xff - low 8 bits
#define S(a) s_box[a & 0x1ff]				//511 - 0x1ff - low 9 bits

typedef unsigned long   u4byte; /* a 32 bit unsigned integer type   */

#define f_mix(a,b,c,d)   \
    r = rotr(a, 8);      \
    b ^= S0(a);          \
    b += S1(r);			 \
    r = rotr(a, 16);     \
    a  = rotr(a, 24);    \
    c += S0(r);          \
    d ^= S1(a);


#define b_mix(a,b,c,d)   \
    r = rotl(a, 8);      \
    b ^= S1(a);			 \
    c -= S0(r);          \
    r = rotl(a, 16);     \
    a  = rotl(a, 24);    \
    d -= S1(r);			 \
    d ^= S0(a);



#define f_ktr(a,b,c,d,i)    \
    m = a + l_key[i];       \
    a = rotl(a, 13);        \
    r = a * l_key[i + 1];   \
    l = S(m);				\
    r = rotl(r, 5);         \
    c += rotl(m, r);        \
    l ^= r;                 \
    r = rotl(r, 5);         \
    l ^= r;                 \
    d ^= r;                 \
    b += rotl(l, r)


#define r_ktr(a,b,c,d,i)    \
    r = a * l_key[i + 1];   \
    a = rotr(a, 13);        \
    m = a + l_key[i];       \
    l = S(m);				\
    r = rotl(r, 5);         \
    l ^= r;                 \
    c -= rotl(m, r);        \
    r = rotl(r, 5);         \
    l ^= r;                 \
    d ^= r;                 \
    b -= rotl(l, r)

#define set4(b3,b2,b1,b0,res)	\
	res |= b0 & 0xff;			\
	res |= (b1 & 0xff) << 8;	\
	res |= (b2 & 0xff) << 16;	\
	res |= (b3 & 0xff) << 24;	\




