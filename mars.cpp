
#include "mars.h"
#include "sblocks.h"

#define S(a)	Sbox[(a)&0x1ff]	//low 9 bits			???concatenation
#define S0(a)	Sbox[(a)&0xff]	//low 8 bits
#define S1(a)	Sbox[((a)&0xff) + 256] //low 8 bits		???why 256

/*
	NOTE: 
	S0[X] and S1[X] use low 8 bits of X. 
	S[X] uses low 9 bits of X. S is the concatenation of S0 and S1. 
	// concatenation (b1 << 8) + b2

	inblock/outblock is 4-bytes
	*/


void Mars::MakeKey(const word32 *k, unsigned int n, word32* key)
{
	//AssertValidKeyLength(n);//k

	// Initialize T[] With the Original Key Data k[]
	word32 T[15];
	for (size_t i = 0; i < n; i++)
	{
		T[i] = k[i];
	}
	T[n] = n;
	for (int i = n + 1; i < 15; i++)
	{
		T[i] = 0;
	}
	for (size_t j = 0; j < 4; j++)	// compute 10 words of K[] in each iteration
	{
		// Linear Key-Word Expansion
		for (size_t i = 0; i < 15; i++)
		{
			T[i] = T[i] ^ _lrotl(T[(i + 8) % 15] ^ T[(i + 13) % 15], 3) ^ (4 * i + j);
		}
		// S-box Based Stirring of Key-Words, Repeat 4 times
		for (size_t k = 0; k < 4; k++)
		{
			for (size_t i = 0; i < 15; i++)
			{
				T[i] = _lrotl((T[i] + Sbox[(T[(i + 14) % 15] % 512) & 0x1ff]), 9);
			}
		}
		// Store Next 10 Key-Words into K[ ]
		for (size_t i = 0; i < 10; i++)
		{
			key[10 * j + i] = T[4 * i % 15];
		}
	}
	/*
	// Modify multiplication key-words
	word32 B[] = { 0xa4a8d57b, 0x5b5d193b, 0xc8a8309b, 0x73f9a978};
	for(size_t i = 5; i < 37; i += 2)
	{
		word32 m, w = key[i] | 3;
		m = (~w ^ (w<<1)) & (~w ^ (w>>1)) & 0x7ffffffe;//0111 1111 1111 1111 1111 1111 1111 1110
		m &= m>>1; m &= m>>2; m &= m>>4;
		m |= m<<1; m |= m<<2; m |= m<<4;
		m &= 0x7ffffffc;
		w ^= _lrotl(Sbox[265 + (key[i] & 3)], key[i - 1]) & m;
		key[i] = w;
	}
	*/
}

void Mars::Encryption(word32 key[40], word32* inblock, word32* outblock) const
{
	word32 a = inblock[0], b = inblock[1], c = inblock[2], d = inblock[3];
	a += key[0]; b += key[1]; c += key[2]; d += key[3];
	
	for (size_t i = 0; i < 8; i++)
	{
		b = (b ^ S0(a)) + S1(a >> 8);
		c = c + S0(a >> 16);
		d = d ^ S1(a);
		
		a = _lrotr(a, 24);
		a += (i % 4 == 0) ? d : 0;
		a += (i % 4 == 1) ? b : 0;

		word32 t = a;	
		a = b;	b = c;	c = d;	d = t;
	}

	for (size_t i = 0; i < 16; i++)
	{
		word32 r = _lrotl(_lrotl(a, 13) * key[2 * i + 5], 10);
		word32 m = _lrotl((a + key[2 * i + 4]), _lrotr(r, 5) & 0x1F);	//0x1F ~ 11111
		word32 l = _lrotl((S(m) ^ _lrotr(r, 5) ^ r), r & 0x1F);
		(i < 8 ? b : d) += l;
		(i < 8 ? d : b) ^= r;
		c = c + m;
		
		word32 t = _lrotl(a, 13);
		a = b;	b = c;	c = d;	d = t;
	}

	for (size_t i = 0; i < 8; i++)
	{
		a -= (i % 4 == 2) ? d : 0;
		a -= (i % 4 == 3) ? b : 0;
		b ^= S1(a);
		c = c - S0(_lrotl(a, 8));
		d = (d - S1(_lrotl(a, 16))) ^ S0(_lrotl(a, 24));
		
		word32 t = _lrotl(a, 24);
		a = b;	b = c;	c = d;	d = t;
	}

	a -= key[36];	b -= key[37];	c -= key[38];	d -= key[39];
	outblock[0] = a; outblock[1] = b; outblock[2] = c; outblock[3] = d;
}

void Mars::Decryption(word32 key[40], word32* inblock, word32* outblock) const
{
	word32 a = inblock[3], b = inblock[2], c = inblock[1], d = inblock[0];
	a += key[36]; b += key[37]; c += key[38]; d += key[39];

	for (size_t i = 0; i < 8; i++)
	{
		b = (b ^ S0(a)) + S1(a >> 8);
		c = c + S0(a >> 16);
		d = d ^ S1(a);

		a = _lrotr(a, 24);
		a += (i % 4 == 0) ? d : 0;
		a += (i % 4 == 1) ? b : 0;

		word32 t = a;
		a = b;	b = c;	c = d;	d = t;
	}

	for (size_t i = 0; i < 16; i++)
	{
		word32 r = _lrotl(_lrotl(a, 13) * key[35 - 2 * i], 10);
		word32 m = _lrotl((a + key[34 - 2 * i + 4]), _lrotr(r, 5) & 0x1F);	//0x1F ~ 11111
		word32 l = _lrotl((S(m) ^ _lrotr(r, 5) ^ r), r & 0x1F);
		(i < 8 ? b : d) += l;
		(i < 8 ? d : b) ^= r;
		c = c + m;

		word32 t = _lrotl(a, 13);
		a = b;	b = c;	c = d;	d = t;
	}

	for (size_t i = 0; i < 8; i++)
	{
		a -= (i % 4 == 2) ? d : 0;
		a -= (i % 4 == 3) ? b : 0;
		b ^= S1(a);
		c = c - S0(_lrotl(a, 8));
		d = (d - S1(_lrotl(a, 16))) ^ S0(_lrotl(a, 24));

		word32 t = _lrotl(a, 24);
		a = b;	b = c;	c = d;	d = t;
	}

	a -= key[3];	b -= key[2];	c -= key[1];	d -= key[0];
	outblock[3] = a; outblock[2] = b; outblock[1] = c; outblock[0] = d;
}

/*
процедура расширения ключа расширяет заданный исходный массив ключей k[], 
состоящий из n 32-битных слов (где n целое число от 4 до 14) 
в массив K[] из 40 элементов.
*/
//делим ключ на подключи по 32 бита, нехватку дополняем нулями
bool AssertValidKeyLength(int length)
{
	if (length == 0)
		return true;
	return false;
}

word32 Modulo(word32 val)
{
	val = val + 4294967296 % 4294967296;
	return val;
}