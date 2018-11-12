
#include "mars.h"
#include "sblocks.h"

#define S(a)	Sbox[(a)&0x1ff]	//low 9 bits			???concatenation
#define S0(a)	Sbox[(a)&0xff]	//low 8 bits
#define S1(a)	Sbox[((a)&0xff) + 256] //low 8 bits		

/*
	NOTE: 
	S0[X] and S1[X] use low 8 bits of X. 
	S[X] uses low 9 bits of X. S is the concatenation of S0 and S1. 
	// concatenation (b1 << 8) + b2

	inblock/outblock is 4-bytes
	initially sboxes were consists of 2 boxes with 256 values in each.
	Now they are connected and 1 consists of 512 values. 
	That's why there is S0 and S1 in description.
	*/


void Mars::MakeKey(const word32* k, unsigned int n, word32* key)
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
			T[i] = T[i] ^ _rotl(T[(i + 8) % 15] ^ T[(i + 13) % 15], 3) ^ (4 * i + j);
		}
		// S-box Based Stirring of Key-Words, Repeat 4 times
		for (size_t k = 0; k < 4; k++)
		{
			for (size_t i = 0; i < 15; i++)
			{
				T[i] = _rotl((T[i] + Sbox[(T[(i + 14) % 15] % 512) & 0x1ff]), 9);
			}
		}
		// Store Next 10 Key-Words into K[]
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
		w ^= _rotl(Sbox[265 + (key[i] & 3)], key[i - 1]) & m;	
		key[i] = w;
	}
	*/
}

void Mars::Encryption(word32 key[40], word32* inblock, word32* outblock)
{
	word32 a = inblock[0], b = inblock[1], c = inblock[2], d = inblock[3];
	a = Modul(a + key[0]); b = Modul(b + key[1]); c = Modul(c + key[2]); d = Modul(d + key[3]);
	//use a to modify b,c,d
	for (size_t i = 0; i < 8; i++)
	{
		b = Modul((b ^ S0(a)) + S1(a >> 8));
		c = Modul(c + S0(a >> 16));
		d = d ^ S1(a >> 24);
		
		a = _rotr(a, 24);
		a = Modul(a + (i % 4 == 0) ? d : 0);
		a = Modul(a + (i % 4 == 1) ? b : 0);

		word32 t = a;	
		a = b;	b = c;	c = d;	d = t;
	}

	for (size_t i = 0; i < 16; i++)
	{
		word32 r = _rotl(Modul(_rotl(a, 13) * key[2 * i + 5]), 10);
		word32 m = _rotl((Modul(a + key[2 * i + 4])), _rotr(r, 5) & 0x1f);	//0x1f ~ 11111
		word32 l = _rotl((S(m) ^ _rotr(r, 5) ^ r), r & 0x1f);
		b = Modul(i < 8 ? Modul(b + l) : b ^ r);
		d = Modul(i < 8 ? d ^ r : Modul(d + l));
		c = Modul(c + m);
		
		word32 t = _rotl(a, 13);
		a = b;	b = c;	c = d;	d = t;
	}

	for (size_t i = 0; i < 8; i++)
	{
		a = Modul(a - (i % 4 == 2) ? d : 0);
		a = Modul(a - (i % 4 == 3) ? b : 0);
		b ^= S1(a);
		c = Modul(c - S0(_rotl(a, 8)));
		d = Modul((d - S1(_rotl(a, 16)))) ^ S0(_rotl(a, 24));
		
		word32 t = _rotl(a, 24);
		a = b;	b = c;	c = d;	d = t;
	}

	a = Modul(a - key[36]);	b = Modul( b - key[37]);	c = Modul(c - key[38]);	d = Modul(d - key[39]);
	outblock[0] = a; outblock[1] = b; outblock[2] = c; outblock[3] = d;
}

void Mars::Decryption(word32 key[40], word32* inblock, word32* outblock) 
{
	word32 a = inblock[0], b = inblock[1], c = inblock[2], d = inblock[3];
	a = Modul(a + key[36]); b = Modul(b + key[37]); c = Modul(c + key[38]); d = Modul(d + key[39]);

	for (size_t i = 0; i < 8; i++)
	{
		word32 t = a;
		a = b;	b = c;	c = d;	d = t;
		a = _rotr(a, 24);

		d = (d ^ Modul(S0(a >> 8)) + S1(a >> 16));
		c = Modul(c + S0(a >> 24));
		b = b ^ S1(a);

		
		a = Modul(a + (i % 4 == 0) ? d : 0);
		a = Modul(a + (i % 4 == 1) ? b : 0);	
	}

	for (size_t i = 0; i < 16; i++)
	{
		word32 t = a;// = _rotl(a, 13);
		a = b;	b = c;	c = d;	d = t;

		word32 r = _rotl(Modul(_rotl(a, 13) * key[35 - 2 * i]), 10);
		word32 m = _rotl((Modul(a + key[34 - 2 * i + 4])), _rotr(r, 5) & 0x1f);	//0x1F ~ 11111
		word32 l = _rotl((S(m) ^ _rotr(r, 5) ^ r), r & 0x1f);
		b = (i < 8 ? Modul(b + l) : b ^ r);
		d = (i < 8 ? d ^ l : Modul(d + r));
		c = c + m;
	}

	for (size_t i = 0; i < 8; i++)
	{
		word32 t = _rotl(a, 24);
		a = b;	b = c;	c = d;	d = t;

		a =  Modul(a - (i % 4 == 2) ? d : 0);
		a = Modul(a - (i % 4 == 3) ? b : 0);
		b ^= S1(a);
		c = Modul(c - S0(_rotl(a, 8)));
		d = Modul((d - S1(_rotl(a, 16)))) ^ S0(_rotl(a, 24));

		
	}

	a = a - key[0];	b = Modul(b - key[1]);	c = Modul(c - key[2]);	d = Modul(d - key[3]);
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

word32 Mars:: Modul(word32 a)
{
	word32 mod = 4294967296;
	if (a >= 0)
	{
		a = a % mod;

	}
	if (a < 0)
	{
		while (a < 0)
		{
			a = a + mod;
		}
	}
	return a;
}
