#pragma once

#include <vector>
#include <iostream>
//typedef unsigned int word32;
typedef long long word32;
typedef unsigned char byte;

class Mars 
{
private:
	
public:
	//void Encryption(word32 key[40], word32* inblock, word32* outblock);
	//void Decryption(word32 key[40], word32* inblock, word32* outblock);
	void Encryption(word32 key[40], word32* inblock, word32* outblock);
	void Decryption(word32 key[40], word32* inblock, word32* outblock);
	void MakeKey(const word32* userKey, unsigned int length, word32* key);
	word32 Modul(word32 a);
	void eFunction(word32 in, word32 key1, word32 key2, word32* LMR);

};