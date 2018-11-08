#pragma once

#include <vector>
#include <iostream>
typedef unsigned int word32;
typedef unsigned char byte;

class Mars 
{
private:
	
public:
	void Encryption(word32 key[40], word32* inblock, word32* outblock) const;
	void Decryption(word32 key[40], word32* inblock, word32* outblock) const;
	void MakeKey(const word32 *userKey, unsigned int length, word32* key);
};