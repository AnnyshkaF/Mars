#include <bitset>
#include "mars.h"

int main()
{
	Mars m;
	const word32 userKey[4] = { 0b10101000101011111100000011001110, 0b11111101000101111000011111100110, 0b00111100011110001111001101011101, 0b11001110011100100111010110100000 };
	word32 key[40] = { 0 };
	word32 inblock[4] = { 0, 3, 4, 5 };
	word32 outblock[4] = { 0 };
	word32 resblock[4] = { 0 };

	m.MakeKey(userKey, 1, key);
	std::cout << "Original: " << inblock[0] << std::endl;
	m.Encryption(key, inblock, outblock);
	std::cout << "Encrypted: " << outblock[0] << std::endl;
	m.Decryption(key, outblock, resblock);
	std::cout << "Decrypted: " << resblock[0] << std::endl;


	/*
	std::bitset<64> b1(0b10010101000101011111100000011000);
	std::bitset<64> b2(_rotl(b1.to_ulong(), 4));
	std::cout << b1 << std::endl;
	std::cout << b2 << std::endl;
	*/
	return 0;
}