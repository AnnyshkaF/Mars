#include <bitset>
#include "mars.h"

int main()
{
	Mars m;
	const word32 userKey1[1] = { 1};
	word32 key[40] = { 0 };
	word32 inblock[4] = { 2, 3, 4, 5 };
	word32 outblock[4] = { 0 };
	word32 resblock[4] = { 0 };

	m.MakeKey(userKey1, 1, key);
	m.Encryption(key, inblock, outblock);
	m.Decryption(key, outblock, resblock);

	std::cout << "Original: " << inblock[0] << std::endl;
	std::cout << "Result: " << outblock[0] << std::endl;
	return 0;
}