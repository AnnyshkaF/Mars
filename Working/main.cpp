#include "mars.h"
#include <bitset>

int main()
{
	//key (4 words - 14 words) (128bits - 448bits) (1 word - 4 symbols) => min = 16 symbols
	std::vector<u4byte> key;
	std::vector<u4byte> text;
	std::vector<u4byte> entext;
	std::vector<u4byte> detext;
	
	Mars mars;
	//mars.ReadFromFile("C:/Users/Anna/Desktop/ciphers/text/text1.txt", text);
	//mars.ReadFromFile("C:/Users/Anna/Desktop/ciphers/text/cat.bmp", text);
	mars.ReadFromFile("C:/Users/Anna/Desktop/ciphers/text/p.jpg", text);
	mars.ReadFromFile("C:/Users/Anna/Desktop/ciphers/key/key1.txt", key);
	mars.SetKey(key);
	mars.EncryptMessage(text, entext);
	mars.DecryptMessage(entext, detext);
	
	/*
	mars.WriteToFile("C:/Users/Anna/Desktop/original.txt", text);
	mars.WriteToFile("C:/Users/Anna/Desktop/encrypted.txt", entext);
	mars.WriteToFile("C:/Users/Anna/Desktop/result.txt", detext);
	*/
	
	/*
	mars.WriteToFile("C:/Users/Anna/Desktop/original.bmp", text);
	mars.WriteToFile("C:/Users/Anna/Desktop/encrypted.bmp", entext);
	mars.WriteToFile("C:/Users/Anna/Desktop/result.bmp", detext);
	*/
	
	
	mars.WriteToFile("C:/Users/Anna/Desktop/original.jpg", text);
	mars.WriteToFile("C:/Users/Anna/Desktop/encrypted.jpg", entext);
	mars.WriteToFile("C:/Users/Anna/Desktop/result.jpg", detext);
	

	return 0;
}
