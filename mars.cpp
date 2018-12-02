#include "mars.h"

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

void Mars::Encrypt(const u4byte in_blk[4], u4byte out_blk[4])
{
	u4byte  a, b, c, d, l, m, r;

	a = in_blk[0] + l_key[0]; b = in_blk[1] + l_key[1];
	c = in_blk[2] + l_key[2]; d = in_blk[3] + l_key[3];

	f_mix(a, b, c, d); a += d;	//D[0] = D[0] + D[3]
	f_mix(b, c, d, a); b += c;	//D[0] = D[0] + D[1]
	f_mix(c, d, a, b);
	f_mix(d, a, b, c);
	f_mix(a, b, c, d); a += d;	//D[0] = D[0] + D[3]
	f_mix(b, c, d, a); b += c;	//D[0] = D[0] + D[1]
	f_mix(c, d, a, b);
	f_mix(d, a, b, c);
	// f_ktr - Forward KeyTRansformation
	f_ktr(a, b, c, d, 4); f_ktr(b, c, d, a, 6); f_ktr(c, d, a, b, 8); f_ktr(d, a, b, c, 10);	//2*i+4 for i=0:15
	f_ktr(a, b, c, d, 12); f_ktr(b, c, d, a, 14); f_ktr(c, d, a, b, 16); f_ktr(d, a, b, c, 18);
	f_ktr(a, d, c, b, 20); f_ktr(b, a, d, c, 22); f_ktr(c, b, a, d, 24); f_ktr(d, c, b, a, 26);
	f_ktr(a, d, c, b, 28); f_ktr(b, a, d, c, 30); f_ktr(c, b, a, d, 32); f_ktr(d, c, b, a, 34);

	b_mix(a, b, c, d);
	b_mix(b, c, d, a); c -= b;
	b_mix(c, d, a, b); d -= a;
	b_mix(d, a, b, c);
	b_mix(a, b, c, d);
	b_mix(b, c, d, a); c -= b;
	b_mix(c, d, a, b); d -= a;
	b_mix(d, a, b, c);

	out_blk[0] = a - l_key[36]; out_blk[1] = b - l_key[37];
	out_blk[2] = c - l_key[38]; out_blk[3] = d - l_key[39];
}

void Mars::Decrypt(const u4byte in_blk[4], u4byte out_blk[4])
{
	u4byte  a, b, c, d, l, m, r;

	d = in_blk[0] + l_key[36]; c = in_blk[1] + l_key[37];
	b = in_blk[2] + l_key[38]; a = in_blk[3] + l_key[39];

	f_mix(a, b, c, d); a += d;
	f_mix(b, c, d, a); b += c;
	f_mix(c, d, a, b);
	f_mix(d, a, b, c);
	f_mix(a, b, c, d); a += d;
	f_mix(b, c, d, a); b += c;
	f_mix(c, d, a, b);
	f_mix(d, a, b, c);

	r_ktr(a, b, c, d, 34); r_ktr(b, c, d, a, 32); r_ktr(c, d, a, b, 30); r_ktr(d, a, b, c, 28);
	r_ktr(a, b, c, d, 26); r_ktr(b, c, d, a, 24); r_ktr(c, d, a, b, 22); r_ktr(d, a, b, c, 20);
	r_ktr(a, d, c, b, 18); r_ktr(b, a, d, c, 16); r_ktr(c, b, a, d, 14); r_ktr(d, c, b, a, 12);
	r_ktr(a, d, c, b, 10); r_ktr(b, a, d, c, 8); r_ktr(c, b, a, d, 6); r_ktr(d, c, b, a, 4);

	b_mix(a, b, c, d);
	b_mix(b, c, d, a); c -= b;
	b_mix(c, d, a, b); d -= a;
	b_mix(d, a, b, c);
	b_mix(a, b, c, d);
	b_mix(b, c, d, a); c -= b;
	b_mix(c, d, a, b); d -= a;
	b_mix(d, a, b, c);

	out_blk[0] = d - l_key[0]; out_blk[1] = c - l_key[1];
	out_blk[2] = b - l_key[2]; out_blk[3] = a - l_key[3];
}

bool Mars::SetKey(const std::vector<u4byte>& k)
{
	u4byte n = k.size();
	if (n < 4 || n > 14) 
	{
		std::cout << "Standart key is taken" << std::endl;
		return false;
	}
	u4byte T[15] = {0};
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
			T[i] = _rotl((T[(i + 8) % 15] ^ T[(i + 13) % 15]), 3) ^ (4 * i + j);
		}
		// S-box Based Stirring of Key-Words, Repeat 4 times
		for (size_t k = 0; k < 4; k++)
		{
			for (size_t i = 0; i < 15; i++)
			{
				T[i] = _rotl((T[i] + S((T[(i + 14) % 15]))), 9);
			}
		}
		// Store Next 10 Key-Words into K[]
		for (size_t i = 0; i < 10; i++)
		{
			l_key[10 * j + i] = T[4 * i % 15];
		}
	}
	std::cout << "User's key is taken" << std::endl;
	return true;
}

void Mars::ReadFromFile(const char* filename, std::vector<u4byte>& v)
{
	std::ifstream file(filename, std::ios::binary | std::ios::ate);
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<char> buffer(size);
	if (file.read(buffer.data(), size))
	{
		int i = 0;
		int j = 0;
		u4byte t = 0;
		while (i <= buffer.size() - 4)
		{
			t = 0;
			set4(buffer[i + 3], buffer[i + 2], buffer[i + 1], buffer[i], t);
			v.push_back(t);
			i += 4;
		}
		int padding = buffer.size() % 4;
		t = 0;
		int p = 0;
		for (p = 0; p < padding; p++)	//add left bytes
		{
			setByte(p, buffer[i++], t);
		}
		if (padding != 0)	//complete not-full block //last byte of data + 10s
		{
			setByte(p, 80, t);
			p++;
			i++;
			while (p < 4)	//0s after 1 after data
			{
				setByte(p, 0, t);
				p++;
			}
			v.push_back(t);
		}
		else
		{	//padding == 0; complete full block
			t = 0;
			setByte(3, 80, t);
			setByte(2, 0, t);
			setByte(1, 0, t);
			setByte(0, 0, t);
			v.push_back(t);
		}
	}
	else
	{
		std::cout << "Unable to open file.";
	}
	file.close();
}

void Mars::WriteToFile(const char* filename, const std::vector<u4byte>& v)
{
	int i = 0, j = 0;
	std::ofstream file(filename, std::ios::binary);
	if (file.is_open())
	{
		for (i = 0; i < v.size() - 2; i++)
		{
			file << char(v[i] & 0xff);
			file << char((v[i] >> 8) & 0xff);
			file << char((v[i] >> 16) & 0xff);
			file << char((v[i] >> 24) & 0xff);
		}
		if (((((v[i + 1] >> 24) & 0xff) == 80)	//if full block was added 
			&& ((v[i + 1] >> 16) & 0xff) == 0)	//i=size()-1
			&& (((v[i + 1] >> 8) & 0xff) == 0)
			&& ((v[i + 1] & 0xff) == 0))
		{
			file << char(v[i] & 0xff);			//entire block before addition block
			file << char((v[i] >> 8) & 0xff);	//i=size()-2
			file << char((v[i] >> 16) & 0xff);
			file << char((v[i] >> 24) & 0xff);
		}
		else
		{
			file << char(v[i] & 0xff);			//entire block before half-block (because reading until -2 block)
			file << char((v[i] >> 8) & 0xff);	//i=size()-2
			file << char((v[i] >> 16) & 0xff);
			file << char((v[i] >> 24) & 0xff);
			i++;
			for (int k = j; k < 4; k++)
			{
				if (v[i] >> (8 * k) == 80)
				{
					break;
				}
				file << char((v[i] >> (8 * k)) & 0xff);


			}
		}
	}
	else
	{
		std::cout << "Unable to open file";
	}
	file.close();
}

void Mars::setByte(int pos, u4byte value, u4byte& b)
{
	int shift = pos * 8;
	b |= value << shift;
}

void Mars::EncryptMessage(const std::vector<u4byte>& v, std::vector<u4byte>& res)
{
	res.resize(v.size());
	for (size_t i = 0; i < v.size(); i += 4)
	{
		Encrypt(&v[i], &res[i]);
	}
}

void Mars::DecryptMessage(const std::vector<u4byte>& v, std::vector<u4byte>& res)
{
	res.resize(v.size());
	for (size_t i = 0; i < v.size(); i += 4)
	{
		Decrypt(&v[i], &res[i]);
	}
}

