#ifndef DNAS_H
#define DNAS_H

#include <vector>

namespace DNAS
{
	std::vector<unsigned char> encrypt3(const std::vector<unsigned char>& data, int offset, int length,
		const std::vector<unsigned char>& des_key1, const std::vector<unsigned char>& des_key2,
		const std::vector<unsigned char>& des_key3, const std::vector<unsigned char>& xor_seed);
		
	std::vector<unsigned char> decrypt3(const std::vector<unsigned char>& data, int offset, int length,
		const std::vector<unsigned char>& des_key1, const std::vector<unsigned char>& des_key2,
		const std::vector<unsigned char>& des_key3, const std::vector<unsigned char>& xor_seed);
}

#endif // DNAS_H
