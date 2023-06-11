#include <openssl/des.h>

#include <dnasbypass/dnas.h>

std::vector<unsigned char> DNAS::encrypt3(const std::vector<unsigned char>& data, int offset, int length,
		const std::vector<unsigned char>& des_key1, const std::vector<unsigned char>& des_key2,
		const std::vector<unsigned char>& des_key3, const std::vector<unsigned char>& xor_seed)
{
    std::vector<unsigned char> encryptedData = data;
    std::vector<unsigned char> key = xor_seed;

    for (int i = 0; i < length; i += 8)
	{
        std::vector<unsigned char> dat(encryptedData.begin() + offset + i, encryptedData.begin() + offset + i + 8);
        
		for (int t = 0; t < 8; t++)
		{
            dat[t] = dat[t] ^ key[t];
        }

        DES_key_schedule ks1, ks2, ks3;
        DES_set_key((const_DES_cblock*)des_key1.data(), &ks1);
        DES_set_key((const_DES_cblock*)des_key2.data(), &ks2);
        DES_set_key((const_DES_cblock*)des_key3.data(), &ks3);

        DES_ecb_encrypt((const_DES_cblock*)dat.data(), (DES_cblock*)dat.data(), &ks1, DES_ENCRYPT);
        DES_ecb_encrypt((const_DES_cblock*)dat.data(), (DES_cblock*)dat.data(), &ks2, DES_DECRYPT);
        DES_ecb_encrypt((const_DES_cblock*)dat.data(), (DES_cblock*)dat.data(), &ks3, DES_ENCRYPT);

        for (int t = 0; t < 8; t++)
		{
            encryptedData[offset + i + t] = dat[t];
        }
		
        key = dat;
    }

    return encryptedData;
}

std::vector<unsigned char> DNAS::decrypt3(const std::vector<unsigned char>& encryptedData, int offset, int length,
		const std::vector<unsigned char>& des_key1, const std::vector<unsigned char>& des_key2,
		const std::vector<unsigned char>& des_key3, const std::vector<unsigned char>& xor_seed)
{
    std::vector<unsigned char> data = encryptedData;
    //std::vector<unsigned char> key = xor_seed;

    for (int i = length; i >= 0; i -= 8)
	{
		/*
        std::vector<unsigned char> dat(encryptedData.begin() + offset + i, encryptedData.begin() + offset + i + 8);
        
		for (int t = 0; t < 8; t++)
		{
            dat[t] = dat[t] ^ key[t];
        }

        DES_key_schedule ks1, ks2, ks3;
        DES_set_key((const_DES_cblock*)des_key1.data(), &ks1);
        DES_set_key((const_DES_cblock*)des_key2.data(), &ks2);
        DES_set_key((const_DES_cblock*)des_key3.data(), &ks3);

        DES_ecb_encrypt((const_DES_cblock*)dat.data(), (DES_cblock*)dat.data(), &ks1, DES_ENCRYPT);
        DES_ecb_encrypt((const_DES_cblock*)dat.data(), (DES_cblock*)dat.data(), &ks2, DES_DECRYPT);
        DES_ecb_encrypt((const_DES_cblock*)dat.data(), (DES_cblock*)dat.data(), &ks3, DES_ENCRYPT);

        for (int t = 0; t < 8; t++)
		{
            encryptedData[offset + i + t] = dat[t];
        }
		
        key = dat;
		*/
    }

    return data;
}