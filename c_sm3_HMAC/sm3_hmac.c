/*#include <stdlib.h>*/
#include <string.h>
#include "sm3.h"

#define LEN_OF_SM3_KEY 16

#define LEN_OF_SM3_BLOCK 64

#define LEN_OF_SM3_HASHES 32

static const unsigned char ipad = 0x36;

static const unsigned char opad = 0x5c;

void sm3_hmac(unsigned char *message, unsigned int len,
			  unsigned char key[LEN_OF_SM3_KEY], unsigned char hmac[LEN_OF_SM3_HASHES])
{
	/*unsigned char *inner;
	unsigned char *outer;*/
	unsigned char block[LEN_OF_SM3_BLOCK];
	unsigned char inner[(unsigned int)LEN_OF_SM3_BLOCK+len];
	unsigned char outer[LEN_OF_SM3_BLOCK+LEN_OF_SM3_HASHES];
	int i;

	/*inner = (unsigned char*)malloc(((unsigned int)LEN_OF_SM3_BLOCK+len),  \
									sizeof(unsigned char));
	}
	outer = (unsigned char*)malloc((size_t)(LEN_OF_SM3_BLOCK+LEN_OF_SM3_HASHES),  \
									sizeof(unsigned char));
	if(inner == NULL || outer == NULL)
	{
		hmac[0] = 0x0c;
		return;
	}*/

	/*密钥使用sm4的对称密钥，固定长度128比特*/
	memcpy(block, key, (size_t)LEN_OF_SM3_KEY);
	memset(block+(unsigned int)LEN_OF_SM3_KEY, 0x00, (size_t)(LEN_OF_SM3_BLOCK-LEN_OF_SM3_KEY));
	for(i=0; i<LEN_OF_SM3_BLOCK; i++)
	{
		inner[i] = block[i] ^ ipad;
		outer[i] = block[i] ^ opad;
	}

	memcpy(inner+(unsigned int)LEN_OF_SM3_BLOCK, message, len);

	sm3(inner, (unsigned int)LEN_OF_SM3_BLOCK+len, hmac);

	/*free(inner);*/

	memcpy(outer+(unsigned int)LEN_OF_SM3_BLOCK, hmac, (size_t)LEN_OF_SM3_HASHES);

	sm3(outer, (unsigned int)(LEN_OF_SM3_BLOCK+LEN_OF_SM3_HASHES), hmac);

	/*free(outer);*/
}
