#include <stdio.h>
#include "sm3_hmac.h"

int main(void)
{
	unsigned int len;

	unsigned char m[100];

	unsigned char hashes[32];

	unsigned char key[16];

	int i;

	for(i=0; i<=99; i++)
	{
		m[i] = (unsigned char)i;
	}

	for(i=0; i<16; i++)
	{
		key[i] = (unsigned char)i;
	}

	len = (unsigned int)100;

	sm3_hmac(m, len, key, hashes);

	for(i=0; i<32; i++)
	{
		printf("%02x", hashes[i]);
	}

	printf("\n");

	return 0;
}
