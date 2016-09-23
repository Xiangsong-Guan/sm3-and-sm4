#include <stdio.h>
#include <string.h>
#include "sm4.h"

int main(int argc, char *argv[])
{
	unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd ,0xef,
		                     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
	unsigned char plain[16];
	unsigned char cypher[16];

	int i = 0;
	int j = 0;
	char *ret;

	for(i=1; i<=10; i++)
	{
		plain[i-1] = (unsigned char)i;
	}

	ret = sm4(encrypt, (unsigned long)10, key, plain, cypher);
	memcpy(plain, cypher, (size_t)16);
	
	for(i=2; i<=1000000; i++)
	{
		ret = sm4(encrypt, (unsigned long)0, key, plain, cypher);
		memcpy(plain, cypher, (size_t)16);
	}

	for(i=1; i<=1000000; i++)
	{
		ret = sm4(decrypt, (unsigned long)16, key, cypher, plain);
		memcpy(cypher, plain, (size_t)16);
	}

	/*ret = sm4(encrypt, (unsigned long)16, key, plain, cypher);

	for(i=0; i<=31; i++)
	{
		printf("%x..", cypher[i]);
	}
	printf("\n");

	ret = sm4(decrypt, (unsigned long)32, key, cypher, plain);*/

	for(i=0; i<=15; i++)
	{
		printf("%x..", plain[i]);
	}
	printf("\n");
	return 0;
}
