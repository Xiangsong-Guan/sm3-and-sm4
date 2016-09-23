#ifndef SM4_H
#define SM4_H

enum sm4_mode
{
	encrypt = 1,
	decrypt = 0
};

char *sm4(enum sm4_mode mode, unsigned long len, unsigned char key[16],
         unsigned char *input, unsigned char *output);

#endif