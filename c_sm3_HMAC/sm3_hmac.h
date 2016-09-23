#ifndef SM3_HMAC_H
#define SM3_HMAC_H

void sm3_hamc(unsigned char *message, unsigned int len, unsigned char key[16], unsigned char hmac[32]);

#endif
