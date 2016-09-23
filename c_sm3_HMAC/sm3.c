#include <string.h>
#include <stdio.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define SM3_FUNC_FF0_15(x, y, z) ((x) ^ (y) ^ (z))

#define SM3_FUNC_FF16_63(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))

#define SM3_FUNC_GG0_15(x, y, z) ((x) ^ (y) ^ (z))

#define SM3_FUNC_GG16_63(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

#define SM3_FUNC_P0(x) ((x) ^ (ROTL((x), 9)) ^ (ROTL((x), 17)))

#define SM3_FUNC_P1(x) ((x) ^ (ROTL((x), 15)) ^ (ROTL((x), 23)))

#define INT_2_CHARX4(n, b, i)				        \
{													\
	((b)[(i)  ] = (unsigned char)((n) >> 24)); 		\
    ((b)[(i)+1] = (unsigned char)((n) >> 16));		\
	((b)[(i)+2] = (unsigned char)((n) >>  8));		\
	((b)[(i)+3] = (unsigned char)((n)      ));		\
}

#define CHARX4_2_INT(n, b, i)						\
(													\
 	(n) = ((unsigned int)((b)[(i)  ] << 24))		\
 		| ((unsigned int)((b)[(i)+1] << 16))		\
 		| ((unsigned int)((b)[(i)+2] <<  8))		\
 		| ((unsigned int)((b)[(i)+3]      ))		\
)

static const unsigned int iv[8] = {0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
							 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e};
static const unsigned int t0_t15 = 0x79cc4519;
static const unsigned int t16_t63 = 0x7a879d8a;

struct sm3_context
{
	unsigned int reg[8];
	unsigned int ss1;
	unsigned int ss2;
	unsigned int tt1;
	unsigned int tt2;
	unsigned int v[8];
};

/*不支持最大长度2^64比特，所支持最大长度修改为2^32比特。*/
static void sm3_padding(unsigned char *message, unsigned int len, unsigned char *message1)
{
	unsigned int len_pad_zero;

	len_pad_zero = (unsigned int)59 - (len % (unsigned int)64);
	memcpy(message1, message, len);
	message1[len] = 0x80;
	memset(message1+len+1, 0x00, len_pad_zero);
	INT_2_CHARX4(len*(unsigned int)8, message1, len+len_pad_zero+1);
}

static void sm3_extend(unsigned char b[64], unsigned int w[68], unsigned int w1[64])
{
	int i;

	for(i=0; i<16; i++)
	{
		CHARX4_2_INT(w[i], b, i*4);
	}

	for(i=16; i<=67; i++)
	{
		w[i] = SM3_FUNC_P1(w[i-16] ^ w[i-9] ^ (ROTL(w[i-3], 15))) ^ ROTL(w[i-13], 7) ^ w[i-6];
	}

	for(i=0; i<=63; i++)
	{
		w1[i] = w[i] ^ w[i+4];
	}
}

static void sm3_func_cf(struct sm3_context *ctx, unsigned int w[68], unsigned int w1[64])
{
	int i;

	for(i=0; i<8; i++)
	{
		ctx->reg[i] = ctx->v[i];
	}

	for(i=0; i<=15; i++)
	{
		ctx->ss1 = ROTL((ROTL(ctx->reg[0], 12) + ctx->reg[4] + ROTL(t0_t15, i)), 7);
		ctx->ss2 = ctx->ss1 ^ ROTL(ctx->reg[0], 12);
		ctx->tt1 = SM3_FUNC_FF0_15(ctx->reg[0], ctx->reg[1], ctx->reg[2]) + \
				   				   ctx->reg[3] + ctx->ss2 + w1[i];
		ctx->tt2 = SM3_FUNC_GG0_15(ctx->reg[4], ctx->reg[5], ctx->reg[6]) + \
				   				   ctx->reg[7] + ctx->ss1 + w[i];
		ctx->reg[3] = ctx->reg[2];
		ctx->reg[2] = ROTL(ctx->reg[1], 9);
		ctx->reg[1] = ctx->reg[0];
		ctx->reg[0] = ctx->tt1;
		ctx->reg[7] = ctx->reg[6];
		ctx->reg[6] = ROTL(ctx->reg[5], 19);
		ctx->reg[5] = ctx->reg[4];
		ctx->reg[4] = SM3_FUNC_P0(ctx->tt2);
	}
	for(i=16; i<=63; i++)
	{
		ctx->ss1 = ROTL((ROTL(ctx->reg[0], 12) + ctx->reg[4] + ROTL(t16_t63, i)), 7);
		ctx->ss2 = ctx->ss1 ^ ROTL(ctx->reg[0], 12);
		ctx->tt1 = SM3_FUNC_FF16_63(ctx->reg[0], ctx->reg[1], ctx->reg[2]) + \
				   				   ctx->reg[3] + ctx->ss2 + w1[i];
		ctx->tt2 = SM3_FUNC_GG16_63(ctx->reg[4], ctx->reg[5], ctx->reg[6]) + \
				   				   ctx->reg[7] + ctx->ss1 + w[i];
		ctx->reg[3] = ctx->reg[2];
		ctx->reg[2] = ROTL(ctx->reg[1], 9);
		ctx->reg[1] = ctx->reg[0];
		ctx->reg[0] = ctx->tt1;
		ctx->reg[7] = ctx->reg[6];
		ctx->reg[6] = ROTL(ctx->reg[5], 19);
		ctx->reg[5] = ctx->reg[4];
		ctx->reg[4] = SM3_FUNC_P0(ctx->tt2);
	}

	for(i=0; i<8; i++)
	{
		ctx->v[i] = ctx->reg[i] ^ ctx->v[i];
	}
}

static void sm3_iteration(unsigned char *message1, unsigned int len, struct sm3_context *ctx)
{
	unsigned int n;
	unsigned int i;
	unsigned int w[68];
	unsigned int w1[64];

	n = (len + ((unsigned int)64 - (len % (unsigned int)64))) / (unsigned int)64;
	memcpy(ctx->v, iv, ((size_t)8*sizeof(unsigned int)));

	for(i=(unsigned int)0; i<n; i++)
	{
		sm3_extend(message1+(i*(unsigned int)64), w, w1);

		sm3_func_cf(ctx, w, w1);
	}
}

void sm3(unsigned char *message, unsigned int len, unsigned char sm3_hashes[32])
{
	int i;
	struct sm3_context context;
	unsigned char message1[len+((unsigned int)64-(len%(unsigned int)64))];

	sm3_padding(message, len, message1);

	sm3_iteration(message1, len, &context);

	for(i=0; i<8; i++)
	{
		INT_2_CHARX4(context.v[i], sm3_hashes, i*4);
	}
}
