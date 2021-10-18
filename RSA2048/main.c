/*****************************************************************************
Filename    : main.c
Author      : Terrantsh (tanshanhe@foxmail.com)
Date        : 2018-9-22 18:18:54
Description : 实现了RSA2048加密解密的各项功能，并能够进行最大256位的加密操作
*****************************************************************************/
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "rsa.h"
#include "keys.h"
/*
 * RSA2048 encrypt and decrypt
 * include rsa.c/bignum.c/rsa.h/bignum.h/keys.h
 */

#ifdef RSA2048
	#define output_len 256
#else
	#define output_len 512
#endif
static int RSA_test(void){
	int ret;
	rsa_pk_t pk = {0};
	rsa_sk_t sk = {0};
	uint8_t output[output_len];

	// message to encrypt
	uint8_t input[output_len];

	unsigned char msg[output_len];
	uint32_t outputLen, msg_len;
	uint8_t  inputLen;

	// copy keys.h message about public key and private key to the flash RAM
	pk.bits = KEY_M_BITS;
	memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m) ],  key_m,  sizeof(key_m ));
	memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e) ],  key_e,  sizeof(key_e ));
	sk.bits = KEY_M_BITS;
	memcpy(&sk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m) ],  key_m,  sizeof(key_m ));
	memcpy(&sk.public_exponet  [RSA_MAX_MODULUS_LEN-sizeof(key_e) ],  key_e,  sizeof(key_e ));
	memcpy(&sk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_pe)],  key_pe, sizeof(key_pe));
	memcpy(&sk.prime1          [RSA_MAX_PRIME_LEN - sizeof(key_p1)],  key_p1, sizeof(key_p1));
	memcpy(&sk.prime2          [RSA_MAX_PRIME_LEN - sizeof(key_p2)],  key_p2, sizeof(key_p2));
	memcpy(&sk.prime_exponent1 [RSA_MAX_PRIME_LEN - sizeof(key_e1)],  key_e1, sizeof(key_e1));
	memcpy(&sk.prime_exponent2 [RSA_MAX_PRIME_LEN - sizeof(key_e2)],  key_e2, sizeof(key_e2));
	memcpy(&sk.coefficient     [RSA_MAX_PRIME_LEN - sizeof(key_c) ],  key_c,  sizeof(key_c ));

	generate_rand(input,200);
	inputLen = strlen((const char*)input);
	printf("Input: %s, inputLen:%d\n",input, inputLen);
	// public key encrypt
	rsa_public_encrypt(output, &outputLen, input, inputLen, &pk);

	printf("-------------Begining of the RSA Corection Test!----------------\n");

	// private key decrypt
	rsa_private_decrypt(msg, &msg_len, output, outputLen, &sk);
	if(memcmp(input,msg,inputLen)==0){
		printf("Public key encrypt and private key decrypt success!\n");
	}
	else{
		printf("Public key encrypt and private key decrypt fail!\n");
	}

	// private key encrypt
	rsa_private_encrypt(output, &outputLen, input, inputLen, &sk);

	// public key decrypted
	rsa_public_decrypt(msg, &msg_len, output, outputLen, &pk);
	if(memcmp(input,msg,inputLen)==0){
		printf("Private key encrypt and public key decrypt success!\n");
	}
	else{
		printf("Private key encrypt and public key decrypt fail!\n");
	}
	printf("-------------End of the RSA Corection Test!----------------\n");
	return 0;
}
/* RSA2048 function ended */

static int RSA_speed(void){
	int ret;
	rsa_pk_t pk = {0};
	rsa_sk_t sk = {0};
	uint8_t output[output_len];

	// message to encrypt
	uint8_t input [256] = { 0x21,0x55,0x53,0x53,0x53,0x53};

	unsigned char msg [output_len];
	uint32_t outputLen, msg_len;
	uint8_t  inputLen;
	clock_t start1=0, end1=0, start2=0, end2=0;
	// copy keys.h message about public key and private key to the flash RAM
	pk.bits = KEY_M_BITS;
	memcpy(&pk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m) ],  key_m,  sizeof(key_m ));
	memcpy(&pk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_e) ],  key_e,  sizeof(key_e ));
	sk.bits = KEY_M_BITS;
	memcpy(&sk.modulus         [RSA_MAX_MODULUS_LEN-sizeof(key_m) ],  key_m,  sizeof(key_m ));
	memcpy(&sk.public_exponet  [RSA_MAX_MODULUS_LEN-sizeof(key_e) ],  key_e,  sizeof(key_e ));
	memcpy(&sk.exponent        [RSA_MAX_MODULUS_LEN-sizeof(key_pe)],  key_pe, sizeof(key_pe));
	memcpy(&sk.prime1          [RSA_MAX_PRIME_LEN - sizeof(key_p1)],  key_p1, sizeof(key_p1));
	memcpy(&sk.prime2          [RSA_MAX_PRIME_LEN - sizeof(key_p2)],  key_p2, sizeof(key_p2));
	memcpy(&sk.prime_exponent1 [RSA_MAX_PRIME_LEN - sizeof(key_e1)],  key_e1, sizeof(key_e1));
	memcpy(&sk.prime_exponent2 [RSA_MAX_PRIME_LEN - sizeof(key_e2)],  key_e2, sizeof(key_e2));
	memcpy(&sk.coefficient     [RSA_MAX_PRIME_LEN - sizeof(key_c) ],  key_c,  sizeof(key_c ));

	inputLen = strlen((const char*)input);
	
	printf("-----------------Begining of RSA Speed Test-----------------\n");
	// public key encrypt
	double sum1=0;
	double sum2=0;
	int count=1000;
	for(int i=0;i<count;i++){
		generate_rand(input,200);
		inputLen = strlen((const char*)input);
		// printf("Input: %s, inputLen:%d\n",input, inputLen);
		start1=clock();
		rsa_public_encrypt(output, &outputLen, input, inputLen, &pk);
		end1=clock();
		sum1+=(double)(end1-start1)/CLOCKS_PER_SEC;
		// private key decrypt
		start2=clock();
		rsa_private_decrypt(msg, &msg_len, output, outputLen, &sk);
		end2=clock();
		sum2+=(double)(end2-start2)/CLOCKS_PER_SEC;
	}
	printf("rsa_public_encrypt Average time(s): %lf, rsa_private_decrypt Average time(s): %lf\n",sum1/count,sum2/count);

	sum1=0;
	sum2=0;
	for(int i=0;i<count;i++){
		generate_rand(input,200);
		inputLen = strlen((const char*)input);
		start1=clock();
		rsa_private_encrypt(output, &outputLen, input, inputLen, &sk);
		end1=clock();
		sum1+=(double)(end1-start1)/CLOCKS_PER_SEC;
		// private key decrypt
		start2=clock();
		// public key decrypted
		rsa_public_decrypt(msg, &msg_len, output, outputLen, &pk);
		end2=clock();
		sum2+=(double)(end2-start2)/CLOCKS_PER_SEC;
	}
	printf("rsa_private_encrypt Average time(s): %lf, rsa_public_decrypt Average time(s): %lf\n",sum1/count,sum2/count);

	printf("-----------------End of RSA Speed Test-----------------\n");
	return 0;
}

int main(int argc, char const *argv[])
{
	clock_t start, finish;
	double  duration;
	start = clock();    // init start time
	RSA_test();
	finish = clock();   // print end time
	duration = (double)(finish - start) / CLOCKS_PER_SEC;   // print encrypt and decrypt time
	printf( "%f seconds\n", duration );
	RSA_speed();
	return 0;
}
