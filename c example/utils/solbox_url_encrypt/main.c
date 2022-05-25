#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/buffer.h>

const char * progname;

static int aes_init(unsigned char * key_string, int key_string_len, unsigned char * cipher_key); //, unsigned char * iv)
static int aes_encrypt(unsigned char * p_in, unsigned char * p_out, int size, unsigned char * cipher_key, unsigned char * iv);
static char * encode_base64(const unsigned char *in_str, int length);
static void base64_urlencode(char * str);

/*
 * 1: url (string, mandatory) 
 * 2: key (string, mandatory)
 * 3: skip path (number, optional)
 * 4: not encrypt file (boolean, optional)
 */
void
print_usage(const char * prog)
{
	if(prog == NULL) 
	{
		fprintf(stderr, "%s: <url> <key> [<timeout> [<skip count>(0~9) [<except file>(0|1)]]]\n", progname);
	}else
	{
		fprintf(stderr, "%s: <url> <key> [<timeout> [<skip count>(0~9) [<except file>(0|1)]]]\n", prog);
	}
	fprintf(stderr, "	url		: url string\n");
	fprintf(stderr, "	key		: encrypt key\n");
	fprintf(stderr, "	timeout		: expire timeout(default: 60)\n");
	fprintf(stderr, "	skip count	: skip directory count (default: 0)\n");
	fprintf(stderr, "	except file	: unencrypt filename (default: 0)\n");
}
int
main(int argc, char * argv[])
{
	char * url;
	char * key;
	char * end_skip_path = NULL;
	char * target_url;
	char * ptr;
	char * json_string = NULL;
	char * encrypt_data = NULL;
	int timeout = 60;
	time_t exp;
	int skip_path = 0;
	int except_file = 0;
	int json_len = 0;
	int i;

	unsigned char cipher_key_e[SHA256_DIGEST_LENGTH];
	//unsigned char cipher_key_d[SHA256_DIGEST_LENGTH];
	unsigned char iv[SHA256_DIGEST_LENGTH];
	memset(iv, 0x00, SHA256_DIGEST_LENGTH);

	/* parse_args */
	progname = argv[0];
	srand(time(NULL));
	do
	{
		if(argc < 3)
		{
			print_usage(argv[0]);
			return 1;
		}
		url = argv[1];
		key = argv[2];
		if(argc > 3)
		{
			timeout = atoi(argv[3]);
			if(timeout <= 0 || timeout >= INT_MAX )
			{
				fprintf(stderr, "timeout error: %d\n", timeout);
				print_usage(argv[0]);
				return 1;
			}
		}
		if(argc > 4)
		{
			skip_path = atoi(argv[4]);
			if(skip_path < 0 || skip_path > 9)
			{
				print_usage(argv[0]);
				return 1;
			}
		}
		if(argc > 5)
		{
			except_file = atoi(argv[5]);
			if(except_file < 0 || except_file> 9)
			{
				print_usage(argv[0]);
				return 1;
			}
		}
	}while(0);
	
	/* extract string */
	end_skip_path = url;
	for(i = 0; i < skip_path; ++i)
	{
		end_skip_path = strchr(end_skip_path + 1, '/');
		if(end_skip_path == NULL)
		{
			print_usage(NULL);
			return 2;
		}
	}
	target_url = strdup(end_skip_path);
	if(NULL == target_url)
	{
		fprintf(stderr, "%s: Failed to allocation memory for path\n", progname);
		return 2;
	}
	if(0 != except_file)
	{
		ptr = strrchr(target_url, '/');
		if(ptr == NULL || ptr == target_url)
		{
			print_usage(NULL);
			goto _error;
		}
		*ptr = 0;
	}

	/* make exp */
	time(&exp);
	exp += timeout;

	/* make json */
	json_len = 60 + strlen(target_url);
	json_string = (char *)calloc(json_len+1, 1);
	if(NULL == json_string)
	{
		fprintf(stderr, "%s: Failed to allocation memory for json\n", progname);
		return 2;
	}
#if 0
	snprintf(json_string, json_len, "{ \"seq\": %d, \"path\": \"%s\", \"exp\": %ld }", (int)12345, target_url, exp);
#else
	snprintf(json_string, json_len, "{ \"seq\": %d, \"path\": \"%s\", \"exp\": %ld }", (int)(random() & 0xFFF), target_url, exp);
#endif
	json_len = strlen(json_string);

	if(0 != aes_init((unsigned char *)key, strlen(key), cipher_key_e))
	{
		fprintf(stderr, "%s: Failed to preprocess encode key\n", progname);
		goto _error;
	}
	encrypt_data = calloc(json_len * 2 + 1, 1);
	if(NULL == encrypt_data)
	{
		fprintf(stderr, "%s: Failed to allocation memory for encode aes\n", progname);
		goto _error;
	}
	printf("Text: \n%s\n", json_string);
#if 1
	i = aes_encrypt((unsigned char *)json_string, (unsigned char *)encrypt_data, json_len, cipher_key_e, iv);
	if(i != 0)
	{
		fprintf(stderr, "%s: Failed to encode aes256\n", progname);
		goto _error;
	}
	json_len = (json_len / 16 + 1) * 16;
	ptr = (char *)encode_base64((unsigned char *)encrypt_data, json_len);
#else
	ptr = (char *)encode_base64((unsigned char *)json_string, json_len);
#endif
	if(NULL == ptr)
	{
		fprintf(stderr, "%s: Failed to encode base64\n", progname);
		goto _error;
	}
#if 0
	printf("Result: \n%s\n", ptr);
#else
	char * file ;
	if(!except_file)
	{
		file = "";
	}else
	{
		file = strrchr(url, '/');
	}
	if(skip_path > 0)
	{
		*end_skip_path = 0;
	}
	printf("Result: \n%s/%s%s\n", url, ptr, file);
#endif
	free(ptr);

	free(target_url);
	free(json_string);
	free(encrypt_data);
	return 0;
_error:
	if(encrypt_data) { free(encrypt_data); }
	if(json_string) { free(json_string); }
	free(target_url);
	return 3;
}

static char * encode_base64(const unsigned char *in_str, int length)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	if(NULL == b64) { return NULL; }
	bmem = BIO_new(BIO_s_mem());
	if(NULL == bmem) { BIO_free_all(b64); return NULL; }
	b64 = BIO_push(b64, bmem);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b64, in_str, length);
	(void) BIO_flush(b64);
	//BIO_get_mem_ptr(b64, &bptr);
	BIO_get_mem_ptr(bmem, &bptr);

	char * buff = (char *)calloc(((int)bptr->length)+1, 1);
	memcpy(buff, bptr->data, (int)bptr->length);
	buff[(int)(bptr->length)] = 0;

	BIO_free_all(b64);
	base64_urlencode(buff);

	return buff;
}
#if 0
static void base64_urldecode(char * str)
{
	int len = strlen(str);
	int i, t;

	for(i = t = 0; i < len; i++)
	{
		switch(str[i])
		{
		case '-':
			str[t] = '+';
			break;
		case '_':
			str[t] = '/';
			break;
		}
		++t;
	}
	str[t] = '\0';
}
#endif
static void base64_urlencode(char * str)
{
	int len = strlen(str);
	int i, t;

	for(i = t = 0; i < len; i++)
	{
		switch(str[i])
		{
		case '+':
			str[t] = '-';
			break;
		case '/':
			str[t] = '_';
			break;
		case '=':
			continue;
		}
		++t;
	}
	str[t] = '\0';
}

static int
aes_init(unsigned char * key_string, int key_string_len, unsigned char * cipher_key) //, unsigned char * iv)
{
        int res;
        SHA256_CTX c;
        res = SHA256_Init(&c);
        if(!res) return -1;
        res = SHA256_Update(&c, key_string, key_string_len);
        if(!res) return -1;
        res = SHA256_Final(cipher_key, &c);
        if(!res) return -1;
        OPENSSL_cleanse(&c, sizeof(c));
#if 0
        res = SHA256_Init(&c);
        if(res) return -1;
        res = SHA256_Update(&c, "AES Encrypt", 11);
        if(res) return -1;
        res = SHA256_Update(&c, key_string, key_string_len);
        if(res) return -1;
        res = SHA256_Final(iv, &c);
        if(res) return -1;
        OPENSSL_cleanse(&c, sizeof(c));
#endif
        return 0;
}

static int
aes_encrypt(unsigned char * p_in, unsigned char * p_out, int size, unsigned char * cipher_key, unsigned char * iv)
{
        int res;
        AES_KEY aes_key;
        unsigned char   iv_data[SHA256_DIGEST_LENGTH];

        memcpy(iv_data, iv, SHA256_DIGEST_LENGTH);
        res = AES_set_encrypt_key(cipher_key, SHA256_DIGEST_LENGTH*8, &aes_key);
        if(res) return -1;
        AES_cbc_encrypt(p_in, p_out, size, &aes_key, iv_data, AES_ENCRYPT);
        return 0;

}
