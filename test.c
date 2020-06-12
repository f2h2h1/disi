/*
Digital signature
使用rsa算法，md5哈希函数
路径只能有ascii字符，参数只能是ascii字符，因为c语言处理字符有点麻烦所以这里限制了只支持ascii字符
文件不能大于2G

gcc test.c -o disi && disi --sign example.txt rsa_private.pem example.sign

生成数字签名
disi --sign example.txt rsa_private.pem example.sign
验证数字签名
disi --check example.txt rsa_public.pem example.sign

新建一个用于测试的文件
echo "this is a test file" > example.txt
使用openssl生成rsa私钥
openssl genrsa -out rsa_private.pem 2048
使用openssl根据rsa私钥生成rsa公钥
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
使用openssl输出example.txt的数字摘要
openssl dgst -md5 example.txt
使用openssl对example.txt生成数字签名
openssl dgst -md5 -sign rsa_private.pem -out example.sign example.txt
使用openssl验证example.txt的数字签名
openssl dgst -prverify rsa_private.pem -md5 -signature example.sign example.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
    #include <io.h>
#else
    #include <unistd.h>
#endif

#define DISI_PARAM_ERROR 1
#define DISI_FILE_NOT_EXISTS 2

typedef struct uString
{
    char *str;
    int len;
} uString;

void copyCharToString(char *src, uString *tag);
void copyCharToString(char *src, uString *tag)
{
    int len = 0;
    for (; src[len] != '\0'; len++);
    tag->str = (char*)malloc(len*sizeof(char));
    tag->len = len;
    for (int i = 0; i <= len; i++) {
        tag->str[i] = src[i];
    }
}

void printuString(uString *tag);
void printuString(uString *tag)
{
    if (tag->len != 0) {
        printf("%s", tag->str);
    }
    printf("\n");
}

uString fileFath = {
    .str = NULL,
    .len = 0
};
uString Privatekey = {
    .str = NULL,
    .len = 0
};
uString PublicKey = {
    .str = NULL,
    .len = 0
};
uString outSignaturePath = {
    .str = NULL,
    .len = 0
};
uString inSignaturePath = {
    .str = NULL,
    .len = 0
};

int mode; // 程序运行的模式，1是签名，2是验证签名
char *help = "Please Input correct parameters\n--sign FilePath Privatekey outSignaturePath\n--check FilePath PublicKey inSignaturePath\n";

void isFileExists(uString *tag);
void isFileExists(uString *tag)
{
    if (_access(tag->str, F_OK) != 0) {
        printf("%s not exists.\n", tag->str);
        exit(DISI_FILE_NOT_EXISTS);
    }
}

void printftest();
void printtest()
{
    printf("mode:\t%d\n", mode);
    printf("fileFath:\t");
    printuString(&fileFath);
    printf("Privatekey:\t");
    printuString(&Privatekey);
    printf("PublicKey:\t");
    printuString(&PublicKey);
    printf("outSignaturePath:\t");
    printuString(&outSignaturePath);
    printf("inSignaturePath:\t");
    printuString(&inSignaturePath);
}

void sign(char *md5Str);


void check();
void check()
{

}

void dump(void * p, int length) {
    char * s = p;
    int i, a, k;
    int b[8];
    for (i = 0; i < length; i++, s++) {
        printf("%p: %x\t", s, *s);
        a = *s;
        printf("%d\t", a);
        for (k = 0; k < 8; k++) {
            while (a) {
                b[k] = a % 2;
                a /= 2;
                k++;
            }
            b[k] = 0;
        }
        while (k > 0) {
            printf("%d", b[--k]);
        }
        printf("\n");
    }
}

/* md5相关的实现 */

#ifndef MD5_H
#define MD5_H

#define MD5_SIZE		16
#define MD5_STR_LEN		(MD5_SIZE * 2)

typedef struct
{
    unsigned int count[2];
    unsigned int state[4];
    unsigned char buffer[64];   
} MD5_CTX;


#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))

#define FF(a,b,c,d,x,s,ac) \
{ \
    a += F(b,c,d) + x + ac; \
    a = ROTATE_LEFT(a,s); \
    a += b; \
}
#define GG(a,b,c,d,x,s,ac) \
{ \
    a += G(b,c,d) + x + ac; \
    a = ROTATE_LEFT(a,s); \
    a += b; \
}
#define HH(a,b,c,d,x,s,ac) \
{ \
    a += H(b,c,d) + x + ac; \
    a = ROTATE_LEFT(a,s); \
    a += b; \
}
#define II(a,b,c,d,x,s,ac) \
{ \
    a += I(b,c,d) + x + ac; \
    a = ROTATE_LEFT(a,s); \
    a += b; \
}                                            
void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen);
void MD5Final(MD5_CTX *context, unsigned char digest[16]);
void MD5Transform(unsigned int state[4], unsigned char block[64]);
void MD5Encode(unsigned char *output, unsigned int *input, unsigned int len);
void MD5Decode(unsigned int *output, unsigned char *input, unsigned int len);

#endif

unsigned char PADDING[] =
{
    0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

void MD5Init(MD5_CTX *context)
{
    context->count[0] = 0;
    context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
}

void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen)
{
    unsigned int i = 0;
    unsigned int index = 0;
    unsigned int partlen = 0;

    index = (context->count[0] >> 3) & 0x3F;
    partlen = 64 - index;
    context->count[0] += inputlen << 3;

    if(context->count[0] < (inputlen << 3))
        context->count[1]++;
    context->count[1] += inputlen >> 29;

    if(inputlen >= partlen)
    {
        memcpy(&context->buffer[index], input,partlen);
        MD5Transform(context->state, context->buffer);

        for(i = partlen; i+64 <= inputlen; i+=64)
            MD5Transform(context->state, &input[i]);

        index = 0;        
    }  
    else
    {
        i = 0;
    }
    memcpy(&context->buffer[index], &input[i], inputlen-i);
}

void MD5Final(MD5_CTX *context, unsigned char digest[16])
{
    unsigned int index = 0,padlen = 0;
    unsigned char bits[8];

    index = (context->count[0] >> 3) & 0x3F;
    padlen = (index < 56)?(56-index):(120-index);
    MD5Encode(bits, context->count, 8);
    MD5Update(context, PADDING, padlen);
    MD5Update(context, bits, 8);
    MD5Encode(digest, context->state, 16);
}

void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{
    unsigned int i = 0;
    unsigned int j = 0;

    while(j < len)
    {
        output[j] = input[i] & 0xFF;  
        output[j+1] = (input[i] >> 8) & 0xFF;
        output[j+2] = (input[i] >> 16) & 0xFF;
        output[j+3] = (input[i] >> 24) & 0xFF;
        i++;
        j += 4;
    }
}

void MD5Decode(unsigned int *output, unsigned char *input, unsigned int len)
{
    unsigned int i = 0;
    unsigned int j = 0;

    while(j < len)
    {
        output[i] = (input[j]) |
            (input[j+1] << 8) |
            (input[j+2] << 16) |
            (input[j+3] << 24);
        i++;
        j += 4; 
    }
}

void MD5Transform(unsigned int state[4], unsigned char block[64])
{
    unsigned int a = state[0];
    unsigned int b = state[1];
    unsigned int c = state[2];
    unsigned int d = state[3];
    unsigned int x[64];

    MD5Decode(x,block,64);

    FF(a, b, c, d, x[ 0], 7, 0xd76aa478); /* 1 */
    FF(d, a, b, c, x[ 1], 12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[ 2], 17, 0x242070db); /* 3 */
    FF(b, c, d, a, x[ 3], 22, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[ 4], 7, 0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[ 5], 12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[ 6], 17, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[ 7], 22, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[ 8], 7, 0x698098d8); /* 9 */
    FF(d, a, b, c, x[ 9], 12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[ 1], 5, 0xf61e2562); /* 17 */
    GG(d, a, b, c, x[ 6], 9, 0xc040b340); /* 18 */
    GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa); /* 20 */
    GG(a, b, c, d, x[ 5], 5, 0xd62f105d); /* 21 */
    GG(d, a, b, c, x[10], 9,  0x2441453); /* 22 */
    GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8); /* 24 */
    GG(a, b, c, d, x[ 9], 5, 0x21e1cde6); /* 25 */
    GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87); /* 27 */
    GG(b, c, d, a, x[ 8], 20, 0x455a14ed); /* 28 */
    GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8); /* 30 */
    GG(c, d, a, b, x[ 7], 14, 0x676f02d9); /* 31 */
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[ 5], 4, 0xfffa3942); /* 33 */
    HH(d, a, b, c, x[ 8], 11, 0x8771f681); /* 34 */
    HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[ 1], 4, 0xa4beea44); /* 37 */
    HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9); /* 38 */
    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60); /* 39 */
    HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[ 0], 11, 0xeaa127fa); /* 42 */
    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085); /* 43 */
    HH(b, c, d, a, x[ 6], 23,  0x4881d05); /* 44 */
    HH(a, b, c, d, x[ 9], 4, 0xd9d4d039); /* 45 */
    HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[ 2], 23, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II(a, b, c, d, x[ 0], 6, 0xf4292244); /* 49 */
    II(d, a, b, c, x[ 7], 10, 0x432aff97); /* 50 */
    II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[ 5], 21, 0xfc93a039); /* 52 */
    II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[ 3], 10, 0x8f0ccc92); /* 54 */
    II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[ 1], 21, 0x85845dd1); /* 56 */
    II(a, b, c, d, x[ 8], 6, 0x6fa87e4f); /* 57 */
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[ 6], 15, 0xa3014314); /* 59 */
    II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[ 4], 6, 0xf7537e82); /* 61 */
    II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb); /* 63 */
    II(b, c, d, a, x[ 9], 21, 0xeb86d391); /* 64 */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/* md5相关的实现 */

int main(int argc, char *argv[])
{
    if (argc != 5) {
        printf("%s %d\n", help, __LINE__);
        return DISI_PARAM_ERROR;
    }

    copyCharToString(argv[2], &fileFath);
    isFileExists(&fileFath);

    if (strcmp("--sign", argv[1]) == 0) {
        mode = 1;
        copyCharToString(argv[3], &Privatekey);
        isFileExists(&Privatekey);
        copyCharToString(argv[4], &outSignaturePath);
        char md5Str[MD5_STR_LEN + 1];
        sign(md5Str);
        


    } else if (strcmp("--check", argv[1]) == 0) {
        mode = 2;
        copyCharToString(argv[3], &PublicKey);
        isFileExists(&PublicKey);
        copyCharToString(argv[4], &inSignaturePath);
        isFileExists(&inSignaturePath);
        check();
    } else {
        printf("%s %d\n", help, __LINE__);
        return DISI_PARAM_ERROR;
    }

    // for (int i = 0; i < argc; i++) {
    //     printf("%s\n", argv[i]);
    // }


    printtest();




    return 0;
}

void sign(char *md5Str)
{
    // struct stat st;
    unsigned char digest[16] = {0};
    MD5_CTX context;
    int i = 0;

    /* 计算文件MD5 */
    FILE *fp;
    // fopen_s(&fp, fileFath.str, "rb"); // 以二进制打开文件
    fp = fopen(fileFath.str, "rb"); 
    char *data = NULL;
    int ret = 0;

    if (!fp) {
        printf("Can not open this file!\n");    //以二进制打开文件
    }
    MD5Init(&context);

    fseek(fp, 0, SEEK_END); // 文件指针转到文件末尾
    long fileSize = ftell(fp);
    if (fileSize == -1) {
        printf("Sorry! Can not calculate files which larger than 2 GB!\n"); // ftell函数返回long,最大为2GB,超出返回-1
        fclose(fp);
        exit(1);
    }

    rewind(fp); // 文件指针复位到文件头
    // printf("size %d\n", fileSize);
    data = (char*)malloc(sizeof(char)*fileSize);
    fread(data, 1, fileSize, fp);

    MD5Update(&context, data, fileSize);
// printf("%d\n", __LINE__);
    fclose(fp);
    free(data);

    MD5Final(&context, digest);

    printf("MD5(%s)= ", fileFath.str);
    for(i = 0; i < 16; i++) {
        printf("%02x", digest[i]);
        snprintf(md5Str + i*2, 2+1, "%02x", digest[i]);
    }
    printf("\n");
}
