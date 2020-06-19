/*
Digital signature
使用rsa算法，md5哈希函数
路径只能有ascii字符，参数只能是ascii字符，因为c语言处理字符有点麻烦所以这里限制了只支持ascii字符
文件不能大于2G

编译
gcc -std=c11 disi.c -o disi
新建一个用于测试的文件
echo "this is a test file" > example.txt
生成数字签名
disi --sign example.txt example.sign
验证数字签名
disi --check example.txt example.sign
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER // 这种ifdef是用来区分vc和gcc环境的
    #include <io.h>
#else
    #include <unistd.h>
#endif

// 这三个参数是错误代码，用来指示程序因为什么原因而退出的
#define DISI_PARAM_ERROR 1 // 参数错误
#define DISI_FILE_NOT_EXISTS 2 // 文件不存在
#define DISI_FTELL_FAIL 3 // ftell 函数执行错误，执行错误通常是因为文件太大了

// 这两个参数是用来生成 rsa 密钥对的
#define RSA_P 8419
#define RSA_Q 7069

void copyCharToString(char *src, char **tag); // 复制字符串
void isFileExists(char *str); // 判断文件是否存在
void ras_init(); // 初始化 rsa 变量的结构体
void sign(); // 生成数字签名
void check(); // 验证文件

// 这是用来保存 rsa 相关参数的结构体
typedef struct rsa_st {
    int n;
    int e;
    int d;
    int p;
    int q;
    int phi;
    int bytes;
} RSA;

char *fileFath; // 需要数字签名或验证的文件路径
char *outSignaturePath; // 数字签名的输出路径
char *inSignaturePath; // 验证文件时的数字签名路径

char *help = "Please Input correct parameters\n--sign FilePath outSignaturePath\n--check FilePath inSignaturePath\n";

RSA rsa;

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
void MD5String(char *src, int len, char *md5Str);
void MD5File(char *filePath, char *md5Str);

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

void MD5String(char *src, int len, char *md5Str)
{
    unsigned char digest[16] = {0};
    MD5_CTX context;
    int i = 0;

    MD5Init(&context);
    MD5Update(&context, src, len);

    MD5Final(&context, digest);

    for(i = 0; i < 16; i++) {
        snprintf(md5Str + i*2, 2+1, "%02x", digest[i]);
    }
}

void MD5File(char *filePath, char *md5Str)
{
    unsigned char digest[16] = {0};
    MD5_CTX context;
    int i = 0;

    /* 计算文件MD5 */
    FILE *fp;

    #ifdef _MSC_VER
        fopen_s(&fp, filePath, "rb");
    #else
        fp = fopen(filePath, "rb");
    #endif

    char *data = NULL;

    if (!fp) {
        printf("Can not open this file!\n");
    }
    MD5Init(&context);

    fseek(fp, 0, SEEK_END); // 文件指针转到文件末尾
    long fileSize = ftell(fp);
    if (fileSize == -1) {
        printf("Sorry! Can not calculate files which larger than 2 GB!\n");
        fclose(fp);
        exit(1);
    }

    rewind(fp); // 文件指针复位到文件头

    data = (char*)malloc(sizeof(char)*fileSize);
    fread(data, sizeof(char), fileSize, fp);

    MD5Update(&context, data, fileSize);

    fclose(fp);
    free(data);

    MD5Final(&context, digest);

    for(i = 0; i < 16; i++) {
        snprintf(md5Str + i*2, 2+1, "%02x", digest[i]);
    }
}

/* md5相关的实现 */

/* rsa相关实现 */

#ifndef RSA_H
#define RSA_H

#define ACCURACY 5
#define SINGLE_MAX 10000
#define EXPONENT_MAX 1000
#define BUF_SIZE 1024

int modpow(long long a, long long b, int c); // 计算 a^b mod c
int gcd(int a, int b); // 计算最大公约数
int randExponent(int phi, int n); // 获取 e
int inverse(int n, int modulus); // 获取 d
int encode(int m, int e, int n); // 使用公钥加密 c = m^e mod n
int decode(int c, int d, int n); // 使用私钥加密 m = c^d mod n
int* encodeMessage(int len, int bytes, char* message, int exponent, int modulus); // 加密消息
int* decodeMessage(int len, int bytes, int* cryptogram, int exponent, int modulus); // 解密消息

#endif

/**
 * Computes a^b mod c
 */
int modpow(long long a, long long b, int c) {
    int res = 1;
    while(b > 0) {
        /* Need long multiplication else this will overflow... */
        if(b & 1) {
            res = (res * a) % c;
        }
        b = b >> 1;
        a = (a * a) % c; /* Same deal here */
    }
    return res;
}

/**
 * Compute gcd(a, b)
 */
int gcd(int a, int b) {
    int temp;
    while(b != 0) {
        temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

/**
 * Find a random exponent x between 3 and n - 1 such that gcd(x, phi) = 1,
 * this distribution is similarly nowhere near uniform
 */
int randExponent(int phi, int n) {
    int e = rand() % n;
    while(1) {
        if(gcd(e, phi) == 1) return e;
        e = (e + 1) % n;
        if(e <= 2) e = 3;
    }
}

/**
 * Compute n^-1 mod m by extended euclidian method
 */
int inverse(int n, int modulus) {
    int a = n, b = modulus;
    int x = 0, y = 1, x0 = 1, y0 = 0, q, temp;
    while(b != 0) {
        q = a / b;
        temp = a % b;
        a = b;
        b = temp;
        temp = x; x = x0 - q * x; x0 = temp;
        temp = y; y = y0 - q * y; y0 = temp;
    }
    if(x0 < 0) x0 += modulus;
    return x0;
}

/**
 * Encode the message m using public exponent and modulus, c = m^e mod n
 */
int encode(int m, int e, int n) {
    return modpow(m, e, n);
}

/**
 * Decode cryptogram c using private exponent and public modulus, m = c^d mod n
 */
int decode(int c, int d, int n) {
    return modpow(c, d, n);
}

/**
 * Encode the message of given length, using the public key (exponent, modulus)
 * The resulting array will be of size len/bytes, each index being the encryption
 * of "bytes" consecutive characters, given by m = (m1 + m2*128 + m3*128^2 + ..),
 * encoded = m^exponent mod modulus
 */
int* encodeMessage(int len, int bytes, char* message, int exponent, int modulus) {
    int *encoded = malloc((len/bytes) * sizeof(int));
    int x, i, j;
    for(i = 0; i < len; i += bytes) {
        x = 0;
        for(j = 0; j < bytes; j++) x += message[i + j] * (1 << (7 * j));
        encoded[i/bytes] = encode(x, exponent, modulus);
    }
    return encoded;
}

/**
 * Decode the cryptogram of given length, using the private key (exponent, modulus)
 * Each encrypted packet should represent "bytes" characters as per encodeMessage.
 * The returned message will be of size len * bytes.
 */
int* decodeMessage(int len, int bytes, int* cryptogram, int exponent, int modulus) {
    int *decoded = malloc(len * bytes * sizeof(int));
    int x, i, j;
    for(i = 0; i < len; i++) {
        x = decode(cryptogram[i], exponent, modulus);
        for(j = 0; j < bytes; j++) {
            decoded[i*bytes + j] = (x >> (7 * j)) % 128;
        }
    }

    return decoded;
}

/* rsa相关实现 */

int main(int argc, char *argv[])
{
    if (argc != 4) { // 判断参数个数，当参数个数不能少于4个
        printf("%s\n", help);
        return DISI_PARAM_ERROR;
    }

    copyCharToString(argv[2], &fileFath); // 把参数赋值至全局变量里
    isFileExists(fileFath); // 判断需要数字签名或验证的文件是否存在

    ras_init(); // 初始化 rsa 变量的结构体

    if (strcmp("--sign", argv[1]) == 0) { // 通过第二个参数判断是生成数字签名还是验证文件
        copyCharToString(argv[3], &outSignaturePath);
        sign(); // 生成数字签名
    } else if (strcmp("--check", argv[1]) == 0) {
        copyCharToString(argv[3], &inSignaturePath);
        isFileExists(inSignaturePath);
        check(); // 验证文件
    } else {
        printf("%s\n", help);
        return DISI_PARAM_ERROR;
    }

    return 0;
}

void sign()
{
    // 获取文件的md5值
    char md5Str[MD5_STR_LEN + 1];
    MD5File(fileFath, md5Str);

    // 输出文件的md5值
    printf("MD5(%s)= ", fileFath);
    printf("%s\n", md5Str);

    // 生成数字签名
    int *encoded;
    encoded = encodeMessage(strlen(md5Str) + 2, rsa.bytes, md5Str, rsa.d, rsa.n);

    // 把数字签名保存至文件里
    FILE *fp;
    #ifdef _MSC_VER
        fopen_s(&fp, outSignaturePath, "wb");
    #else
        fp = fopen(outSignaturePath, "w");
    #endif
    fwrite((char *)encoded, sizeof(int), ((strlen(md5Str) + 2)/rsa.bytes), fp);
    fclose(fp);
}

void check()
{
    // 获取文件的md5值
    char md5Str[MD5_STR_LEN + 1];
    MD5File(fileFath, md5Str);

    // 从文件里获取数字签名
    FILE *fp;
    #ifdef _MSC_VER
        fopen_s(&fp, inSignaturePath, "rb");
    #else
        fp = fopen(inSignaturePath, "r");
    #endif

    if (!fp) {
        printf("Can not open this file!\n");
    }

    fseek(fp, 0, SEEK_END); // 文件指针转到文件末尾
    int fileSize = ftell(fp);
    if (fileSize == -1) {
        printf("Sorry! Can not calculate files which larger than 2 GB!\n");
        fclose(fp);
        exit(DISI_FTELL_FAIL);
    }
    rewind(fp); // 文件指针复位到文件头

    char *keyContent;
    keyContent = (char*)malloc(sizeof(char)*(fileSize));
    memset(keyContent, 0, fileSize);
    fread(keyContent, sizeof(char), fileSize, fp);

    fclose(fp);

    // 解密数字签名
    int* decoded;
    decoded = decodeMessage(fileSize/rsa.bytes, rsa.bytes, (int*)keyContent, rsa.e, rsa.n);
    char test2[33] = {'0'};
    for (int i = 0; i < 32; i++) {
        test2[i] = decoded[i];
    }

    // 判断数字签名是否通过验证
    if (strcmp(md5Str, test2) == 0) {
        printf("Verified OK\n");
    } else {
        printf("Verification Failure\n");
    }
}

void ras_init()
{
    rsa.p = RSA_P;
    rsa.q = RSA_Q;
    rsa.n = rsa.p * rsa.q;

    if(rsa.n >> 21) rsa.bytes = 3;
    else if(rsa.n >> 14) rsa.bytes = 2;
    else rsa.bytes = 1;

    rsa.phi = (rsa.p - 1) * (rsa.q - 1);
    rsa.e = randExponent(rsa.phi, EXPONENT_MAX);
    rsa.d = inverse(rsa.e, rsa.phi);
}

void copyCharToString(char *src, char **tag)
{
    int len = 0;
    for (; src[len] != '\0'; len++);
    char *butf = (char*)malloc(len*sizeof(char));
    for (int i = 0; i <= len; i++) {
        butf[i] = src[i];
    }
    *tag = butf;
}

void isFileExists(char *str)
{
    if (_access(str, 0) != 0) {
        printf("%s not exists.\n", str);
        exit(DISI_FILE_NOT_EXISTS);
    }
}
