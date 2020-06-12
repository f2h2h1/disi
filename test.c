/*
Digital signature
使用rsa算法，md5哈希函数
路径只能有ascii字符，参数只能是ascii字符，因为c语言处理字符有点麻烦所以这里限制了只支持ascii字符

gcc test.c -o disi && disi --sign example.txt example.sign rsa_private.pem

disi --sign example.txt example.sign rsa_private.pem
disi --check example.txt example.sign rsa_public.pem

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
    printf("%s %d\n", tag->str, tag->len);

    return;
}

uString fileFath;
uString Privatekey;
uString PublicKey;
uString outSignaturePath;
uString inSignaturePath;

int main(int argc, char *argv[])
{

    int mode; // 程序运行的模式，1是签名，2是验证签名

    char *help = "Please Input correct parameters\n--sign FilePath Privatekey outSignaturePath\n--check FilePath PublicKey inSignaturePath\n";

    if (argc != 5) {
        printf("%s %d\n", help, __LINE__);
        return 1;
    }

    if (strcmp("--check", argv[1]) == 0) {
        mode = 1;
    } else if (strcmp("--sign", argv[1]) == 0) {
        mode = 2;
    } else {
        printf("%s %d\n", help, __LINE__);
        return 1;
    }

    for (int i = 0; i < argc; i++) {
        printf("%s\n", argv[i]);
    }




    return 0;
}
