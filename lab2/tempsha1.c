#include <openssl/sha.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h> // For time measures

const unsigned char *read_inputtext(const char *filename)
{
    // Total number of bytes
    unsigned long fsize;

    // Result of reading the file
    size_t result;

    // Now... Open the file binary with reading capabilities
    FILE *fp = fopen(filename, "rb");

    // If it can't be open, then return an error message
    if (fp == NULL) {fputs ("File error",stderr); exit (1);}

    /* Find out the number of bytes */
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);      /* Get the size of the file */
    rewind(fp);             /* Go back to the start */

    // Allocate the buffer + 1 for termination
    unsigned char* buffer = malloc(fsize * sizeof *buffer + 1);

    // Test that everything went as we expected
    if(buffer == NULL) { fputs("Memory error!", stderr); exit(2); }

    // Read the buffer
    result = fread(buffer, 1, fsize * sizeof *buffer, fp);

    // Something went wrong when we read the file; sizes to not match
    if (result != fsize) {fputs ("Reading error", stderr); exit (3);}

    // Terminate the str
    buffer[fsize] = '\0';

    // Close the file
    fclose(fp);

    // Return the pointer to the dynamic allocated array
    return buffer;
}


int main(int argc, char *argv[])
{
    int i;
    unsigned char *rbuff;            // Input of SHA1
    unsigned char wbuff[20];         // Output of SHA1
    SHA_CTX	c;

    /*
      Additional variables
    */
    int result;/* 関数の戻り値を格納するint型変数result. */
    struct timeval t_start, t_end;
    long elapsed;
    /*
      Read text file and print out its length (in bytes)
    */
    
    memset(wbuff,0,sizeof(wbuff));//initialization
    
    rbuff = (unsigned char*)read_inputtext(argv[1]);//Get plaintext
//    printf("%s",rbuff);
    
    unsigned char* bla = (unsigned char*)rbuff;
    long length = strlen((char*)bla);//Get length
    printf("File containes %ld bytes\n",length);
    
    /*
      SHA1 encryption and its processing time
      Use Sha1_Init(), Sha1_Update() and Sha1_Final()
    */
    gettimeofday(&t_start, 0);
    
    result = SHA1_Init(&c); /* SHA1_Initにsha_ctxのアドレスを渡して初期化. */
  if (result == 1){ /* 成功 */
    printf("SHA1_Init success!\n"); /* "SHA1_Init success!"と出力. */
  }
  else{
    printf("SHA1_Init error!\n"); /* SHA1_Init error!"と出力. */
    return -1; /* -1を返して終了. */
  }
    
    result = SHA1_Update(&c, rbuff, length); /* SHA1_Updateでソースデータとしてstrを追加. */
  if (result == 1){ /* 成功 */
    printf("SHA1_Update success!\n"); /* "SHA1_Update success!"と出力. */
  }
  else{
    printf("SHA1_Update error!\n"); /* "SHA1_Update error!"と出力. */
    return -2; /* -2を返して終了. */
  }
    
     result = SHA1_Final(wbuff, &c); /* SHA1_Finalでsha1にハッシュ値を書き出す. */
  if (result == 1){ /* 成功 */
    printf("SHA1_Final success!\n"); /* "SHA1_Final success!"と出力. */
  }
  else{
    printf("SHA1_Final error!\n"); /* "SHA1_Final error!"と出力. */
    return -3; /* -3を返して終了. */
  }
    
    gettimeofday(&t_end, 0);
    elapsed = (t_end.tv_sec-t_start.tv_sec)*1000000 +
              (t_end.tv_usec - t_start.tv_usec);
    printf("Encryption time: %ld us\n",elapsed);
    
  /* Output of SHA1. */
    printf("sha1 = ");
  for (i = 0; i < SHA_DIGEST_LENGTH; i++){ /* SHA_DIGEST_LENGTHの分だけ繰り返す. */
    printf("%02x", wbuff[i]); /* sha1の各要素を16神数で出力. */
  }
    printf("\n");/* 改行 */
   
    return 0;
}
