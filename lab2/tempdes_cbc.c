#include <openssl/des.h>
#include <sys/time.h> // For time measures
#include <string.h>
#include <ctype.h>//for １６進数
#include <stdlib.h>
// Encryption/Decryption switches
#define ENC 1
#define DEC 0

// From char to DES_LONG (be aware that c is shifted)
#define c2l(c,l)    (l =((DES_LONG)(*((c)++))), \
                     l|=((DES_LONG)(*((c)++)))<< 8L, \
                     l|=((DES_LONG)(*((c)++)))<<16L, \
                     l|=((DES_LONG)(*((c)++)))<<24L)

// From DES_LONG to char (be aware that c is shifted)
#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)     )&0xff), \
                     *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                     *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                     *((c)++)=(unsigned char)(((l)>>24L)&0xff))

void write_output(const char *filename, const unsigned char *in)
{
    // Now... Open the file binary with writing capabilities
    FILE *fp = fopen(filename, "wb");

    // If it can't be open, then return an error message
    if (fp == NULL) {fputs ("File error", stderr); exit (1);}

    // Write the in-array to specificed file-location
    fwrite(in, sizeof(unsigned char), strlen((const char *)in), fp);
    // Close the it
    fclose(fp);
}

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

void str2DES_cblock(const char *str, DES_cblock *out)
{
    // Make a char pointer and point it at the start of the array
    unsigned char *o;
    o = out[0];

    // Read the string
    int i;
    for (i = 0; i < 8; i++)
        sscanf(&(str[i*2]),"%2hhx", o++);
}

void my_des_cbc_encrypt(unsigned char *input, unsigned char *output, long length, DES_key_schedule ks, DES_cblock *ivec, int env){
  /*
    Assume that the input length (in byte) is a multiple of 8
    Try to undestand the macros l2c and c2l. They are important in implementation of CBC
  */
  
    unsigned char *iv;            // Initialization vector
    long l = length;
    
  /*
     Addtional variables
  */
    iv=ivec[0];
    DES_LONG out0,out1;
    DES_LONG in0,in1;
    DES_LONG data[2];
  /*
    Initalize XOR-variables from iv
  */
   c2l(iv,out0);
   c2l(iv,out1);
    
  for(l -= 8; l >= 0; l -= 8){
    
    /*
      Your implementation of DES in CBC mode.
      Using l2c, c2l, des_encrypt1().
    */
      c2l(input, in0);
      c2l(input, in1);
            
      in0 ^= out0;//XOR
      in1 ^= out1;
      
      data[0] = in0;
      data[1] = in1;
      
      des_encrypt1((DES_LONG *)data, ks, env);
      
      out0 = data[0];
      out1 = data[1];
      
//     fprintf(stderr,"data:%u %u\n",data[0],data[1]);
//     fprintf(stderr,"out:%u %u\n",out0,out1);
      
      l2c(out0, output);
      l2c(out1, output);
      
//     printf("out:%s\n",output);
  }
}

int main(int argc, char *argv[])
{
    int k;
    des_key_schedule key;
    DES_cblock iv, cbc_key;

    /*
      Other variables
    */
    const unsigned char *inputtext;
    const unsigned char *outputtext;
    const unsigned char *outputtext2;
    long length;
    
    /*
      Check number of command line arguments
    */
    if(argc != 5) {
      printf( "足りない\n" );
        exit(1);
    }
    /*
      Check key and initialization vector validities. (comprise of Hexadicimal digits or not)
    */
    if(isxdigit(atoi(argv[1])) != 0) {
        printf( "not Hexadicimal digits\n" );
        exit(1);
    }
    /*
      Convert key and initialization vector from string to DES_cblock
    */
    str2DES_cblock(argv[1],&iv);
    str2DES_cblock(argv[2], &cbc_key);
    
    if ((k = des_set_key_checked(&cbc_key,key)) != 0) //Generate the actual key from des_key for encyption
        printf("\nkey error\n");
    
    /*
      read_inputtext();
    */
    inputtext = read_inputtext(argv[3]);
    /*
      my_des_cbc_encrypt();
    */
    unsigned char* bla = (unsigned char*)inputtext;
    length = strlen((char*)bla);
    
    outputtext = malloc(length * sizeof(unsigned char*));//Get size;
    my_des_cbc_encrypt( (unsigned char*)inputtext, (unsigned char*)outputtext,
                       length, key, &iv, ENC);
    /*
      write_output();
    */
    write_output(argv[4], outputtext);
    //Compare the resutl with that using built-in funtion des_cbc_encrypt(). Details of des_cbc_encrypt() can be seen at http://web.mit.edu/macdev/Development/MITKerberos/MITKerberosLib/DESLib/Documentation/api.html 
    
    /*
      des_cbc_encrypt();
      
    */
    outputtext2 = malloc(length * sizeof(unsigned char*));//Get size;
    des_cbc_encrypt( (unsigned char*)inputtext, (unsigned char*)outputtext2,
                       length, key, &iv, ENC);
    
    /*
     Print out ciphertexts from  my_des_cbc_encrypt() and  des_cbc_encrypt() to compare
    */
//    printf("aaa %s",inputtext);
    printf("from my_des_cbc_encrypt: %s\n", outputtext);
    printf("from des_cbc_encrypt:    %s\n", outputtext2);
    return 0;
}
