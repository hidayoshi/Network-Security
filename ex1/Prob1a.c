#include<stdio.h>
#include<string.h>
#include<stdlib.h>

/* Caesar Encryption */
char* CaesarEncrypt(int, char*);
char* CaesarDecrypt(int, char*);

//65~90 A~Z
//97~122 a~z

int main(){
  char plaintext[1024];
  char ciphertext[1024];
  char decrypttext[1024];
  int key,flag=0;

  
//    Check the validity of key (key must be an interger number between 1 ~ 25)
    printf("Select 1 or 2(encrypt or decrypt)");
    scanf("%d%*c", &flag);
    
    if(flag == 1) {
    printf("Input plaintext:");
    scanf("%[^\n]%*c", plaintext);
    
    printf("Input key(from 1 to 25):");
    scanf("%d%*c",&key);
   /*
    Perform Caesar Encryption: CaesarEncrypt(key, plaintext) and print out the ciphertext
  */
    strcpy(ciphertext, CaesarEncrypt(key,plaintext));
    printf("Ciphertext: %s\n", ciphertext);
    }
    
    else if(flag == 2){
    printf("Input ciphertext:");
    scanf("%[^\n]%*c", ciphertext);
    
    printf("Input key(from 1 to 25):");
    scanf("%d%*c",&key);
  /*
    Perform Caesar Decryption: CaesarDecrypt(key, ciphertext) and print out the decryted ciphertext (decrypttext)
  */strcpy(decrypttext,CaesarDecrypt(key,ciphertext));
    printf("Decrypted plaintext:%s\n",decrypttext);
    }
    else return 0;
 return 0;
}

char* CaesarEncrypt(int key, char *plaintext){
    int i=0,suji;
    char* ciphertext;
    ciphertext = (char *)malloc(strlen(plaintext) * sizeof(char) + 1);
    
    while(plaintext[i] != '\0'){
        
    if(plaintext[i] >= 'a' && plaintext[i] <= 'z') 
            ciphertext[i] = (plaintext[i] - 'a' + key) % 26 + 'a';
    else if(plaintext[i] >= 'A' && plaintext[i] <= 'Z') 
            ciphertext[i] = (plaintext[i] - 'A' + key) % 26 + 'A';
    else ciphertext[i] = plaintext[i];
        
        ++i;
    }
    ciphertext[i]='\0';
    return ciphertext;
}

char* CaesarDecrypt(int key, char *ciphertext){
    int i=0, sign=0;
    char* decrypttext;
    decrypttext = (char *)malloc(strlen(ciphertext) * sizeof(char) + 1);
    
    while(ciphertext[i] != '\0'){

    if(ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
           sign = ciphertext[i] - 'a' - key;
           if(sign < 0) decrypttext[i] = (sign + 26) + 'a';//mod of C focuses on minus.
           else decrypttext[i] = sign % 26 + 'a';
    }
           
    else if(ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
           sign = ciphertext[i] - 'A' - key;
           if(sign < 0) decrypttext[i] = (sign + 26) + 'A';//mod of C focuses on minus.
           else decrypttext[i] = sign % 26 + 'A';
    }
    else decrypttext[i] = ciphertext[i];
        ++i;
    }
    decrypttext[i]='\0';
    return decrypttext;
}