#include<stdio.h>
#include<string.h>
#include <stdlib.h>

/* Caesar Decryption */
char* CaesarDecrypt(int, char*);
/* BruteForceAttack */
void BruteForceAttack(char*, char*); 

int main(){
 
  char ciphertext[1024];  
  char keyword[1024];
  int i=0,ch;

    memset(keyword, '\0', strlen(keyword));//initialization
    /*Input ciphertext and keyword. 
    If keyword is not specified (no keyword), press ENTER
  */
    printf("Input ciphertext:");
    scanf("%[^\n]%*c", ciphertext);
    
    printf("Input keyword:");
    while (( ch = getchar()) != '\n') {
        keyword[i++] = ch;
        if ( i >= 1024 - 1 ){
            break;
        }
    }
  BruteForceAttack(ciphertext, keyword);
  return 0;
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

void BruteForceAttack(char *ciphertext, char *keyword){
    int i;
    char tmp[1024];
    char *matchkey;
    if(keyword[0] == 0){//blute force attack
           for(i=0;i<26;i++){
            strcpy(tmp, CaesarDecrypt(i, ciphertext));
            printf("Key:%5d Plaintext: %s\n",i,tmp);
    }
    }
    else{//search keyword
        for(i=0;i<26;i++){
            strcpy(tmp, CaesarDecrypt(i, ciphertext));
            if(strstr(tmp,keyword) == NULL)continue;//matchkeyがNULLのままstrncmpをするとせぐる
            matchkey = strstr(tmp,keyword);
            if(strncmp(keyword,matchkey,strlen(keyword)) == 0){
                printf("Key: %d Plaintext: %s\n",i,tmp);
                return;
            }
        }
        printf("There is no decryption keyword: %s\n", keyword);
    }
}
