#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include <ctype.h>

struct incidence_pair{         
  char c[26];                                        // Letter in the cipher text
  double freq[26];                                   // Incidence percentage of each letter
};
  
struct incidence_pair getIncidence(char*);           // Computing a histogram of the incidence each letter (ignoring all non alphabet characters)
char* monoalphabetic_substitution(char*, char*);     // Takes a partial mono-alphabetic substitution (subs)  and a ciphertext and returns a potential plaintext
struct incidence_pair bubbleSort(struct incidence_pair );

int main(int argc, char *argv[]){
  
  char ciphertext[1024] = "ztmn pxtne cfa peqef kecnp cjt tmn zcwsenp ontmjsw ztnws tf wsvp xtfwvfefw, c feb fcwvtf, xtfxevqea vf gvoenwk, cfa aeavxcwea wt wse rntrtpvwvtf wscw cgg lef cne xnecwea eymcg";
  char plaintext[1024] = "";
  char subs[27] = "";
  int length = strlen(ciphertext);
    
  struct incidence_pair ip = getIncidence(ciphertext);

  if(argc != 2){
    printf("Not enough or too many arguments!\n");
    exit(1);
  }
    
  strcpy(subs, argv[1]);
    
  if(strcmp(subs, "") == 0){
    for(int i = 0; i < 26; i++)
      printf("%c:%5f\n", ip.c[i], ip.freq[i]/length);
  }

  strcpy(plaintext, monoalphabetic_substitution(ciphertext, subs));
  printf("Potential Plaintext: %s\n", plaintext);
  return 0;
}


struct incidence_pair getIncidence(char *ciphertext){
    struct incidence_pair pair;
    int i;
    
    for(i=0;i<26;i++) pair.c[i] = 'a' + i;//initialization
    for(i=0;i<26;i++) pair.freq[i] = 0;//initialization
    i=0;
    while(ciphertext[i] != '\0'){
        if('a' <= ciphertext[i] && ciphertext[i] <= 'z'){
            pair.freq[ciphertext[i] - 'a']++;
            i++;
        }
        else i++;
    }
    
    pair = bubbleSort(pair);
    return pair;
}

struct incidence_pair bubbleSort(struct incidence_pair pair){
    int i,j;
    double tempfreq;
    char tempc;
    
    for(i=0;i<26;i++){
        for(j=26-1;j>i;j--){
            if(pair.freq[j] > pair.freq[j-1]){
                tempfreq = pair.freq[j];//exchange freq
                pair.freq[j] = pair.freq[j-1];
                pair.freq[j-1] = tempfreq;
                
                tempc = pair.c[j];//exchange c
                pair.c[j] = pair.c[j-1];
                pair.c[j-1] = tempc;
            }
    
        }
    }
    return pair;
}

char* monoalphabetic_substitution(char *ciphertext, char *subs){
    int i=0,j=0;
    char* plaintext;
    
    plaintext = (char *)malloc(strlen(ciphertext) * sizeof(char) + 1);
    
    for(j=0;ciphertext[j]!='\0';j++) plaintext[j] = toupper(ciphertext[j]);//initialization
    
    for(i=0;subs[i]!='\0';i++){
        if(subs[i] == '_') continue;
        else
            for(j=0;ciphertext[j]!='\0';j++) {
                if(ciphertext[j] == ',') plaintext[j] = ',';
                if(ciphertext[j] == ' ') plaintext[j] = ' ';
                if(ciphertext[j] == 'a' + i) 
                    plaintext[j] = subs[i];
     }
    }
    plaintext[j] = '\0';
    return plaintext;
}
