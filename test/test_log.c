#include <stdio.h>
#include <stdlib.h>
#include "../log.h"

#include <string.h>

char* get_file_content(char* name){
    FILE *fp;
    char *line = malloc(1025);
    char *content = malloc(2048);

    fp = fopen("test/tcp1", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);
    while(fgets(line, 1024, fp) != NULL) {
        strcat(content, line);
    }
    fclose(fp);
    return content;
}

unsigned char* get_file_buffer(char* file){
   FILE *fp;
   char c;
   unsigned char *content = malloc(2048);
   fp = fopen(file, "r");
   if(fp == NULL)
     return NULL;
   char *cp = malloc(2*sizeof(char));
   while((c = fgetc(fp)) != EOF){
     if(c != ' ' && c != '\n'){
        cp[0] = c;
        cp[1] = '\0';
        strcat(content, cp); 
     }
   }
   free(cp);
   fclose(fp);
   return content;
}

int main(){
    unsigned char* str = get_file_buffer("test/tcp1");
    printf("print, %s", str);
    generatorLog(str, strlen(str));
}
