#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#define FLAG_BUFFER 200
#define LINE_BUFFER_SIZE 20

void win() {
  char buf[FLAG_BUFFER];
  FILE *f = fopen("flag.txt","r");
  fgets(buf,FLAG_BUFFER,f);
  fprintf(stdout,"%s\n",buf);
  fflush(stdout);
}

int main(int argc, char *argv[])
{
   //This is rather an artificial pieace of code taken from Secure Coding in c by Robert C. Seacord 
   char *first, *second, *third, *fourth;
   char *fifth, *sixth, *seventh;
   first=malloc(256); // ebp-0x30
   printf("Oops! a new developer copy pasted and printed an address as a decimal...\n");
   printf("%d\n",first);
   strncpy(first,argv[1],LINE_BUFFER_SIZE);
   second=malloc(256); // ebp-0x2c
   third=malloc(256); // ebp-0x28
   fourth=malloc(256); // ebp-0x24
   free(first);
   free(third);
   fifth=malloc(128);  // ebp-0x20
   puts("you will write on first after it was freed... an overflow will not be very useful...");
   gets(first);
   seventh=malloc(256); // ebp-0x1c
   exit(0);
}

