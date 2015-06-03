#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>

void ret_15(void) {
  asm("mov r7, #173\n");
  asm("svc 0x00000000\n");
  asm("bx lr\n");
}

int read_input() {
  char buffer[512];
  printf("Buffer = %p\n", buffer);
  printf("Function = %p\n", ret_15);
  read(0, buffer, 600);
  return 0;
}

int main(int argc, char const *argv[])
{
  read_input();
	return 0;
}
