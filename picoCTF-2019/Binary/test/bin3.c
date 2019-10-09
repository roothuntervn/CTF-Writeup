/* Compile: gcc -fno-stack-protector leak.c -o leak          */
/* Enable ASLR: echo 2 > /proc/sys/kernel/randomize_va_space */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void helper() {
    asm("pop %rdi; pop %rsi; pop %rdx; ret");
}

int vuln() {
    char buf[150];
    ssize_t b;
    memset(buf, 0, 150);
    printf("Enter input: ");
    b = read(0, buf, 400);

    printf("Recv: ");
    write(1, buf, b);
    return 0;
}

int main(int argc, char *argv[]){
    setbuf(stdout, 0);
    vuln();
    return 0;
}
