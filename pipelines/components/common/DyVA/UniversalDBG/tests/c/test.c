#include<stdio.h>


char *d = "Global!\n";

void main() {
    int a, b;
    char *c = "Hello World!\n";
    printf("%s", c);
    printf("%s", d);
    printf("Enter two numbers: ");
    scanf("%d %d", &a, &b);
    printf("Sum: %d\n", a+b);
}
