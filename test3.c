#include <stdio.h> 
#include <stdlib.h> 

int main() {
    int* a = malloc(sizeof(int));
    printf("Address of four bytes allocated on heap: %p\n", a);
    free(a);
    return 0;
}
