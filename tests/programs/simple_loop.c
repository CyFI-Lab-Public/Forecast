#include <stdio.h>

int main() {
    int count = 0;
    for (int i = 0; i < 10; i++) {
        count += i * 2;
    }
    printf("Count: %d\n", count);
}
