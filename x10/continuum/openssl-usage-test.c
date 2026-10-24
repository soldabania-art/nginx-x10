/* Synthetic metadata predicate driver. No SSL object, I/O or key material. */
#include "openssl-usage.h"
#include "openssl-probe.h"
#include <stdio.h>
#include <string.h>

static int nibble(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    return -1;
}

int main(int argc, char **argv)
{
    unsigned char sequence[8];
    int arg;
    size_t i;

    if (argc < 2 || argc > 258)
        return 2;
    printf("%d %llu %llu\n", x10_sequence_usage_allowed(NULL),
           (unsigned long long) X10_REASON_READ_USAGE,
           (unsigned long long) X10_REASON_WRITE_USAGE);
    for (arg = 1; arg < argc; ++arg) {
        if (strlen(argv[arg]) != 16)
            return 2;
        for (i = 0; i < sizeof(sequence); ++i) {
            int high = nibble(argv[arg][i * 2]);
            int low = nibble(argv[arg][i * 2 + 1]);
            if (high < 0 || low < 0)
                return 2;
            sequence[i] = (unsigned char) ((high << 4) | low);
        }
        printf("%d\n", x10_sequence_usage_allowed(sequence));
    }
    return 0;
}
