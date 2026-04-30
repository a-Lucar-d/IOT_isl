#include "utility.h"

void normalize_spaces(char *str)
{
    char *src = str, *dst = str;
    int space = 0;

    while (*src)
    {
        if (*src == ' ' || *src == '\t')
        {
            if (!space)
            {
                *dst++ = ' ';
                space = 1;
            }
        }
        else
        {
            *dst++ = *src;
            space = 0;
        }
        src++;
    }
    *dst = '\0';
}