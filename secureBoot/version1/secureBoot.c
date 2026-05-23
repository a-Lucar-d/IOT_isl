#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include "secureBoot.h"

#define BUFFER_SIZE 4096

const char *path[] = {"test.txt", "test2.txt"};
int count_files = sizeof(path) / sizeof(path[0]);

bool hash_true(char *buffer[256], int count)
{
    char filename[256];
    char hash[256];

    for(int i = 0; i < count; i++)
    {
        if(buffer[i] == NULL)
        {
            return false;
        }

        if(sscanf(buffer[i], "%255s : %64s", filename, hash) != 2)
        {
            return false;
        }

        char *test_hash = sha256_file(filename);

        if(test_hash == NULL)
        {
            return false;
        }

        if(strcmp(test_hash, hash) != 0)
        {
            free(test_hash);
            return false;
        }

        free(test_hash);
    }

    return true;
}

char* sha256_file(const char *path)
{
    if(path == NULL)
    {
        return NULL;
    }

    char *output = malloc(65);

    if(output == NULL)
    {
        return NULL;
    }

    FILE *file = fopen(path, "rb");

    if(file == NULL)
    {
        free(output);
        return NULL;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;

    while((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0)
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    fclose(file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }

    output[64] = '\0';

    return output;
}

void file_integrity()
{
    int fd = open("secureBoot.boot", O_CREAT | O_EXCL | O_RDWR, 0644);

    if(fd >= 0)
    {
        printf("config created\n");

        for(int i = 0; i < count_files; i++)
        {
            char *hash = sha256_file(path[i]);

            if(hash == NULL)
            {
                printf("[-] Failed to hash file: %s\n", path[i]);
                continue;
            }

            printf("Hash of %s : %s\n", path[i], hash);

            dprintf(fd, "%s : %s\n", path[i], hash);

            free(hash);
        }

        close(fd);
    }
    else
    {
        char *buffer[256];
        char temp[256];

        FILE *file = fopen("secureBoot.boot", "r");

        if(file == NULL)
        {
            printf("[-] Failed to open secureBoot.boot\n");
            return;
        }

        int i = 0;

        while(fgets(temp, sizeof(temp), file) != NULL)
        {
            buffer[i] = malloc(strlen(temp) + 1);

            if(buffer[i] == NULL)
            {
                printf("[-] Memory allocation failed\n");

                for(int j = 0; j < i; j++)
                {
                    free(buffer[j]);
                }

                fclose(file);
                return;
            }

            strcpy(buffer[i], temp);

            printf("Hash entry: %s", buffer[i]);

            i++;

            if(i >= 256)
            {
                break;
            }
        }

        int count = i;

        bool integrity = hash_true(buffer, count);

        for(int j = 0; j < count; j++)
        {
            free(buffer[j]);
        }

        if(!integrity)
        {
            printf("[*] INTEGRITY COMPROMISED !!\n");
        }
        else
        {
            printf("[*] SAFE\n");
        }

        fclose(file);
    }
}

int main()
{
    file_integrity();
    return 0;
}