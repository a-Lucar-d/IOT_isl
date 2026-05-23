#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdbool.h>

#define BUFFER_SIZE 4096
#define MANIFEST_FILE "secureBoot.boot"

char* sha256_file(const char *path)
{
    if(path == NULL)
    {
        return NULL;
    }

    FILE *file = fopen(path, "rb");

    if(file == NULL)
    {
        return NULL;
    }

    char *output = malloc(65);

    if(output == NULL)
    {
        fclose(file);
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

bool verify_integrity()
{
    FILE *manifest = fopen(MANIFEST_FILE, "r");

    if(manifest == NULL)
    {
        printf("[-] Failed to open manifest file\n");
        return false;
    }

    char line[512];

    while(fgets(line, sizeof(line), manifest) != NULL)
    {
        char expected_hash[65];
        char filename[256];

        /*
            Manifest format:
            HASH  FILENAME
        */

        if(sscanf(line, "%64s %255s", expected_hash, filename) != 2)
        {
            printf("[-] Invalid manifest entry\n");
            fclose(manifest);
            return false;
        }

        char *calculated_hash = sha256_file(filename);

        if(calculated_hash == NULL)
        {
            printf("[-] Failed to hash file: %s\n", filename);
            fclose(manifest);
            return false;
        }

        if(strcmp(expected_hash, calculated_hash) != 0)
        {
            printf("[!] Integrity compromised: %s\n", filename);

            free(calculated_hash);
            fclose(manifest);

            return false;
        }

        printf("[+] Verified: %s\n", filename);

        free(calculated_hash);
    }

    fclose(manifest);

    return true;
}

int main()
{
    if(verify_integrity())
    {
        printf("\n[*] SYSTEM SAFE\n");
        return 0;
    }

    printf("\n[*] SYSTEM COMPROMISED\n");

    return 1;
}
