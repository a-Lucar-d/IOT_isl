#include <stdlib.h>
#include <string.h>
#include "config.h"
#include <stdio.h>

config_t config = {0};

static int parse_bool(const char *val)
{
    return (strcasecmp(val, "true") == 0 || strcmp(val, "1") == 0);
}

int set_config(const char *config_file)
{
    FILE* fd = fopen(config_file, "r");
    if (!fd) {
        perror("fopen");
        return 1;
    }

    char line[512];
    char section[50] = {0};
    char key[50];
    char val[50];

    while (fgets(line, sizeof(line), fd))
    {
        if (strlen(line) <= 1)
            continue;

        if (sscanf(line, "[%49[^]]", section) == 1)
            continue;

        if (sscanf(line, "%49[^=]=%49s", key, val) != 2)
        {
             
            continue;
        }
        //val[strcspn(val, "\n")] = 0;   
        
            if (strcmp(section, "passwd") == 0)
        {
            if (strcmp(key, "enable") == 0)
                config.passwd_check = parse_bool(val);

        }
        else if (strcmp(section, "services") == 0)
        {
            if (strcmp(key, "active_connections") == 0)
                config.active_connections = parse_bool(val);
            else if (strcmp(key, "current_access") == 0)
                config.current_access = parse_bool(val);
            else if (strcmp(key, "reverse_shell") == 0)
                config.reverse_shell = parse_bool(val);
            else if (strcmp(key, "running_services") == 0)
                config.running_services = parse_bool(val);
        }
        else if(strcmp(section, "http") == 0)
        {
            if(strcmp(key, "http_sniffer") == 0)
                config.http_sniffer = parse_bool(val);
        }
    }

    fclose(fd);
    return 0;
}