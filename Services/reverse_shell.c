#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "services.h"
#include "utility.h"

void reverse_shell()
{
    FILE *fp = popen("ps -ef", "r");
    char line[512];

    while (fgets(line, sizeof(line), fp))
    {   
        line[strcspn(line, "\n")] = 0;
        normalize_spaces(line); 
        if (strstr(line, "bash") && strstr(line, "tcp"))
        {
            syslog(LOG_ALERT,"[ALERT][REVERSE_SHELL][SUSPECT] %.200s", line);
        }
    }

    pclose(fp);
}