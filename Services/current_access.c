#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include "services.h"
#include "utility.h"
#include <string.h>

void current_access()
{
    FILE* fd = popen("who r", "r");

    if (fd == NULL)
    {
        syslog(LOG_ERR, "popen failed in current_access");
        return;
    }

    char line[512];

    while (fgets(line, sizeof(line), fd))
    {
        line[strcspn(line, "\n")] = 0;
        normalize_spaces(line);

        syslog(LOG_ALERT,
            "[INFO][ACCESS][ACTIVE_SESSION] %.200s", line);
    }

    pclose(fd);
}