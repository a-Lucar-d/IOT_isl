#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "services.h"
#include "utility.h"

void active_connections()
{
    FILE* fd = popen("ss -tnp", "r");
    if (fd == NULL)
    {
        syslog(LOG_ERR, "popen failed in active_connections");
        return;
    }

    char line[1024];

    while (fgets(line, sizeof(line), fd))
    {
        line[strcspn(line, "\n")] = 0;
        normalize_spaces(line);

        // TELNET (port 23)
        if (strstr(line, ":23") && strstr(line, "ESTAB"))
        {
            syslog(LOG_ALERT,
                "[ALERT][TELNET][ESTAB] %.200s", line);
        }

        // SSH (port 22)
        else if (strstr(line, ":22") && strstr(line, "ESTAB"))
        {
            syslog(LOG_ALERT,
                "[INFO][SSH][ESTAB] %.200s", line);
        }

        // NETCAT connection
        else if (strstr(line, "nc") && strstr(line, "ESTAB"))
        {
            syslog(LOG_ALERT,
                "[ALERT][NETCAT][ESTAB] %.200s", line);
        }
    }

    pclose(fd);
}