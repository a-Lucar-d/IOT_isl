#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "services.h"
#include "utility.h"


void running_services()
{
    FILE* fd = popen("ss -tulnp", "r");
    if (fd == NULL)
    {
        syslog(LOG_ERR, "popen failed");
        exit(EXIT_FAILURE);
    }

    char line[1024];

    while (fgets(line, sizeof(line), fd))
    {
        line[strcspn(line, "\n")] = 0;  // remove newline
        normalize_spaces(line); 
        // TELNET (port 23)
        if (strstr(line, ":23") && strstr(line, "LISTEN"))
        {
            syslog(LOG_ALERT,
                "[ALERT][TELNET][LISTEN] %.200s", line);
        }

        // SSH (port 22)
        else if (strstr(line, ":22") && strstr(line, "LISTEN"))
        {
            syslog(LOG_ALERT,
                "[INFO][SSH][LISTEN] %.200s", line);
        }

        // NETCAT LISTENER
        else if (strstr(line, "nc") && strstr(line, "LISTEN"))
        {
            syslog(LOG_ALERT,
                "[ALERT][NETCAT][LISTENER] %.200s", line);
        }

    }

    pclose(fd);
}