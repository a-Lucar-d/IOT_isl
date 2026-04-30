#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <pcap.h>

#include "passwd_check/pass.h"
#include "services.h"
#include "config/config.h"
#include "http/http.h"

#define PID_FILE "/tmp/simple_daemon.pid"

const char daemon_file[] = "/home/adityakrishna/kichu/inspark/kezhap/IOT_isl/dameon/config/daemon.conf";

volatile sig_atomic_t running = 1;
pcap_t *global_handle = NULL;

/* -------- PID -------- */
void create_pid()
{
    FILE *fd = fopen(PID_FILE, "w");
    if (!fd)
    {
        syslog(LOG_ERR, "PID file creation failed");
        exit(EXIT_FAILURE);
    }
    fprintf(fd, "%d\n", getpid());
    fclose(fd);
}

/* -------- SIGNAL -------- */
void handle_signal(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
    {
        syslog(LOG_INFO, "Daemon shutting down...");
        running = 0;

        if (global_handle)
            pcap_breakloop(global_handle);

        unlink(PID_FILE);
    }
}

/* -------- DAEMON -------- */
void create_daemon()
{
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    if (setsid() < 0) exit(EXIT_FAILURE);

    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);

    umask(0);
    chdir("/");

    for (int i = 0; i < 1024; i++)
        close(i);

    open("/dev/null", O_RDONLY);
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);

    openlog("simple_daemon", LOG_PID, LOG_LOCAL0);
}

/* -------- HTTP THREAD -------- */
void *http_thread(void *arg)
{
    return http_sniffer_thread(arg);
}

/* -------- SERVICES THREAD -------- */
void *service_thread(void *arg)
{
    (void)arg;
    time_t last_run = 0;

    while (running)
    {
        time_t now = time(NULL);

        // Run services every 2 seconds
        if (now - last_run >= 2)
        {
            if (config.active_connections)
                active_connections();

            if (config.current_access)
                current_access();

            if (config.reverse_shell)
                reverse_shell();

            if (config.running_services)
                running_services();

            last_run = now;
        }

        usleep(200000); // 200 ms loop
    }

    return NULL;
}

/* -------- MAIN -------- */
int main(int argc, char *argv[])
{
    const char *config_path = NULL;

    if (argc > 1)
    {
        config_path = argv[1];
    }
    else
    {
        config_path = daemon_file; // default
    }

    create_daemon();
    create_pid();

    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);

    if (set_config(config_path))
        syslog(LOG_ERR, "Config load failed: %s", config_path);

    pthread_t t_http, t_services;

    if (config.http_sniffer)
        pthread_create(&t_http, NULL, http_thread, NULL);

    pthread_create(&t_services, NULL, service_thread, NULL);

    time_t last_check = 0;

    while (running)
    {
        time_t now = time(NULL);

        if (config.passwd_check)
        {
            if (last_check == 0 || (now - last_check) >= 1800)
            {
                syslog(LOG_INFO, "[*] Running shadow password check...");
                check_shadow();
                last_check = now;
            }
        }

        sleep(5);
    }

    if (config.http_sniffer)
        pthread_join(t_http, NULL);

    pthread_join(t_services, NULL);

    closelog();
    return 0;
}
