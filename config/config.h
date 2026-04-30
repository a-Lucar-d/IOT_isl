typedef struct {
    int passwd_check;
    int active_connections;
    int current_access;
    int reverse_shell;
    int running_services;
    int http_sniffer;
} config_t;

extern config_t config;

int set_config(const char *config_file);