CC = gcc
CFLAGS = -Wall -Wextra -g -MMD -MP
INCLUDES = -Ipasswd_check -IServices -IUtility -Iconfig -Ihttp
LDFLAGS = -lcrypt -lpcap -pthread

SRC = main.c \
      passwd_check/pass.c \
      Services/current_access.c \
      Services/active_connections.c \
      Services/reverse_shell.c \
      Services/running_services.c \
      Utility/utility.c \
      config/config.c \
      http/http.c

BUILD_DIR = build
OBJ = $(SRC:%.c=$(BUILD_DIR)/%.o)

TARGET = my_daemon

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

-include $(OBJ:.o=.d)