CC = gcc
CFLAGS = -Wall -Wextra -g -MMD -MP
INCLUDES = -Ipasswd_check -IServices -IUtility -Iconfig -Ihttp
LDFLAGS = -lcrypt -lpcap -pthread

###############################################################################
# SecureBoot Configuration
###############################################################################

SECUREBOOT ?= false
SECUREBOOT_DIR = secureBoot/version2

SECUREBOOT_HOOK = $(SECUREBOOT_DIR)/initramfs_codes/iot_isl_hook
SECUREBOOT_CHECK = $(SECUREBOOT_DIR)/initramfs_codes/iot_isl_check

HOOK_DEST = /etc/initramfs-tools/hooks/iot_isl_hook
CHECK_DEST = /etc/initramfs-tools/scripts/init-premount/iot_isl_check

###############################################################################
# Daemon Sources
###############################################################################

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

###############################################################################
# Targets
###############################################################################

.PHONY: all clean secureboot deploy-secureboot

all: $(TARGET) $(if $(filter true,$(SECUREBOOT)),secureboot)

###############################################################################
# Daemon Build
###############################################################################

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

###############################################################################
# SecureBoot Build
###############################################################################

secureboot:
	@echo ""
	@echo "[*] Building SecureBoot..."
	$(MAKE) -C $(SECUREBOOT_DIR)
	$(MAKE) -C $(SECUREBOOT_DIR) manifest
	@echo "[+] SecureBoot manifest generated"
	@echo ""

###############################################################################
# SecureBoot Deployment
###############################################################################

deploy-secureboot:
	@echo ""
	@echo "[*] Building daemon..."
	$(MAKE) $(TARGET)

	@echo ""
	@echo "[*] Building SecureBoot..."
	$(MAKE) -C $(SECUREBOOT_DIR)
	$(MAKE) -C $(SECUREBOOT_DIR) manifest

	@echo ""
	@echo "[*] Installing initramfs hook scripts..."

	sudo cp $(SECUREBOOT_HOOK) $(HOOK_DEST)
	sudo chmod 755 $(HOOK_DEST)

	sudo cp $(SECUREBOOT_CHECK) $(CHECK_DEST)
	sudo chmod 755 $(CHECK_DEST)

	@echo "[+] Hook scripts installed"

	@echo ""
	@echo "[*] Updating initramfs..."
	sudo update-initramfs -u

	@echo ""
	@echo "[+] SecureBoot deployment completed"
	@echo "[+] Reboot required"
	@echo ""
	@echo "After reboot:"
	@echo "  cat /boot/firmware/iot_isl_status.txt"
	@echo "  cat /boot/firmware/iot_isl_debug.txt"
	@echo ""

###############################################################################
# Clean
###############################################################################

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
	$(MAKE) -C $(SECUREBOOT_DIR) clean

-include $(OBJ:.o=.d)
