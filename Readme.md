# 🛡️ IoT_ISL – IoT Security Layer

![C](https://img.shields.io/badge/language-C-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Build](https://img.shields.io/badge/build-Makefile-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)
![Status](https://img.shields.io/badge/status-Active-success.svg)

A lightweight security framework for Linux-based IoT systems that combines:

- Boot-time integrity verification
- Runtime security monitoring
- Network traffic inspection
- Service and user activity monitoring

The project is designed to provide a foundational security layer for resource-constrained IoT devices without requiring specialized hardware such as TPMs.

---

# 📌 Overview

IoT_ISL consists of two major components:

## 1️⃣ SecureBoot Integrity Verification

Executed during the boot process through **initramfs**.

Responsibilities:

- Verify integrity of critical files
- Detect unauthorized modifications
- Establish an initial trusted state before user-space services start
- Prevent compromised systems from booting unnoticed

---

## 2️⃣ Runtime Security Monitoring Daemon

Executed after boot.

Responsibilities:

- Weak password detection
- Active connection monitoring
- Logged-in user monitoring
- Reverse shell detection
- Running service monitoring
- HTTP traffic inspection

---

# ⚙️ Features

## 🛡️ Boot-Time Integrity Verification

- SHA256-based file integrity verification
- Manifest-driven verification
- Executed during initramfs stage
- Detects unauthorized file modifications
- Generates boot-time integrity status reports

### Monitored Files

Configured through:

```text
secureBoot/version2/monitored_files.txt
```

Examples:

```text
./my_daemon
config/daemon.conf
/etc/passwd
```

---

## 🔑 Weak Password Detection

- Scans `/etc/shadow`
- Detects weak password hashes
- Runs every 30 minutes

---

## 🧠 System & Service Monitoring

Runs every 2 seconds:

- Active network connections
- Logged-in users
- Running services
- Reverse shell detection

---

## 🌐 HTTP Traffic Monitoring

- Uses libpcap
- Captures HTTP traffic
- Monitors incoming and outgoing packets

---

# 🧵 Architecture

```text
                Boot Process
                     │
                     ▼
              Initramfs Stage
                     │
                     ▼
        SecureBoot Integrity Check
                     │
         ┌───────────┴───────────┐
         │                       │
         ▼                       ▼
      SAFE                 COMPROMISED
         │
         ▼
      systemd
         │
         ▼
      IoT_ISL Daemon
         │
         ├── Service Monitoring Thread
         │
         ├── Password Audit Thread
         │
         └── HTTP Sniffer Thread
```

---

# 📁 Project Structure

```text
.
├── build/
├── config/
├── http/
├── passwd_check/
├── Services/
├── Utility/
│
├── secureBoot/
│   ├── version1/
│   └── version2/
│       ├── verifier.c
│       ├── monitored_files.txt
│       ├── generate_manifest.sh
│       ├── secureBoot.boot
│       └── initramfs_codes/
│           ├── iot_isl_hook
│           └── iot_isl_check
│
├── main.c
├── Makefile
├── my_daemon
└── README.md
```

---

# 🧰 Requirements

Install dependencies:

```bash
sudo apt update

sudo apt install \
    build-essential \
    libpcap-dev \
    libcrypt-dev \
    libssl-dev \
    initramfs-tools
```

---

# 🔨 Build

Build daemon only:

```bash
make
```

Output:

```text
my_daemon
```

---

# 🛡️ SecureBoot Build

Build daemon and SecureBoot components:

```bash
make SECUREBOOT=true
```

This performs:

- Daemon build
- SecureBoot verifier build
- Manifest generation

---

# 🚀 SecureBoot Deployment

Deploy SecureBoot into initramfs:

```bash
make deploy-secureboot
```

This automatically:

- Builds daemon
- Builds verifier
- Generates integrity manifest
- Installs initramfs hook scripts
- Updates initramfs

Reboot afterwards:

```bash
sudo reboot
```

---

# 🔍 SecureBoot Verification Results

After reboot:

```bash
cat /boot/firmware/iot_isl_status.txt
```

Debug information:

```bash
cat /boot/firmware/iot_isl_debug.txt
```

Example:

```text
SYSTEM SAFE
```

or

```text
INTEGRITY COMPROMISED
```

---

# ▶️ Run Runtime Daemon

```bash
sudo ./my_daemon
```

Root privileges are required for:

- `/etc/shadow` access
- Packet capture
- Service monitoring
- Network inspection

---

# ⚙️ Configuration

Configuration file:

```text
config/daemon.conf
```

Example:

```ini
[passwd]
enable=true

[services]
active_connections=true
current_access=true
reverse_shell=true
running_services=true

[http]
http_sniffer=true

[secureboot]
enable=true
```

---

# 📜 Logging

Logs are written using syslog.

## Traditional Syslog

```bash
sudo tail -f /var/log/syslog
```

Filter daemon logs:

```bash
sudo grep simple_daemon /var/log/syslog
```

---

## journalctl

View logs:

```bash
sudo journalctl -t simple_daemon
```

Follow logs:

```bash
sudo journalctl -t simple_daemon -f
```

Recent logs:

```bash
sudo journalctl -t simple_daemon -n 50
```

---

# 📌 Boot-Time Reports

Generated by SecureBoot:

```text
/boot/firmware/iot_isl_status.txt
/boot/firmware/iot_isl_debug.txt
```

These files contain:

- Integrity verification result
- Files checked
- Verification status
- Debug information

---

# 🔬 Research Focus

IoT_ISL is intended as a lightweight software-based security framework for Linux IoT systems and explores:

- Secure boot concepts without TPM hardware
- File integrity verification
- Runtime security monitoring
- Early boot trust establishment
- Embedded Linux security

---

# ⚠️ Current Limitations

## SecureBoot

- SHA256 manifest is not digitally signed yet
- No TPM integration
- No measured boot support
- Software-only trust model

## Runtime Monitoring

- No deep packet inspection
- Heuristic reverse shell detection
- No alerting mechanism
- No centralized logging
- HTTP-only packet monitoring
- Requires root privileges

---

# 👨‍💻 Author

**Adityakrishna Vinod**

---

# 📄 License (MIT)

MIT License

Copyright (c) 2026 Adityakrishna Vinod

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
