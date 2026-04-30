# 🛡️ IoT Security Monitoring Daemon

![C](https://img.shields.io/badge/language-C-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)
![Build](https://img.shields.io/badge/build-Makefile-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)
![Status](https://img.shields.io/badge/status-Active-success.svg)

A lightweight, multi-threaded Linux daemon written in C that continuously monitors a system for potential security risks such as weak passwords, suspicious services, reverse shells, and HTTP traffic.

---

## 📌 Overview

This project provides **real-time security monitoring** for Linux/IoT systems by combining:

- Password auditing  
- Network traffic inspection  
- Service/process monitoring  

---

## ⚙️ Features

### 🔑 Weak Password Detection
- Scans `/etc/shadow`
- Runs every **30 minutes**

### 🧠 System & Service Monitoring
Runs every **2 seconds**:
- Active connections  
- Logged-in users  
- Running services  
- Reverse shell detection  

### 🌐 HTTP Traffic Monitoring
- Uses **libpcap**
- Captures HTTP traffic (incoming/outgoing)

---

## 🧵 Architecture

    Main Thread (Scheduler)
            |
            |----> Service Thread (2 sec loop)
            |
            |----> HTTP Sniffer Thread (pcap)

---

## 📁 Project Structure

    .
    ├── build/
    ├── config/
    ├── http/
    ├── passwd_check/
    ├── Services/
    ├── Utility/
    ├── main.c
    ├── Makefile
    ├── my_daemon
    └── README.md

---

## 🧰 Requirements

Install dependencies:

    sudo apt update
    sudo apt install build-essential libpcap-dev libcrypt-dev

---

## 🔨 Build

    make

Output:

    my_daemon

---

## ▶️ Run

    sudo ./my_daemon

⚠️ Requires root privileges:
- `/etc/shadow` access  
- Packet capture  
- System monitoring  

---

## ⚙️ Configuration

File:

    config/daemon.conf

Example:

        [passwd]
        enable=true
        
        [services]
        active_connections=true
        current_access=true
        reverse_shell=true
        running_services=true
        
        [http]
        http_sniffer=true
        
---

## 📜 Logging

Logs are written using **syslog**.

### 📄 View logs (traditional syslog)

    sudo tail -f /var/log/syslog

Filter only daemon logs:

    sudo grep simple_daemon /var/log/syslog

---

### 📘 View logs using journalctl (systemd systems)

If running on a system with systemd:

    sudo journalctl -t simple_daemon

Follow logs in real-time:

    sudo journalctl -t simple_daemon -f

Show recent logs:

    sudo journalctl -t simple_daemon -n 50

---

### 📌 PID File

    /tmp/simple_daemon.pid

## ⚠️ Limitations

- No deep packet inspection  
- Heuristic reverse shell detection  
- No alerting system  
- No structured logging  
- HTTP-only monitoring  
- User-space only  
- Requires root  

---

## 👨‍💻 Author

Adityakrishna Vinod

---

## 📄 License (MIT)

MIT License

Copyright (c) 2026 Adityakrishna Vinod

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.