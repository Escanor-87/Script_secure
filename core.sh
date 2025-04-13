#!/bin/bash

# === Основные переменные ===
LOG_DIR="/var/log/script_secure"
LOG_FILE="$LOG_DIR/changes.log"
BACKUP_BASE_DIR="/var/backups/script_secure"
BACKUP_DIR="$BACKUP_BASE_DIR/$(date +%F_%H-%M-%S)"
SSH_SERVICE="ssh"  # or "sshd" для некоторых систем

ARROW="➤"

# === Утилиты ===
print_info() { echo -e "\e[34m[INFO]\e[0m $1"; }
print_success() { echo -e "\e[32m[SUCCESS]\e[0m $1"; }
print_warning() { echo -e "\e[33m[WARNING]\e[0m $1"; }
print_error() { echo -e "\e[31m[ERROR]\e[0m $1"; }
print_header() { echo -e "\n\e[1;35m==== $1 ====\e[0m\n"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Скрипт должен запускаться от root"
        exit 1
    fi
}

check_disk_space() {
    local required_mb="$1"
    local available=$(df / | tail -1 | awk '{print $4}')
    if [ "$available" -lt $((required_mb * 1024)) ]; then
        print_error "Недостаточно места ($required_mb MB нужно)"
        return 1
    fi
    return 0
}

confirm_action() {
    read -r -p "$1 (y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]]
}

prompt_input() {
    local prompt="$1"
    local default="$2"
    read -r -p "$prompt [$default]: " input
    echo "${input:-$default}"
}

log_change() {
    local message="$1"
    local level="${2:-INFO}"
    local source="${3:-script}"
    mkdir -p "$LOG_DIR"
    echo "[$(date +'%F %T')] [$level] [$source] $message" >> "$LOG_FILE"
}

init_directories() {
    mkdir -p "$LOG_DIR"
    mkdir -p "$BACKUP_DIR"
}
