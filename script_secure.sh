#!/bin/bash

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Стрелка для ввода
ARROW="->"

# Путь для логов и бэкапов
LOG_DIR="/root/logs"
LOG_FILE="$LOG_DIR/secure_ubuntu.log"
BACKUP_BASE_DIR="/root/backups"
BACKUP_DIR="$BACKUP_BASE_DIR/backup_$(date +%F_%H-%M-%S)"

# Определение имени сервиса SSH
if systemctl status sshd >/dev/null 2>&1; then
    SSH_SERVICE="sshd"
elif systemctl status ssh >/dev/null 2>&1; then
    SSH_SERVICE="ssh"
else
    echo -e "${RED}[ERROR]${NC} Сервис SSH не найден. Убедитесь, что SSH установлен."
    exit 1
fi

# Функции для вывода сообщений
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "\n${BLUE}+$(printf '%*s' 60 | tr ' ' '-')+${NC}"
    echo -e "${BLUE}|${NC} $(printf '%-58s' "$1") ${BLUE}|${NC}"
    echo -e "${BLUE}+$(printf '%*s' 60 | tr ' ' '-')+${NC}"
}

# Функция для ввода с значением по умолчанию
prompt_input() {
    local prompt="$1"
    local default="$2"
    local input
    read -r -p "$ARROW $prompt (по умолчанию: $default): " input
    echo "${input:-$default}"
}

# Функция для подтверждения действия
confirm_action() {
    local prompt="$1"
    local response
    read -r -p "$ARROW $prompt [y/N]: " response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# Функция для валидации имени пользователя
validate_username() {
    local username="$1"
    if [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        return 0
    else
        print_error "Недопустимое имя пользователя. Используйте только строчные буквы, цифры, подчеркивания и дефисы."
        return 1
    fi
}

# Функция для валидации порта
validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        print_error "Недопустимый порт. Введите число от 1 до 65535."
        return 1
    fi
}

# Функция для логирования изменений
log_change() {
    echo "$(date '+%F %T'): $1" >> "$LOG_FILE"
}

# Создание директории для логов
mkdir -p "$LOG_DIR"
print_success "Создана директория для логов: $LOG_DIR"

# Создание директории для бэкапов
mkdir -p "$BACKUP_BASE_DIR"
print_success "Создана директория для бэкапов: $BACKUP_BASE_DIR"

# Создание лог-файла, если он не существует
touch "$LOG_FILE"

# Основное меню
while true; do
    clear
    print_header "Интерактивный скрипт для повышения безопасности Ubuntu-сервера"
    echo "Текущий статус:"
    echo "  $INFO Лог-файл: $LOG_FILE"
    echo "  $INFO Бэкапы: $BACKUP_DIR"
    echo "Выберите действие:"
    echo "  1) Обновить систему"
    echo "  2) Создать нового пользователя"
    echo "  3) Настроить SSH-ключи для пользователя"
    echo "  4) Настройка порта SSH и брандмауэра UFW"
    echo "  5) Запретить root-доступ"
    echo "  6) Отключить вход по паролю"
    echo "  7) Настроить Fail2Ban для защиты от атак"
    echo "  8) Настроить двухфакторную аутентификацию (2FA) для SSH"
    echo "  9) Откатить изменения"
    echo "  0) Выход"
    echo
    read -r -p "$ARROW Выберите опцию (0-9): " option

    case $option in
        1)
            print_header "Обновление системы"
            print_info "Этот шаг установит последние обновления для системы, включая патчи безопасности."
            if confirm_action "Обновить систему?"; then
                print_info "Обновление пакетов..."
                apt update && apt upgrade -y
                print_success "Система успешно обновлена."
                log_change "System updated."
                echo "system_updated=1" >> "$LOG_FILE"  # Флаг для отслеживания
            else
                print_warning "Обновление системы пропущено."
            fi
            read -r -p "Нажмите Enter, чтобы продолжить..."
            ;;
        2)
            print_header "Создание нового пользователя"
            print_info "Этот шаг создаст нового пользователя с правами sudo для безопасного управления сервером."
            while true; do
                NEW_USER=$(prompt_input "Введите имя нового пользователя" "adminuser")
                if validate_username "$NEW_USER"; then
                    break
                fi
            done
            if confirm_action "Создать пользователя $NEW_USER?"; then
                print_info "Создание пользователя $NEW_USER..."
                adduser --gecos "" --disabled-password "$NEW_USER"
                read -r -p "$ARROW Введите пароль для $NEW_USER: " user_password
                echo "$NEW_USER:$user_password" | chpasswd
                usermod -aG sudo "$NEW_USER"
                print_success "Пользователь $NEW_USER создан и добавлен в группу sudo."
                log_change "Created user $NEW_USER."
                echo "user_created=$NEW_USER" >> "$LOG_FILE"  # Флаг для отслеживания
            else
                print_warning "Создание пользователя пропущено."
            fi
            read -r -p "Нажмите Enter, чтобы продолжить..."
            ;;
                    3)
                        if [ -n "$SSH_KEYS_GENERATED" ]; then
                            print_info "Удаление SSH-ключей для пользователя: $SSH_KEYS_GENERATED"
                            if [ "$SSH_KEYS_GENERATED" = "root" ]; then
                                USER_HOME="/root"
                            else
                                USER_HOME="/home/$SSH_KEYS_GENERATED"
                            fi
                            print_info "Проверяемая директория: $USER_HOME/.ssh"
                            if [ -d "$USER_HOME" ]; then
                                if [ -d "$USER_HOME/.ssh" ]; then
                                    rm -rf "$USER_HOME/.ssh"
                                    print_success "SSH-ключи для $SSH_KEYS_GENERATED удалены с сервера."
                                    log_change "SSH keys for $SSH_KEYS_GENERATED deleted from server."
                                else
                                    print_warning "Папка $USER_HOME/.ssh не существует. Ключи уже удалены или не были созданы."
                                fi
                            else
                                print_warning "Домашняя директория $USER_HOME не существует. Пользователь, возможно, был удалён."
                            fi
                            sed -i "/^ssh_keys_generated=/d" "$LOG_FILE"
                        else
                            print_warning "Переменная SSH_KEYS_GENERATED пуста. Откат невозможен."
                        fi
                        ;;
        4)
            print_header "Настройка порта SSH и брандмауэра UFW"
            print_info "Этот шаг изменит порт SSH и обновит правила UFW, сохраняя существующие настройки."
            CURRENT_SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
            print_info "Текущий порт SSH: $CURRENT_SSH_PORT"
            while true; do
                SSH_PORT=$(prompt_input "Введите новый порт для SSH" "2222")
                if validate_port "$SSH_PORT"; then
                    break
                fi
            done
            if confirm_action "Изменить порт SSH на $SSH_PORT и обновить UFW?"; then
                # Создаём директорию для бэкапов только после подтверждения
                mkdir -p "$BACKUP_DIR"
                print_success "Создана директория для бэкапов: $BACKUP_DIR"

                # Установка UFW, если он ещё не установлен
                if ! command -v ufw >/dev/null 2>&1; then
                    print_info "Установка UFW..."
                    apt install -y ufw
                fi

                # Проверяем, включён ли UFW
                UFW_STATUS=$(ufw status | grep -i "Status:" | awk '{print $2}')
                if [ "$UFW_STATUS" = "active" ]; then
                    # UFW уже включён — обновляем только правила для SSH
                    print_info "UFW уже включён. Обновление правил для SSH..."

                    # Делаем бэкап текущих правил UFW
                    print_info "Создание бэкапа текущих правил UFW..."
                    UFW_BACKUP_FILE="$BACKUP_DIR/ufw_rules.bak"
                    ufw status numbered > "$UFW_BACKUP_FILE"
                    log_change "Backed up UFW rules to $UFW_BACKUP_FILE"

                    # Проверяем текущие правила
                    print_info "Текущие правила UFW:"
                    ufw status

                    # Разрешаем новый порт SSH (до изменения порта, чтобы не потерять доступ)
                    print_info "Разрешение нового порта SSH ($SSH_PORT) в UFW..."
                    ufw allow "$SSH_PORT/tcp"

                    # Удаляем правило для старого SSH-порта
                    print_info "Удаление правила для старого порта SSH ($CURRENT_SSH_PORT)..."
                    RULE_NUM=$(ufw status numbered | grep "\[.*\] $CURRENT_SSH_PORT/tcp" | awk -F'[][]' '{print $2}' | head -n 1)
                    if [ -n "$RULE_NUM" ]; then
                        echo "y" | ufw delete "$RULE_NUM"
                        print_success "Правило для порта $CURRENT_SSH_PORT удалено."
                    else
                        print_warning "Правило для порта $CURRENT_SSH_PORT не найдено."
                    fi
                else
                    # UFW не включён — настраиваем с нуля
                    print_info "UFW не включён. Настройка с нуля..."
                    print_info "Разрешение нового порта SSH ($SSH_PORT) в UFW..."
                    ufw allow "$SSH_PORT/tcp"
                    print_info "Настройка базовых правил UFW..."
                    ufw default deny incoming
                    ufw default allow outgoing
                    ufw allow 80/tcp
                    ufw allow 443/tcp
                    print_info "Включение UFW..."
                    ufw --force enable
                    print_success "UFW настроен с нуля."
                fi

                # Показываем обновлённые правила UFW
                print_info "Текущие правила UFW после обновления:"
                ufw status

                # Создаём бэкап конфигурации SSH
                print_info "Создание бэкапа /etc/ssh/sshd_config..."
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"
                log_change "Backed up /etc/ssh/sshd_config to $BACKUP_DIR/sshd_config.bak"

                # Изменяем порт SSH
                print_info "Изменение порта SSH на $SSH_PORT..."
                sed -i "s/Port $CURRENT_SSH_PORT/Port $SSH_PORT/" /etc/ssh/sshd_config
                # Если строка Port отсутствует, добавляем её
                if ! grep -q "^Port $SSH_PORT" /etc/ssh/sshd_config; then
                    echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
                fi
                systemctl restart "$SSH_SERVICE"
                print_success "Порт SSH изменён на $SSH_PORT."

                print_info "Текущие правила UFW:"
                ufw status
                log_change "SSH port changed to $SSH_PORT and UFW updated with new SSH port."
                echo "ssh_port_changed=$SSH_PORT" >> "$LOG_FILE"  # Флаг для отслеживания
            else
                print_warning "Настройка порта SSH и UFW пропущена."
            fi
            read -r -p "Нажмите Enter, чтобы продолжить..."
            ;;
        5)
            print_header "Запретить root-доступ"
            print_info "Этот шаг отключит вход через root, оставив возможность входа для других пользователей."
            if confirm_action "Запретить root-доступ?"; then
                # Создаём директорию для бэкапов только после подтверждения
                mkdir -p "$BACKUP_DIR"
                print_success "Создана директория для бэкапов: $BACKUP_DIR"

                print_info "Создание бэкапа /etc/ssh/sshd_config..."
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config_root_access.bak"
                log_change "Backed up /etc/ssh/sshd_config to $BACKUP_DIR/sshd_config_root_access.bak"

                # Проверяем дополнительные конфиги в /etc/ssh/sshd_config.d/
                print_info "Проверка дополнительных конфигурационных файлов SSH..."
                if ls /etc/ssh/sshd_config.d/*.conf >/dev/null 2>&1; then
                    for config_file in /etc/ssh/sshd_config.d/*.conf; do
                        print_info "Проверка файла: $config_file"
                        # Удаляем или комментируем конфликтующие настройки
                        sed -i "s/^PermitRootLogin.*/#PermitRootLogin yes/" "$config_file"
                    done
                else
                    print_info "Дополнительные конфиги в /etc/ssh/sshd_config.d/ не найдены."
                fi

                print_info "Настройка SSH..."
                # Удаляем существующую строку PermitRootLogin
                sed -i "/^PermitRootLogin/d" /etc/ssh/sshd_config
                # Добавляем новую строку в конец файла
                echo "PermitRootLogin no" >> /etc/ssh/sshd_config

                systemctl restart "$SSH_SERVICE"
                print_success "Root-доступ отключён."
                log_change "Root login disabled."
                echo "root_access_disabled=1" >> "$LOG_FILE"  # Флаг для отслеживания
            else
                print_warning "Настройка пропущена."
            fi
            read -r -p "Нажмите Enter, чтобы продолжить..."
            ;;
        6)
            print_header "Отключить вход по паролю"
            print_info "Этот шаг отключит вход по паролю, оставив только вход по SSH-ключам."
            if confirm_action "Отключить вход по паролю?"; then
                # Создаём директорию для бэкапов только после подтверждения
                mkdir -p "$BACKUP_DIR"
                print_success "Создана директория для бэкапов: $BACKUP_DIR"

                print_info "Создание бэкапа /etc/ssh/sshd_config..."
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config_password.bak"
                log_change "Backed up /etc/ssh/sshd_config to $BACKUP_DIR/sshd_config_password.bak"

                # Проверяем дополнительные конфиги в /etc/ssh/sshd_config.d/
                print_info "Проверка дополнительных конфигурационных файлов SSH..."
                if ls /etc/ssh/sshd_config.d/*.conf >/dev/null 2>&1; then
                    for config_file in /etc/ssh/sshd_config.d/*.conf; do
                        print_info "Проверка файла: $config_file"
                        # Удаляем или комментируем конфликтующие настройки
                        sed -i "s/^PasswordAuthentication.*/#PasswordAuthentication yes/" "$config_file"
                        sed -i "s/^PubkeyAuthentication.*/#PubkeyAuthentication no/" "$config_file"
                        sed -i "s/^ChallengeResponseAuthentication.*/#ChallengeResponseAuthentication yes/" "$config_file"
                    done
                else
                    print_info "Дополнительные конфиги в /etc/ssh/sshd_config.d/ не найдены."
                fi

                print_info "Настройка SSH..."
                # Удаляем существующие строки, если они есть
                sed -i "/^PasswordAuthentication/d" /etc/ssh/sshd_config
                sed -i "/^PubkeyAuthentication/d" /etc/ssh/sshd_config
                sed -i "/^ChallengeResponseAuthentication/d" /etc/ssh/sshd_config
                # Добавляем новые строки в конец файла
                echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
                echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
                echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config

                # Перезапускаем сервис SSH
                if systemctl restart "$SSH_SERVICE"; then
                    print_success "Сервис SSH успешно перезапущен."
                else
                    print_error "Не удалось перезапустить сервис SSH. Проверьте конфигурацию вручную."
                    exit 1
                fi

                print_success "Вход по паролю отключён."
                log_change "Password authentication disabled."
                echo "password_auth_disabled=1" >> "$LOG_FILE"  # Флаг для отслеживания
            else
                print_warning "Настройка пропущена."
            fi
            read -r -p "Нажмите Enter, чтобы продолжить..."
            ;;
        7)
            print_header "Настройка Fail2Ban"
            print_info "Этот шаг защитит сервер от brute-force атак с помощью Fail2Ban."
            SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
            print_info "Текущий порт SSH: $SSH_PORT"
            if confirm_action "Настроить Fail2Ban?"; then
                # Создаём директорию для бэкапов только после подтверждения
                mkdir -p "$BACKUP_DIR"
                print_success "Создана директория для бэкапов: $BACKUP_DIR"

                print_info "Установка Fail2Ban..."
                apt install -y fail2ban
                cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime  = 3600
findtime  = 600
maxretry = 5

[sshd]
enabled = true
port    = $SSH_PORT
filter  = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF
                systemctl restart fail2ban
                systemctl enable fail2ban
                print_success "Fail2Ban настроен для защиты SSH на порту $SSH_PORT."
                log_change "Fail2Ban configured for SSH on port $SSH_PORT."
                echo "fail2ban_configured=1" >> "$LOG_FILE"  # Флаг для отслеживания
            else
                print_warning "Настройка Fail2Ban пропущена."
            fi
            read -r -p "Нажмите Enter, чтобы продолжить..."
            ;;
        8)
            print_header "Настройка двухфакторной аутентификации (2FA) для SSH"
            print_info "Этот шаг добавит второй фактор аутентификации для SSH (код из приложения)."
            while true; do
                SSH_USER=$(prompt_input "Введите имя пользователя для настройки 2FA" "adminuser")
                if id "$SSH_USER" >/dev/null 2>&1; then
                    break
                else
                    print_error "Пользователь $SSH_USER не существует. Попробуйте снова."
                fi
            done
            if confirm_action "Настроить 2FA для $SSH_USER?"; then
                # Создаём директорию для бэкапов только после подтверждения
                mkdir -p "$BACKUP_DIR"
                print_success "Создана директория для бэкапов: $BACKUP_DIR"

                print_info "Установка Google Authenticator..."
                apt install -y libpam-google-authenticator
                sudo -u "$SSH_USER" google-authenticator
                echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
                cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config_2fa.bak"
                sed -i "s/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/" /etc/ssh/sshd_config
                echo "AuthenticationMethods publickey,keyboard-interactive" >> /etc/ssh/sshd_config
                systemctl restart "$SSH_SERVICE"
                print_success "2FA настроена для $SSH_USER."
                print_info "Используйте приложение-аутентификатор (например, Google Authenticator) для входа."
                log_change "2FA enabled for SSH user $SSH_USER."
                echo "2fa_configured=$SSH_USER" >> "$LOG_FILE"  # Флаг для отслеживания
            else
                print_warning "Настройка 2FA пропущена."
            fi
            read -r -p "Нажмите Enter, чтобы продолжить..."
            ;;
        9)
            print_header "Откат изменений"
            print_info "Этот шаг позволяет откатить изменения, сделанные этим скриптом."
            echo "Какие изменения откатить? (можно выбрать несколько, через пробел):"
            
            # Проверяем, какие действия были выполнены
            SYSTEM_UPDATED=$(grep "system_updated=1" "$LOG_FILE" || echo "")
            USER_CREATED=$(grep "user_created=" "$LOG_FILE" | cut -d'=' -f2 || echo "")
            SSH_KEYS_GENERATED=$(grep "ssh_keys_generated=" "$LOG_FILE" | cut -d'=' -f2 || echo "")
            SSH_PORT_CHANGED=$(grep "ssh_port_changed=" "$LOG_FILE" | cut -d'=' -f2 || echo "")
            ROOT_ACCESS_DISABLED=$(grep "root_access_disabled=1" "$LOG_FILE" || echo "")
            PASSWORD_AUTH_DISABLED=$(grep "password_auth_disabled=1" "$LOG_FILE" || echo "")
            FAIL2BAN_CONFIGURED=$(grep "fail2ban_configured=1" "$LOG_FILE" || echo "")
            TWO_FA_CONFIGURED=$(grep "2fa_configured=" "$LOG_FILE" | cut -d'=' -f2 || echo "")

            # Формируем меню отката
            i=1
            if [ -n "$SYSTEM_UPDATED" ]; then
                echo "  $i) Откатить обновление системы"
                ((i++))
            fi
            if [ -n "$USER_CREATED" ]; then
                echo "  $i) Удалить пользователя $USER_CREATED"
                ((i++))
            fi
            if [ -n "$SSH_KEYS_GENERATED" ]; then
                echo "  $i) Удалить SSH-ключи для $SSH_KEYS_GENERATED (на сервере)"
                ((i++))
            fi
            if [ -n "$SSH_PORT_CHANGED" ]; then
                echo "  $i) Восстановить порт SSH (изменён на $SSH_PORT_CHANGED)"
                ((i++))
            fi
            if [ -n "$ROOT_ACCESS_DISABLED" ]; then
                echo "  $i) Восстановить root-доступ"
                ((i++))
            fi
            if [ -n "$PASSWORD_AUTH_DISABLED" ]; then
                echo "  $i) Восстановить вход по паролю"
                ((i++))
            fi
            if [ -n "$FAIL2BAN_CONFIGURED" ]; then
                echo "  $i) Удалить Fail2Ban"
                ((i++))
            fi
            if [ -n "$TWO_FA_CONFIGURED" ]; then
                echo "  $i) Удалить 2FA для $TWO_FA_CONFIGURED"
                ((i++))
            fi
            echo "  0) Отмена"

            read -r -p "$ARROW Выберите опции (например, 1 3 4): " revert_options

            if [ "$revert_options" = "0" ]; then
                print_warning "Откат изменений отменён."
                read -r -p "Нажмите Enter, чтобы продолжить..."
                continue
            fi

            print_info "Откат изменений..."
            for opt in $revert_options; do
                case $opt in
                    1)
                        if [ -n "$SYSTEM_UPDATED" ]; then
                            print_info "Откат обновления системы невозможен (apt не поддерживает откат). Рекомендуется вручную проверить установленные пакеты."
                            log_change "System update revert attempted (not supported)."
                            # Удаляем флаг из лог-файла
                            sed -i "/^system_updated=/d" "$LOG_FILE"
                        fi
                        ;;
                    2)
                        if [ -n "$USER_CREATED" ]; then
                            print_info "Удаление пользователя $USER_CREATED..."
                            userdel -r "$USER_CREATED" 2>/dev/null
                            rm -rf "/home/${USER_CREATED:?}"
                            print_success "Пользователь $USER_CREATED удалён."
                            log_change "User $USER_CREATED deleted."
                            # Удаляем флаг из лог-файла
                            sed -i "/^user_created=/d" "$LOG_FILE"
                        fi
                        ;;
                    3)
                        if [ -n "$SSH_KEYS_GENERATED" ]; then
                            print_info "Удаление SSH-ключей для $SSH_KEYS_GENERATED на сервере..."
                            if [ "$SSH_KEYS_GENERATED" = "root" ]; then
                                USER_HOME="/root"
                            else
                                USER_HOME="/home/$SSH_KEYS_GENERATED"
                            fi
                            if [ -d "$USER_HOME/.ssh" ]; then
                                rm -rf "$USER_HOME/.ssh"
                                print_success "SSH-ключи для $SSH_KEYS_GENERATED удалены с сервера."
                            else
                                print_warning "Папка $USER_HOME/.ssh не найдена. Ключи уже удалены или не существовали."
                            fi
                            log_change "SSH keys for $SSH_KEYS_GENERATED deleted from server."
                            # Удаляем флаг из лог-файла
                            sed -i "/^ssh_keys_generated=/d" "$LOG_FILE"
                        fi
                        ;;
                    4)
                        if [ -n "$SSH_PORT_CHANGED" ]; then
                            # Ищем бэкап, связанный с изменением порта
                            LATEST_BACKUP=""
                            for backup_dir in $(ls -td $BACKUP_BASE_DIR/backup_* 2>/dev/null); do
                                if [ -f "$backup_dir/sshd_config.bak" ]; then
                                    RESTORED_SSH_PORT=$(grep "^Port" "$backup_dir/sshd_config.bak" | awk '{print $2}' || echo "22")
                                    if [ "$RESTORED_SSH_PORT" != "$SSH_PORT_CHANGED" ]; then
                                        LATEST_BACKUP="$backup_dir"
                                        break
                                    fi
                                fi
                            done

                            if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/sshd_config.bak" ]; then
                                RESTORED_SSH_PORT=$(grep "^Port" "$LATEST_BACKUP/sshd_config.bak" | awk '{print $2}' || echo "22")
                                CURRENT_SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22")
                                cp "$LATEST_BACKUP/sshd_config.bak" /etc/ssh/sshd_config
                                systemctl restart "$SSH_SERVICE"
                                print_success "SSH порт восстановлен (на $RESTORED_SSH_PORT)."

                                # Восстанавливаем правила UFW
                                if [ -f "$LATEST_BACKUP/ufw_rules.bak" ]; then
                                    print_info "Восстановление правил UFW..."
                                    # Удаляем правило для текущего SSH-порта (IPv4)
                                    RULE_NUM=$(ufw status numbered | grep -E "\[.*\] $CURRENT_SSH_PORT/tcp\s+ALLOW" | awk -F'[][]' '{print $2}' | head -n 1)
                                    if [ -n "$RULE_NUM" ]; then
                                        echo "y" | ufw delete "$RULE_NUM"
                                        print_success "Правило для порта $CURRENT_SSH_PORT (IPv4) удалено."
                                    fi

                                    # Удаляем правило для текущего SSH-порта (IPv6)
                                    RULE_NUM_V6=$(ufw status numbered | grep -E "\[.*\] $CURRENT_SSH_PORT/tcp\s+ALLOW.*\(v6\)" | awk -F'[][]' '{print $2}' | head -n 1)
                                    if [ -n "$RULE_NUM_V6" ]; then
                                        echo "y" | ufw delete "$RULE_NUM_V6"
                                        print_success "Правило для порта $CURRENT_SSH_PORT (IPv6) удалено."
                                    fi

                                    # Разрешаем восстановленный SSH-порт
                                    print_info "Разрешение порта SSH ($RESTORED_SSH_PORT) в UFW..."
                                    ufw allow "$RESTORED_SSH_PORT/tcp"
                                    print_success "Правило для порта $RESTORED_SSH_PORT добавлено."
                                else
                                    print_warning "Бэкап правил UFW не найден. Правила не восстановлены."
                                fi
                            else
                                print_warning "Подходящий бэкап /etc/ssh/sshd_config не найден. Порт не восстановлен."
                            fi
                            # Удаляем флаг из лог-файла
                            sed -i "/^ssh_port_changed=/d" "$LOG_FILE"
                        fi
                        ;;
                    5)
                        if [ -n "$ROOT_ACCESS_DISABLED" ]; then
                            # Ищем последний бэкап для восстановления
                            LATEST_BACKUP=""
                            for backup_dir in $(ls -td $BACKUP_BASE_DIR/backup_* 2>/dev/null); do
                                if [ -f "$backup_dir/sshd_config_root_access.bak" ]; then
                                    LATEST_BACKUP="$backup_dir"
                                    break
                                fi
                            done

                            if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/sshd_config_root_access.bak" ]; then
                                cp "$LATEST_BACKUP/sshd_config_root_access.bak" /etc/ssh/sshd_config
                                systemctl restart "$SSH_SERVICE"
                                print_success "Root-доступ восстановлен."
                                log_change "Root access restored."
                            else
                                print_warning "Бэкап /etc/ssh/sshd_config_root_access.bak не найден. Root-доступ не восстановлен."
                            fi
                            # Удаляем флаг из лог-файла
                            sed -i "/^root_access_disabled=/d" "$LOG_FILE"
                        fi
                        ;;
                    6)
                        if [ -n "$PASSWORD_AUTH_DISABLED" ]; then
                            # Ищем последний бэкап для восстановления
                            LATEST_BACKUP=""
                            for backup_dir in $(ls -td $BACKUP_BASE_DIR/backup_* 2>/dev/null); do
                                if [ -f "$backup_dir/sshd_config_password.bak" ]; then
                                    LATEST_BACKUP="$backup_dir"
                                    break
                                fi
                            done

                            if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP/sshd_config_password.bak" ]; then
                                cp "$LATEST_BACKUP/sshd_config_password.bak" /etc/ssh/sshd_config
                                systemctl restart "$SSH_SERVICE"
                                print_success "Вход по паролю восстановлен."
                                log_change "Password authentication restored."
                            else
                                print_warning "Бэкап /etc/ssh/sshd_config_password.bak не найден. Вход по паролю не восстановлен."
                            fi
                            # Удаляем флаг из лог-файла
                            sed -i "/^password_auth_disabled=/d" "$LOG_FILE"
                        fi
                        ;;
                    7)
                        if [ -n "$FAIL2BAN_CONFIGURED" ]; then
                            print_info "Удаление Fail2Ban..."
                            apt purge -y fail2ban
                            apt autoremove -y
                            rm -f /etc/fail2ban/jail.local
                            print_success "Fail2Ban удалён."
                            log_change "Fail2Ban removed."
                            # Удаляем флаг из лог-файла
                            sed -i "/^fail2ban_configured=/d" "$LOG_FILE"
                        fi
                        ;;
                    8)
                        if [ -n "$TWO_FA_CONFIGURED" ]; then
                            print_info "Удаление 2FA для $TWO_FA_CONFIGURED..."
                            sed -i '/auth required pam_google_authenticator.so/d' /etc/pam.d/sshd
                            sed -i '/AuthenticationMethods publickey,keyboard-interactive/d' /etc/ssh/sshd_config
                            sed -i "s/ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/" /etc/ssh/sshd_config
                            systemctl restart "$SSH_SERVICE"
                            apt purge -y libpam-google-authenticator
                            print_success "2FA удалена."
                            log_change "2FA removed for $TWO_FA_CONFIGURED."
                            # Удаляем флаг из лог-файла
                            sed -i "/^2fa_configured=/d" "$LOG_FILE"
                        fi
                        ;;
                    *)
                        print_warning "Неверная опция: $opt. Пропущена."
                        ;;
                esac
            done
            print_success "Выбранные изменения откатаны."
            read -r -p "Нажмите Enter, чтобы продолжить..."
            ;;
    esac
done