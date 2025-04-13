#!/bin/bash

# Точка входа
# Подключаем основной модуль
source "$(dirname "$0")/modules/core.sh"

# Проверка прав
check_root

# Инициализация папок
init_directories

# Подключение остальных модулей
source "$(dirname "$0")/modules/menu.sh"

# Запуск главного меню
main_menu
