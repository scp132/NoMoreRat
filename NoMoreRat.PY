import psutil
import time
import socket
import traceback
from datetime import datetime
import ipaddress
import threading
import os
import sys
from colorama import init, Fore, Style

# Инициализация colorama
init(autoreset=True)

LOG_FILE = "ratcheck_crashlog.txt"
SUSPICIOUS_PORTS = {3389, 5900, 22, 1337, 6667, 31337, 12345, 54321}  # Порты для RAT и подозрительные
COMMON_SAFE_PORTS = {80, 443, 53, 123}  # Обычные безопасные порты

TERMINAL_WIDTH = 90

# Опции управления
SHOW_FULL_PATH = False
SHOW_ONLY_UNSAFE = False
SHOW_MATRIX = False
RUNNING = True


def crash_handler(func):
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write("\n=== CRASH @ {} ===\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                traceback.print_exc(file=f)
            print("\n[!] Произошла ошибка. Подробнее в ratcheck_crashlog.txt")
            input("Нажмите Enter для выхода...")
            sys.exit(1)
    return wrapper


def format_addr(addr):
    if not addr:
        return "N/A"
    try:
        return f"{addr.ip}:{addr.port}"
    except:
        return str(addr)


def resolve_proto(conn):
    if conn.type == socket.SOCK_STREAM:
        return "TCP"
    elif conn.type == socket.SOCK_DGRAM:
        return "UDP"
    return "UNK"


def classify_connection(raddr):
    if not raddr:
        return "GREEN"  # Локальное подключение
    try:
        ip = ipaddress.ip_address(raddr.ip)
        if ip.is_private:
            return "GREEN"
        elif raddr.port in SUSPICIOUS_PORTS:
            return "RED"
        elif raddr.port not in COMMON_SAFE_PORTS:
            return "ORANGE"
        else:
            return "GREEN"
    except:
        return "ORANGE"


def colorize(text, level):
    if level == "RED":
        return Fore.RED + text + Style.RESET_ALL
    elif level == "ORANGE":
        return Fore.YELLOW + text + Style.RESET_ALL
    elif level == "GREEN":
        return Fore.GREEN + text + Style.RESET_ALL
    return text


def get_process_path(pid):
    try:
        p = psutil.Process(pid)
        return p.exe()
    except Exception:
        return "N/A"


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header():
    green = Fore.GREEN
    reset = Style.RESET_ALL
    ascii_art = f"""
{green}   _  ______     ___  ___ ______
  / |/ / __ \   / _ \/ _ /_  __/
 /    / /_/ /  / , _/ __ |/ /   
/_/|_/\____/  /_/|_/_/ |_/_/  
  CREATE BY https://discord.gg/w88Su5JvHZ
            THE CODE 
{reset}"""
    print(ascii_art.center(TERMINAL_WIDTH))


def print_menu():
    full_path_status = "Вкл" if SHOW_FULL_PATH else "Выкл"
    unsafe_only_status = "Вкл" if SHOW_ONLY_UNSAFE else "Выкл"
    matrix_status = "Вкл" if SHOW_MATRIX else "Выкл"

    menu_line = (
        f"[1] Обновить список  |  "
        f"[2] Полный путь: {full_path_status}  |  "
        f"[3] Только опасные: {unsafe_only_status}  |  "
        f"[4] Matrix Rain: {matrix_status}  |  "
        f"[Q] Выход"
    )

    print("\n" + "=" * TERMINAL_WIDTH)
    print(menu_line.center(TERMINAL_WIDTH))
    print("=" * TERMINAL_WIDTH)
    print("Введите номер опции и нажмите Enter:")


def matrix_rain():
    import random
    import shutil

    columns = shutil.get_terminal_size((80, 20)).columns
    drops = [0] * columns
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@#$%^&*()-_=+"

    try:
        while SHOW_MATRIX and RUNNING:
            line = ''
            for i in range(columns):
                if drops[i] == 0:
                    line += ' '
                else:
                    line += random.choice(chars)
                drops[i] = drops[i] + 1 if drops[i] < 10 and random.random() > 0.5 else 0
            print(Fore.GREEN + line + Style.RESET_ALL)
            time.sleep(0.1)
            clear_screen()
    except KeyboardInterrupt:
        pass


@crash_handler
def main():
    global SHOW_FULL_PATH, SHOW_ONLY_UNSAFE, SHOW_MATRIX, RUNNING

    matrix_thread = None

    while RUNNING:
        clear_screen()
        print_header()
        print(f"{'Время':<10} {'Протокол':<7} {'Локальный адрес':<22} {'Удалённый адрес':<22} {'Статус':<10} {'Файл':<35}")
        print("-" * TERMINAL_WIDTH)

        connections = psutil.net_connections()
        current_time = datetime.now().strftime("%H:%M:%S")

        filtered_connections = []

        for conn in connections:
            if not conn.raddr:
                continue  # Игнорируем локальные только

            risk = classify_connection(conn.raddr)
            if SHOW_ONLY_UNSAFE and risk == "GREEN":
                continue  # Фильтруем безопасные

            laddr = format_addr(conn.laddr)
            raddr = format_addr(conn.raddr)
            status = conn.status if conn.status else "NONE"
            proto = resolve_proto(conn)
            path = get_process_path(conn.pid) if SHOW_FULL_PATH else ""

            line = f"{current_time:<10} {proto:<7} {laddr:<22} {raddr:<22} {status:<10} {path:<35}"

            print(colorize(line, risk))

            filtered_connections.append(line)

        print_menu()

        # Управление меню
        choice = input().strip().lower()

        if choice == "1":
            # Обновить список - просто перезапускаем цикл
            continue
        elif choice == "2":
            SHOW_FULL_PATH = not SHOW_FULL_PATH
        elif choice == "3":
            SHOW_ONLY_UNSAFE = not SHOW_ONLY_UNSAFE
        elif choice == "4":
            SHOW_MATRIX = not SHOW_MATRIX
            if SHOW_MATRIX and (matrix_thread is None or not matrix_thread.is_alive()):
                matrix_thread = threading.Thread(target=matrix_rain, daemon=True)
                matrix_thread.start()
        elif choice == "q":
            RUNNING = False
        else:
            print("Неверный ввод, попробуйте снова.")
            time.sleep(1)


if __name__ == "__main__":
    main()
