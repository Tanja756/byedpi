// socks5_auth.c
#define _POSIX_C_SOURCE 200809L
#include "socks5_auth.h"
#include "error.h"
#include "params.h"   // для params.debug и LOG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#endif

// Максимальное количество учётных записей
#define MAX_CREDENTIALS 256

// Структура для хранения одной учётной записи
typedef struct {
    char *username;
    char *password;
} auth_entry_t;

static auth_entry_t *auth_entries = NULL;
static int auth_count = 0;
static int auth_enabled = 0;  // 1 - аутентификация включена

// Вспомогательная функция: чтение строки из файла с удалением \r\n
static char *read_line(FILE *f, char *buf, size_t size) {
    if (!fgets(buf, size, f)) return NULL;
    char *p = strpbrk(buf, "\r\n");
    if (p) *p = '\0';
    return buf;
}

int socks5_auth_init(const char *authfile, const char *single_auth) {
    auth_enabled = 0;
    auth_count = 0;
    free(auth_entries);
    auth_entries = NULL;

    // Приоритет: если задан single_auth, используем только его
    if (single_auth && *single_auth) {
        char *copy = strdup(single_auth);
        if (!copy) return -1;
        char *colon = strchr(copy, ':');
        if (!colon) {
            free(copy);
            LOG(LOG_E, "Invalid auth string format (expected user:pass)\n");
            return -1;
        }
        *colon = '\0';
        auth_entries = calloc(1, sizeof(auth_entry_t));
        if (!auth_entries) {
            free(copy);
            return -1;
        }
        auth_entries[0].username = strdup(copy);
        auth_entries[0].password = strdup(colon + 1);
        free(copy);
        if (!auth_entries[0].username || !auth_entries[0].password) {
            free(auth_entries[0].username);
            free(auth_entries[0].password);
            free(auth_entries);
            auth_entries = NULL;
            return -1;
        }
        auth_count = 1;
        auth_enabled = 1;
        LOG(LOG_S, "SOCKS5 authentication enabled with single user: %s\n", auth_entries[0].username);
        return 0;
    }

    // Загрузка из файла
    if (!authfile || !*authfile) {
        // Файл не задан – аутентификация отключена
        return 0;
    }

    FILE *f = fopen(authfile, "r");
    if (!f) {
        LOG(LOG_E, "Cannot open auth file '%s': %s\n", authfile, strerror(errno));
        return -1;
    }

    char line[512];
    auth_entry_t *tmp_entries = calloc(MAX_CREDENTIALS, sizeof(auth_entry_t));
    if (!tmp_entries) {
        fclose(f);
        return -1;
    }

    int cnt = 0;
    while (cnt < MAX_CREDENTIALS && read_line(f, line, sizeof(line))) {
        // Пропуск пустых строк и комментариев
        if (line[0] == '#' || line[0] == '\0') continue;
        char *colon = strchr(line, ':');
        if (!colon) {
            LOG(LOG_E, "Invalid line in auth file (no colon): %s\n", line);
            continue;
        }
        *colon = '\0';
        tmp_entries[cnt].username = strdup(line);
        tmp_entries[cnt].password = strdup(colon + 1);
        if (!tmp_entries[cnt].username || !tmp_entries[cnt].password) {
            // Ошибка памяти – очищаем уже выделенное
            for (int i = 0; i <= cnt; i++) {
                free(tmp_entries[i].username);
                free(tmp_entries[i].password);
            }
            free(tmp_entries);
            fclose(f);
            return -1;
        }
        cnt++;
    }
    fclose(f);

    if (cnt == 0) {
        LOG(LOG_E, "No valid credentials found in auth file\n");
        free(tmp_entries);
        return -1;
    }

    auth_entries = tmp_entries;
    auth_count = cnt;
    auth_enabled = 1;
    LOG(LOG_S, "SOCKS5 authentication enabled with %d user(s) from file '%s'\n", cnt, authfile);
    return 0;
}

int socks5_auth_check(const char *username, const char *password) {
    if (!auth_enabled) return 1;  // если аутентификация отключена, любой доступ разрешён

    for (int i = 0; i < auth_count; i++) {
        if (strcmp(auth_entries[i].username, username) == 0 &&
            strcmp(auth_entries[i].password, password) == 0) {
            return 1;
        }
    }
    return 0;
}

int socks5_auth_handshake(int fd, const char *buffer, ssize_t n, unsigned int *methods, int *auth_state) {
    // auth_state: 0 - ожидание выбора метода, 1 - ожидание user/pass
    if (*auth_state == 0) {
        // Первый этап: VER, NMETHODS, METHODS
        if (n < 2) return 0;
        uint8_t ver = (uint8_t)buffer[0];
        uint8_t nmethods = (uint8_t)buffer[1];
        if (ver != 0x05) return -1;
        if (n < 2 + nmethods) return 0;

        int selected = 0xFF;
        int has_none = 0, has_passwd = 0;
        for (int i = 0; i < nmethods; i++) {
            uint8_t m = buffer[2+i];
            if (m == 0x00) has_none = 1;
            if (m == 0x02) has_passwd = 1;
        }
        if (auth_enabled) {
            if (has_passwd) selected = 0x02;
        } else {
            if (has_none) selected = 0x00;
        }
        uint8_t reply[2] = {0x05, selected};
        if (send(fd, (char*)reply, 2, 0) != 2) return -1;
        if (selected == 0xFF) return -1;

        if (methods) *methods = (1 << selected);
        int consumed = 2 + nmethods;
        if (selected == 0x00) {
            return consumed; // handshake done
        }
        // Переход ко второму этапу
        *auth_state = 1;
        return consumed;
    } else {
        // Второй этап: VER=1, ULEN, UNAME, PLEN, PASSWD
        if (n < 5) return 0;
        uint8_t ver = buffer[0];
        if (ver != 0x01) return -1;
        uint8_t ulen = buffer[1];
        if (n < 2 + ulen + 1) return 0;
        uint8_t plen = buffer[2 + ulen];
        if (n < 2 + ulen + 1 + plen) return 0;

        char user[256], pass[256];
        memcpy(user, buffer+2, ulen); user[ulen] = 0;
        memcpy(pass, buffer+2+ulen+1, plen); pass[plen] = 0;
        int ok = socks5_auth_check(user, pass);
        uint8_t resp[2] = {0x01, ok ? 0x00 : 0x01};
        if (send(fd, (char*)resp, 2, 0) != 2) return -1;
        if (!ok) return -1;
        *auth_state = 0;
        return 2 + ulen + 1 + plen;
    }
}
void socks5_auth_cleanup(void) {
    if (auth_entries) {
        for (int i = 0; i < auth_count; i++) {
            free(auth_entries[i].username);
            free(auth_entries[i].password);
        }
        free(auth_entries);
        auth_entries = NULL;
    }
    auth_count = 0;
    auth_enabled = 0;
}