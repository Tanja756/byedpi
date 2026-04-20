// socks5_auth.h
#ifndef SOCKS5_AUTH_H
#define SOCKS5_AUTH_H

#include <stdbool.h>
#include <unistd.h>

// SOCKS5 authentication constants
#define SOCKS5_VER          0x05
#define SOCKS5_AUTH_NONE    0x00
#define SOCKS5_AUTH_PASSWD  0x02
#define SOCKS5_AUTH_NO_ACCEPTABLE 0xFF
#define SOCKS5_USERPASS_VER 0x01

// Инициализация модуля аутентификации.
// authfile - путь к файлу с учетными данными (формат "user:pass" построчно),
//            или NULL, если аутентификация не требуется.
// single_auth - строка вида "user:pass" для одного пользователя (переопределяет файл).
// Возвращает 0 при успехе, -1 при ошибке.
int socks5_auth_init(const char *authfile, const char *single_auth);

// Проверка пары логин/пароль.
// Возвращает 1, если учетные данные верны, 0 - иначе.
int socks5_auth_check(const char *username, const char *password);

// Обработка handshake аутентификации SOCKS5.
// fd - сокет клиента.
// buffer - данные, уже прочитанные (содержат начальный запрос с методами).
// n - размер данных в buffer.
// methods - выходной параметр: поддерживаемые методы (битовая маска).
// Возвращает:
//   >0 - количество байт, потреблённых из buffer (handshake завершён успешно),
//   0  - требуется больше данных (неполный запрос),
//   -1 - ошибка аутентификации или протокола.
int socks5_auth_handshake(int fd, const char *buffer, ssize_t n, unsigned int *methods, int *auth_state);

// Очистка ресурсов модуля (вызывается при завершении).
void socks5_auth_cleanup(void);

#endif // SOCKS5_AUTH_H