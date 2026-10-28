# DNS Server Test

A cache-backed UDP DNS server for reproducible experiments. It replays responses captured
by `dns-client-test` without querying an upstream DNS resolver.

Тестовый UDP DNS-сервер для воспроизводимых экспериментов. Воспроизводит ответы из кеша,
записанного `dns-client-test`, без обращения к вышестоящему DNS-резолверу.

## Описание

Вместо рекурсивного разрешения имен сервер загружает cache-файл, созданный `dns-client-test`, индексирует сохраненные ответы по домену и возвращает соответствующий DNS-пакет клиенту.

Один запуск сервера использует один cache-файл. Это намеренно оставляет реализацию простой: для `A` и `HTTPS` используются отдельные cache-файлы, поэтому серверу не требуется общий индекс `(domain, QTYPE)`.

## Содержание

- [Разработка и проверка изменений](#%D1%80%D0%B0%D0%B7%D1%80%D0%B0%D0%B1%D0%BE%D1%82%D0%BA%D0%B0-%D0%B8-%D0%BF%D1%80%D0%BE%D0%B2%D0%B5%D1%80%D0%BA%D0%B0-%D0%B8%D0%B7%D0%BC%D0%B5%D0%BD%D0%B5%D0%BD%D0%B8%D0%B9)
- [Сборка](#%D1%81%D0%B1%D0%BE%D1%80%D0%BA%D0%B0)
- [Использование](#%D0%B8%D1%81%D0%BF%D0%BE%D0%BB%D1%8C%D0%B7%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B5)
  - [Подготовка cache-файла](#%D0%BF%D0%BE%D0%B4%D0%B3%D0%BE%D1%82%D0%BE%D0%B2%D0%BA%D0%B0-cache-%D1%84%D0%B0%D0%B9%D0%BB%D0%B0)
- [Почему сервер не хранит A и HTTPS одновременно](#%D0%BF%D0%BE%D1%87%D0%B5%D0%BC%D1%83-%D1%81%D0%B5%D1%80%D0%B2%D0%B5%D1%80-%D0%BD%D0%B5-%D1%85%D1%80%D0%B0%D0%BD%D0%B8%D1%82-a-%D0%B8-https-%D0%BE%D0%B4%D0%BD%D0%BE%D0%B2%D1%80%D0%B5%D0%BC%D0%B5%D0%BD%D0%BD%D0%BE)
- [Лицензия](#%D0%BB%D0%B8%D1%86%D0%B5%D0%BD%D0%B7%D0%B8%D1%8F)

## Разработка и проверка изменений

**Основные точки изменения:**

- `src/dns_server_test.c` - загрузка кеша и формирование DNS-ответов по полученным запросам;
- `include/dns_server_test.h` - объявления и настройки сервера;
- `CMakeLists.txt` - сборка и интеграция зависимости `hashmap`.

**Проверка изменений:** Формат кеша согласован с выходом `dns-client-test`; изменение формата требует проверки обоих проектов. При правке логики ответов соблюдайте описанное выше ограничение на одновременное хранение A и HTTPS, затем повторите сборку и тестовый запрос.

## Сборка

```sh
git submodule update --init --recursive
cmake --preset release
cmake --build --preset release
```

Исполняемый файл:

```text
build/release/dns-server-test
```

## Использование

```text
Required:
  -l IPv4:port       Адрес прослушивания

Optional:
  -c path            Путь к cache-файлу, по умолчанию cache.data
```

Старый вариант остается рабочим:

```sh
./build/release/dns-server-test -l 127.0.0.1:5353
```

В этом случае сервер читает `./cache.data`.

Для нового `A` cache:

```sh
./build/release/dns-server-test \
    -l 127.0.0.1:5353 \
    -c cache-A.data
```

Для `HTTPS` cache:

```sh
./build/release/dns-server-test \
    -l 127.0.0.1:5353 \
    -c cache-HTTPS.data
```

### Подготовка cache-файла

Например, `A` dataset можно собрать так:

```sh
dns-client-test \
    -f domains.txt \
    -d 1.1.1.1:53 \
    -r 300 \
    -A \
    --save
```

Будет создан:

```text
cache-A.data
```

Для `HTTPS`:

```sh
dns-client-test \
    -f domains.txt \
    -d 1.1.1.1:53 \
    -r 300 \
    -H \
    --save
```

Будет создан:

```text
cache-HTTPS.data
```

Бинарный формат cache-файла не изменен по сравнению с исходным `cache.data`.

## Почему сервер не хранит A и HTTPS одновременно

Клиент намеренно создает отдельные datasets:

```text
cache-A.data
cache-HTTPS.data
```

Поэтому серверу достаточно старой простой модели:

```text
domain -> saved DNS response
```

Для replay нужно запускать сервер с cache-файлом того же типа, который затем запрашивает клиент. Например, `cache-HTTPS.data` используется вместе с клиентом в режиме `-H`.

## Лицензия

Проект распространяется под лицензией GNU Affero General Public License v3.0. Подробности см. в файле [LICENSE](LICENSE).
