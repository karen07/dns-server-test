# DNS server test

DNS server test is a small cache-backed UDP DNS server for reproducible DNS experiments.

It loads responses previously recorded by `dns-client-test` and replies directly from that cache instead of using an upstream resolver. The cache file can be selected explicitly, which makes separate `A` and `HTTPS` replay datasets easy to use.

## Описание

DNS server test - небольшой UDP DNS сервер для воспроизводимых DNS-экспериментов.

Вместо рекурсивного разрешения имен сервер загружает cache-файл, созданный `dns-client-test`, индексирует сохраненные ответы по домену и возвращает соответствующий DNS-пакет клиенту.

Один запуск сервера использует один cache-файл. Это намеренно оставляет реализацию простой: для `A` и `HTTPS` используются отдельные cache-файлы, поэтому серверу не требуется общий индекс `(domain, QTYPE)`.

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

## Подготовка cache-файла

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
