# DNS server test

DNS server test is a cache-backed UDP DNS server for repeatable resolver and network experiments.

Instead of resolving names recursively, it loads `cache.data` recorded by the companion `dns-client-test` program and serves the stored response for each known domain. This makes it possible to replay a previously collected DNS dataset without depending on upstream DNS servers.

The implementation uses the local `hashmap` submodule to index cached domains and is intentionally small: one input cache file, one listen address, and direct UDP DNS replies.

## Описание

DNS server test - небольшой UDP DNS сервер, который отвечает данными из локального кеша и предназначен для воспроизводимых экспериментов с DNS и сетью.

Вместо рекурсивного разрешения имен он загружает `cache.data`, записанный связанной программой `dns-client-test`, и возвращает сохраненный ответ для каждого известного домена. Это позволяет повторно воспроизводить ранее собранный набор DNS данных без зависимости от внешних DNS серверов.

Реализация использует локальный подмодуль `hashmap` для индексации доменов из кеша и намеренно остается простой: один входной файл кеша, один адрес прослушивания и прямые ответы по UDP.

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

## Подготовка `cache.data`

Сначала запустите `dns-client-test` с `--save`:

```sh
dns-client-test -f domains.txt -d 1.1.1.1:53 -r 1000 --save
```

Полученный `cache.data` должен находиться в текущем рабочем каталоге `dns-server-test`.

## Запуск

```text
Commands:
  Required parameters:
    -l  "x.x.x.x:xx"  Listen address
```

Например:

```sh
./build/release/dns-server-test -l 0.0.0.0:5353
```

Сервер принимает UDP DNS-запросы и для известных доменов возвращает сохраненный пакет из cache-файла.
