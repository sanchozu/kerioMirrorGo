# Kerio Mirror Go v0.5.1: подпись дистрибутивов зеркалом

Версия 0.5.1 добавляет механизм загрузки дистрибутива Kerio Control и создания внешней detached-подписи зеркала. Содержимое `.img` не изменяется: сервер потоково сохраняет файл, одновременно вычисляет SHA-256 и подписывает хеш RSA-ключом администратора.

Эта подпись подтверждает, что конкретный файл был опубликован вашим экземпляром Kerio Mirror Go. Она не заменяет внутренние или официальные подписи GFI/Kerio.

## Подготовка ключей

Приватный ключ не должен находиться в Git. Файлы `*.pem` уже исключены через `.gitignore`.

```bash
mkdir -p certs
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out certs/key.pem
openssl rsa -in certs/key.pem -pubout -out certs/public.pem
chmod 600 certs/key.pem
```

Поддерживаются RSA-ключи PEM в форматах PKCS#1 и PKCS#8.

## Переменные окружения

```bash
KERIO_DISTRO_SIGNING_KEY=certs/key.pem
KERIO_DISTRO_MAX_UPLOAD_BYTES=2147483648
KERIO_DISTRO_ENABLED=true
KERIO_DISTRO_FILE=kerio-control-upgrade-9.5.0-9017.img
KERIO_DISTRO_VERSION=9.5.0-9017
```

- `KERIO_DISTRO_SIGNING_KEY` — путь к приватному RSA-ключу; значение по умолчанию `certs/key.pem`.
- `KERIO_DISTRO_MAX_UPLOAD_BYTES` — максимальный размер загрузки; по умолчанию 2 ГиБ.
- остальные параметры управляют уже существующим механизмом предложения локального дистрибутива клиентам Kerio Control.

## Загрузка и подпись

Endpoint требует действующую административную сессию Kerio Mirror Go:

```text
POST /api/kerio/updates/distro/upload
Content-Type: multipart/form-data
field: distro_file
```

Поддерживается также имя поля `file`. Имя файла должно соответствовать формату:

```text
kerio-control-upgrade-<version>.img
```

После успешной загрузки в `mirror/distros` атомарно публикуется пара:

```text
kerio-control-upgrade-9.5.0-9017.img
kerio-control-upgrade-9.5.0-9017.img.sig
```

Ответ содержит имя файла, имя подписи, SHA-256 и размер:

```json
{
  "file": "kerio-control-upgrade-9.5.0-9017.img",
  "signature": "kerio-control-upgrade-9.5.0-9017.img.sig",
  "sha256": "...",
  "size": 123456789
}
```

Список готовых пар доступен администратору:

```text
GET /api/kerio/updates/distro/list
```

Сами `.img` и `.sig` раздаются существующим публичным endpoint:

```text
GET /api/kerio/updates/distro/files/<filename>
```

## Проверка подписи

```bash
openssl dgst -sha256 \
  -verify certs/public.pem \
  -signature mirror/distros/kerio-control-upgrade-9.5.0-9017.img.sig \
  mirror/distros/kerio-control-upgrade-9.5.0-9017.img
```

Ожидаемый результат:

```text
Verified OK
```

## Надёжность публикации

- файл читается потоково и не загружается целиком в память;
- размер ограничивается до записи;
- `.img` сохраняется без изменения байтов;
- подпись создаётся как RSA PKCS#1 v1.5 над SHA-256;
- временные файлы синхронизируются на диск;
- существующая пара резервируется и восстанавливается при ошибке публикации;
- административная загрузка защищена существующей cookie-сессией;
- список содержит только `.img`, для которых присутствует соответствующий `.img.sig`.
