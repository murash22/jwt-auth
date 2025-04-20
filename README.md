
## Запуск
Заполинте `.env` файл. Затем выполните `docker-compose up`


### Пример .env файла
```
# in minutes
JWT_ACCESS_TTL=30
# in hours
JWT_REFRESH_TTL=720
COOKIES_TTL=${JWT_REFRESH_TTL}
JWT_SECRET=qwfsnkk32tusxnksgjo13sf

SERVER_OUTER_PORT=8080
SERVER_HOSTNAME=app_host.com
SERVER_INNER_PORT=8080

DB_HOST=db_host
DB_USER=bob
DB_PASSWORD=1234
DB_NAME=auth_db
DB_URL=postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:5432/${DB_NAME}
DB_PORT=5432

GOOSE_DRIVER=postgres
GOOSE_DBSTRING=postgresql://bob:1234@db_host:5432/auth_db
GOOSE_MIGRATION_DIR=./migrations

POSTGRES_PASSWORD=1234
POSTGRES_USER=bob
POSTGRES_DB=auth_db
```

### ТЗ
Ссылка: https://medods.yonote.ru/share/a74f6d8d-1489-4b54-bd82-81af5bf50a03/doc/test-task-backdev-sCBrYs5n6e

Тесты написаны только для handler-ов пока что.

### Объяснение решения:
Формат refresh-токена - JWT. Структура такая же как и у access, но только
с большим временем жизни. В бд храню refresh-token как (столбцы):
- user_id - guid пользователя которому этот токен принадлежит. 
Если придет запрос на /auth/access до истечения срока старого
токена, мы удаляем старый токен по user_id (инвалидируем) и создаем новый.
- token_hash - bcrypt-хеш от подписи refresh токена. Вроде можно было бы и просто
подпись хранить, но по заданию сказано хранить в виде bcrypt-хеша. Хотел хранить 
bcrypt хеш от payload, но оказалось что bcrypt-хеш на вход принимает только
текст длиной <72 байта. Так что при увеличении тела payload (добавлении новых полей),
пришлось бы переделывать. А длина подписи фиксированная.
- created at - дата создания токена. Просто так добавил. Если в будущем понадобится как-то
время от времени очищать старые токены, то этот столбец может помочь.


Был еще вариант сделать тип refresh токена как случайную строку (так как в задании указано тип произвольный).
В таком случае пришлось бы хранить владельца и срок жизни токена в бд (это дополнительный запрос в бд
чтобы валидировать токен). Хотя по заданию нужно хранить 
только bcrypt хеш. Возможно я где-то не так понял.