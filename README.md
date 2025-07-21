# marketplace-api

REST API для маркетплейса с авторизацией, JWT, лентой объявлений и фильтрацией.


## 🚀 Запуск

- Добавь путь `.env` файла (`marketplace-api/.env`)

#### Пример:
```env
env=local
secret_word="exampleword"

server:
  address: "localhost"
  port: "80"

POSTGRES_HOST=postgres-db
POSTGRES_PORT=5432
POSTGRES_USER=root
POSTGRES_PASSWORD=root
POSTGRES_DB=auth_db
postgres_db_pool_max_conns=20

sender_host="smtp.example.com"
sender_email="example@mail.com"
sender_password="password"
sender_port=587
```

#### Сам запуск производится из корня проекта:

```bash
docker compose -f marketplace-api/deployments/docker-compose up -d --build
```

---

## 📦 Функциональность

- ✅ Регистрация и авторизация пользователей (JWT + Refresh токены)
- ✅ Размещение объявлений (только авторизованные пользователи)
- ✅ Просмотр ленты объявлений с пагинацией, сортировкой и фильтрацией по цене
- ✅ Признак `isMine` у объявлений — автор ли текущий пользователь
- ✅ Одноразовые refresh токены, хранимые в БД
- ✅ Logout удаляет только текущую сессию
- ✅ Middleware авторизации (обязательный и необязательный)
- ✅ Валидация входных данных (JSON body и query)
- ✅ Логирование всех операций

---

## 🧪 Эндпоинты

### 🔐 Аутентификация

| Method | URL                     | Auth | Description                     |
|--------|--------------------------|------|---------------------------------|
| POST   | `/api/signup`            | 🔓   | Регистрация                    |
| POST   | `/api/login`             | 🔓   | Вход по логину и паролю        |
| POST   | `/api/logout`            | 🔒   | Выход с текущего устройства     |
| POST   | `/api/token/refresh`     | 🔓   | Обновить Access + Refresh токены |

> **Authorization:** передавать access-токен в заголовке:
>  
> `access_token: <access_token>`
> `refresh_token: <refresh_token>`

---

### 📢 Объявления
 
| Method | URL               | Auth | Description                      |
|--------|--------------------|------|----------------------------------|
| GET    | `/api/ads`         | 🔓   | Получить ленту объявлений        |
| POST   | `/api/ads/create`  | 🔒   | Создать объявление               |

---

### 📥 Пример запроса на создание объявления

```json
{
  "title": "Продам MacBook",
  "description": "Состояние отличное, 16 ГБ ОЗУ, SSD 512 ГБ",
  "image_url": "https://example.com/macbook.jpg",
  "price": 115000
}

```

### Технологический стек
  
- Go — язык программирования
- Gin — HTTP-фреймворк
- PGX — PostgreSQL-драйвер
- PostgreSQL — база данных
- JWT — авторизация (access + refresh)
- Docker / Docker Compose — для сборки и запуска
- bcrypt — хеширование refresh токенов
- slog — логирование
  
### 📌 Примечания 

- Refresh токены хранятся в таблице refresh_tokens, связаны с user_id.
- Токены одноразовые — при рефреше старый удаляется и создаётся новый.
- Access токены короткоживущие, не сохраняются.
- Logout удаляет только токены текущей сессии, остальные остаются активны.
- Объявления доступны неавторизованным, но без isMine в ответе.
- Middleware ValidateTokenOptional безопасно пропускает запросы без токена, использовался для определения, что пользователь авторизирован или нет при просмотре объявлений
