# auth-service
## Requirements
### Docker
### Docker Compose
## .env config example:
```
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
