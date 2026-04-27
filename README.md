# pipeliine-deals

Dashboard de acompanhamento de deals

## Database connection

The repository uses Supabase PostgreSQL for database connectivity.

### Environment variables

Create a `.env` file from `.env.example` and set the database password:

```env
DB_HOST=db.varkabkouznhupdisdcg.supabase.co
DB_PORT=5432
DB_NAME=postgres
DB_USER=postgres
DB_PASSWORD=your_database_password_here
```

### Connection string

Use the following format if you need the raw connection URL:

```text
postgresql://postgres:[YOUR-PASSWORD]@db.varkabkouznhupdisdcg.supabase.co:5432/postgres
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Usage

The `conn_db.py` helper initializes a connection pool and exposes functions for getting and returning connections.

```python
from conn_db import init_db_pool, get_connection, put_connection, close_db_pool

init_db_pool()
conn = get_connection()
try:
    with conn.cursor() as cursor:
        cursor.execute('SELECT version();')
        print(cursor.fetchone())
finally:
    put_connection(conn)
    close_db_pool()
```
