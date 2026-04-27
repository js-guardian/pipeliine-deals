import os
from typing import Optional

import psycopg2
from psycopg2 import pool

DATABASE_HOST = os.getenv("DB_HOST", "db.varkabkouznhupdisdcg.supabase.co")
DATABASE_PORT = int(os.getenv("DB_PORT", "5432"))
DATABASE_NAME = os.getenv("DB_NAME", "postgres")
DATABASE_USER = os.getenv("DB_USER", "postgres")
DATABASE_PASSWORD = os.getenv("DB_PASSWORD")
DATABASE_URL = os.getenv("DATABASE_URL") or (
    f"postgresql://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}"
)

_db_pool: Optional[pool.SimpleConnectionPool] = None


def init_db_pool(minconn: int = 1, maxconn: int = 5) -> pool.SimpleConnectionPool:
    """Initialize and return the global PostgreSQL connection pool."""
    global _db_pool
    if _db_pool is not None:
        return _db_pool

    if DATABASE_PASSWORD is None:
        raise RuntimeError("DB_PASSWORD is not set. Set it in environment variables before connecting.")

    _db_pool = pool.SimpleConnectionPool(minconn, maxconn, dsn=DATABASE_URL)
    return _db_pool


def get_connection() -> psycopg2.extensions.connection:
    """Get a connection from the pool."""
    if _db_pool is None:
        init_db_pool()

    conn = _db_pool.getconn()
    conn.autocommit = True
    return conn


def put_connection(conn: psycopg2.extensions.connection) -> None:
    """Return a connection to the pool."""
    if _db_pool is not None and conn is not None:
        _db_pool.putconn(conn)


def close_db_pool() -> None:
    """Close all open connections in the pool."""
    if _db_pool is not None:
        _db_pool.closeall()


if __name__ == "__main__":
    init_db_pool()
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT version();")
            print(cursor.fetchone())
    finally:
        put_connection(conn)
        close_db_pool()
