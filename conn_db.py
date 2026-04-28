import os
from typing import Optional
from urllib.parse import quote_plus

import pandas as pd
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

load_dotenv()

os.environ.setdefault("PYTHONUTF8", "1")

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    host = os.getenv("DB_HOST", "db.varkabkouznhupdisdcg.supabase.co")
    port = os.getenv("DB_PORT", "5432")
    name = os.getenv("DB_NAME", "postgres")
    user = os.getenv("DB_USER", "postgres")
    password = os.getenv("DB_PASSWORD")
    if not password:
        raise RuntimeError("DB_PASSWORD is not set. Set it in environment variables before importing this module.")
    DATABASE_URL = f"postgresql+psycopg2://{user}:{quote_plus(password)}@{host}:{port}/{name}"
else:
    if "postgresql://" in DATABASE_URL and "+psycopg2" not in DATABASE_URL:
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://")

_engine: Optional[Engine] = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = create_engine(
            DATABASE_URL,
            connect_args={"sslmode": "require"},
            pool_size=5,
            max_overflow=0,
        )
    return _engine


def read_table(query: str, params: Optional[dict] = None) -> pd.DataFrame:
    """Execute a SELECT query and return results as a DataFrame.

    Args:
        query: SQL SELECT query. Use :param_name placeholders for parameters.
        params: Optional dict of query parameters.

    Returns:
        pd.DataFrame with the query results.

    Raises:
        ValueError: If query is not a SELECT statement.
        RuntimeError: If connection fails.
    """
    if not query.strip().upper().startswith("SELECT"):
        raise ValueError("Only SELECT queries are allowed in read_table.")

    try:
        with get_engine().connect() as conn:
            return pd.read_sql_query(text(query), conn, params=params)
    except Exception as e:
        raise RuntimeError(f"Failed to read from database: {e}") from e


def insert_deal(
    user_id: int,
    ativo: Optional[str] = None,
    status: Optional[str] = None,
    last_update: Optional[str] = None,
    next_steps: Optional[str] = None,
    responsavel: Optional[str] = None,
    perfil_ativo: Optional[str] = None,
    endereco: Optional[str] = None,
    cidade: Optional[str] = None,
    uf: Optional[str] = None,
    aluguel_mensal: Optional[float] = None,
    ultimo_valor_enviado: Optional[float] = None,
    yield_ultima_proposta: Optional[float] = None,
    abl: Optional[float] = None,
    estrategia: Optional[str] = None,
    veiculo_oferta: Optional[str] = None,
    perfil_vendedor: Optional[str] = None,
    broker_envolvido: Optional[bool] = None,
    nome_broker: Optional[str] = None,
    principais_locatarios: Optional[str] = None,
    proximos_passos: Optional[str] = None,
    historico_negociacoes: Optional[str] = None,
) -> int:
    """Insert a new deal into pipe_deals and return the generated id.

    Args:
        user_id: Required. ID of the user creating the deal.
        All other fields are optional and default to NULL.

    Returns:
        The id of the newly inserted row.

    Raises:
        RuntimeError: If the insert fails.
    """
    params = {
        "user_id": user_id,
        "ativo": ativo,
        "status": status,
        "last_update": last_update,
        "next_steps": next_steps,
        "responsavel": responsavel,
        "perfil_ativo": perfil_ativo,
        "endereco": endereco,
        "cidade": cidade,
        "uf": uf,
        "aluguel_mensal": aluguel_mensal,
        "ultimo_valor_enviado": ultimo_valor_enviado,
        "yield_ultima_proposta": yield_ultima_proposta,
        "abl": abl,
        "estrategia": estrategia,
        "veiculo_oferta": veiculo_oferta,
        "perfil_vendedor": perfil_vendedor,
        "broker_envolvido": broker_envolvido,
        "nome_broker": nome_broker,
        "principais_locatarios": principais_locatarios,
        "proximos_passos": proximos_passos,
        "historico_negociacoes": historico_negociacoes,
    }

    sql = text("""
        INSERT INTO pipe_deals (
            user_id, ativo, status, last_update, next_steps, responsavel,
            perfil_ativo, endereco, cidade, uf, aluguel_mensal,
            ultimo_valor_enviado, yield_ultima_proposta, abl, estrategia,
            veiculo_oferta, perfil_vendedor, broker_envolvido, nome_broker,
            principais_locatarios, proximos_passos, historico_negociacoes
        ) VALUES (
            :user_id, :ativo, :status, :last_update, :next_steps, :responsavel,
            :perfil_ativo, :endereco, :cidade, :uf, :aluguel_mensal,
            :ultimo_valor_enviado, :yield_ultima_proposta, :abl, :estrategia,
            :veiculo_oferta, :perfil_vendedor, :broker_envolvido, :nome_broker,
            :principais_locatarios, :proximos_passos, :historico_negociacoes
        )
        RETURNING id
    """)

    try:
        with get_engine().begin() as conn:
            result = conn.execute(sql, params)
            return result.scalar_one()
    except Exception as e:
        raise RuntimeError(f"Failed to insert deal: {e}") from e


def update_deal(
    id: int,
    ativo: Optional[str] = None,
    status: Optional[str] = None,
    last_update: Optional[str] = None,
    next_steps: Optional[str] = None,
    responsavel: Optional[str] = None,
    perfil_ativo: Optional[str] = None,
    endereco: Optional[str] = None,
    cidade: Optional[str] = None,
    uf: Optional[str] = None,
    aluguel_mensal: Optional[float] = None,
    ultimo_valor_enviado: Optional[float] = None,
    yield_ultima_proposta: Optional[float] = None,
    abl: Optional[float] = None,
    estrategia: Optional[str] = None,
    veiculo_oferta: Optional[str] = None,
    perfil_vendedor: Optional[str] = None,
    broker_envolvido: Optional[bool] = None,
    nome_broker: Optional[str] = None,
    principais_locatarios: Optional[str] = None,
    proximos_passos: Optional[str] = None,
    historico_negociacoes: Optional[str] = None,
) -> bool:
    """Update fields of an existing deal. Only provided (non-None) fields are updated.

    Args:
        id: Required. ID of the deal to update.
        All other fields are optional — only passed fields will be changed.

    Returns:
        True if a row was updated, False if id was not found.

    Raises:
        ValueError: If no fields are provided to update.
        RuntimeError: If the update fails.
    """
    fields = {
        "ativo": ativo,
        "status": status,
        "last_update": last_update,
        "next_steps": next_steps,
        "responsavel": responsavel,
        "perfil_ativo": perfil_ativo,
        "endereco": endereco,
        "cidade": cidade,
        "uf": uf,
        "aluguel_mensal": aluguel_mensal,
        "ultimo_valor_enviado": ultimo_valor_enviado,
        "yield_ultima_proposta": yield_ultima_proposta,
        "abl": abl,
        "estrategia": estrategia,
        "veiculo_oferta": veiculo_oferta,
        "perfil_vendedor": perfil_vendedor,
        "broker_envolvido": broker_envolvido,
        "nome_broker": nome_broker,
        "principais_locatarios": principais_locatarios,
        "proximos_passos": proximos_passos,
        "historico_negociacoes": historico_negociacoes,
    }

    to_update = {k: v for k, v in fields.items() if v is not None}

    if not to_update:
        raise ValueError("At least one field must be provided to update.")

    set_clause = ", ".join(f"{col} = :{col}" for col in to_update)
    to_update["id"] = id

    sql = text(f"UPDATE pipe_deals SET {set_clause}, updated_at = now() WHERE id = :id")

    try:
        with get_engine().begin() as conn:
            result = conn.execute(sql, to_update)
            return result.rowcount > 0
    except Exception as e:
        raise RuntimeError(f"Failed to update deal: {e}") from e


if __name__ == "__main__":
    df = read_table("SELECT * FROM pipe_deals")
    print(df.shape)
    print(df.tail())
