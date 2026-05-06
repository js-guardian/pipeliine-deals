import os
import json
import math
import urllib.request
from functools import lru_cache

import jwt
import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import text

from conn_db import get_engine, read_table, insert_deal

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- AUTH ----------
_SUPABASE_URL        = "https://varkabkouznhupdisdcg.supabase.co"
_SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")
_bearer = HTTPBearer()

@lru_cache(maxsize=1)
def _get_jwks() -> dict:
    url = f"{_SUPABASE_URL}/auth/v1/.well-known/jwks.json"
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())

def require_auth(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    token = creds.credentials
    try:
        header = jwt.get_unverified_header(token)
        alg    = header.get("alg", "HS256")

        if alg.startswith("ES"):
            # Supabase new projects use ES256 with asymmetric keys via JWKS
            from jwt.algorithms import ECAlgorithm
            kid  = header.get("kid")
            jwks = _get_jwks()
            pub  = next(
                (k for k in jwks.get("keys", []) if k.get("kid") == kid),
                None,
            )
            if pub is None:
                raise ValueError(f"kid '{kid}' não encontrado no JWKS")
            public_key = ECAlgorithm.from_jwk(json.dumps(pub))
            return jwt.decode(token, public_key, algorithms=["ES256"], options={"verify_aud": False})
        else:
            # HS256 fallback para projetos antigos
            return jwt.decode(token, _SUPABASE_JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except HTTPException:
        raise
    except Exception as e:
        print(f"[AUTH ERROR] {type(e).__name__}: {e}")
        raise HTTPException(status_code=401, detail=f"Token inválido: {e}")


# ---------- HELPERS ----------
def _float(v):
    if v is None:
        return None
    try:
        f = float(v)
        return None if math.isnan(f) else f
    except (TypeError, ValueError):
        return None


def _bool(v):
    if v is None:
        return None
    return bool(v)


def row_to_deal(row: dict) -> dict:
    row = {k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in row.items()}
    updated_at = row.get("updated_at")
    created_at = row.get("created_at")
    return {
        "id": int(row["id"]),
        "produto": row.get("ativo"),
        "status": row.get("status"),
        "responsavel": row.get("responsavel"),
        "perfil_ativo": row.get("perfil_ativo"),
        "endereco": row.get("endereco"),
        "cidade": row.get("cidade"),
        "uf": row.get("uf"),
        "aluguel_mensal": _float(row.get("aluguel_mensal")),
        "ultimo_valor": _float(row.get("ultimo_valor_enviado")),
        "yield_ultima_proposta": _float(row.get("yield_ultima_proposta")),
        "area_locavel": _float(row.get("abl")),
        "estrategia": row.get("estrategia"),
        "veiculo_oferta": row.get("veiculo_oferta"),
        "perfil_vendedor": row.get("perfil_vendedor"),
        "broker_envolvido": _bool(row.get("broker_envolvido")),
        "nome_broker": row.get("nome_broker"),
        "principais_locatarios": row.get("principais_locatarios"),
        "proximos_passos": row.get("proximos_passos"),
        "historico_negociacoes": row.get("historico_negociacoes"),
        "created_at": created_at.isoformat() if created_at else None,
        "updated_at": updated_at.isoformat() if updated_at else None,
        "preco_pedido": None,
        "ocupacao": None,
    }


# ---------- ROUTES ----------
@app.get("/")
def serve_frontend():
    return FileResponse("front end/index.html")


@app.get("/api/deals")
def list_deals(_: dict = Depends(require_auth)):
    df = read_table("SELECT * FROM pipe_deals ORDER BY created_at DESC")
    return [row_to_deal(dict(row)) for _, row in df.iterrows()]


# ---------- PORTFOLIO ----------
def row_to_portfolio_item(row: dict) -> dict:
    row = {k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in row.items()}
    created_at = row.get("created_at")
    return {
        "id":         int(row["id"]),
        "deal_id":    int(row["deal_id"]),
        "perfil":     row.get("perfil"),
        "imovel":     row.get("imovel"),
        "aluguel":    _float(row.get("aluguel")),
        "endereco":   row.get("endereco"),
        "cidade":     row.get("cidade"),
        "uf":         row.get("uf"),
        "abl":        _float(row.get("abl")),
        "created_at": created_at.isoformat() if created_at else None,
    }


class PortfolioItemPayload(BaseModel):
    perfil:   Optional[str]   = None
    imovel:   Optional[str]   = None
    aluguel:  Optional[float] = None
    endereco: Optional[str]   = None
    cidade:   Optional[str]   = None
    uf:       Optional[str]   = None
    abl:      Optional[float] = None


# ---------- HISTORICO NEGOCIACOES ----------
def row_to_historico(row: dict) -> dict:
    row = {k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in row.items()}
    created_at = row.get("created_at")
    return {
        "id":              int(row["id"]),
        "deal_id":         int(row["deal_id"]) if row.get("deal_id") else None,
        "created_at":      created_at.isoformat() if created_at else None,
        "lado":            row.get("lado") or "GUARDIAN",
        "tipo":            row.get("tipo"),
        "valor_aquisicao": _float(row.get("valor_aquisicao")),
        "cap":             _float(row.get("cap")),
        "modo_pgto":       row.get("modo_pgto"),
        "entrada_pct":     _float(row.get("entrada_pct")),
        "parcelamento":    row.get("parcelamento"),
        "notas":           row.get("notas"),
    }


@app.get("/api/deals/{deal_id}/historico")
def list_historico(deal_id: int, _: dict = Depends(require_auth)):
    df = read_table(
        "SELECT * FROM historico_negociacoes WHERE deal_id = :deal_id ORDER BY created_at DESC",
        {"deal_id": deal_id},
    )
    return [row_to_historico(dict(row)) for _, row in df.iterrows()]


class HistoricoPayload(BaseModel):
    lado:            Optional[str]   = "GUARDIAN"
    tipo:            Optional[str]   = None
    valor_aquisicao: Optional[float] = None
    cap:             Optional[float] = None
    modo_pgto:       Optional[str]   = None
    entrada_pct:     Optional[float] = None
    parcelamento:    Optional[str]   = None
    notas:           Optional[str]   = None


@app.post("/api/deals/{deal_id}/historico", status_code=201)
def create_historico(deal_id: int, payload: HistoricoPayload, _: dict = Depends(require_auth)):
    sql = text("""
        INSERT INTO historico_negociacoes
            (deal_id, lado, tipo, valor_aquisicao, cap, modo_pgto, entrada_pct, parcelamento, notas)
        VALUES
            (:deal_id, :lado, :tipo, :valor_aquisicao, :cap, :modo_pgto, :entrada_pct, :parcelamento, :notas)
        RETURNING id
    """)
    with get_engine().begin() as conn:
        new_id = conn.execute(sql, {
            "deal_id": deal_id, "lado": payload.lado or "GUARDIAN", "tipo": payload.tipo,
            "valor_aquisicao": payload.valor_aquisicao, "cap": payload.cap,
            "modo_pgto": payload.modo_pgto, "entrada_pct": payload.entrada_pct,
            "parcelamento": payload.parcelamento, "notas": payload.notas,
        }).scalar_one()
    df = read_table("SELECT * FROM historico_negociacoes WHERE id = :id", {"id": new_id})
    return row_to_historico(dict(df.iloc[0]))


@app.put("/api/historico/{item_id}")
def update_historico(item_id: int, payload: HistoricoPayload, _: dict = Depends(require_auth)):
    sql = text("""
        UPDATE historico_negociacoes SET
            lado            = :lado,
            tipo            = :tipo,
            valor_aquisicao = :valor_aquisicao,
            cap             = :cap,
            modo_pgto       = :modo_pgto,
            entrada_pct     = :entrada_pct,
            parcelamento    = :parcelamento,
            notas           = :notas
        WHERE id = :id
    """)
    with get_engine().begin() as conn:
        result = conn.execute(sql, {
            "id": item_id, "lado": payload.lado or "GUARDIAN", "tipo": payload.tipo,
            "valor_aquisicao": payload.valor_aquisicao, "cap": payload.cap,
            "modo_pgto": payload.modo_pgto, "entrada_pct": payload.entrada_pct,
            "parcelamento": payload.parcelamento, "notas": payload.notas,
        })
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Histórico item not found")
    df = read_table("SELECT * FROM historico_negociacoes WHERE id = :id", {"id": item_id})
    return row_to_historico(dict(df.iloc[0]))


@app.delete("/api/historico/{item_id}", status_code=204)
def delete_historico(item_id: int, _: dict = Depends(require_auth)):
    sql = text("DELETE FROM historico_negociacoes WHERE id = :id")
    with get_engine().begin() as conn:
        result = conn.execute(sql, {"id": item_id})
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Histórico item not found")


# ---------- CONTRAPROPOSTAS ----------
def row_to_contraproposta(row: dict) -> dict:
    row = {k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in row.items()}
    created_at = row.get("created_at")
    return {
        "id":                                int(row["id"]),
        "offer_id":                          int(row["offer_id"]) if row.get("offer_id") else None,
        "created_at":                        created_at.isoformat() if created_at else None,
        "valor_contraproposta":              _float(row.get("valor_contraproposta")),
        "cap_contraproposta":                _float(row.get("cap_contraproposta")),
        "modo_pgto_contraproposta":          row.get("modo_pgto_contraproposta"),
        "entrada_percentual_contraproposta": _float(row.get("entrada_percentual_contraproposta")),
        "parcelamento_contraproposta":       row.get("parcelamento_contraproposta"),
        "notas_contraproposta":              row.get("notas_contraproposta"),
    }


@app.get("/api/deals/{deal_id}/contrapropostas")
def list_contrapropostas_by_deal(deal_id: int, _: dict = Depends(require_auth)):
    """Returns all contrapropostas for a deal, joined through historico_negociacoes."""
    df = read_table("""
        SELECT c.*
        FROM historico_contrapropostas c
        JOIN historico_negociacoes h ON h.id = c.offer_id
        WHERE h.deal_id = :deal_id
        ORDER BY c.created_at ASC
    """, {"deal_id": deal_id})
    return [row_to_contraproposta(dict(row)) for _, row in df.iterrows()]


@app.post("/api/historico/{offer_id}/contrapropostas", status_code=201)
def create_contraproposta(offer_id: int, payload: dict, _: dict = Depends(require_auth)):
    sql = text("""
        INSERT INTO historico_contrapropostas
            (offer_id, valor_contraproposta, cap_contraproposta, modo_pgto_contraproposta,
             entrada_percentual_contraproposta, parcelamento_contraproposta, notas_contraproposta)
        VALUES
            (:offer_id, :valor, :cap, :modo_pgto, :entrada_pct, :parcelamento, :notas)
        RETURNING id
    """)
    with get_engine().begin() as conn:
        new_id = conn.execute(sql, {
            "offer_id":      offer_id,
            "valor":         payload.get("valor_contraproposta"),
            "cap":           payload.get("cap_contraproposta"),
            "modo_pgto":     payload.get("modo_pgto_contraproposta"),
            "entrada_pct":   payload.get("entrada_percentual_contraproposta"),
            "parcelamento":  payload.get("parcelamento_contraproposta"),
            "notas":         payload.get("notas_contraproposta"),
        }).scalar_one()
    df = read_table("SELECT * FROM historico_contrapropostas WHERE id = :id", {"id": new_id})
    return row_to_contraproposta(dict(df.iloc[0]))


@app.put("/api/contrapropostas/{item_id}")
def update_contraproposta(item_id: int, payload: dict, _: dict = Depends(require_auth)):
    sql = text("""
        UPDATE historico_contrapropostas SET
            valor_contraproposta              = :valor,
            cap_contraproposta                = :cap,
            modo_pgto_contraproposta          = :modo_pgto,
            entrada_percentual_contraproposta = :entrada_pct,
            parcelamento_contraproposta       = :parcelamento,
            notas_contraproposta              = :notas
        WHERE id = :id
    """)
    with get_engine().begin() as conn:
        result = conn.execute(sql, {
            "id":           item_id,
            "valor":        payload.get("valor_contraproposta"),
            "cap":          payload.get("cap_contraproposta"),
            "modo_pgto":    payload.get("modo_pgto_contraproposta"),
            "entrada_pct":  payload.get("entrada_percentual_contraproposta"),
            "parcelamento": payload.get("parcelamento_contraproposta"),
            "notas":        payload.get("notas_contraproposta"),
        })
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Contraproposta not found")
    df = read_table("SELECT * FROM historico_contrapropostas WHERE id = :id", {"id": item_id})
    return row_to_contraproposta(dict(df.iloc[0]))


@app.delete("/api/contrapropostas/{item_id}", status_code=204)
def delete_contraproposta(item_id: int, _: dict = Depends(require_auth)):
    sql = text("DELETE FROM historico_contrapropostas WHERE id = :id")
    with get_engine().begin() as conn:
        result = conn.execute(sql, {"id": item_id})
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Contraproposta not found")


@app.get("/api/deals/{deal_id}/portfolio")
def list_portfolio(deal_id: int, _: dict = Depends(require_auth)):
    df = read_table(
        "SELECT * FROM portfolio WHERE deal_id = :deal_id ORDER BY created_at ASC",
        {"deal_id": deal_id},
    )
    return [row_to_portfolio_item(dict(row)) for _, row in df.iterrows()]


@app.post("/api/deals/{deal_id}/portfolio", status_code=201)
def create_portfolio_item(deal_id: int, payload: PortfolioItemPayload, _: dict = Depends(require_auth)):
    sql = text("""
        INSERT INTO portfolio (deal_id, perfil, imovel, aluguel, endereco, cidade, uf, abl)
        VALUES (:deal_id, :perfil, :imovel, :aluguel, :endereco, :cidade, :uf, :abl)
        RETURNING id
    """)
    with get_engine().begin() as conn:
        new_id = conn.execute(sql, {
            "deal_id":  deal_id,
            "perfil":   payload.perfil,
            "imovel":   payload.imovel,
            "aluguel":  payload.aluguel,
            "endereco": payload.endereco,
            "cidade":   payload.cidade,
            "uf":       payload.uf,
            "abl":      payload.abl,
        }).scalar_one()
    df = read_table("SELECT * FROM portfolio WHERE id = :id", {"id": new_id})
    return row_to_portfolio_item(dict(df.iloc[0]))


@app.put("/api/portfolio/{item_id}")
def update_portfolio_item(item_id: int, payload: PortfolioItemPayload, _: dict = Depends(require_auth)):
    sql = text("""
        UPDATE portfolio SET
            perfil   = :perfil,
            imovel   = :imovel,
            aluguel  = :aluguel,
            endereco = :endereco,
            cidade   = :cidade,
            uf       = :uf,
            abl      = :abl
        WHERE id = :id
    """)
    with get_engine().begin() as conn:
        result = conn.execute(sql, {
            "id":       item_id,
            "perfil":   payload.perfil,
            "imovel":   payload.imovel,
            "aluguel":  payload.aluguel,
            "endereco": payload.endereco,
            "cidade":   payload.cidade,
            "uf":       payload.uf,
            "abl":      payload.abl,
        })
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Portfolio item not found")
    df = read_table("SELECT * FROM portfolio WHERE id = :id", {"id": item_id})
    return row_to_portfolio_item(dict(df.iloc[0]))


@app.delete("/api/portfolio/{item_id}", status_code=204)
def delete_portfolio_item(item_id: int, _: dict = Depends(require_auth)):
    sql = text("DELETE FROM portfolio WHERE id = :id")
    with get_engine().begin() as conn:
        result = conn.execute(sql, {"id": item_id})
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Portfolio item not found")


class DealPayload(BaseModel):
    produto: Optional[str] = None
    status: Optional[str] = None
    responsavel: Optional[str] = None
    perfil_ativo: Optional[str] = None
    endereco: Optional[str] = None
    cidade: Optional[str] = None
    uf: Optional[str] = None
    aluguel_mensal: Optional[float] = None
    ultimo_valor: Optional[float] = None
    yield_ultima_proposta: Optional[float] = None
    area_locavel: Optional[float] = None
    estrategia: Optional[str] = None
    veiculo_oferta: Optional[str] = None
    perfil_vendedor: Optional[str] = None
    broker_envolvido: Optional[bool] = None
    nome_broker: Optional[str] = None
    principais_locatarios: Optional[str] = None
    proximos_passos: Optional[str] = None
    historico_negociacoes: Optional[str] = None


@app.post("/api/deals", status_code=201)
def create_deal(payload: DealPayload, _: dict = Depends(require_auth)):
    new_id = insert_deal(
        user_id=1,
        ativo=payload.produto,
        status=payload.status,
        responsavel=payload.responsavel,
        perfil_ativo=payload.perfil_ativo,
        endereco=payload.endereco,
        aluguel_mensal=payload.aluguel_mensal,
        ultimo_valor_enviado=payload.ultimo_valor,
        yield_ultima_proposta=payload.yield_ultima_proposta,
        abl=payload.area_locavel,
        estrategia=payload.estrategia,
        veiculo_oferta=payload.veiculo_oferta,
        perfil_vendedor=payload.perfil_vendedor,
        broker_envolvido=payload.broker_envolvido,
        nome_broker=payload.nome_broker,
        principais_locatarios=payload.principais_locatarios,
        proximos_passos=payload.proximos_passos,
        historico_negociacoes=payload.historico_negociacoes,
    )
    df = read_table("SELECT * FROM pipe_deals WHERE id = :id", {"id": new_id})
    return row_to_deal(dict(df.iloc[0]))


@app.put("/api/deals/{deal_id}")
def edit_deal(deal_id: int, payload: DealPayload, _: dict = Depends(require_auth)):
    sql = text("""
        UPDATE pipe_deals SET
            ativo                 = :ativo,
            status                = :status,
            responsavel           = :responsavel,
            perfil_ativo          = :perfil_ativo,
            endereco              = :endereco,
            cidade                = :cidade,
            uf                    = :uf,
            aluguel_mensal        = :aluguel_mensal,
            ultimo_valor_enviado  = :ultimo_valor_enviado,
            yield_ultima_proposta = :yield_ultima_proposta,
            abl                   = :abl,
            estrategia            = :estrategia,
            veiculo_oferta        = :veiculo_oferta,
            perfil_vendedor       = :perfil_vendedor,
            broker_envolvido      = :broker_envolvido,
            nome_broker           = :nome_broker,
            principais_locatarios = :principais_locatarios,
            proximos_passos       = :proximos_passos,
            historico_negociacoes = :historico_negociacoes,
            updated_at            = now()
        WHERE id = :id
    """)
    with get_engine().begin() as conn:
        result = conn.execute(sql, {
            "id": deal_id,
            "ativo": payload.produto,
            "status": payload.status,
            "responsavel": payload.responsavel,
            "perfil_ativo": payload.perfil_ativo,
            "endereco": payload.endereco,
            "cidade": payload.cidade,
            "uf": payload.uf,
            "aluguel_mensal": payload.aluguel_mensal,
            "ultimo_valor_enviado": payload.ultimo_valor,
            "yield_ultima_proposta": payload.yield_ultima_proposta,
            "abl": payload.area_locavel,
            "estrategia": payload.estrategia,
            "veiculo_oferta": payload.veiculo_oferta,
            "perfil_vendedor": payload.perfil_vendedor,
            "broker_envolvido": payload.broker_envolvido,
            "nome_broker": payload.nome_broker,
            "principais_locatarios": payload.principais_locatarios,
            "proximos_passos": payload.proximos_passos,
            "historico_negociacoes": payload.historico_negociacoes,
        })
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Deal not found")
    df = read_table("SELECT * FROM pipe_deals WHERE id = :id", {"id": deal_id})
    return row_to_deal(dict(df.iloc[0]))


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("api:app", host="0.0.0.0", port=port, reload=False)
