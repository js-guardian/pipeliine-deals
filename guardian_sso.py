"""Guardian SSO — gate de acesso dos dashboards.

Um dashboard protegido por este módulo NÃO tem login próprio. A única maneira
de abrir sessão nele é apresentar um ticket assinado pelo Guardian HUB. Quem
digita o URL direto não é barrado com uma porta na cara: é mandado ao HUB, que
decide. Tem permissão, volta e entra; não tem, para por lá.

Instalação:  pip install "pyjwt[crypto]>=2.8"

Dash:
    app = Dash(__name__)
    proteger_flask(app.server, slug="aum")

Flask:
    proteger_flask(app, slug="pipeline")

FastAPI:
    proteger_fastapi(app, slug="emissoes")

Hoje cada serviço atende a um card só, e basta o `slug`. Se um dia um mesmo
serviço passar a atender dois cards, use `cards_por_caminho` para dizer qual
trecho do endereço pertence a qual — senão entrar por um abriria o outro:
    proteger_flask(app, slug="passivo",
                   cards_por_caminho={"/outro-painel": "outro-card"})

Ambiente (todas obrigatórias, exceto onde indicado):
    GUARDIAN_HUB_URL       https://hub.guardian-asset.com
    GUARDIAN_SSO_PUBKEY    chave pública ES256/P-256 (PEM ou o base64 do PEM)
    GUARDIAN_SESSION_KEY   segredo do cookie DESTE dashboard (um por dashboard)
    GUARDIAN_SESSAO_HORAS  teto da sessão local; default 8

Depois de proteger, o usuário autenticado fica em:
    Flask/Dash → flask.g.guardian_user
    FastAPI    → request.state.guardian_user
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlencode, urlsplit

import jwt

PARAM_TICKET = "ticket"
COOKIE = "guardian_sess"
EMISSOR = "guardian-hub"
_TOLERANCIA_RELOGIO = 10  # segundos de folga para dessincronia entre servidores


# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------
def _env(nome: str, default: str | None = None) -> str:
    valor = os.environ.get(nome, default)
    if valor is None:
        raise RuntimeError(
            f"Guardian SSO: variável de ambiente {nome} não definida. "
            f"Sem ela o dashboard subiria SEM proteção — abortando."
        )
    return valor


def _pem(valor: str) -> bytes:
    """Aceita o PEM cru ou o base64 de uma linha (mais prático em env var)."""
    valor = valor.strip()
    if valor.startswith("-----"):
        return valor.encode()
    return base64.b64decode(valor)


def _hub_url() -> str:
    # Aceita o endereco sem "https://" na frente: e o esquecimento mais
    # comum ao cadastrar a variavel, e o erro resultante fala de
    # redirect_uri invalido sem nunca mencionar o esquema ausente.
    valor = _env("GUARDIAN_HUB_URL").strip().rstrip("/")
    if not valor.startswith(("http://", "https://")):
        valor = "https://" + valor
    return valor


def _chave_sessao() -> bytes:
    return _env("GUARDIAN_SESSION_KEY").encode()


def _teto_sessao() -> int:
    return int(os.environ.get("GUARDIAN_SESSAO_HORAS", "8")) * 3600


# --------------------------------------------------------------------------
# Ticket: validação e proteção contra reuso
# --------------------------------------------------------------------------
class _JtisQueimados:
    """Cada ticket vale uma única vez.

    Guarda em memória porque o ticket vive 60 s — não compensa ida ao banco.
    Se um dia o dashboard rodar em mais de uma instância, troque por Redis:
    com duas instâncias o mesmo ticket poderia ser usado uma vez em cada.
    """

    def __init__(self) -> None:
        self._vistos: dict[str, float] = {}
        self._lock = threading.Lock()

    def queimar(self, jti: str, exp: float) -> bool:
        agora = time.time()
        with self._lock:
            if len(self._vistos) > 5000:
                self._vistos = {k: v for k, v in self._vistos.items() if v > agora}
            if self._vistos.get(jti, 0) > agora:
                return False
            self._vistos[jti] = exp
            return True


_jtis = _JtisQueimados()


def validar_ticket(token: str, slugs: str | Sequence[str]) -> dict[str, Any]:
    """Confere assinatura, destinatário, validade e reuso. Levanta em caso de falha."""
    aceitos = [slugs] if isinstance(slugs, str) else list(slugs)
    claims = jwt.decode(
        token,
        _pem(_env("GUARDIAN_SSO_PUBKEY")),
        algorithms=["ES256"],          # lista fixa: nunca confie no "alg" do token
        audience=aceitos,              # ticket do AUM não abre o Pipeline
        issuer=EMISSOR,
        leeway=_TOLERANCIA_RELOGIO,
        options={"require": ["exp", "iat", "jti", "aud", "iss", "sub"]},
    )
    if not _jtis.queimar(claims["jti"], claims["exp"]):
        raise jwt.InvalidTokenError("ticket já utilizado")
    return claims


def _slug_do_caminho(path: str, padrao: str, mapa: Mapping[str, str]) -> str:
    """Qual card responde por este endereço.

    Serve ao caso de um mesmo serviço atender a mais de um card do HUB. Sem
    isso, quem entrasse com permissão de um card ganharia a sessão do serviço
    inteiro e alcançaria o outro — a separação entre os cards seria enfeite.
    """
    for prefixo, slug in mapa.items():
        limpo = "/" + prefixo.strip("/")
        if path == limpo or path.startswith(limpo + "/"):
            return slug
    return padrao


# --------------------------------------------------------------------------
# Sessão local do dashboard (cookie assinado, sem estado no servidor)
# --------------------------------------------------------------------------
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _assinar_sessao(claims: dict[str, Any]) -> str:
    aud = claims.get("aud")
    dados = {
        "sub": claims["sub"],
        "email": claims.get("email", ""),
        "nome": claims.get("nome", ""),
        "adm": bool(claims.get("adm")),
        # Para qual card esta sessão foi aberta. Conferido a cada requisição
        # quando um serviço atende a mais de um card.
        "slug": aud[0] if isinstance(aud, list) else aud,
        # Teto duro: o navegador pode ressuscitar o cookie de sessão ao restaurar
        # abas (Chrome/Edge com "continuar de onde parou"), então o prazo real
        # tem de estar aqui dentro, não só na ausência de Max-Age.
        "exp": int(time.time()) + _teto_sessao(),
    }
    corpo = _b64e(json.dumps(dados, separators=(",", ":")).encode())
    mac = hmac.new(_chave_sessao(), corpo.encode(), hashlib.sha256).digest()
    return f"{corpo}.{_b64e(mac)}"


def _ler_sessao(cookie: str | None) -> dict[str, Any] | None:
    if not cookie or "." not in cookie:
        return None
    corpo, _, mac = cookie.partition(".")
    esperado = hmac.new(_chave_sessao(), corpo.encode(), hashlib.sha256).digest()
    try:
        if not hmac.compare_digest(_b64d(mac), esperado):
            return None
        dados = json.loads(_b64d(corpo))
    except Exception:
        return None
    if dados.get("exp", 0) < time.time():
        return None
    return dados


# --------------------------------------------------------------------------
# Destinos
# --------------------------------------------------------------------------
def _destino_seguro(nxt: str | None) -> str:
    """Só caminho relativo. `next=https://site-do-atacante` seria open redirect."""
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return "/"
    partes = urlsplit(nxt)
    return partes.path + (f"?{partes.query}" if partes.query else "")


def _url_do_hub(slug: str, caminho: str) -> str:
    return f"{_hub_url()}/go/{slug}?" + urlencode({"next": _destino_seguro(caminho)})


def _e_chamada_de_fundo(path: str, accept: str, xhr: str) -> bool:
    """Callback do Dash e XHR não seguem 302 — devolva 401 e deixe o front recarregar."""
    return (
        path.startswith("/_dash-")
        or path.startswith("/api/")
        or xhr == "XMLHttpRequest"
        or ("application/json" in accept and "text/html" not in accept)
    )


_HTML_FALHA = (
    "<!doctype html><meta charset=utf-8><title>Acesso negado</title>"
    "<body style='font-family:system-ui;background:#131a20;color:#fff;"
    "display:grid;place-items:center;height:100vh;margin:0'>"
    "<div style='text-align:center'>"
    "<h1 style='font-weight:300;letter-spacing:.02em'>ACESSO NEGADO</h1>"
    "<p style='color:#bcc6cd'>Este painel só abre pelo Guardian HUB.</p>"
    "<p><a href='{hub}' style='color:#31b0cb'>Ir para o HUB</a></p>"
    "</div>"
)


# --------------------------------------------------------------------------
# Flask / Dash
# --------------------------------------------------------------------------
def proteger_flask(
    app,
    slug: str,
    rotas_livres: tuple[str, ...] = ("/healthz",),
    cards_por_caminho: Mapping[str, str] | None = None,
) -> None:
    """Tranca um app Flask ou Dash.

    `slug` é o card que este serviço representa. Se o MESMO serviço atende a
    mais de um card do HUB, use `cards_por_caminho` para dizer qual trecho do
    endereço pertence a qual card:

        proteger_flask(app, slug="passivo",
                       cards_por_caminho={"/outro-painel": "outro-card"})

    Sem esse mapa, quem entrasse com permissão de um card teria a sessão do
    serviço inteiro e alcançaria o outro.
    """
    from flask import g, make_response, redirect, request

    mapa = dict(cards_por_caminho or {})
    aceitos = [slug, *mapa.values()]

    # Falha no boot, não no primeiro acesso: dashboard mal configurado não sobe.
    _env("GUARDIAN_SSO_PUBKEY")
    _chave_sessao()
    _hub_url()

    @app.before_request
    def _gate():
        if request.path in rotas_livres:
            return None

        exigido = _slug_do_caminho(request.path, slug, mapa)

        ticket = request.args.get(PARAM_TICKET)
        if ticket:
            try:
                claims = validar_ticket(ticket, aceitos)
            except Exception:
                # NÃO devolver ao HUB aqui: se a chave ou o relógio estiverem
                # errados, o par de redirects vira laço infinito.
                resp = make_response(_HTML_FALHA.format(hub=_hub_url()), 403)
                resp.set_cookie(COOKIE, "", expires=0, path="/")
                return resp
            # Redireciona para o endereço limpo: o ticket não fica no histórico.
            resp = make_response(redirect(_destino_seguro(claims.get("nxt"))))
            resp.set_cookie(
                COOKIE,
                _assinar_sessao(claims),
                max_age=None,      # cookie de sessão: cai ao fechar a aba
                httponly=True,     # JavaScript não enxerga
                secure=True,       # só HTTPS
                samesite="Lax",    # sobrevive ao redirect do HUB, barra POST de fora
                path="/",
            )
            return resp

        sessao = _ler_sessao(request.cookies.get(COOKIE))
        # A sessão vale para o card com que ela foi aberta. Entrar pelo Passivo
        # não dá passagem ao Fundos–Imob quando os dois moram no mesmo serviço.
        if sessao and (not mapa or sessao.get("slug") == exigido):
            g.guardian_user = sessao
            return None

        if _e_chamada_de_fundo(
            request.path,
            request.headers.get("Accept", ""),
            request.headers.get("X-Requested-With", ""),
        ):
            return {"erro": "sessao_expirada", "hub": _url_do_hub(exigido, "/")}, 401
        if request.method != "GET":
            return {"erro": "sessao_expirada"}, 401
        return redirect(_url_do_hub(exigido, request.full_path.rstrip("?")))


# --------------------------------------------------------------------------
# FastAPI
# --------------------------------------------------------------------------
def proteger_fastapi(
    app,
    slug: str,
    rotas_livres: tuple[str, ...] = ("/healthz",),
    cards_por_caminho: Mapping[str, str] | None = None,
) -> None:
    """Tranca um app FastAPI. Ver proteger_flask para o uso de cards_por_caminho."""
    from fastapi import Request
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

    mapa = dict(cards_por_caminho or {})
    aceitos = [slug, *mapa.values()]

    _env("GUARDIAN_SSO_PUBKEY")
    _chave_sessao()
    _hub_url()

    @app.middleware("http")
    async def _gate(request: Request, call_next):
        if request.url.path in rotas_livres:
            return await call_next(request)

        exigido = _slug_do_caminho(request.url.path, slug, mapa)

        ticket = request.query_params.get(PARAM_TICKET)
        if ticket:
            try:
                claims = validar_ticket(ticket, aceitos)
            except Exception:
                resp = HTMLResponse(_HTML_FALHA.format(hub=_hub_url()), status_code=403)
                resp.delete_cookie(COOKIE, path="/")
                return resp
            resp = RedirectResponse(_destino_seguro(claims.get("nxt")), status_code=303)
            resp.set_cookie(
                COOKIE,
                _assinar_sessao(claims),
                max_age=None,
                httponly=True,
                secure=True,
                samesite="lax",
                path="/",
            )
            return resp

        sessao = _ler_sessao(request.cookies.get(COOKIE))
        # A sessão vale para o card com que ela foi aberta.
        if sessao and (not mapa or sessao.get("slug") == exigido):
            request.state.guardian_user = sessao
            return await call_next(request)

        caminho = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        if request.method != "GET" or _e_chamada_de_fundo(
            request.url.path,
            request.headers.get("accept", ""),
            request.headers.get("x-requested-with", ""),
        ):
            return JSONResponse({"erro": "sessao_expirada"}, status_code=401)
        return RedirectResponse(_url_do_hub(exigido, caminho), status_code=303)
