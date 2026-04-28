"""OIDC 认证 & 授权

配置优先级: data/config.json > 环境变量
在控制台 系统配置 页面可修改 OIDC 参数，保存后立即生效。
需要 IdP 在 id_token 或 userinfo 中返回 groups claim。
"""
import os, secrets
from pathlib import Path
os.environ.setdefault("AUTHLIB_INSECURE_TRANSPORT", "1")
import store
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, HTMLResponse

PUBLIC_PATHS = ("/auth/", "/static/")

oauth = OAuth()
_oidc_registered_issuer = None


def _cfg() -> dict:
    saved = store.load().get("oidc", {})
    return {
        "enabled":        saved.get("enabled", os.environ.get("OIDC_ENABLED", "0")) not in ("0", "", False),
        "issuer":         saved.get("issuer", os.environ.get("OIDC_ISSUER", "")),
        "client_id":      saved.get("client_id", os.environ.get("OIDC_CLIENT_ID", "")),
        "client_secret":  saved.get("client_secret", os.environ.get("OIDC_CLIENT_SECRET", "")),
        "redirect_uri":   saved.get("redirect_uri", os.environ.get("OIDC_REDIRECT_URI", "")),
        "required_group": saved.get("required_group", os.environ.get("OIDC_REQUIRED_GROUP", "opsadmin")),
    }


def get_cfg() -> dict:
    c = _cfg()
    if c["client_secret"]:
        c["client_secret_set"] = True
        c["client_secret"] = "••••••••"
    else:
        c["client_secret_set"] = False
    return c


def save_cfg(data: dict):
    all_data = store.load()
    old = all_data.get("oidc", {})
    if data.get("client_secret", "").startswith("••"):
        data["client_secret"] = old.get("client_secret", "")
    all_data["oidc"] = data
    store.save(all_data)
    global _oidc_registered_issuer
    _oidc_registered_issuer = None


def _ensure_registered():
    global _oidc_registered_issuer
    c = _cfg()
    issuer = c.get("issuer", "")
    if not issuer or not c.get("client_id"):
        return False
    if _oidc_registered_issuer == issuer:
        return True
    oauth.register(
        name="oidc",
        client_id=c["client_id"],
        client_secret=c["client_secret"],
        server_metadata_url=issuer.rstrip("/") + "/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile groups"},
        overwrite=True,
    )
    _oidc_registered_issuer = issuer
    return True


class AuthGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in PUBLIC_PATHS):
            return await call_next(request)

        c = _cfg()
        if not c["enabled"]:
            return await call_next(request)

        user = request.session.get("user")
        if not user:
            return RedirectResponse("/auth/login")

        groups = request.session.get("groups", [])
        required = c["required_group"]
        if required and required not in groups:
            return HTMLResponse(
                "<h2>403 Forbidden</h2>"
                f"<p>用户 <b>{user}</b> 不在 <code>{required}</code> 组中，无权访问。</p>"
                '<p><a href="/auth/logout">切换账号</a></p>',
                status_code=403,
            )
        return await call_next(request)


def setup(app):
    """注册 session 中间件、认证路由和全局守卫"""
    # 持久化 session key，避免重启后 session 失效
    key_file = Path("data/.session_key")
    if key_file.exists():
        secret_key = key_file.read_text().strip()
    else:
        secret_key = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
        key_file.parent.mkdir(exist_ok=True)
        key_file.write_text(secret_key)
    app.add_middleware(AuthGuardMiddleware)
    app.add_middleware(SessionMiddleware, secret_key=secret_key, max_age=86400, same_site="lax", https_only=False)

    @app.get("/auth/login")
    async def login(request: Request):
        if not _ensure_registered():
            return HTMLResponse("<h2>OIDC 未配置</h2><p>请先在 <a href='/system'>系统配置</a> 中填写 OIDC 参数。</p>")
        c = _cfg()
        redirect_uri = c["redirect_uri"] or str(request.url_for("callback"))
        return await oauth.oidc.authorize_redirect(request, redirect_uri)

    @app.get("/auth/callback")
    async def callback(request: Request):
        if not _ensure_registered():
            return RedirectResponse("/")
        try:
            token = await oauth.oidc.authorize_access_token(request)
        except Exception:
            # state 校验失败（session 丢失/过期），重新登录
            return RedirectResponse("/auth/login")
        userinfo = token.get("userinfo") or {}
        id_claims = token.get("id_token", {}) if isinstance(token.get("id_token"), dict) else {}
        groups = userinfo.get("groups") or id_claims.get("groups") or []
        user = userinfo.get("preferred_username") or userinfo.get("sub", "unknown")
        request.session["user"] = user
        request.session["groups"] = groups
        return RedirectResponse("/")

    @app.get("/auth/logout")
    async def logout(request: Request):
        request.session.clear()
        return RedirectResponse("/auth/login")
