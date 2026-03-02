from contextlib import asynccontextmanager
from os import environ

import casbin
import jwt
from casbin_redis_adapter.adapter import Adapter
from casbin_redis_watcher import WatcherOptions, new_watcher
from casbin_redis_watcher.watcher import RedisWatcher
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

CASBIN_REDIS_HOST = environ.get("CASBIN_REDIS_HOST", "localhost")
CASBIN_REDIS_PORT = environ.get("CASBIN_REDIS_PORT", "6379")


def get_token_sub(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
) -> str:
    """Read the sub field from the jwt. You need to verify sigs in production (unless you want to be pwned)."""
    token = credentials.credentials
    payload = jwt.decode(token, options={"verify_signature": False})
    sub = payload.get("sub")

    if not sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing 'sub' claim",
        )

    return sub


def create_enforcer_with_watcher() -> tuple[casbin.Enforcer, RedisWatcher]:
    """Mostly lifed from the casbin docs"""
    adapter = Adapter(host=CASBIN_REDIS_HOST, port=CASBIN_REDIS_PORT)
    enforcer = casbin.Enforcer("examples/rbac_model.conf", adapter)
    enforcer.enable_auto_save(True)
    enforcer.load_policy()

    def callback_function(event):
        print(f"update callback, event: {format(event)}")
        enforcer.load_policy()

    watcher_options = WatcherOptions()
    watcher_options.host = CASBIN_REDIS_HOST
    watcher_options.port = CASBIN_REDIS_PORT
    watcher_options.ssl = False
    watcher_options.optional_update_callback = callback_function  # pyright: ignore[reportAttributeAccessIssue] casbin has some typing issues
    watcher = new_watcher(watcher_options)
    enforcer.set_watcher(watcher)

    return enforcer, watcher


@asynccontextmanager
async def lifespan(app: FastAPI):
    enforcer, watcher = create_enforcer_with_watcher()
    app.state.enforcer = enforcer
    app.state.watcher = watcher

    yield

    ...


def get_enforcer(request: Request) -> casbin.Enforcer:
    """Small helper to grab the enforcer out of fastapi app state. There might be a more elegant way to do this?"""
    return request.app.state.enforcer


app = FastAPI(lifespan=lifespan)


@app.get(
    "/protected",
    description="Example protected endpoint. You need a jwt to access this.",
)
def get_obj(
    obj: str,
    request: Request,
    enforcer: casbin.Enforcer = Depends(get_enforcer),
    sub=Depends(get_token_sub),
):
    act = request.method.lower()
    if enforcer.enforce(sub, obj, act):
        return {f"User {sub} got object {obj}"}
    return HTTPException(status.HTTP_403_FORBIDDEN)


@app.post(
    "/permission/test",
    description="Use this endpoint to test if you have permissions correctly set.",
)
def permission_tes(
    sub: str,
    obj: str,
    act: str,
    enforcer: casbin.Enforcer = Depends(get_enforcer),
):
    if enforcer.enforce(sub, obj, act):
        return {f"User {sub} got object {obj}"}
    return HTTPException(status.HTTP_403_FORBIDDEN)


@app.post(
    "/permission/add",
    description="This simulates an admin method to grant permissions.",
)
def permission_add(
    sub: str,
    obj: str,
    act: str,
    enforcer: casbin.Enforcer = Depends(get_enforcer),
):
    enforcer.add_policy(sub, obj, act)
    return {"status": "added permission"}


@app.delete(
    "/permission/remove",
    description="This simulates an admin method to revoke permissions.",
)
def permission_remove(
    sub: str,
    obj: str,
    act: str,
    enforcer: casbin.Enforcer = Depends(get_enforcer),
):
    enforcer.remove_policy(sub, obj, act)
    return {"status": "removed permission"}
