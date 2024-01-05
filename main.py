from fastapi import Depends, FastAPI, Header, Query, Request, HTTPException, status
import secrets
from typing import Optional
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from databases import Database
from datetime import datetime
from starlette.templating import Jinja2Templates
from fastapi_oauth_client import OAuthClient

# # 데이터베이스 URL 설정
# DATABASE_URL = "mysql+pymysql://root:6Aqpc374zmi!@localhost:3306/exampledb"

# FastAPI 앱 인스턴스 생성
app = FastAPI()

templates = Jinja2Templates(directory="templates")


naver_client = OAuthClient(
    client_id="i1sgslgPmM9xO83ouini",
    client_secret_id="i1sgslgPmM9xO83ouini",
    redirect_uri="http://127.0.0.1:8000",
    authentication_uri="https://nid.naver.com/oauth2.0",
    resource_uri="https://openapi.naver.com/v1/nid/me",
    verify_uri="https://openapi.naver.com/v1/nid/verify",
)

kakao_client = OAuthClient(
    client_id="your_client_id",
    client_secret_id="your_client_secret_id",
    redirect_uri="your_callback_uri",
    authentication_uri="https://kauth.kakao.com/oauth",
    resource_uri="https://kapi.kakao.com/v2/user/me",
    verify_uri="https://kapi.kakao.com/v1/user/access_token_info",
)

# # Database 인스턴스 생성
# database = Database(DATABASE_URL)

# @app.on_event("startup")
# async def startup():
#     await database.connect()

# @app.on_event("shutdown")
# async def shutdown():
#     await database.disconnect()

def get_oauth_client():
        return naver_client


def get_authorization_token(authorization: str = Header(...)) -> str:
    scheme, _, param = authorization.partition(" ")
    if not authorization or scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return param


async def login_required(
    oauth_client: OAuthClient = Depends(get_oauth_client),
    access_token: str = Depends(get_authorization_token),
):
    if not await oauth_client.is_authenticated(access_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    
@app.get("/naver_login")
async def login_naver(oauth_client=Depends(get_oauth_client)):
    state = secrets.token_urlsafe(32)
    login_url = oauth_client.get_oauth_login_url(state=state)
    return RedirectResponse(login_url)

@app.get("/callback")
async def callback(
    code: str, state: Optional[str] = None, oauth_client=Depends(get_oauth_client)
):
    token_response = await oauth_client.get_tokens(code, state)

    return {"response": token_response}

@app.get("/refresh")
async def callback(
    oauth_client=Depends(get_oauth_client),
    refresh_token: str = Depends(get_authorization_token),
):
    token_response = await oauth_client.refresh_access_token(
        refresh_token=refresh_token
    )

    return {"response": token_response}