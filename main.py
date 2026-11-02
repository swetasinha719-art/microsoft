import os
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI(title="Microsoft Graph Backend", version="0.1.0")
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET", secrets.token_urlsafe(32)), same_site="lax", https_only=True)

TENANT = os.getenv("MICROSOFT_TENANT", "consumers")
CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET", "")
REDIRECT_URI = os.getenv("MICROSOFT_REDIRECT_URI", "")
SCOPES = os.getenv("MICROSOFT_SCOPES", "openid profile offline_access User.Read Mail.ReadWrite Calendars.ReadWrite Files.ReadWrite")

def configured():
    return all([CLIENT_ID, CLIENT_SECRET, REDIRECT_URI])

@app.get("/")
def root():
    return {"service": "Microsoft Graph Backend", "status": "ready", "oauth_configured": configured(), "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/auth/microsoft")
def microsoft_login(request: Request):
    if not configured():
        raise HTTPException(503, "Microsoft OAuth environment variables are not configured.")
    state = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state
    params = {"client_id": CLIENT_ID, "response_type": "code", "redirect_uri": REDIRECT_URI,
              "response_mode": "query", "scope": SCOPES, "state": state}
    return RedirectResponse(f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize?{urlencode(params)}")

@app.get("/auth/callback")
async def microsoft_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        raise HTTPException(400, f"Microsoft sign-in error: {error}")
    expected = request.session.pop("oauth_state", None)
    if not expected or not secrets.compare_digest(expected, state):
        raise HTTPException(400, "Invalid OAuth state. Please restart sign-in.")
    if not code:
        raise HTTPException(400, "Missing authorization code.")
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token", data={
            "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "grant_type": "authorization_code",
            "code": code, "redirect_uri": REDIRECT_URI, "scope": SCOPES})
    if response.status_code >= 400:
        raise HTTPException(502, "Microsoft token exchange failed; check OAuth configuration.")
    tokens = response.json()
    request.session["access_token"] = tokens["access_token"]
    request.session["refresh_token"] = tokens.get("refresh_token")
    return {"signed_in": True, "message": "Microsoft sign-in succeeded. Token is stored in a secure session cookie."}

@app.get("/graph/me")
async def graph_me(request: Request):
    token = request.session.get("access_token")
    if not token:
        raise HTTPException(401, "Sign in first at /auth/microsoft")
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.get("https://graph.microsoft.com/v1.0/me", headers={"Authorization": f"Bearer {token}"})
    if r.status_code >= 400:
        raise HTTPException(r.status_code, "Microsoft Graph request failed.")
    return r.json()
