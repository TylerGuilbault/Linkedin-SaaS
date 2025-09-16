# app/services/linkedin_api.py
import httpx
import time
from typing import Tuple, Dict, Any
from urllib.parse import urlencode, quote
from app.config import settings

AUTH_URL  = "https://www.linkedin.com/oauth/v2/authorization"
TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
UGC_URL   = "https://api.linkedin.com/v2/ugcPosts"

# Helper: log request id if present in LinkedIn response
def log_request_id(resp):
    req_id = resp.headers.get("x-restli-request-id")
    if req_id:
        print(f"[LinkedIn] request id: {req_id}", flush=True)

# Helper: retry logic for LinkedIn API
def linkedin_request_with_retry(method, url, **kwargs):
    max_attempts = 4
    backoff = 2
    for attempt in range(1, max_attempts + 1):
        try:
            with httpx.Client(timeout=httpx.Timeout(30, connect=5)) as c:
                resp = c.request(method, url, **kwargs)
            log_request_id(resp)
            if resp.status_code in (429, 500, 502, 503, 504):
                print(f"[LinkedIn] {url} attempt {attempt} got {resp.status_code}, retrying...", flush=True)
                if attempt < max_attempts:
                    time.sleep(backoff * attempt)
                    continue
            return resp
        except httpx.RequestError as e:
            print(f"[LinkedIn] Request error: {e}", flush=True)
            if attempt < max_attempts:
                time.sleep(backoff * attempt)
                continue
            raise
    raise Exception(f"LinkedIn API failed after {max_attempts} attempts")

def auth_url(state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": settings.linkedin_client_id,
        "redirect_uri": settings.linkedin_redirect_uri,
        "scope": settings.linkedin_scopes,
        "state": state,
    }
    qs = urlencode(params, quote_via=quote, safe=":/")
    return f"{AUTH_URL}?{qs}"

def exchange_code_for_token(code: str) -> Dict[str, Any]:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.linkedin_redirect_uri,
        "client_id": settings.linkedin_client_id,
        "client_secret": settings.linkedin_client_secret,
    }
    # Harden: use retry logic and timeouts
    resp = linkedin_request_with_retry(
        "POST", TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    resp.raise_for_status()
    data = resp.json()
    # Capture refresh_token if present
    refresh_token = data.get("refresh_token")
    if refresh_token:
        data["refresh_token"] = refresh_token
    return data

# New: exchange refresh_token for new access token
def exchange_refresh_for_token(refresh_token: str) -> Dict[str, Any]:
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": settings.linkedin_client_id,
        "client_secret": settings.linkedin_client_secret,
    }
    resp = linkedin_request_with_retry(
        "POST", TOKEN_URL,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    resp.raise_for_status()
    return resp.json()

def post_text(access_token: str, author_urn: str, text: str) -> Tuple[bool, str]:
    payload = {
        "author": author_urn,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": text},
                "shareMediaCategory": "NONE",
            }
        },
        "visibility": {"com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"},
    }
    try:
        with httpx.Client(timeout=60) as c:
            r = c.post(
                UGC_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "X-Restli-Protocol-Version": "2.0.0",
                },
                json=payload,
            )
            print("[post_text] status:", r.status_code, flush=True)
            print("[post_text] request json:", payload, flush=True)
            print("[post_text] response text:", r.text, flush=True)
            # Return request id for traceability
            log_request_id(r)
            return r.status_code in (201, 202), r if r.status_code in (201, 202) else r
    except Exception as e:
        print("[post_text] error:", e, flush=True)
        return False, str(e)
    except Exception as e:
        return False, f"exception: {e}"
