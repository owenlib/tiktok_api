#!/usr/bin/env python3
"""Export your own TikTok channel analytics to a CSV.

Uses the TikTok Display API (Login Kit OAuth). Pulls account-level stats and
per-video stats for the account that authorizes the app, then writes a CSV with
one row per video plus a leading account-summary row.

Only works for the account that completes the OAuth consent screen -- the API
cannot read arbitrary public channels.

Usage:
    python tiktok_analytics.py               # authorize + export
    python tiktok_analytics.py --out my.csv  # custom output path
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

AUTHORIZE_URL = "https://www.tiktok.com/v2/auth/authorize/"
TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
USER_INFO_URL = "https://open.tiktokapis.com/v2/user/info/"
VIDEO_LIST_URL = "https://open.tiktokapis.com/v2/video/list/"

# Scopes needed for a read-only analytics export of your own channel.
SCOPES = "user.info.basic,user.info.stats,video.list"

# Fields to request from each endpoint (comma-separated per the API contract).
USER_FIELDS = (
    "open_id,union_id,display_name,is_verified,bio_description,"
    "profile_deep_link,follower_count,following_count,likes_count,video_count"
)
VIDEO_FIELDS = (
    "id,create_time,title,video_description,duration,share_url,"
    "view_count,like_count,comment_count,share_count"
)

TOKEN_CACHE = Path(".token.json")


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def load_config() -> dict[str, str]:
    load_dotenv()
    cfg = {
        "client_key": os.getenv("TIKTOK_CLIENT_KEY", ""),
        "client_secret": os.getenv("TIKTOK_CLIENT_SECRET", ""),
        "redirect_uri": os.getenv("TIKTOK_REDIRECT_URI", ""),
    }
    missing = [k for k, v in cfg.items() if not v]
    if missing:
        die(
            "missing env vars: "
            + ", ".join("TIKTOK_" + k.upper() for k in missing)
            + " (copy .env.example to .env and fill it in)"
        )
    return cfg


# --- OAuth -----------------------------------------------------------------

def get_access_token(cfg: dict[str, str]) -> str:
    """Return a valid access token, refreshing or re-authorizing as needed."""
    tok = _read_cached_token()
    if tok and tok["expires_at"] > time.time() + 60:
        return tok["access_token"]
    if tok and tok.get("refresh_token"):
        refreshed = _try_refresh(cfg, tok["refresh_token"])
        if refreshed:
            return refreshed
    return _authorize_interactive(cfg)


def _read_cached_token() -> dict | None:
    if not TOKEN_CACHE.exists():
        return None
    try:
        return json.loads(TOKEN_CACHE.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _save_token(payload: dict) -> None:
    payload = dict(payload)
    payload["expires_at"] = time.time() + int(payload.get("expires_in", 0))
    TOKEN_CACHE.write_text(json.dumps(payload, indent=2))


def _make_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge).

    TikTok deviates from RFC 7636: code_challenge is the *hex* digest of
    SHA256(code_verifier), not the base64url digest. Only S256 is supported.
    """
    verifier = secrets.token_hex(48)  # 96 chars, within the 43-128 range
    challenge = hashlib.sha256(verifier.encode("ascii")).hexdigest()
    return verifier, challenge


def _authorize_interactive(cfg: dict[str, str]) -> str:
    state = os.urandom(8).hex()
    code_verifier, code_challenge = _make_pkce_pair()
    params = {
        "client_key": cfg["client_key"],
        "scope": SCOPES,
        "response_type": "code",
        "redirect_uri": cfg["redirect_uri"],
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    url = AUTHORIZE_URL + "?" + urllib.parse.urlencode(params)

    print("\n1. Opening TikTok authorization in your browser...")
    print("   If it doesn't open, paste this URL manually:\n")
    print("   " + url + "\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass

    print("2. After you approve, your browser redirects to a URL like:")
    print(f"   {cfg['redirect_uri']}?code=XXXX&state={state}")
    print("   (the page may fail to load -- that's fine, you just need the URL)\n")
    pasted = input("3. Paste the FULL redirect URL (or just the code) here: ").strip()

    code = _extract_code(pasted, expected_state=state)
    return _exchange_code(cfg, code, code_verifier)


def _extract_code(pasted: str, expected_state: str) -> str:
    if pasted.startswith("http"):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(pasted).query)
        if "error" in qs:
            die(f"authorization failed: {qs.get('error_description', qs['error'])}")
        returned_state = qs.get("state", [None])[0]
        if returned_state and returned_state != expected_state:
            die("state mismatch -- possible CSRF, aborting")
        code = qs.get("code", [None])[0]
        if not code:
            die("no 'code' found in the pasted URL")
    else:
        code = pasted
    # TikTok appends a stray '*' fragment to the code in some flows; strip it.
    return urllib.parse.unquote(code).rstrip("*")


def _exchange_code(cfg: dict[str, str], code: str, code_verifier: str) -> str:
    resp = requests.post(
        TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "client_key": cfg["client_key"],
            "client_secret": cfg["client_secret"],
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": cfg["redirect_uri"],
            "code_verifier": code_verifier,
        },
        timeout=30,
    )
    payload = resp.json()
    if "access_token" not in payload:
        die(f"token exchange failed: {payload}")
    _save_token(payload)
    print("   ...authorized.\n")
    return payload["access_token"]


def _try_refresh(cfg: dict[str, str], refresh_token: str) -> str | None:
    resp = requests.post(
        TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "client_key": cfg["client_key"],
            "client_secret": cfg["client_secret"],
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
        timeout=30,
    )
    payload = resp.json()
    if "access_token" not in payload:
        return None
    _save_token(payload)
    return payload["access_token"]


# --- Display API calls -----------------------------------------------------

def fetch_user_info(token: str) -> dict:
    resp = requests.get(
        USER_INFO_URL,
        headers={"Authorization": f"Bearer {token}"},
        params={"fields": USER_FIELDS},
        timeout=30,
    )
    body = resp.json()
    _check_api_error(body, "user/info")
    return body["data"]["user"]


def fetch_all_videos(token: str) -> list[dict]:
    videos: list[dict] = []
    cursor = 0
    while True:
        resp = requests.post(
            VIDEO_LIST_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            params={"fields": VIDEO_FIELDS},
            json={"max_count": 20, "cursor": cursor},
            timeout=30,
        )
        body = resp.json()
        _check_api_error(body, "video/list")
        data = body["data"]
        videos.extend(data.get("videos", []))
        if not data.get("has_more"):
            break
        cursor = data["cursor"]
    return videos


def _check_api_error(body: dict, where: str) -> None:
    err = body.get("error", {})
    # The API always returns an "error" object; code "ok" means success.
    if err and err.get("code") not in (None, "ok"):
        die(f"{where} API error: {err.get('code')} - {err.get('message')}")


# --- CSV output ------------------------------------------------------------

def write_csv(user: dict, videos: list[dict], out_path: Path) -> None:
    snapshot = datetime.now(timezone.utc).isoformat()
    columns = [
        "snapshot_utc", "row_type", "video_id", "created_utc",
        "title", "view_count", "like_count", "comment_count", "share_count",
        "duration_sec", "share_url",
        "follower_count", "following_count", "total_likes", "video_count",
    ]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()

        # Account-summary row.
        w.writerow({
            "snapshot_utc": snapshot,
            "row_type": "account",
            "title": user.get("display_name"),
            "follower_count": user.get("follower_count"),
            "following_count": user.get("following_count"),
            "total_likes": user.get("likes_count"),
            "video_count": user.get("video_count"),
        })

        # One row per video.
        for v in videos:
            created = v.get("create_time")
            w.writerow({
                "snapshot_utc": snapshot,
                "row_type": "video",
                "video_id": v.get("id"),
                "created_utc": (
                    datetime.fromtimestamp(created, timezone.utc).isoformat()
                    if created else None
                ),
                "title": v.get("title") or v.get("video_description"),
                "view_count": v.get("view_count"),
                "like_count": v.get("like_count"),
                "comment_count": v.get("comment_count"),
                "share_count": v.get("share_count"),
                "duration_sec": v.get("duration"),
                "share_url": v.get("share_url"),
            })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", default="tiktok_analytics.csv", help="output CSV path"
    )
    args = parser.parse_args()

    cfg = load_config()
    token = get_access_token(cfg)

    print("Fetching account stats...")
    user = fetch_user_info(token)
    print("Fetching videos...")
    videos = fetch_all_videos(token)

    out_path = Path(args.out)
    write_csv(user, videos, out_path)
    print(
        f"\nDone: {len(videos)} videos + 1 account row -> {out_path}"
        f"\n  {user.get('display_name')}: {user.get('follower_count')} followers,"
        f" {user.get('likes_count')} total likes"
    )


if __name__ == "__main__":
    main()
