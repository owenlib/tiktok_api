# TikTok channel analytics → CSV

Exports **your own** TikTok channel's stats to a CSV using the official
[Display API](https://developers.tiktok.com/doc/display-api-overview). One row
per video (views/likes/comments/shares) plus an account-summary row.

> The Display API only reads the account that authorizes the app. It cannot pull
> arbitrary public channels, and it has **no historical data** — each run is a
> point-in-time snapshot. To build trends, run it on a schedule and append.

## 1. Create the TikTok app (one time)

1. Sign up at <https://developers.tiktok.com> and create an app under **Manage apps**.
2. Add the **Login Kit** and **Display API** products.
3. Add scopes: `user.info.basic`, `user.info.stats`, `video.list`.
4. Add a **Redirect URI** (HTTPS required): `https://localhost/callback`.
5. Copy your **Client key** and **Client secret**.

While your app is in **Sandbox**, add your own TikTok account as a target user
so you can authorize it before submitting for review.

## 2. Configure

```bash
cp .env.example .env      # then paste in your client key/secret
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 3. Run

```bash
python tiktok_analytics.py
```

- A browser opens to TikTok's consent screen. Approve it.
- Your browser redirects to `https://localhost/callback?code=...` — the page
  won't load, that's fine. Copy the **full URL** from the address bar and paste
  it into the terminal.
- The script exchanges the code, pulls your stats, and writes
  `tiktok_analytics.csv`.

The access token is cached in `.token.json` and auto-refreshed, so subsequent
runs skip the browser step (refresh token lasts 365 days).

```bash
python tiktok_analytics.py --out weekly/2026-07-07.csv
```

## Notes

- `.env`, `.token.json`, and `*.csv` are git-ignored — they hold secrets/data.
- Sandbox video stats may be limited; full data comes once the app is **Live**.
