# barge2rail-camera

Django service connecting Google Nest dock cameras to Claude Vision for automated dock activity classification. API-only, staff access via SSO.

## Setup

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Edit with your credentials
python manage.py migrate
python manage.py createcachetable
python manage.py runserver
```

## Google SDM OAuth Walkthrough

1. Configure Google Cloud project with SDM API enabled
2. Set `GOOGLE_*` env vars in `.env`
3. Register `camera` app in SSO admin, assign Admin role to your account
4. Login via SSO at `/auth/login/`
5. `POST /api/oauth/initiate/` — returns Google consent URL
6. Visit URL, authorize camera access
7. Google redirects to `/api/oauth/callback/` — tokens stored automatically

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/oauth/initiate/` | Admin | Start Google SDM OAuth |
| GET | `/api/oauth/callback/` | None | Google OAuth callback |
| GET | `/api/grab-frame/` | Login | Grab camera frame |
| POST | `/api/classify/` | Login | Classify snapshot |
| GET | `/api/grab-and-classify/` | Login | Grab + classify |
| GET | `/api/health/` | None | Health check |
| GET | `/api/status/` | Login | System status |

## Deployment

Deployed via Coolify with Docker. Domain: `cam.barge2rail.com`.

Auto-deploys on push to `main`.

Required env vars:
- `SECRET_KEY`, `DATABASE_URL`, `ALLOWED_HOSTS`
- `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`, `SSO_REDIRECT_URI`
- `GOOGLE_SDM_PROJECT_ID`, `GOOGLE_CLOUD_PROJECT_ID`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`
- `ANTHROPIC_API_KEY`
- `DEFAULT_CAMERA_DEVICE_ID`
