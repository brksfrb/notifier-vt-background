import os
import hashlib
import asyncio
import json
import uuid
from io import BytesIO

import cloudinary
import cloudinary.uploader
import httpx
from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.responses import StreamingResponse
import google.auth.transport.requests
from google.oauth2 import service_account

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request
from starlette.responses import JSONResponse


# ── Env loading ───────────────────────────────────────────────────────────────

def load_env_from_file(filepath: str):
    if not os.path.exists(filepath):
        print(f"[WARN] Env file not found: {filepath}")
        return
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if not os.environ.get(key):
                os.environ[key] = value
                print(f"[INFO] Loaded from env.txt.")


DESKTOP_ENV_FILE = os.path.join(os.path.expanduser("~"), "Desktop", "env.txt")
load_env_from_file(DESKTOP_ENV_FILE)

# ── Config ────────────────────────────────────────────────────────────────────

VT_API_KEY                  = os.environ.get("VIRUSTOTAL_API_KEY")
CLOUDINARY_CLOUD_NAME       = os.environ.get("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY          = os.environ.get("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET       = os.environ.get("CLOUDINARY_API_SECRET")
GOOGLE_CLOUD_PROJECT_NUMBER = os.environ.get("GOOGLE_CLOUD_PROJECT_NUMBER")
GOOGLE_SERVICE_ACCOUNT_JSON = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON")

# REQUIRE_INTEGRITY=false during local dev, true in production on Render
REQUIRE_INTEGRITY = True

missing = [k for k, v in {
    "VIRUSTOTAL_API_KEY":           VT_API_KEY,
    "CLOUDINARY_CLOUD_NAME":        CLOUDINARY_CLOUD_NAME,
    "CLOUDINARY_API_KEY":           CLOUDINARY_API_KEY,
    "CLOUDINARY_API_SECRET":        CLOUDINARY_API_SECRET,
    "GOOGLE_CLOUD_PROJECT_NUMBER":  GOOGLE_CLOUD_PROJECT_NUMBER,
    "GOOGLE_SERVICE_ACCOUNT_JSON": GOOGLE_SERVICE_ACCOUNT_JSON,
}.items() if not v]

# Only require service account JSON if integrity is enabled
if REQUIRE_INTEGRITY and not GOOGLE_SERVICE_ACCOUNT_JSON:
    missing.append("GOOGLE_SERVICE_ACCOUNT_JSON")

if missing:
    raise RuntimeError(f"[ERROR] Missing required environment variables: {missing}")

cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET
)

VT_HEADERS       = {"x-apikey": VT_API_KEY}
VT_BASE_URL      = "https://www.virustotal.com/api/v3"
VT_POLL_INTERVAL = 10   # seconds
VT_MAX_POLLS     = 36   # 36 × 10s = 6 minutes max

app = FastAPI()
limiter = Limiter(key_func=get_remote_address, default_limits=["50/minute"])
app.state.limiter = limiter

# ── Helpers ───────────────────────────────────────────────────────────────────

def sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def get_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def get_google_auth_headers() -> dict:
    creds_dict = json.loads(GOOGLE_SERVICE_ACCOUNT_JSON)
    credentials = service_account.Credentials.from_service_account_info(
        creds_dict,
        scopes=["https://www.googleapis.com/auth/playintegrity"]
    )
    auth_req = google.auth.transport.requests.Request()
    credentials.refresh(auth_req)
    return {"Authorization": f"Bearer {credentials.token}"}


async def verify_integrity_token(token: str) -> bool:
    try:
        headers = get_google_auth_headers()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"https://playintegrity.googleapis.com/v1/{GOOGLE_CLOUD_PROJECT_NUMBER}:decodeIntegrityToken",
                json={"integrity_token": token},
                headers=headers
            )

        if resp.status_code != 200:
            print(f"[WARN] Integrity verify failed: {resp.status_code} - {resp.text}")
            return False

        verdict       = resp.json().get("tokenPayloadExternal", {})
        app_integrity = verdict.get("appIntegrity", {})
        device_integrity = verdict.get("deviceIntegrity", {})

        app_ok    = app_integrity.get("appRecognitionVerdict") == "PLAY_RECOGNIZED"
        device_ok = "MEETS_DEVICE_INTEGRITY" in device_integrity.get("deviceRecognitionVerdict", [])

        print(f"[INFO] Integrity — app_ok: {app_ok}, device_ok: {device_ok}")
        return app_ok and device_ok

    except Exception as e:
        print(f"[ERROR] Integrity verification error: {e}")
        return False


# ── Endpoint ──────────────────────────────────────────────────────────────────

async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Çok fazla istek gönderildi. Lütfen biraz bekleyin."}
    )

app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

@app.post("/scan")
@limiter.limit("5/minute")
async def scan_file(
    request: Request,
    file: UploadFile = File(...),
    x_integrity_token: str = Header(default=None)
):
    # ── Integrity check ───────────────────────────────────────────────────────
    if REQUIRE_INTEGRITY:
        if not x_integrity_token:
            raise HTTPException(status_code=401, detail="Unauthorized")
        if not await verify_integrity_token(x_integrity_token):
            raise HTTPException(status_code=401, detail="Unauthorized")

    # ── Read file ─────────────────────────────────────────────────────────────
    file_bytes = await file.read()
    filename   = file.filename

    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    print(f"[INFO] Received: {filename} ({len(file_bytes)} bytes)")

    async def event_stream():
        async with httpx.AsyncClient(timeout=60.0) as client:

            # ── Step 1: Received ──────────────────────────────────────────────
            yield sse_event("status", {
                "step": "received",
                "message": f"Dosya alındı, tarama başlatılıyor..."
            })

            sha256       = get_sha256(file_bytes)
            analysis_id  = None
            stats        = None

            print(f"[INFO] SHA-256: {sha256}")

            # ── Step 2: Hash cache check ──────────────────────────────────────
            existing_resp = await client.get(
                f"{VT_BASE_URL}/files/{sha256}",
                headers=VT_HEADERS
            )

            if existing_resp.status_code == 200:
                print(f"[INFO] Cache hit — using existing VT report")
                yield sse_event("status", {
                    "step": "vt_cached",
                    "message": "Dosya daha önce taranmış, sonuçlar alınıyor..."
                })
                stats = existing_resp.json()["data"]["attributes"].get("last_analysis_stats")

            else:
                # ── Step 3: Upload to VT ──────────────────────────────────────
                yield sse_event("status", {
                    "step": "vt_uploading",
                    "message": "Dosya VirusTotal'e yükleniyor..."
                })

                vt_resp = await client.post(
                    f"{VT_BASE_URL}/files",
                    headers=VT_HEADERS,
                    files={"file": (filename, file_bytes)}
                )

                if vt_resp.status_code == 409:
                    # Conflict — file known but upload conflicted, retry hash lookup
                    print(f"[WARN] VT 409 conflict, retrying hash lookup...")
                    yield sse_event("status", {
                        "step": "vt_conflict",
                        "message": "Çakışma tespit edildi, tekrar deneniyor..."
                    })
                    await asyncio.sleep(3)
                    retry_resp = await client.get(
                        f"{VT_BASE_URL}/files/{sha256}",
                        headers=VT_HEADERS
                    )
                    if retry_resp.status_code == 200:
                        stats = retry_resp.json()["data"]["attributes"].get("last_analysis_stats")
                    else:
                        yield sse_event("error", {
                            "step": "vt_conflict",
                            "message": "Bir sorun oluştu. Lütfen daha sonra tekrar deneyin."
                        })
                        return

                elif vt_resp.status_code != 200:
                    print(f"[ERROR] VT upload failed: {vt_resp.status_code} - {vt_resp.text}")
                    yield sse_event("error", {
                        "step": "vt_upload",
                        "message": "Tarama başlatılamadı. Lütfen tekrar deneyin."
                    })
                    return

                else:
                    analysis_id = vt_resp.json()["data"]["id"]
                    print(f"[INFO] Analysis ID: {analysis_id}")

            # ── Step 4: Poll for results ──────────────────────────────────────
            if analysis_id and not stats:
                yield sse_event("status", {
                    "step": "vt_scanning",
                    "message": "Dosya taranıyor, lütfen bekleyin..."
                })

                timed_out = True
                for attempt in range(VT_MAX_POLLS):
                    poll_resp = await client.get(
                        f"{VT_BASE_URL}/analyses/{analysis_id}",
                        headers=VT_HEADERS
                    )

                    if poll_resp.status_code != 200:
                        print(f"[ERROR] Poll failed: {poll_resp.status_code}")
                        yield sse_event("error", {
                            "step": "vt_polling",
                            "message": "Tarama sonuçları alınamadı."
                        })
                        return

                    vt_status = poll_resp.json()["data"]["attributes"]["status"]
                    print(f"[INFO] Poll {attempt + 1}/{VT_MAX_POLLS}: {vt_status}")

                    yield sse_event("status", {
                        "step": "vt_polling",
                        "message": f"Taranıyor... ({attempt + 1}/{VT_MAX_POLLS})",
                        "vt_status": vt_status
                    })

                    if vt_status == "completed":
                        stats     = poll_resp.json()["data"]["attributes"]["stats"]
                        timed_out = False
                        break

                    # If stuck queued after 3 attempts, try hash lookup
                    if vt_status == "queued" and attempt >= 3:
                        print(f"[INFO] Stuck in queue, trying hash lookup...")
                        fallback = await client.get(
                            f"{VT_BASE_URL}/files/{sha256}",
                            headers=VT_HEADERS
                        )
                        if fallback.status_code == 200:
                            fallback_stats = fallback.json()["data"]["attributes"].get("last_analysis_stats")
                            if fallback_stats:
                                stats     = fallback_stats
                                timed_out = False
                                break

                    await asyncio.sleep(VT_POLL_INTERVAL)

                if timed_out:
                    yield sse_event("error", {
                        "step": "vt_timeout",
                        "message": "Tarama zaman aşımına uğradı. Lütfen daha sonra tekrar deneyin."
                    })
                    return

            # ── Step 5: Evaluate ──────────────────────────────────────────────
            print(f"[INFO] VT stats: {stats}")

            if not stats:
                yield sse_event("error", {
                    "step": "vt_no_stats",
                    "message": "Tarama sonuçları alınamadı."
                })
                return

            if stats.get("malicious", 0) > 0:
                print(f"[WARN] File flagged: {stats['malicious']} engine(s)")
                yield sse_event("error", {
                    "step": "vt_flagged",
                    "message": f"Dosyada virüs tespit edildi, yükleme engellendi.",
                    "stats": stats
                })
                return

            yield sse_event("status", {
                "step": "vt_clean",
                "message": "Tarama temiz! Dosya yükleniyor...",
                "stats": stats
            })

            # ── Step 6: Upload to Cloudinary ──────────────────────────────────
            file_stream = BytesIO(file_bytes)
            file_stream.seek(0)

            # Unique public_id to prevent collisions
            unique_id = uuid.uuid4().hex
            public_id = f"bug_reports/{unique_id}/{filename}"

            try:
                loop = asyncio.get_running_loop()  # fixed: get_event_loop is deprecated
                cloud_resp = await loop.run_in_executor(
                    None,
                    lambda: cloudinary.uploader.upload(
                        file_stream,
                        public_id=public_id,
                        resource_type="auto"
                    )
                )
            except Exception as e:
                print(f"[ERROR] Cloudinary upload failed: {e}")
                yield sse_event("error", {
                    "step": "cloudinary_upload",
                    "message": "Dosya yüklenemedi. Lütfen tekrar deneyin."
                })
                return

            cloud_url = cloud_resp.get("secure_url")
            print(f"[INFO] Cloudinary upload successful: {cloud_url}")

            # ── Step 7: Done ──────────────────────────────────────────────────
            yield sse_event("done", {
                "step": "complete",
                "message": "Dosya başarıyla tarandı ve yüklendi.",
                "filename": filename,
                "cloud_url": cloud_url,
                "virustotal_stats": stats
            })

    return StreamingResponse(event_stream(), media_type="text/event-stream")