import os
import time
import hashlib
from io import BytesIO

import cloudinary
import cloudinary.uploader
import httpx
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
import asyncio
import json


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
                print(f"[INFO] Loaded from env.txt: {key}")


DESKTOP_ENV_FILE = os.path.join(os.path.expanduser("~"), "Desktop", "env.txt")
load_env_from_file(DESKTOP_ENV_FILE)

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
CLOUDINARY_CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.environ.get("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET")

missing = [k for k, v in {
    "VIRUSTOTAL_API_KEY": VT_API_KEY,
    "CLOUDINARY_CLOUD_NAME": CLOUDINARY_CLOUD_NAME,
    "CLOUDINARY_API_KEY": CLOUDINARY_API_KEY,
    "CLOUDINARY_API_SECRET": CLOUDINARY_API_SECRET,
}.items() if not v]

if missing:
    raise RuntimeError(f"[ERROR] Missing required environment variables: {missing}")

cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET
)

HEADERS = {"x-apikey": VT_API_KEY}
VT_POLL_INTERVAL = 5
VT_MAX_POLLS = 24

app = FastAPI()


def sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def get_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    file_bytes = await file.read()
    filename = file.filename

    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    print(f"[INFO] Received file: {filename}, size: {len(file_bytes)} bytes")

    async def event_stream():
        async with httpx.AsyncClient(timeout=60.0) as client:

            # ── Step 1: File received ─────────────────────────────────────────
            yield sse_event("status", {
                "step": "received",
                "message": f"Dosya '{filename}' alındı ({len(file_bytes)} bytes). Taramayı başlatıyoruz..."
            })

            sha256 = get_sha256(file_bytes)
            print(f"[INFO] SHA-256: {sha256}")

            analysis_id = None
            stats = None

            # ── Step 2: Check if VT already has a report ──────────────────────
            existing_resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers=HEADERS
            )

            if existing_resp.status_code == 200:
                print(f"[INFO] File already known to VirusTotal, using cached report.")
                yield sse_event("status", {
                    "step": "vt_cached",
                    "message": "Dosya zaten taranmış, mevcut rapor kullanılıyor..."
                })
                stats = existing_resp.json()["data"]["attributes"].get("last_analysis_stats")

            else:
                # ── Step 3: Upload to VirusTotal ──────────────────────────────
                yield sse_event("status", {
                    "step": "vt_uploading",
                    "message": "Dosya yükleniyor..."
                })

                vt_resp = await client.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=HEADERS,
                    files={"file": (filename, file_bytes)}
                )

                if vt_resp.status_code == 409:
                    print(f"[WARN] VT conflict, retrying hash lookup...")
                    yield sse_event("status", {
                        "step": "vt_conflict",
                        "message": "Bir sorun oluştu, tekrar deniyoruz..."
                    })
                    await asyncio.sleep(3)
                    retry_resp = await client.get(
                        f"https://www.virustotal.com/api/v3/files/{sha256}",
                        headers=HEADERS
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
                    yield sse_event("error", {
                        "step": "vt_upload",
                        "message": f"Tarama başarısız oldu."
                    })
                    return

                else:
                    analysis_id = vt_resp.json()["data"]["id"]
                    print(f"[INFO] VirusTotal analysis ID: {analysis_id}")

            # ── Step 4: Poll if fresh upload ──────────────────────────────────
            if analysis_id and not stats:
                yield sse_event("status", {
                    "step": "vt_scanning",
                    "message": "Dosya yüklendi, taranıyor..."
                })

                timed_out = True
                for attempt in range(VT_MAX_POLLS):
                    poll_resp = await client.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=HEADERS
                    )

                    if poll_resp.status_code != 200:
                        yield sse_event("error", {
                            "step": "vt_polling",
                            "message": "Tarama sonuçları alınamadı."
                        })
                        return

                    vt_status = poll_resp.json()["data"]["attributes"]["status"]
                    print(f"[INFO] Poll attempt {attempt + 1}: status = {vt_status}")

                    yield sse_event("status", {
                        "step": "vt_polling",
                        "message": f"Dosya taranıyor... (deneme {attempt + 1}/{VT_MAX_POLLS})",
                        "vt_status": vt_status
                    })

                    if vt_status == "completed":
                        stats = poll_resp.json()["data"]["attributes"]["stats"]
                        timed_out = False
                        break

                    await asyncio.sleep(VT_POLL_INTERVAL)  # ← non-blocking sleep

                if timed_out:
                    yield sse_event("error", {
                        "step": "vt_timeout",
                        "message": "Tarama zaman aşımına uğradı, lütfen daha sonra tekrar deneyin."
                    })
                    return

            # ── Step 5: Evaluate results ──────────────────────────────────────
            print(f"[INFO] VirusTotal stats: {stats}")

            if not stats:
                yield sse_event("error", {
                    "step": "vt_no_stats",
                    "message": "Tarama sonuçları alınamadı."
                })
                return

            if stats.get("malicious", 0) > 0:
                yield sse_event("error", {
                    "step": "vt_flagged",
                    "message": f"Dosyada virüs tespit edildi.",
                    "stats": stats
                })
                return

            yield sse_event("status", {
                "step": "vt_clean",
                "message": "Tarama başarılı! Dosya yükleniyor...",
                "stats": stats
            })

            # ── Step 6: Upload to Cloudinary ──────────────────────────────────
            file_stream = BytesIO(file_bytes)
            file_stream.seek(0)

            try:
                # Run blocking cloudinary upload in a thread so it doesn't block the stream
                loop = asyncio.get_event_loop()
                cloud_resp = await loop.run_in_executor(
                    None,
                    lambda: cloudinary.uploader.upload(
                        file_stream,
                        public_id=filename,
                        resource_type="auto"
                    )
                )
            except Exception as e:
                print(f"[ERROR] Cloudinary upload failed: {e}")
                yield sse_event("error", {
                    "step": "cloudinary_upload",
                    "message": f"Yükleme başarısız."
                })
                return

            cloud_url = cloud_resp.get("secure_url")
            print(f"[INFO] Cloudinary upload successful: {cloud_url}")

            # ── Step 7: Done ──────────────────────────────────────────────────
            yield sse_event("done", {
                "step": "complete",
                "message": "Dosya başarıyla yüklendi.",
                "filename": filename,
                "cloud_url": cloud_url,
                "virustotal_stats": stats
            })

    return StreamingResponse(event_stream(), media_type="text/event-stream")