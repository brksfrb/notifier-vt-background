import os
import time
from io import BytesIO

import cloudinary
import cloudinary.uploader
import requests
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

# Load credentials from env
VT_API_KEY = os.environ.get("VT_API_KEY")
CLOUDINARY_CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.environ.get("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET")

# Configure Cloudinary SDK
cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET
)

HEADERS = {"x-apikey": VT_API_KEY}
VT_POLL_INTERVAL = 5  # seconds

app = FastAPI()


@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    # 1️⃣ Read file bytes
    file_bytes = await file.read()

    # 2️⃣ Upload to VirusTotal
    files = {"file": (file.filename, file_bytes)}
    vt_resp = requests.post("https://www.virustotal.com/api/v3/files", headers=HEADERS, files=files)
    if vt_resp.status_code != 200:
        print(vt_resp.status_code)
        print(vt_resp.text)
        raise HTTPException(status_code=500, detail="VirusTotal upload failed")
    analysis_id = vt_resp.json()["data"]["id"]

    # 3️⃣ Poll VirusTotal until scan completes
    while True:
        poll_resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=HEADERS)
        if poll_resp.status_code != 200:
            raise HTTPException(status_code=500, detail="VirusTotal polling failed")

        status = poll_resp.json()["data"]["attributes"]["status"]
        if status == "completed":
            break
        # Wait before polling again
        time.sleep(VT_POLL_INTERVAL)

    # 4️⃣ Check for malicious results
    stats = poll_resp.json()["data"]["attributes"]["stats"]
    if stats.get("malicious", 0) > 0:
        raise HTTPException(status_code=400, detail="File flagged as malicious")

    # 5️⃣ Upload to Cloudinary using BytesIO
    file_stream = BytesIO(file_bytes)
    cloud_resp = cloudinary.uploader.upload(file_stream, public_id=file.filename)
    cloud_url = cloud_resp.get("secure_url")

    return JSONResponse({"status": "done", "cloud_url": cloud_url})
