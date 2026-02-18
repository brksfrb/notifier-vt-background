import os
import time
import requests
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import cloudinary.uploader

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
CLOUDINARY_URL = os.environ.get("CLOUDINARY_URL")  # Cloudinary env

HEADERS = {"x-apikey": VT_API_KEY}
app = FastAPI()

VT_POLL_INTERVAL = 5  # seconds


@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    # 1️⃣ Send file to VirusTotal
    file_bytes = await file.read()
    files = {"file": (file.filename, file_bytes)}
    response = requests.post("https://www.virustotal.com/api/v3/files", headers=HEADERS, files=files)
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="VT upload failed")

    data = response.json()
    analysis_id = data["data"]["id"]

    # 2️⃣ Poll VT until scan completes
    while True:
        poll = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=HEADERS)
        if poll.status_code != 200:
            raise HTTPException(status_code=500, detail="VT poll failed")

        poll_data = poll.json()
        status = poll_data["data"]["attributes"]["status"]
        if status == "completed":
            break
        # Optional: return intermediate status
        # Could use StreamingResponse or just wait
        time.sleep(VT_POLL_INTERVAL)

    # 3️⃣ Upload to Cloudinary if scan passed
    # Example: simple check for malicious count
    stats = poll_data["data"]["attributes"]["stats"]
    if stats.get("malicious", 0) > 0:
        raise HTTPException(status_code=400, detail="File flagged as malicious")

    cloudinary_response = cloudinary.uploader.upload(file_bytes, public_id=file.filename)
    cloud_url = cloudinary_response.get("secure_url")

    return JSONResponse({"status": "done", "cloud_url": cloud_url})
