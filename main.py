import os

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import requests
import uvicorn

# ---------------- CONFIG ----------------
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"
ALLOWED_ORIGINS = ["*"]  # Replace with your app's domain in production
# ---------------------------------------

app = FastAPI()

# Enable CORS for Flutter or other clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HEADERS = {
    "x-apikey": VT_API_KEY
}


@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    """
    Uploads file to VirusTotal and returns analysis ID immediately.
    """
    try:
        # Read file content
        content = await file.read()
        files = {"file": (file.filename, content)}

        # Upload to VirusTotal
        response = requests.post(VT_UPLOAD_URL, headers=HEADERS, files=files)
        if response.status_code != 200 and response.status_code != 202:
            raise HTTPException(status_code=500, detail=f"VirusTotal upload failed: {response.text}")

        data = response.json()
        analysis_id = data.get("data", {}).get("id")
        if not analysis_id:
            raise HTTPException(status_code=500, detail=f"No analysis ID returned: {data}")

        return {"analysis_id": analysis_id}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/results/{analysis_id}")
def get_results(analysis_id: str):
    """
    Polls VirusTotal for scan results using analysis ID.
    """
    try:
        url = VT_ANALYSIS_URL.format(analysis_id)
        response = requests.get(url, headers=HEADERS)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        data = response.json()
        status = data["data"]["attributes"]["status"]

        if status != "completed":
            return {"status": status}

        results = data["data"]["attributes"]["results"]

        malicious_count = sum(1 for r in results.values() if r['category'] == 'malicious')
        suspicious_count = sum(1 for r in results.values() if r['category'] == 'suspicious')
        undetected_count = sum(1 for r in results.values() if r['category'] == 'undetected')

        return {
            "status": status,
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "undetected": undetected_count
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
