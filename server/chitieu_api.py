#!/usr/bin/env python3
"""Sổ Thu Chi 360 — API server v2 cho đường deploy Oracle.

Nhiệm vụ:
- Phục vụ tĩnh: GET /chitieu/ và /chitieu/index.html -> index.html.
- Dữ liệu bền trên volume server, xác thực bằng token HMAC tự chứa:
    GET  /chitieu-api/data   (header X-Link-Token)
    POST /chitieu-api/data   (header X-Link-Token, body = toàn bộ state)
- Hàng đợi OCR dùng chung cho Mini App và worker phía VM:
    POST /chitieu-api/ocr          -> tạo job pending, trả job_id
    GET  /chitieu-api/ocr-status   -> chủ job xem trạng thái/kết quả
    GET  /chitieu-api/ocr-pending  -> worker liệt kê job pending (không có ảnh)
    GET  /chitieu-api/ocr-job      -> worker lấy nội dung một job (có ảnh)
    POST /chitieu-api/ocr-result   -> worker ghi items hoặc error

Token worker có uid đúng bằng chuỗi "worker" và dùng cùng link secret.
State lưu tại CHITIEU_DATA_DIR/data-<uid>.json; job lưu tại
CHITIEU_DATA_DIR/ocr-jobs/<job-id>.json. Job quá 24 giờ được dọn khi có
request OCR mới.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DATA_DIR = os.environ.get("CHITIEU_DATA_DIR", "/data")
STATIC_DIR = os.environ.get("CHITIEU_STATIC_DIR", "/srv/chitieu")
SECRET = os.environ.get("CHITIEU_LINK_SECRET", "")
PORT = int(os.environ.get("CHITIEU_PORT", "8091"))
LOCK = threading.Lock()
MAX_BODY = 4_000_000
MAX_OCR_BODY = 8_000_000
JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,100}$")
ALLOWED_IMAGE_MIMES = {"image/jpeg", "image/png", "image/webp"}


def _b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify_token(token):
    try:
        p, s = token.split(".", 1)
        expected = hmac.new(SECRET.encode(), p.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64d(s)):
            return None
        payload = json.loads(_b64d(p).decode())
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def _jobs_dir():
    path = os.path.join(DATA_DIR, "ocr-jobs")
    os.makedirs(path, exist_ok=True)
    return path


def _job_path(job_id):
    if not JOB_ID_RE.match(job_id or ""):
        return None
    return os.path.join(_jobs_dir(), job_id + ".json")


def _atomic_write_json(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False)
    os.replace(tmp, path)


def _read_job(job_id):
    path = _job_path(job_id)
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _cleanup_old_jobs(now=None):
    """Xóa job có created quá 24 giờ. Trả số job đã xóa."""
    now = time.time() if now is None else now
    removed = 0
    try:
        names = os.listdir(_jobs_dir())
    except FileNotFoundError:
        return 0
    for name in names:
        if not name.endswith(".json"):
            continue
        path = os.path.join(_jobs_dir(), name)
        try:
            with open(path, encoding="utf-8") as f:
                job = json.load(f)
            created = float(job.get("created") or 0)
        except Exception:
            try:
                created = os.path.getmtime(path)
            except OSError:
                continue
        if created and now - created > 24 * 3600:
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
    return removed


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _payload(self):
        if not SECRET:
            return None
        return verify_token(self.headers.get("X-Link-Token") or "")

    def _uid(self):
        payload = self._payload()
        return payload.get("uid") if payload else None

    def _require_uid(self):
        uid = self._uid()
        if uid is None:
            self._send(403, {"ok": False, "error": "bad token"})
        return uid

    def _require_worker(self):
        uid = self._uid()
        if uid != "worker":
            self._send(403, {"ok": False, "error": "worker token required"})
            return False
        return True

    def _read_body(self, max_body):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > max_body:
            self._send(400, {"ok": False, "error": "bad size"})
            return None
        return self.rfile.read(length)

    def _read_json_body(self, max_body):
        raw = self._read_body(max_body)
        if raw is None:
            return None
        try:
            value = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send(400, {"ok": False, "error": "bad json"})
            return None
        if not isinstance(value, dict):
            self._send(400, {"ok": False, "error": "json object required"})
            return None
        return value

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path in ("/chitieu/", "/chitieu/index.html", "/chitieu"):
            file_path = os.path.join(STATIC_DIR, "index.html")
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            else:
                self._send(404, {"ok": False, "error": "no app"})
            return

        if path == "/chitieu-api/health":
            self._send(200, {"ok": True})
            return

        if path == "/chitieu-api/data":
            uid = self._require_uid()
            if uid is None:
                return
            file_path = os.path.join(DATA_DIR, f"data-{uid}.json")
            if os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    self._send(200, f.read())
            else:
                self._send(200, {})
            return

        if path == "/chitieu-api/ocr-status":
            uid = self._require_uid()
            if uid is None:
                return
            job_id = (query.get("id") or [""])[0]
            job = _read_job(job_id)
            if not job:
                self._send(404, {"ok": False, "error": "job not found"})
                return
            if job.get("uid") != uid:
                self._send(403, {"ok": False, "error": "job belongs to another user"})
                return
            result = {"ok": True, "id": job.get("id"), "status": job.get("status")}
            if job.get("status") == "done":
                result["items"] = job.get("items") or []
                if job.get("receipt"):
                    result["receipt"] = job["receipt"]
            elif job.get("status") == "error":
                result["error"] = job.get("error") or "OCR failed"
            self._send(200, result)
            return

        if path == "/chitieu-api/ocr-pending":
            if not self._require_worker():
                return
            with LOCK:
                _cleanup_old_jobs()
                jobs = []
                try:
                    names = os.listdir(_jobs_dir())
                except FileNotFoundError:
                    names = []
                for name in names:
                    if not name.endswith(".json"):
                        continue
                    job = _read_job(name[:-5])
                    if job and job.get("status") == "pending":
                        jobs.append({
                            "id": job.get("id"),
                            "uid": job.get("uid"),
                            "mime": job.get("mime"),
                            "created": job.get("created"),
                        })
            jobs.sort(key=lambda item: item.get("created") or 0)
            self._send(200, {"ok": True, "jobs": jobs})
            return

        if path == "/chitieu-api/ocr-job":
            if not self._require_worker():
                return
            job_id = (query.get("id") or [""])[0]
            job = _read_job(job_id)
            if not job:
                self._send(404, {"ok": False, "error": "job not found"})
                return
            self._send(200, {
                "ok": True,
                "id": job.get("id"),
                "uid": job.get("uid"),
                "image": job.get("image"),
                "mime": job.get("mime"),
                "status": job.get("status"),
                "created": job.get("created"),
            })
            return

        self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/chitieu-api/data":
            uid = self._require_uid()
            if uid is None:
                return
            raw = self._read_body(MAX_BODY)
            if raw is None:
                return
            try:
                json.loads(raw.decode("utf-8"))
            except Exception:
                self._send(400, {"ok": False, "error": "bad json"})
                return
            file_path = os.path.join(DATA_DIR, f"data-{uid}.json")
            with LOCK:
                tmp = file_path + ".tmp"
                with open(tmp, "wb") as f:
                    f.write(raw)
                os.replace(tmp, file_path)
            self._send(200, {"ok": True, "bytes": len(raw)})
            return

        if path == "/chitieu-api/ocr":
            uid = self._require_uid()
            if uid is None:
                return
            body = self._read_json_body(MAX_OCR_BODY)
            if body is None:
                return
            image = body.get("image")
            mime = str(body.get("mime") or "image/jpeg").lower()
            if not isinstance(image, str) or not image:
                self._send(400, {"ok": False, "error": "image required"})
                return
            if mime not in ALLOWED_IMAGE_MIMES:
                self._send(400, {"ok": False, "error": "unsupported image mime"})
                return
            try:
                decoded = base64.b64decode(image, validate=True)
            except Exception:
                self._send(400, {"ok": False, "error": "image is not valid base64"})
                return
            if not decoded or len(decoded) > 6_000_000:
                self._send(400, {"ok": False, "error": "image size out of range"})
                return
            job_id = "ocr_" + secrets.token_urlsafe(18).replace("-", "_")
            job = {
                "id": job_id,
                "uid": uid,
                "image": image,
                "mime": mime,
                "status": "pending",
                "created": time.time(),
            }
            with LOCK:
                _cleanup_old_jobs()
                _atomic_write_json(_job_path(job_id), job)
            self._send(200, {"ok": True, "job_id": job_id, "id": job_id})
            return

        if path == "/chitieu-api/ocr-result":
            if not self._require_worker():
                return
            body = self._read_json_body(MAX_BODY)
            if body is None:
                return
            job_id = str(body.get("id") or "")
            job_path = _job_path(job_id)
            if not job_path:
                self._send(400, {"ok": False, "error": "bad job id"})
                return
            with LOCK:
                job = _read_job(job_id)
                if not job:
                    self._send(404, {"ok": False, "error": "job not found"})
                    return
                if "error" in body and body.get("error"):
                    job["status"] = "error"
                    job["error"] = str(body["error"])[:1000]
                    job.pop("items", None)
                elif isinstance(body.get("items"), list):
                    job["status"] = "done"
                    job["items"] = body["items"]
                    if isinstance(body.get("receipt"), dict):
                        job["receipt"] = body["receipt"]
                    job.pop("error", None)
                else:
                    self._send(400, {"ok": False, "error": "items or error required"})
                    return
                job["completed"] = time.time()
                _atomic_write_json(job_path, job)
            self._send(200, {"ok": True, "id": job_id, "status": job["status"]})
            return

        self._send(404, {"ok": False, "error": "not found"})


if __name__ == "__main__":
    os.makedirs(DATA_DIR, exist_ok=True)
    _jobs_dir()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
