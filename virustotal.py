from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import requests

VT_API_BASE = "https://www.virustotal.com/api/v3"


def _api_key() -> Optional[str]:
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    return key or None


def _headers() -> Dict[str, str]:
    return {"x-apikey": _api_key() or ""}


def scan_url_virustotal(url: str) -> Dict[str, Any]:
    api_key = _api_key()
    if not api_key:
        return {
            "ok": False,
            "enabled": False,
            "error": "VirusTotal API key is not configured",
        }

    clean_url = (url or "").strip()
    if not clean_url:
        return {"ok": False, "enabled": True, "error": "URL is empty"}

    try:
        submit = requests.post(
            f"{VT_API_BASE}/urls",
            headers=_headers(),
            data={"url": clean_url},
            timeout=20,
        )
        if submit.status_code not in (200, 201):
            return {
                "ok": False,
                "enabled": True,
                "error": f"VirusTotal submit failed: HTTP {submit.status_code}",
            }

        analysis_id = submit.json().get("data", {}).get("id")
        if not analysis_id:
            return {"ok": False, "enabled": True, "error": "VirusTotal did not return an analysis ID"}

        last_payload: Dict[str, Any] = {}
        for _ in range(5):
            result = requests.get(
                f"{VT_API_BASE}/analyses/{analysis_id}",
                headers=_headers(),
                timeout=20,
            )
            if result.status_code != 200:
                return {
                    "ok": False,
                    "enabled": True,
                    "error": f"VirusTotal fetch failed: HTTP {result.status_code}",
                }

            payload = result.json()
            last_payload = payload
            attributes = payload.get("data", {}).get("attributes", {})
            if attributes.get("status") == "completed":
                stats = attributes.get("stats", {})
                return {
                    "ok": True,
                    "enabled": True,
                    "status": attributes.get("status", "completed"),
                    "analysis_id": analysis_id,
                    "malicious": int(stats.get("malicious", 0) or 0),
                    "suspicious": int(stats.get("suspicious", 0) or 0),
                    "harmless": int(stats.get("harmless", 0) or 0),
                    "undetected": int(stats.get("undetected", 0) or 0),
                }

            time.sleep(1.5)

        attributes = last_payload.get("data", {}).get("attributes", {})
        stats = attributes.get("stats", {})
        return {
            "ok": True,
            "enabled": True,
            "status": attributes.get("status", "queued"),
            "analysis_id": analysis_id,
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
        }
    except requests.RequestException as exc:
        return {"ok": False, "enabled": True, "error": f"VirusTotal request failed: {exc}"}
    except Exception as exc:
        return {"ok": False, "enabled": True, "error": str(exc)}
