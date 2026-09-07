from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import base64
import struct
from urllib.parse import unquote_plus, urlencode, urlparse, urljoin, quote_plus
import re
from typing import Optional, Dict, List, Any
import json
from bs4 import BeautifulSoup

app = FastAPI(title="DeAsp - ASP.NET Pentesting Tool")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── ASP.NET field classification ─────────────────────────────────────────────

ASPNET_SYSTEM = {
    "__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION",
    "__LASTFOCUS", "__SCROLLPOSITIONX", "__SCROLLPOSITIONY",
    "__PREVIOUSPAGE", "__VIEWSTATEFIELDCOUNT", "__VIEWSTATEENCRYPTED",
}

ASPNET_EVENT = {"__EVENTTARGET", "__EVENTARGUMENT"}
ASPNET_AJAX  = {"__ASYNCPOST"}


def classify_param(name: str) -> str:
    d = unquote_plus(name)
    if d in ASPNET_SYSTEM:
        return "system"
    if d in ASPNET_EVENT:
        return "event"
    if d in ASPNET_AJAX:
        return "ajax"
    if re.match(r"^ctl\d*[_$]scriptManager", d, re.I) or "scriptManager_TSM" in d:
        return "ajax"
    if d.endswith("_TSM"):
        return "system"
    return "user"


# ── ViewState LOS decoder ─────────────────────────────────────────────────────

class _LOS:
    def __init__(self, data: bytes):
        self.d = data
        self.p = 0

    def _rb(self) -> int:
        if self.p >= len(self.d):
            raise ValueError("Unexpected EOF")
        b = self.d[self.p]; self.p += 1; return b

    def _ri32(self) -> int:
        v = struct.unpack_from("<i", self.d, self.p)[0]; self.p += 4; return v

    def _ri16(self) -> int:
        v = struct.unpack_from("<h", self.d, self.p)[0]; self.p += 2; return v

    def _rf(self) -> float:
        v = struct.unpack_from("<f", self.d, self.p)[0]; self.p += 4; return v

    def _rd(self) -> float:
        v = struct.unpack_from("<d", self.d, self.p)[0]; self.p += 8; return v

    def _r7(self) -> int:
        res = shift = 0
        while True:
            b = self._rb()
            res |= (b & 0x7F) << shift
            if not (b & 0x80): return res
            shift += 7
            if shift >= 35: raise ValueError("Bad 7-bit int")

    def _rs(self) -> str:
        n = self._r7()
        s = self.d[self.p:self.p + n].decode("utf-8", errors="replace"); self.p += n; return s

    def val(self, depth: int = 0) -> Any:
        if depth > 60:
            return {"_trunc": True}
        t = self._rb()
        if t == 0x00: return None
        if t == 0x01: return 0
        if t == 0x02: return False
        if t == 0x03: return True
        if t == 0x05: return self._rs()
        if t == 0x06: return ""
        if t == 0x0B: return self._ri32()
        if t == 0x32: return self._ri16()
        if t == 0x33: return self._rb()
        if t == 0x34: return chr(self._ri16())
        if t == 0x35: return self._rf()
        if t == 0x36: return self._rd()
        if t == 0x14:
            a = self.val(depth+1); b = self.val(depth+1)
            return {"_T": "Pair", "first": a, "second": b}
        if t == 0x15:
            a = self.val(depth+1); b = self.val(depth+1); c = self.val(depth+1)
            return {"_T": "Triplet", "first": a, "second": b, "third": c}
        if t == 0x16:
            n = self._r7()
            return {"_T": "ArrayList", "items": [self.val(depth+1) for _ in range(n)]}
        if t == 0x1B:
            n = self._r7()
            return {"_T": "StringArray", "items": [self._rs() for _ in range(n)]}
        if t == 0x1C:
            n = self._r7()
            return {"_T": "IntArray", "items": [self._ri32() for _ in range(n)]}
        if t in (0x0F, 0x10):
            label = "Hashtable" if t == 0x0F else "SortedList"
            n = self._r7()
            entries = {}
            for _ in range(n):
                k = self.val(depth+1); v = self.val(depth+1)
                entries[str(k)] = v
            return {"_T": label, "entries": entries}
        if t == 0x28:
            v = self._ri32()
            return {"_T": "Color", "hex": f"#{v & 0xFFFFFF:06X}", "alpha": (v >> 24) & 0xFF}
        if t == 0x1E:
            v = self._rs(); u = self._rb()
            units = {0:"px",1:"%",2:"em",3:"ex",4:"pt",5:"pc",6:"in",7:"mm",8:"cm"}
            return f"{v}{units.get(u, f'u{u}')}"
        if t == 0x1F: return "0"
        if t == 0x22:
            ti = self._r7(); n = self._r7()
            return {"_T": "TypedArray", "typeIdx": ti,
                    "items": [self.val(depth+1) for _ in range(n)]}
        return {"_T": f"unk_0x{t:02x}", "_hex": self.d[self.p:self.p+32].hex()}


def decode_viewstate(vs: str) -> Dict:
    vs = unquote_plus(vs.strip())
    try:
        data = base64.b64decode(vs + "==")
    except Exception as e:
        return {"error": f"Invalid base64: {e}", "raw": vs[:80]}

    if len(data) < 2 or data[0] != 0xFF or data[1] != 0x01:
        return {
            "error": f"Bad magic: {data[:2].hex() if data else 'empty'}",
            "decoded_bytes": len(data),
            "hex_preview": data[:32].hex(),
        }

    los = _LOS(data)
    los.p = 2
    try:
        value = los.val()
        mac = data[los.p:]
        mac_len = len(mac)
        alg = ("SHA1" if mac_len == 20 else "SHA256" if mac_len == 32
               else "AES/HMAC(16B)" if mac_len == 16
               else f"unknown ({mac_len}B)" if mac_len else None)
        return {
            "value": value,
            "mac_present": mac_len > 0,
            "mac_bytes": mac.hex() if mac else None,
            "mac_length": mac_len,
            "mac_algorithm": alg,
            "total_bytes": len(data),
            "serialized_bytes": los.p,
            "base64_length": len(vs),
            "hex_preview": data[:32].hex() + ("…" if len(data) > 32 else ""),
        }
    except Exception as e:
        return {
            "error": str(e),
            "partial": True,
            "hex_preview": data[:64].hex(),
            "decoded_bytes": len(data),
        }


# ── HTTP parser ───────────────────────────────────────────────────────────────

def _build_params(body: str, content_type: str) -> List[Dict]:
    params: List[Dict] = []
    if "application/x-www-form-urlencoded" not in content_type:
        if "application/json" in content_type:
            try:
                obj = json.loads(body)
                for k, v in obj.items():
                    params.append({
                        "name": k, "raw_name": k,
                        "value": json.dumps(v) if isinstance(v, (dict, list)) else str(v),
                        "raw_value": str(v), "type": "user", "editable": True, "is_json": True,
                    })
            except Exception:
                pass
        return params

    for pair in body.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, _, v = pair.partition("=")
            dk, dv = unquote_plus(k), unquote_plus(v)
            ptype = classify_param(dk)
            p: Dict = {
                "name": dk, "raw_name": k,
                "value": dv, "raw_value": v,
                "type": ptype, "editable": ptype == "user",
            }
            if dk in ("__VIEWSTATE", "__EVENTVALIDATION"):
                p["viewstate"] = decode_viewstate(dv)
            params.append(p)
        else:
            dk = unquote_plus(pair)
            params.append({
                "name": dk, "raw_name": pair,
                "value": "", "raw_value": "",
                "type": classify_param(dk), "editable": True,
            })
    return params


def parse_raw_http(raw: str) -> Dict:
    lines = raw.replace("\r\n", "\n").split("\n")
    if not lines:
        raise ValueError("Empty request")

    m = re.match(r"^(\w+)\s+(\S+)\s+(HTTP/[\d.]+)\s*$", lines[0].strip(), re.I)
    if not m:
        raise ValueError(f"Bad request line: {lines[0]!r}")

    method = m.group(1).upper()
    path   = m.group(2)
    ver    = m.group(3)

    headers: Dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, _, v = lines[i].partition(":")
            headers[k.strip()] = v.strip()
        i += 1

    body = "\n".join(lines[i + 1:]).strip() if i + 1 < len(lines) else ""
    ct   = headers.get("Content-Type", "")
    host = headers.get("Host", "")

    scheme = "https" if headers.get("X-Forwarded-Proto", "https") == "https" else "http"
    url = f"{scheme}://{host}{path}"

    params = _build_params(body, ct)

    return {
        "method": method, "path": path, "url": url,
        "http_version": ver, "headers": headers,
        "body": body, "params": params,
        "content_type": ct,
        "is_ajax": bool(headers.get("X-Requested-With")) or "__ASYNCPOST" in body,
        "is_aspnet": any(p["name"].startswith("__") for p in params),
    }


# ── AJAX response parser ──────────────────────────────────────────────────────

def parse_ajax_response(body: str) -> List[Dict]:
    parts: List[Dict] = []
    i = 0
    while i < len(body):
        p1 = body.find("|", i)
        if p1 == -1: break
        try:
            length = int(body[i:p1])
        except ValueError:
            break
        p2 = body.find("|", p1 + 1)
        if p2 == -1: break
        ptype = body[p1 + 1:p2]
        p3 = body.find("|", p2 + 1)
        if p3 == -1: break
        pid = body[p2 + 1:p3]
        cs = p3 + 1
        content = body[cs:cs + length]
        part: Dict = {"type": ptype, "id": pid, "content": content, "length": length}
        if ptype == "hiddenField" and pid == "__VIEWSTATE":
            part["viewstate_decoded"] = decode_viewstate(content)
            part["highlight"] = True
        elif ptype == "error":
            part["is_error"] = True
        elif ptype == "pageRedirect":
            part["redirect_url"] = content
        parts.append(part)
        i = cs + length + 1
    return parts


# ── Pydantic models ───────────────────────────────────────────────────────────

class RawReq(BaseModel):
    raw_request: str

class FetchUrl(BaseModel):
    url: str
    verify_ssl: bool = False
    cookies: Optional[str] = None

class Replay(BaseModel):
    method: str
    url: str
    headers: Dict[str, str]
    body: str
    verify_ssl: bool = False

class DecodeVS(BaseModel):
    viewstate: str

class CheckMac(BaseModel):
    method: str
    url: str
    headers: Dict[str, str]
    body: str
    viewstate_param: str = "__VIEWSTATE"
    verify_ssl: bool = False

class ParseAjax(BaseModel):
    body: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "tool": "DeAsp"}


@app.post("/api/parse-request")
async def api_parse_request(inp: RawReq):
    try:
        return parse_raw_http(inp.raw_request)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/fetch-url")
async def api_fetch_url(inp: FetchUrl):
    try:
        hdrs = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        cookies: Dict[str, str] = {}
        if inp.cookies:
            for c in inp.cookies.split(";"):
                c = c.strip()
                if "=" in c:
                    ck, _, cv = c.partition("=")
                    cookies[ck.strip()] = cv.strip()

        async with httpx.AsyncClient(verify=inp.verify_ssl, follow_redirects=True, timeout=30) as client:
            r = await client.get(inp.url, headers=hdrs, cookies=cookies)

        soup = BeautifulSoup(r.text, "lxml")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", inp.url) or inp.url
            if not action.startswith("http"):
                action = urljoin(inp.url, action)
            method = (form.get("method") or "POST").upper()
            params = []
            for el in form.find_all(["input", "select", "textarea"]):
                name = el.get("name", "")
                if not name:
                    continue
                value = el.get("value", "")
                itype = (el.get("type") or "text").lower()
                ptype = classify_param(name)
                p: Dict = {
                    "name": name, "raw_name": name,
                    "value": value, "raw_value": value,
                    "type": ptype,
                    "editable": ptype == "user" or itype not in ("hidden",),
                    "input_type": itype,
                }
                if name == "__VIEWSTATE" and value:
                    p["viewstate"] = decode_viewstate(value)
                params.append(p)
            forms.append({"action": action, "method": method, "params": params})

        return {
            "url": str(r.url), "status": r.status_code,
            "forms": forms, "cookies": dict(r.cookies),
            "aspnet_session": r.cookies.get("ASP.NET_SessionId"),
        }
    except httpx.RequestError as e:
        raise HTTPException(502, f"Request failed: {e}")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/replay")
async def api_replay(inp: Replay):
    try:
        hdrs = {k: v for k, v in inp.headers.items()
                if k.lower() not in ("content-length", "connection")}
        async with httpx.AsyncClient(verify=inp.verify_ssl, follow_redirects=False, timeout=30) as client:
            r = await client.request(inp.method, inp.url, headers=hdrs,
                                     content=inp.body.encode())

        body_text = r.text
        ajax_parts: List[Dict] = []
        if re.match(r"^\d+\|", body_text[:30]):
            try:
                ajax_parts = parse_ajax_response(body_text)
            except Exception:
                pass

        return {
            "status": r.status_code,
            "headers": dict(r.headers),
            "body": body_text,
            "is_ajax": bool(ajax_parts),
            "ajax_parts": ajax_parts,
            "content_type": r.headers.get("Content-Type", ""),
            "aspnet_error": r.status_code == 500 or "Runtime Error" in body_text,
            "viewstate_error": "viewstate" in body_text.lower() and
                               any(x in body_text.lower() for x in ("invalid", "tamper", "mac")),
        }
    except httpx.RequestError as e:
        raise HTTPException(502, f"Request failed: {e}")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/decode-viewstate")
async def api_decode_viewstate(inp: DecodeVS):
    return decode_viewstate(inp.viewstate)


@app.post("/api/check-mac")
async def api_check_mac(inp: CheckMac):
    body_params: Dict[str, str] = {}
    for pair in inp.body.split("&"):
        if "=" in pair:
            k, _, v = pair.partition("=")
            body_params[unquote_plus(k)] = unquote_plus(v)

    vs_val = body_params.get(inp.viewstate_param)
    if not vs_val:
        raise HTTPException(400, f"No {inp.viewstate_param} in body")

    try:
        vs_bytes = base64.b64decode(vs_val + "==")
    except Exception:
        raise HTTPException(400, "Invalid ViewState base64")

    vs_info = decode_viewstate(vs_val)
    if not vs_info.get("mac_present"):
        return {
            "mac_present_in_viewstate": False,
            "test_result": "no_mac",
            "message": "No MAC bytes detected — may already be MAC-less or unexpected format.",
        }

    mac_len = vs_info["mac_length"]
    stripped = vs_bytes[:-mac_len]
    stripped_b64 = base64.b64encode(stripped).decode()

    new_pairs = []
    for pair in inp.body.split("&"):
        if not pair: continue
        if "=" in pair:
            k, _, v = pair.partition("=")
            if unquote_plus(k) == inp.viewstate_param:
                new_pairs.append(f"{k}={quote_plus(stripped_b64)}")
            else:
                new_pairs.append(pair)
        else:
            new_pairs.append(pair)
    new_body = "&".join(new_pairs)

    hdrs = {k: v for k, v in inp.headers.items()
            if k.lower() not in ("content-length", "connection")}
    try:
        async with httpx.AsyncClient(verify=inp.verify_ssl, follow_redirects=False, timeout=30) as client:
            r = await client.request(inp.method, inp.url, headers=hdrs,
                                     content=new_body.encode())
        bl = r.text.lower()
        vs_err = any(x in bl for x in ("viewstate", "mac", "tamper", "invalid state", "state information"))
        if r.status_code == 500 or vs_err:
            result = "mac_enabled"; vuln = False
            msg = "MAC validation is ENABLED — server rejected the tampered ViewState."
        else:
            result = "mac_disabled"; vuln = True
            msg = "⚠ MAC validation appears DISABLED — server accepted the tampered ViewState!"
        return {
            "mac_present_in_viewstate": True,
            "mac_length": mac_len,
            "mac_algorithm": vs_info.get("mac_algorithm"),
            "test_result": result,
            "vulnerable": vuln,
            "message": msg,
            "response_status": r.status_code,
            "stripped_viewstate": stripped_b64,
        }
    except httpx.RequestError as e:
        raise HTTPException(502, f"Request failed: {e}")


@app.post("/api/parse-ajax-response")
async def api_parse_ajax(inp: ParseAjax):
    return {"parts": parse_ajax_response(inp.body)}
