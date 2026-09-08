from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import base64
import struct
from urllib.parse import unquote_plus, unquote, urljoin, quote_plus
import re
from typing import Optional, Dict, List, Any
import json
from bs4 import BeautifulSoup

app = FastAPI(title="DeAsp")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── ASP.NET field classification ──────────────────────────────────────────────

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
        self.d = data; self.p = 0

    def _rb(self) -> int:
        if self.p >= len(self.d): raise ValueError("EOF")
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
            b = self._rb(); res |= (b & 0x7F) << shift
            if not (b & 0x80): return res
            shift += 7
            if shift >= 35: raise ValueError("Bad 7-bit int")

    def _rs(self) -> str:
        n = self._r7()
        s = self.d[self.p:self.p+n].decode("utf-8", errors="replace"); self.p += n; return s

    def val(self, depth: int = 0) -> Any:
        if depth > 60: return {"_trunc": True}
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
            return {"_T": "Pair", "first": self.val(depth+1), "second": self.val(depth+1)}
        if t == 0x15:
            return {"_T": "Triplet", "first": self.val(depth+1), "second": self.val(depth+1), "third": self.val(depth+1)}
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
            n = self._r7(); entries = {}
            for _ in range(n):
                k = self.val(depth+1); v = self.val(depth+1); entries[str(k)] = v
            return {"_T": "Hashtable" if t == 0x0F else "SortedList", "entries": entries}
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
            return {"_T": "TypedArray", "typeIdx": ti, "items": [self.val(depth+1) for _ in range(n)]}
        return {"_T": f"unk_0x{t:02x}", "_hex": self.d[self.p:self.p+32].hex()}


def _b64pad(s: str) -> str:
    """Pad a base64 string to a valid length without corrupting already-padded input."""
    return s + "=" * (-len(s) % 4)


def decode_viewstate(vs: str) -> Dict:
    # NOTE: caller must pass already-decoded base64 (raw '+' is a valid base64
    # character and must NOT be run through unquote_plus here, or it gets
    # corrupted into a space — see api_decode_viewstate for the one safe place
    # to unescape %XX sequences from copy-pasted URL-encoded input).
    vs = vs.strip()
    try:
        data = base64.b64decode(_b64pad(vs))
    except Exception as e:
        return {"error": f"Invalid base64: {e}", "raw": vs[:80]}

    if len(data) < 2 or data[0] != 0xFF or data[1] != 0x01:
        return {"error": f"Bad magic: {data[:2].hex() if data else 'empty'}", "decoded_bytes": len(data), "hex_preview": data[:32].hex()}

    los = _LOS(data); los.p = 2
    try:
        value = los.val()
        mac = data[los.p:]
        mac_len = len(mac)
        alg = ("SHA1" if mac_len == 20 else "SHA256" if mac_len == 32
               else "AES/HMAC(16B)" if mac_len == 16
               else f"unknown ({mac_len}B)" if mac_len else None)
        return {
            "value": value, "mac_present": mac_len > 0,
            "mac_bytes": mac.hex() if mac else None,
            "mac_length": mac_len, "mac_algorithm": alg,
            "total_bytes": len(data), "serialized_bytes": los.p,
            "base64_length": len(vs),
            "hex_preview": data[:32].hex() + ("…" if len(data) > 32 else ""),
        }
    except Exception as e:
        return {"error": str(e), "partial": True, "hex_preview": data[:64].hex(), "decoded_bytes": len(data)}


# ── HTTP parser ───────────────────────────────────────────────────────────────

def _parse_query_params(query_string: str) -> List[Dict]:
    """Parse a URL query string into editable params tagged source='query'."""
    params: List[Dict] = []
    for pair in query_string.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, _, v = pair.partition("=")
            dk, dv = unquote_plus(k), unquote_plus(v)
        else:
            dk, dv = unquote_plus(pair), ""
        ptype = classify_param(dk)
        params.append({
            "name": dk, "raw_name": k if "=" in pair else pair,
            "value": dv, "raw_value": v if "=" in pair else "",
            "type": ptype, "editable": True, "source": "query",
        })
    return params


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
                        "raw_value": str(v), "type": "user", "editable": True,
                        "is_json": True, "source": "body",
                    })
            except Exception:
                pass
        return params

    for pair in body.split("&"):
        if not pair: continue
        if "=" in pair:
            k, _, v = pair.partition("=")
            dk, dv = unquote_plus(k), unquote_plus(v)
            ptype = classify_param(dk)
            p: Dict = {
                "name": dk, "raw_name": k, "value": dv, "raw_value": v,
                "type": ptype, "editable": ptype == "user", "source": "body",
            }
            if dk in ("__VIEWSTATE", "__EVENTVALIDATION"):
                p["viewstate"] = decode_viewstate(dv)
            params.append(p)
        else:
            dk = unquote_plus(pair)
            params.append({"name": dk, "raw_name": pair, "value": "", "raw_value": "",
                           "type": classify_param(dk), "editable": True, "source": "body"})
    return params


def _infer_scheme(host: str, force_scheme: Optional[str]) -> str:
    """
    Raw pasted HTTP requests carry no scheme. Production ASP.NET targets are
    overwhelmingly HTTPS, so that's the default — but legacy/intranet ASP.NET
    apps commonly run plaintext HTTP, and an explicit ':80' in the Host header
    is an unambiguous signal for that. force_scheme (from the UI toggle) always
    wins when the caller knows better than either heuristic.
    """
    if force_scheme in ("http", "https"):
        return force_scheme
    if host.endswith(":80"):
        return "http"
    return "https"


def parse_raw_http(raw: str, force_scheme: Optional[str] = None) -> Dict:
    lines = raw.replace("\r\n", "\n").split("\n")
    if not lines: raise ValueError("Empty request")
    m = re.match(r"^(\w+)\s+(\S+)\s+(HTTP/[\d.]+)\s*$", lines[0].strip(), re.I)
    if not m: raise ValueError(f"Bad request line: {lines[0]!r}")

    method, path, ver = m.group(1).upper(), m.group(2), m.group(3)
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
    scheme = _infer_scheme(host, force_scheme)

    path_only, _, query_string = path.partition("?")
    url      = f"{scheme}://{host}{path}"
    url_base = f"{scheme}://{host}{path_only}"

    query_params = _parse_query_params(query_string)
    body_params  = _build_params(body, ct)
    params = query_params + body_params

    return {
        "method": method, "path": path, "url": url, "url_base": url_base,
        "scheme": scheme,
        "http_version": ver, "headers": headers, "body": body,
        "params": params, "content_type": ct,
        "is_ajax": bool(headers.get("X-Requested-With")) or "__ASYNCPOST" in body,
        "is_aspnet": any(p["name"].startswith("__") for p in params),
        "has_query_params": bool(query_params),
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
        ptype = body[p1+1:p2]
        p3 = body.find("|", p2 + 1)
        if p3 == -1: break
        pid = body[p2+1:p3]
        cs = p3 + 1
        content = body[cs:cs+length]
        part: Dict = {"type": ptype, "id": pid, "content": content, "length": length}
        if ptype == "hiddenField" and pid == "__VIEWSTATE":
            part["viewstate_decoded"] = decode_viewstate(content)
            part["highlight"] = True
        elif ptype == "error":
            part["is_error"] = True
        elif ptype == "pageRedirect":
            part["redirect_url"] = content
        elif ptype == "updatePanel":
            # Extract visible text from the HTML for summary
            try:
                soup = BeautifulSoup(content, "lxml")
                part["text_preview"] = soup.get_text(separator=" ", strip=True)[:300]
            except Exception:
                pass
        parts.append(part)
        i = cs + length + 1
    return parts


# ── Cookie jar (in-memory, per-session via header) ────────────────────────────
# We keep it simple: client sends cookies string, we use it.

def _cookie_dict(cookie_str: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for c in (cookie_str or "").split(";"):
        c = c.strip()
        if "=" in c:
            k, _, v = c.partition("=")
            out[k.strip()] = v.strip()
    return out


def _safe_httpx_cookie_dict(cookies) -> Dict[str, str]:
    """
    Build a plain {name: value} dict from an httpx.Cookies jar.

    httpx.Cookies.get()/__getitem__() (and therefore dict(cookies), which
    uses them under the hood) raises CookieConflict as soon as the SAME
    cookie name shows up more than once with a different domain/path —
    e.g. the app sets 'CurrentUserFullName' at '/' and the client also
    already holds one scoped to a specific path from an earlier response.
    That's normal, valid cookie-jar state, not an error condition, so we
    walk the underlying jar directly instead of using the conflict-raising
    accessors. Last one encountered wins — fine here since this dict is
    only used for display/reuse convenience, not strict cookie semantics.
    """
    out: Dict[str, str] = {}
    for cookie in cookies.jar:
        out[cookie.name] = cookie.value
    return out


def _cookie_str(d: Dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in d.items())


# ── Pydantic models ───────────────────────────────────────────────────────────

class RawReq(BaseModel):
    raw_request: str
    force_scheme: Optional[str] = None   # "http" | "https" | None (auto-detect)

class FetchUrl(BaseModel):
    url: str
    verify_ssl: bool = False
    cookies: Optional[str] = None

class LoginFlow(BaseModel):
    login_url: str
    method: str = "POST"
    credentials: Dict[str, str]   # {"username_field": "val", "password_field": "val"}
    verify_ssl: bool = False
    extra_cookies: Optional[str] = None

class Replay(BaseModel):
    method: str
    url: str
    headers: Dict[str, str]
    body: str
    verify_ssl: bool = False
    extra_cookies: Optional[str] = None

class DecodeVS(BaseModel):
    viewstate: str

class CheckMac(BaseModel):
    method: str
    url: str
    headers: Dict[str, str]
    body: str
    viewstate_param: str = "__VIEWSTATE"
    verify_ssl: bool = False
    extra_cookies: Optional[str] = None

class ParseAjax(BaseModel):
    body: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "tool": "DeAsp"}


@app.post("/api/parse-request")
async def api_parse_request(inp: RawReq):
    try:
        return parse_raw_http(inp.raw_request, inp.force_scheme)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/fetch-url")
async def api_fetch_url(inp: FetchUrl):
    """Fetch a URL, auto-fill ViewState/hidden fields, return only user params."""
    try:
        cookies = _cookie_dict(inp.cookies or "")
        hdrs = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-AU,en;q=0.5",
        }
        async with httpx.AsyncClient(verify=inp.verify_ssl, follow_redirects=True, timeout=30,
                                     cookies=cookies) as client:
            r = await client.get(inp.url, headers=hdrs)

        # Merge any new cookies from response
        all_cookies = {**cookies, **_safe_httpx_cookie_dict(r.cookies)}

        soup = BeautifulSoup(r.text, "lxml")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or inp.url
            if not action.startswith("http"):
                action = urljoin(str(r.url), action)
            method = (form.get("method") or "POST").upper()
            all_params = []
            user_params = []
            for el in form.find_all(["input", "select", "textarea"]):
                name = el.get("name", "")
                if not name: continue
                value = el.get("value", "")
                itype = (el.get("type") or "text").lower()
                ptype = classify_param(name)
                p: Dict = {
                    "name": name, "raw_name": name,
                    "value": value, "raw_value": value,
                    "type": ptype, "editable": ptype == "user",
                    "input_type": itype,
                }
                if name == "__VIEWSTATE" and value:
                    p["viewstate"] = decode_viewstate(value)
                all_params.append(p)
                if ptype == "user":
                    user_params.append(p)

            forms.append({
                "action": action, "method": method,
                "all_params": all_params,
                "user_params": user_params,
                "param_counts": {
                    "user": len([x for x in all_params if x["type"] == "user"]),
                    "event": len([x for x in all_params if x["type"] == "event"]),
                    "ajax": len([x for x in all_params if x["type"] == "ajax"]),
                    "system": len([x for x in all_params if x["type"] == "system"]),
                },
            })

        return {
            "url": str(r.url), "status": r.status_code,
            "forms": forms,
            "cookies": all_cookies,
            "aspnet_session": all_cookies.get("ASP.NET_SessionId"),
            "set_cookie_header": r.headers.get("set-cookie", ""),
        }
    except httpx.RequestError as e:
        raise HTTPException(502, f"Request failed: {e}")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/login")
async def api_login(inp: LoginFlow):
    """
    Two-step login: GET the login page (grab ViewState), then POST credentials.
    Returns the resulting cookies so the client can store them.
    """
    try:
        init_cookies = _cookie_dict(inp.extra_cookies or "")
        hdrs = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        async with httpx.AsyncClient(verify=inp.verify_ssl, follow_redirects=True,
                                     timeout=30, cookies=init_cookies) as client:
            # Step 1 — GET the login page to grab ViewState etc.
            get_r = await client.get(inp.login_url, headers=hdrs)
            soup = BeautifulSoup(get_r.text, "lxml")

            # Build form body
            form_data: Dict[str, str] = {}
            form = soup.find("form")
            if form:
                for el in form.find_all("input"):
                    n = el.get("name", "")
                    v = el.get("value", "")
                    if n: form_data[n] = v

            # Override with provided credentials
            form_data.update(inp.credentials)

            # Determine submit URL
            action = (form.get("action") if form else None) or inp.login_url
            if not action.startswith("http"):
                action = urljoin(str(get_r.url), action)

            post_hdrs = {**hdrs, "Content-Type": "application/x-www-form-urlencoded",
                         "Referer": str(get_r.url)}

            # Step 2 — POST the login
            post_r = await client.post(
                action, headers=post_hdrs,
                data=form_data,
            )

        # Collect all cookies across redirects
        all_cookies = {**init_cookies, **_safe_httpx_cookie_dict(client.cookies)}
        session_id = all_cookies.get("ASP.NET_SessionId")

        # Detect login success heuristically
        post_body = post_r.text.lower()
        hints_fail = any(x in post_body for x in ("invalid password", "incorrect", "failed", "error", "login"))
        hints_ok   = not hints_fail or post_r.status_code in (302, 200) and bool(session_id)

        return {
            "login_url": inp.login_url,
            "submit_url": action,
            "response_status": post_r.status_code,
            "final_url": str(post_r.url),
            "cookies": all_cookies,
            "aspnet_session": session_id,
            "likely_success": hints_ok,
            "set_cookie_headers": dict(post_r.headers.multi_items()),
        }
    except httpx.RequestError as e:
        raise HTTPException(502, f"Request failed: {e}")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/replay")
async def api_replay(inp: Replay):
    try:
        extra_cookies = _cookie_dict(inp.extra_cookies or "")
        existing = _cookie_dict(inp.headers.get("Cookie", ""))
        merged = {**existing, **extra_cookies}

        hdrs = {k: v for k, v in inp.headers.items()
                if k.lower() not in ("content-length", "connection", "cookie")}
        if merged:
            hdrs["Cookie"] = _cookie_str(merged)

        async with httpx.AsyncClient(verify=inp.verify_ssl, follow_redirects=False, timeout=30) as client:
            r = await client.request(inp.method, inp.url, headers=hdrs, content=inp.body.encode())

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
            "new_cookies": _safe_httpx_cookie_dict(r.cookies),
        }
    except httpx.RequestError as e:
        raise HTTPException(502, f"Request failed: {e}")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/decode-viewstate")
async def api_decode_vs(inp: DecodeVS):
    # unquote (not unquote_plus) only touches %XX escapes and leaves a literal
    # '+' alone, so it's safe whether the user pastes raw base64 or a
    # URL-encoded value copied straight out of a request body.
    return decode_viewstate(unquote(inp.viewstate.strip()))


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
        vs_bytes = base64.b64decode(_b64pad(vs_val))
    except Exception:
        raise HTTPException(400, "Invalid ViewState base64")

    vs_info = decode_viewstate(vs_val)
    if not vs_info.get("mac_present"):
        return {
            "mac_present_in_viewstate": False, "test_result": "no_mac",
            "message": "No MAC bytes detected — already MAC-less or unexpected format.",
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

    extra_cookies = _cookie_dict(inp.extra_cookies or "")
    existing = _cookie_dict(inp.headers.get("Cookie", ""))
    merged = {**existing, **extra_cookies}
    hdrs = {k: v for k, v in inp.headers.items() if k.lower() not in ("content-length", "connection", "cookie")}
    if merged:
        hdrs["Cookie"] = _cookie_str(merged)

    try:
        async with httpx.AsyncClient(verify=inp.verify_ssl, follow_redirects=False, timeout=30) as client:
            r = await client.request(inp.method, inp.url, headers=hdrs, content=new_body.encode())
        bl = r.text.lower()
        vs_err = any(x in bl for x in ("viewstate", "mac", "tamper", "invalid state", "state information"))
        if r.status_code == 500 or vs_err:
            result = "mac_enabled"; vuln = False
            msg = "MAC validation ENABLED — server rejected the tampered ViewState."
        else:
            result = "mac_disabled"; vuln = True
            msg = "⚠ MAC validation DISABLED — server accepted tampered ViewState!"
        return {
            "mac_present_in_viewstate": True,
            "mac_length": mac_len, "mac_algorithm": vs_info.get("mac_algorithm"),
            "test_result": result, "vulnerable": vuln, "message": msg,
            "response_status": r.status_code, "stripped_viewstate": stripped_b64,
        }
    except httpx.RequestError as e:
        raise HTTPException(502, f"Request failed: {e}")


@app.post("/api/parse-ajax-response")
async def api_parse_ajax(inp: ParseAjax):
    return {"parts": parse_ajax_response(inp.body)}
