#!/usr/bin/env python3
"""Import PTE Magic "share answer" links into SiYuan.

Each link looks like:
    https://ptemagic.com/pte-academic/share-answer?id=0123456789abcdef01234567

For every link the script creates one SiYuan document in the notebook "English" (--notebook) under
the document "PTE" (--root) at
    /PTE/<NN Skill>/<Question type>/<QID> (<YYYY-MM-DD HH:MM>)
for example  /PTE/01 Speaking/Read Aloud/RA0006 (2026-10-15 17:17), containing the score
breakdown, the audio recording (downloaded into SiYuan's assets), the content, pronunciation
and fluency breakdowns. Read Aloud gets the full layout; other question types get a generic
layout (header, scores, your answer, question text).

Usage:
    python3 pte-import/pte_import.py URL_OR_ID [URL_OR_ID ...]
    python3 pte-import/pte_import.py --file links.txt        # one link per line, '#' comments ok
    python3 pte-import/pte_import.py --dry-run URL           # print Markdown, touch nothing
    python3 pte-import/pte_import.py --force URL             # replace an already imported attempt

Options: --notebook NAME, --root NAME, --no-audio, --tz Asia/Ho_Chi_Minh, --no-dashboard, --refresh-dashboard

After importing, the "Progress by question type" and "Recent attempts" tables on
"/PTE/00 Dashboard" are rebuilt from the attributes saved on every attempt document
(created on first use, updated in place afterwards). `--refresh-dashboard` rebuilds them without importing.

SiYuan connection: read from the project's .env (SIYUAN_PORT, SIYUAN_ACCESS_AUTH_CODE) or from the
environment (SIYUAN_URL, SIYUAN_ACCESS_AUTH_CODE). The code is never printed.

Re-running is safe: an attempt is identified by its share id (stored as the document attribute
custom-pte-share-id) and is skipped if it already exists.

How the data is fetched: the share page is a single-page app that calls a public JSON endpoint and
decrypts the reply in the browser with a passphrase shipped in the site's own JavaScript. This
script does the same. If the site changes the endpoint or passphrase, they are re-discovered from
the site's JavaScript bundle automatically. Only use it on links you are entitled to view.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
import uuid
from pathlib import Path

# Defaults taken from the site's JavaScript (see "discover()" for the automatic refresh).
API_BASE = "https://api.lumetest.com/api"
SHARE_PATH = "/practice/pte-academic/question-bank/shared-answer/single"
PASSPHRASE = "oADesQM5j3fHvfx8"
SITE = "https://ptemagic.com"
SITE_HOSTS = {"ptemagic.com", "www.ptemagic.com"}
USER_AGENT = "Mozilla/5.0 (compatible; siyuan-pte-import/1.0)"
MAX_AUDIO_BYTES = 50 * 1024 * 1024

GREEN, ORANGE, RED, BLUE = "#1a9c4a", "#e8890c", "#d93025", "#2563eb"
SKILL_FOLDERS = {"SPEAKING": "01 Speaking", "WRITING": "02 Writing", "READING": "03 Reading", "LISTENING": "04 Listening"}

ROOT = Path(__file__).resolve().parent.parent


class ImportError_(Exception):
    pass


# --------------------------------------------------------------------------- site access
def http_get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def parse_share_id(arg: str) -> str:
    arg = arg.strip()
    if re.fullmatch(r"[0-9a-fA-F]{24}", arg):
        return arg.lower()
    u = urllib.parse.urlparse(arg)
    if u.hostname not in SITE_HOSTS:
        raise ImportError_(f"not a ptemagic.com share link: {arg!r}")
    sid = urllib.parse.parse_qs(u.query).get("id", [""])[0]
    if not re.fullmatch(r"[0-9a-fA-F]{24}", sid):
        raise ImportError_(f"no valid share id in link: {arg!r}")
    return sid.lower()


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    out, prev = b"", b""
    while len(out) < key_len + iv_len:
        prev = hashlib.md5(prev + password + salt).digest()
        out += prev
    return out[:key_len], out[key_len : key_len + iv_len]


def decrypt(payload_b64: str, passphrase: str) -> dict:
    """CryptoJS AES passphrase format: base64('Salted__' + salt + ciphertext), AES-256-CBC, MD5 KDF."""
    raw = base64.b64decode(payload_b64)
    if raw[:8] != b"Salted__":
        raise ImportError_("unexpected payload format (not CryptoJS 'Salted__')")
    salt, ct = raw[8:16], raw[16:]
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        key, iv = _evp_bytes_to_key(passphrase.encode(), salt)
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        pt = pt[: -pt[-1]] if 1 <= pt[-1] <= 16 else pt
    except ImportError:  # fall back to the openssl CLI
        env = dict(os.environ, PTE_PASS=passphrase)
        p = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-d", "-md", "md5", "-salt", "-pass", "env:PTE_PASS"],
            input=raw, capture_output=True, env=env,
        )
        if p.returncode != 0:
            raise ImportError_("openssl could not decrypt the payload")
        pt = p.stdout
    try:
        return json.loads(pt.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ImportError_("decryption produced invalid data (passphrase changed?)")


def discover(share_id: str):
    """Read API base, endpoint path and passphrase from the site's own JavaScript bundle."""
    page = http_get(f"{SITE}/pte-academic/share-answer?id={share_id}").decode("utf-8", "replace")
    m = re.search(r'src="(/pte-academic-assets/index-[^"]+\.js)"', page)
    if not m:
        raise ImportError_("could not find the site's JavaScript bundle")
    js = http_get(SITE + m.group(1), timeout=120).decode("utf-8", "replace")
    base = re.search(r'envConfig=\{baseUrl:"([^"]+)"', js)
    key = re.search(r'wordTranslation:"([^"]+)"', js)
    path = re.search(r'getSharedAnswer:"([^"]+)"', js)
    if not (base and key and path):
        raise ImportError_("could not discover API settings from the site bundle")
    return base.group(1), path.group(1), key.group(1)


def fetch_shared(share_id: str) -> dict:
    global API_BASE, SHARE_PATH, PASSPHRASE

    def attempt():
        url = f"{API_BASE}{SHARE_PATH}?{urllib.parse.urlencode({'id': share_id})}"
        body = json.loads(http_get(url).decode("utf-8"))
        if body.get("statusCode") not in (200, None) or "data" not in body:
            raise ImportError_(f"API said: {body.get('message', body)}")
        return decrypt(body["data"], PASSPHRASE)

    try:
        return attempt()
    except urllib.error.HTTPError as e:
        if e.code in (400, 404):
            raise ImportError_(f"share link not found or no longer public (HTTP {e.code})")
        err = e
    except (ImportError_, urllib.error.URLError, json.JSONDecodeError) as e:
        err = e
    # Something changed on the site: re-discover settings once and retry.
    print(f"  ... default settings failed ({err}); re-discovering from site", file=sys.stderr)
    API_BASE, SHARE_PATH, PASSPHRASE = discover(share_id)
    return attempt()


# --------------------------------------------------------------------------- markdown helpers
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>#|~$=])")


def esc(s) -> str:
    return _MD_SPECIAL.sub(r"\\\1", str(s))


def cell(s) -> str:
    return esc(s).replace("\n", " ")


def span(text: str, color: str) -> str:
    return f'<span data-type="text" style="color: {color};">{html.escape(str(text))}</span>'


def quote(text: str) -> str:
    lines = [ln.strip() for ln in str(text).splitlines() if ln.strip()]
    return "\n>\n".join("> " + esc(ln) for ln in lines) if lines else "> (none)"


def num(x) -> str:
    return f"{float(x):g}"


def table(headers, rows) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def fmt_time(t: dt.datetime) -> str:
    return f"{t:%b} {t.day}, {t.year} at {t.hour % 12 or 12}:{t:%M} {t:%p}"


def titleize(s: str) -> str:
    return " ".join(w.capitalize() for w in s.split("_"))


def classify(answer: dict):
    qid = answer.get("questionId") or "UNKNOWN"
    typ = answer.get("type") or ""
    skill, _, rest = typ.partition("_")
    return qid, typ, skill.upper(), titleize(rest) if rest else titleize(typ)


# --------------------------------------------------------------------------- rendering
def head_section(data, url, tz, audio_ref) -> tuple[str, dict]:
    a, q = data["answer"], data.get("question") or {}
    qid, typ, skill, qname = classify(a)
    created = dt.datetime.fromisoformat(a["createdDate"].replace("Z", "+00:00")).astimezone(tz)
    s = a.get("score") or {}
    prefix = re.match(r"[A-Za-z]+", qid)
    tags = ["pte-attempt", f"pte-{skill.lower()}"] + ([f"pte-{prefix.group(0).lower()}"] if prefix else [])
    meta = table(
        ["Field", "Value"],
        [
            ["Question", cell(qid)],
            ["Type", cell(f"{qname} - {skill.capitalize()}")],
            ["Account", cell((a.get("user") or {}).get("name", ""))],
            ["Attempted", cell(fmt_time(created))],
            ["Difficulty", cell(q.get("difficulty") or "")],
            ["Source", f"[PTE Magic share link]({url})"],
        ],
    )
    md = " ".join(f"#{t}#" for t in tags) + "\n\n" + meta
    info = {"qid": qid, "typ": typ, "skill": skill, "qname": qname, "created": created, "score": s}
    return md, info


def render_read_aloud(data, url, tz, audio_ref) -> tuple[str, dict]:
    a, q = data["answer"], data.get("question") or {}
    s = a["score"]
    md, info = head_section(data, url, tz, audio_ref)
    total, mx = s.get("totalScore", 0), s.get("maxTotalScore", 15)

    out = [md, "## Score Breakdown"]
    out.append(
        table(
            ["Overall", "Content", "Pronunciation", "Fluency"],
            [[f"**{num(total)}/{num(mx)}**", f"{num(s.get('content', 0))}/5", f"{num(s.get('pronunciation', 0))}/5", f"{num(s.get('fluency', 0))}/5"]],
        )
    )

    # Overall tab: audio + text
    out.append("## Overall")
    if audio_ref:
        out.append(f'<audio controls="controls" src="{audio_ref}"></audio>')
    elif a.get("answer"):
        out.append(f"[Recording]({a['answer']})")
    out.append("**Question text**\n\n" + quote(q.get("text") or ""))
    out.append("**What the AI heard (transcript)**\n\n" + quote(s.get("transcript") or ""))

    # Content breakdown tab
    cw = s.get("contentWordBreakdown") or []
    ca = s.get("contentAnalysis") or {}
    missing = [w["value"] for w in cw if w.get("type") == "del"]
    inserted = [w["value"] for w in cw if w.get("type") == "ins"]
    subs = [(w["value"], w.get("spokenWord") or "?") for w in cw if w.get("type") == "sub"]
    out.append("## Content Breakdown")
    acc = ca.get("accuracyRate")
    out.append(
        f"**{num(s.get('content', 0))}/5** - {ca.get('matches', 0)} matched, {ca.get('substitutions', 0)} substituted, "
        f"{ca.get('omissions', len(missing))} missing, {ca.get('insertions', len(inserted))} inserted"
        + (f" (accuracy {acc * 100:.0f}%)" if isinstance(acc, (int, float)) else "")
    )
    out.append(
        "\n".join(
            [
                "- **Missing words:** " + (", ".join(esc(w) for w in missing) or "none"),
                "- **Insertions:** " + (", ".join(esc(w) for w in inserted) or "none"),
                "- **Substitutions (expected -> said):** " + (", ".join(f"{esc(r)} -> {esc(sp)}" for r, sp in subs) or "none"),
            ]
        )
    )
    parts = []
    for w in cw:
        t = w.get("type")
        if t == "match":
            parts.append(esc(w["value"]))
        elif t == "del":
            parts.append(span(w["value"], RED))
        elif t == "sub":
            parts.append(span(f"{w['value']} (said: {w.get('spokenWord') or '?'})", ORANGE))
        elif t == "ins":
            parts.append(span(f"+{w['value']}", BLUE))
        else:
            parts.append(esc(w.get("value", "")))
    if parts:
        out.append(" ".join(parts))
        out.append(f"Legend: plain = matched, {span('red', RED)} = missing, {span('orange', ORANGE)} = substituted, {span('blue', BLUE)} = inserted (+).")

    # Pronunciation breakdown tab
    pb = s.get("pronunciationWordBreakdown") or []
    syl = {}
    for w in s.get("wordPronunciationList") or []:
        syl.setdefault(re.sub(r"[^a-z0-9]", "", str(w.get("value", "")).lower()), w.get("hyphenation") or "")
    tier_label = {"good": "Good", "unclear": "Mis-pronounced", "notPronounced": "Missing"}
    tier_color = {"good": GREEN, "unclear": ORANGE, "notPronounced": RED}
    counts = {k: sum(1 for w in pb if w.get("tier") == k) for k in tier_label}
    out.append("## Pronunciation Breakdown")
    out.append(f"**{num(s.get('pronunciation', 0))}/5** - {counts['good']} good, {counts['unclear']} mis-pronounced, {counts['notPronounced']} missing")
    out.append(" ".join(span(w["value"], tier_color.get(w.get("tier"), GREEN)) for w in pb))
    out.append(f"Legend: {span('green', GREEN)} = good, {span('orange', ORANGE)} = mis-pronunciation, {span('red', RED)} = missing.")
    rows = []
    for w in pb:
        if w.get("tier") in ("unclear", "notPronounced"):
            weak = [p for p in w.get("phonemes") or [] if p.get("isError")]
            weak_s = ", ".join(f"/{p.get('ipaLabel')}/ ({p.get('phonemeScore')})" for p in weak)
            key = re.sub(r"[^a-z0-9]", "", str(w["value"]).lower())
            rows.append([cell(w["value"]), tier_label[w["tier"]], cell(syl.get(key, "")), cell(weak_s)])
    if rows:
        out.append("**Words to practice**\n\n" + table(["Word", "Issue", "Syllables", "Weak sounds (score)"], rows))

    # Fluency tab
    fa = s.get("fluencyAnalysis") or {}
    wc = fa.get("wordCount", 0)
    dur = s.get("duration") or fa.get("totalDurationSeconds") or 0
    wpm = s.get("speechRate") or fa.get("wordsPerMinute") or 0
    out.append("## Fluency")
    out.append(f"**{num(s.get('fluency', 0))}/5** - said {wc} words in {num(dur)} second(s) - {round(wpm)} words per minute. *{esc(fa.get('paceLabel', ''))}*")
    out.append(
        table(
            ["Words", "Duration (s)", "Words/min", "Long pauses", "Hesitations", "False starts", "Repetitions", "Mic cut off"],
            [[str(wc), num(dur), str(round(wpm)), str(fa.get("longPauses", 0)), str(fa.get("hesitations", 0)), str(fa.get("falseStarts", 0)), str(fa.get("repetitions", 0)), "yes" if fa.get("micCutoff") else "no"]],
        )
    )

    info["attrs"] = {
        "custom-pte-total": num(total), "custom-pte-max": num(mx),
        "custom-pte-content": num(s.get("content", 0)), "custom-pte-pronunciation": num(s.get("pronunciation", 0)),
        "custom-pte-fluency": num(s.get("fluency", 0)),
    }
    return "\n\n".join(out) + "\n", info


def render_generic(data, url, tz, audio_ref) -> tuple[str, dict]:
    """Best-effort layout for question types without a dedicated renderer."""
    a, q = data["answer"], data.get("question") or {}
    s = a.get("score") or {}
    md, info = head_section(data, url, tz, audio_ref)
    out = [md]
    nums = [(k, v) for k, v in s.items() if isinstance(v, (int, float)) and not isinstance(v, bool) and v]
    if nums:
        out.append("## Score Breakdown\n\n" + table(["Item", "Score"], [[cell(k), num(v)] for k, v in nums]))
    out.append("## Answer")
    ans = a.get("answer")
    if audio_ref:
        out.append(f'<audio controls="controls" src="{audio_ref}"></audio>')
    elif isinstance(ans, str) and ans.startswith("http"):
        out.append(f"[Answer file]({ans})")
    elif ans:
        out.append(quote(ans if isinstance(ans, str) else json.dumps(ans, ensure_ascii=False)))
    if q.get("text"):
        out.append("## Question\n\n" + quote(q["text"]))
    if s.get("transcript"):
        out.append("## Transcript\n\n" + quote(s["transcript"]))
    for key in ("feedback", "contentFeedback", "vocabularyFeedback", "structureFeedback", "generalLinguisticFeedback"):
        if isinstance(s.get(key), str) and s[key].strip():
            out.append(f"## {titleize(key)}\n\n" + quote(s[key]))
    total = s.get("totalScore")
    info["attrs"] = {"custom-pte-total": num(total), "custom-pte-max": num(s.get("maxTotalScore", 0))} if total is not None else {}
    return "\n\n".join(out) + "\n", info


def render(data, url, tz, audio_ref):
    if (data.get("answer") or {}).get("type") == "SPEAKING_READ_ALOUD" and (data["answer"].get("score") or {}).get("contentWordBreakdown") is not None:
        return render_read_aloud(data, url, tz, audio_ref)
    return render_generic(data, url, tz, audio_ref)


# --------------------------------------------------------------------------- SiYuan
class SiYuan:
    def __init__(self, base: str, code: str):
        self.base = base.rstrip("/")
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        if code:
            self.call("/api/system/loginAuth", {"authCode": code}, what="login (check SIYUAN_ACCESS_AUTH_CODE)")

    def _send(self, path, body: bytes, ctype: str):
        req = urllib.request.Request(self.base + path, data=body, headers={"Content-Type": ctype})
        try:
            with self.op.open(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.URLError as e:
            raise ImportError_(f"cannot reach SiYuan at {self.base}: {e}")

    def call(self, path, body, what=None):
        res = self._send(path, json.dumps(body).encode(), "application/json")
        if res.get("code") != 0:
            raise ImportError_(f"SiYuan {what or path} failed: {res.get('msg')}")
        return res.get("data")

    def notebook(self, name: str) -> str:
        for n in self.call("/api/notebook/lsNotebooks", {})["notebooks"]:
            if n["name"] == name:
                if n.get("closed"):
                    self.call("/api/notebook/openNotebook", {"notebook": n["id"]})
                return n["id"]
        return self.call("/api/notebook/createNotebook", {"name": name})["notebook"]["id"]

    def sql(self, stmt: str):
        return self.call("/api/query/sql", {"stmt": stmt}) or []

    def flush(self):
        # SiYuan indexes asynchronously; wait for pending writes before reading them back.
        self.call("/api/sqlite/flushTransaction", {})

    def insert_block_before(self, next_id: str, md: str):
        self.call("/api/block/insertBlock", {"dataType": "markdown", "data": md, "nextID": next_id})

    def append_to_doc(self, doc_id: str, md: str):
        self.call("/api/block/appendBlock", {"dataType": "markdown", "data": md, "parentID": doc_id})

    def update_block(self, block_id: str, md: str):
        self.call("/api/block/updateBlock", {"dataType": "markdown", "data": md, "id": block_id})

    def find_attempt(self, share_id: str):
        # SiYuan indexes attributes asynchronously; wait for pending writes so a quick re-run
        # still sees the document that was just created.
        self.call("/api/sqlite/flushTransaction", {})
        rows = self.call("/api/query/sql", {"stmt": f"select block_id from attributes where name='custom-pte-share-id' and value='{share_id}'"})
        return rows[0]["block_id"] if rows else None

    def upload(self, filename: str, data: bytes, ctype="application/octet-stream") -> str:
        b = uuid.uuid4().hex
        body = (
            f'--{b}\r\nContent-Disposition: form-data; name="assetsDirPath"\r\n\r\n/assets/\r\n'
            f'--{b}\r\nContent-Disposition: form-data; name="file[]"; filename="{filename}"\r\nContent-Type: {ctype}\r\n\r\n'
        ).encode() + data + f"\r\n--{b}--\r\n".encode()
        res = self._send("/api/asset/upload", body, f"multipart/form-data; boundary={b}")
        if res.get("code") != 0 or res["data"].get("errFiles"):
            raise ImportError_(f"asset upload failed: {res.get('msg') or res['data'].get('errFiles')}")
        return next(iter(res["data"]["succMap"].values()))

    def create_doc(self, nb, path, md) -> str:
        return self.call("/api/filetree/createDocWithMd", {"notebook": nb, "path": path, "markdown": md})

    def set_attrs(self, block_id, attrs):
        self.call("/api/attr/setBlockAttrs", {"id": block_id, "attrs": attrs})

    def remove_doc(self, doc_id):
        self.call("/api/filetree/removeDocByID", {"id": doc_id})


# --------------------------------------------------------------------------- dashboard
def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _avg(vals):
    vals = [v for v in vals if v is not None]
    return sum(vals) / len(vals) if vals else None


def collect_attempts(siyuan: SiYuan) -> list[dict]:
    siyuan.flush()
    ids = [r["block_id"] for r in siyuan.sql("select block_id from attributes where name='custom-pte-share-id' limit 100000")]
    if not ids:
        return []
    by: dict[str, dict] = {}
    for r in siyuan.sql("select block_id, name, value from attributes where name like 'custom-pte-%' limit 1000000"):
        by.setdefault(r["block_id"], {})[r["name"]] = r["value"]
    attempts = []
    for bid in dict.fromkeys(ids):
        a = by.get(bid, {})
        try:
            when = dt.datetime.fromisoformat(a.get("custom-pte-attempted", ""))
        except ValueError:
            when = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
        skill, _, rest = (a.get("custom-pte-type") or "").partition("_")
        total, mx = _f(a.get("custom-pte-total")), _f(a.get("custom-pte-max"))
        attempts.append({
            "id": bid, "qid": a.get("custom-pte-qid", "?"), "when": when,
            "skill": skill.capitalize() or "Other", "qname": titleize(rest) or a.get("custom-pte-qid", "?"),
            "total": total, "max": mx, "pct": (total / mx * 100) if total is not None and mx else None,
            "content": _f(a.get("custom-pte-content")), "pron": _f(a.get("custom-pte-pronunciation")),
            "fluency": _f(a.get("custom-pte-fluency")),
        })
    attempts.sort(key=lambda x: x["when"], reverse=True)
    return attempts


def _p(x, spec="{:.0f}%"):
    return spec.format(x) if x is not None else "-"


def _of5(x):
    return f"{x:.1f}/5" if x is not None else "-"


def progress_table(attempts: list[dict]) -> str:
    groups: dict[tuple, list] = {}
    for a in attempts:
        groups.setdefault((a["skill"], a["qname"]), []).append(a)
    order = {"Speaking": 0, "Writing": 1, "Reading": 2, "Listening": 3}
    rows = []
    for (skill, qname), items in sorted(groups.items(), key=lambda kv: (order.get(kv[0][0], 9), kv[0][1])):
        pcts = [a["pct"] for a in items]
        rows.append([
            cell(qname), cell(skill), str(len(items)), _p(_avg(pcts)), _p(max((p for p in pcts if p is not None), default=None)),
            _p(items[0]["pct"]), _of5(_avg(a["content"] for a in items)), _of5(_avg(a["pron"] for a in items)),
            _of5(_avg(a["fluency"] for a in items)), cell(f"{items[0]['when']:%Y-%m-%d}"),
        ])
    return table(["Question type", "Skill", "Attempts", "Avg", "Best", "Latest", "Avg content", "Avg pronunciation", "Avg fluency", "Last attempt"], rows)


def recent_table(attempts: list[dict], limit: int = 15) -> str:
    rows = []
    for a in attempts[:limit]:
        title = f"{a['qid']} ({a['when']:%Y-%m-%d %H:%M})"
        overall = f"{a['total']:g}/{a['max']:g}" if a["total"] is not None and a["max"] else "-"
        rows.append([
            cell(f"{a['when']:%Y-%m-%d %H:%M}"), f'(({a["id"]} "{title}"))', cell(a["qname"]), overall,
            _of5(a["content"]), _of5(a["pron"]), _of5(a["fluency"]),
        ])
    return table(["Attempted", "Question", "Type", "Overall", "Content", "Pronunciation", "Fluency"], rows)


def refresh_dashboard(siyuan: SiYuan, nb_id: str, root: str) -> str:
    """Rebuild the two attempt tables on '00 Dashboard' from the attributes stored on each attempt."""
    attempts = collect_attempts(siyuan)
    if not attempts:
        return "dashboard: no imported attempts yet"
    dash_path = f"/{safe_title(root)}/00 Dashboard"
    docs = siyuan.sql(f"select id from blocks where type='d' and box='{nb_id}' and hpath='{dash_path}' limit 1")
    if not docs:
        return f"dashboard: '{dash_path}' not found in this notebook, skipped"
    dash = docs[0]["id"]

    sections = [
        ("|Questiontype|Skill|", "Progress by question type", progress_table(attempts)),
        ("|Attempted|Question|", "Recent attempts", recent_table(attempts)),
    ]
    for marker, heading, tbl in sections:
        # SiYuan re-formats table Markdown (drops the padding spaces), so compare without spaces.
        found = siyuan.sql(
            f"select id from blocks where root_id='{dash}' and type='t' and replace(markdown,' ','') like '{marker}%' limit 1"
        )
        if found:
            siyuan.update_block(found[0]["id"], tbl)
            continue
        anchor = siyuan.sql(f"select id from blocks where root_id='{dash}' and type='h' and content='Enabling skills' limit 1")
        md = f"## {heading}\n\n{tbl}\n"
        if anchor:
            siyuan.insert_block_before(anchor[0]["id"], md)
        else:
            siyuan.append_to_doc(dash, md)
        siyuan.flush()
    return f"dashboard: updated from {len(attempts)} attempt(s)"


def load_env() -> dict:
    env = {}
    for p in (ROOT / ".env", Path.cwd() / ".env"):
        if p.is_file():
            for line in p.read_text(encoding="utf-8").splitlines():
                m = re.match(r"\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$", line)
                if m and not line.lstrip().startswith("#"):
                    env.setdefault(m.group(1), m.group(2).strip("\"'"))
    for k in ("SIYUAN_URL", "SIYUAN_PORT", "SIYUAN_ACCESS_AUTH_CODE", "TZ"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def get_tz(name: str | None):
    if name:
        try:
            from zoneinfo import ZoneInfo

            return ZoneInfo(name)
        except Exception:
            print(f"warning: unknown time zone {name!r}, using the system time zone", file=sys.stderr)
    return dt.datetime.now().astimezone().tzinfo


def safe_title(s: str) -> str:
    return re.sub(r"[/\\\x00-\x1f]", "-", s).strip()


def download_audio(url: str) -> tuple[bytes, str]:
    if urllib.parse.urlparse(url).scheme != "https":
        raise ImportError_("refusing to download non-https audio")
    data = http_get(url, timeout=120)
    if len(data) > MAX_AUDIO_BYTES:
        raise ImportError_("audio file is unexpectedly large, skipping")
    ext = Path(urllib.parse.urlparse(url).path).suffix.lower()
    return data, ext if re.fullmatch(r"\.[a-z0-9]{1,5}", ext) else ".m4a"


def import_one(arg, args, siyuan, nb_id, tz) -> str:
    sid = parse_share_id(arg)
    url = f"{SITE}/pte-academic/share-answer?id={sid}"
    if siyuan and not args.force:
        existing = siyuan.find_attempt(sid)
        if existing:
            return f"skip   {sid}: already imported (doc {existing}); use --force to replace"

    data = fetch_shared(sid)
    if not isinstance(data.get("answer"), dict):
        raise ImportError_("response has no 'answer' (link expired or deleted?)")

    audio_ref = None
    audio_url = data["answer"].get("answer")
    if siyuan and not args.no_audio and isinstance(audio_url, str) and audio_url.startswith("http"):
        try:
            blob, ext = download_audio(audio_url)
            qid = re.sub(r"[^A-Za-z0-9]", "", data["answer"].get("questionId") or "audio")
            audio_ref = siyuan.upload(f"{qid}-{sid[:8]}{ext}", blob)
        except (ImportError_, urllib.error.URLError, OSError) as e:
            print(f"  warning: audio not saved ({e}); linking to the original URL instead", file=sys.stderr)

    md, info = render(data, url, tz, audio_ref)
    if args.dry_run:
        print(f"--- {sid} ---\n{md}")
        return f"dry-run {sid}: {info['qid']} ({len(md)} chars)"

    folder = SKILL_FOLDERS.get(info["skill"], titleize(info["skill"]) or "Other")
    title = safe_title(f"{info['qid']} ({info['created']:%Y-%m-%d %H:%M})")
    path = f"/{safe_title(args.root)}/{safe_title(folder)}/{safe_title(info['qname'])}/{title}"

    if args.force:
        old = siyuan.find_attempt(sid)
        if old:
            siyuan.remove_doc(old)
    doc_id = siyuan.create_doc(nb_id, path, md)
    attrs = {
        "custom-pte-share-id": sid, "custom-pte-qid": info["qid"], "custom-pte-type": info["typ"],
        "custom-pte-skill": info["skill"].lower(), "custom-pte-attempted": info["created"].isoformat(timespec="seconds"),
    }
    attrs.update(info.get("attrs", {}))
    siyuan.set_attrs(doc_id, attrs)
    return f"ok     {sid}: {path} (doc {doc_id})"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Import PTE Magic share links into SiYuan.")
    ap.add_argument("links", nargs="*", help="share links or 24-char ids")
    ap.add_argument("--file", help="text file with one link per line")
    ap.add_argument("--notebook", default="English", help="notebook to import into (default: English)")
    ap.add_argument("--root", default="PTE", help="top-level document inside the notebook (default: PTE)")
    ap.add_argument("--tz", help="time zone for the attempt time (default: TZ from .env, else system)")
    ap.add_argument("--no-audio", action="store_true", help="do not download the recording into SiYuan")
    ap.add_argument("--force", action="store_true", help="replace an attempt that was already imported")
    ap.add_argument("--dry-run", action="store_true", help="print the Markdown and do not touch SiYuan")
    ap.add_argument("--no-dashboard", action="store_true", help="do not refresh the '00 Dashboard' attempt tables")
    ap.add_argument("--refresh-dashboard", action="store_true", help="only rebuild the Dashboard tables (no links needed)")
    args = ap.parse_args(argv)

    links = list(args.links)
    if args.file:
        links += [ln.strip() for ln in Path(args.file).read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not links and not args.refresh_dashboard:
        ap.error("give at least one link (or --file, or --refresh-dashboard)")
    if args.refresh_dashboard and args.dry_run:
        ap.error("--refresh-dashboard cannot be combined with --dry-run")

    env = load_env()
    tz = get_tz(args.tz or env.get("TZ"))
    siyuan = nb_id = None
    if not args.dry_run:
        base = env.get("SIYUAN_URL") or f"http://127.0.0.1:{env.get('SIYUAN_PORT', '6806')}"
        try:
            siyuan = SiYuan(base, env.get("SIYUAN_ACCESS_AUTH_CODE", ""))
            nb_id = siyuan.notebook(args.notebook)
        except ImportError_ as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    failed = imported = 0
    for i, link in enumerate(dict.fromkeys(links)):
        if i:
            time.sleep(0.5)
        try:
            msg = import_one(link, args, siyuan, nb_id, tz)
            imported += msg.startswith("ok")
            print(msg)
        except (ImportError_, urllib.error.URLError, OSError) as e:
            failed += 1
            print(f"FAILED {link}: {e}", file=sys.stderr)

    if siyuan and not args.no_dashboard and (imported or args.refresh_dashboard):
        try:
            print(refresh_dashboard(siyuan, nb_id, args.root))
        except (ImportError_, OSError) as e:
            failed += 1
            print(f"FAILED dashboard refresh: {e}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
