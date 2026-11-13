#!/usr/bin/env python3
"""Inbox: a personal mail and calendar app for your Google accounts, running locally.

  python3 inbox.py setup     name your accounts and your city (writes settings.json)
  python3 inbox.py login     sign in to each account (opens your browser; Google asks again about once a week)
  python3 inbox.py serve     fetch, rank, and run the app at http://127.0.0.1:8765 (actions reach Gmail and Calendar)
  python3 inbox.py sync      fetch, rank and write a read-only copy to out/inbox.html
  python3 inbox.py demo      build the page from made-up data, to check it without signing in

What reaches Google: marking read or unread, starring, deleting (to Trash, so it can be undone), replying, sending,
and creating, editing or deleting calendar events with Google Meet links and invites. Nothing happens until you
click the button for it. The server only listens on this Mac and only answers the page it served.

Standard library only. Sign-in tokens stay in .tokens.json (readable only by you). The ranking step sends each email's
sender, subject and a short preview to Claude; results are cached in .rank-cache.json so only new mail is ranked.
"""
import base64, datetime as dt, email.message, email.utils, hashlib, html, http.server, json, os, re, secrets
import subprocess, sys, threading, time, urllib.error, urllib.parse, urllib.request, uuid, webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
CLIENT = os.path.join(HERE, "client_secret.json")
TOKENS = os.path.join(HERE, ".tokens.json")
CACHE = os.path.join(HERE, ".rank-cache.json")
FEEDBACK = os.path.join(HERE, ".feedback.json")
TEMPLATE = os.path.join(HERE, "template.html")
OUT = os.path.join(HERE, "out", "inbox.html")
PORT = 8765
SETTINGS = os.path.join(HERE, "settings.json")


def load_settings():
    """Your accounts, name and city, from settings.json (made by `python3 inbox.py setup`, never committed)."""
    try:
        with open(SETTINGS, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    accounts = [(a["key"], a["name"], a["email"]) for a in cfg.get("accounts", []) if a.get("key") and a.get("email")]
    return cfg, accounts


_cfg, ACCOUNTS = load_settings()
OWNER = (_cfg.get("owner") or "").strip() or "the user"
CITY = _cfg.get("city") or {"name": "London", "lat": 51.51, "lon": -0.13}
ADDRESS = {key: mail for key, _, mail in ACCOUNTS}
SCOPES = " ".join(["openid", "email",
                   "https://www.googleapis.com/auth/gmail.modify",
                   "https://www.googleapis.com/auth/gmail.send",
                   "https://www.googleapis.com/auth/calendar.events",
                   "https://www.googleapis.com/auth/drive.appdata"])
CATS = ["Investors", "Contracts", "Product", "Home", "Government", "Travel", "Money", "Newsletters", "News", "Promotions", "Spam"]
MAX_MAIL = 250  # per account, so about 500 across both inboxes
MAIL_CACHE = os.path.join(HERE, ".mail-cache.json")


def private_write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def read_json(path, default):
    try:
        return json.load(open(path))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


# ---------- sign-in ----------

def client():
    if not os.path.exists(CLIENT):
        sys.exit(f"Missing {CLIENT}. Download the Desktop client JSON from Google Cloud and save it there.")
    data = json.load(open(CLIENT))
    return data.get("installed") or data.get("web")


def post_form(url, fields):
    req = urllib.request.Request(url, urllib.parse.urlencode(fields).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def login(only=None):
    if not ACCOUNTS:
        sys.exit("No accounts yet. Run: python3 inbox.py setup")
    c = client()
    tokens = read_json(TOKENS, {})
    for key, name, address in ACCOUNTS:
        if only and only not in (key, address):
            continue
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        state, got = secrets.token_urlsafe(16), {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                if q.get("state", [""])[0] == state:
                    got.update({k: v[0] for k, v in q.items()})
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<p style='font:16px system-ui;padding:40px'>Signed in. You can close this tab and go back.</p>")

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        redirect = f"http://127.0.0.1:{server.server_port}"
        url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
            "client_id": c["client_id"], "redirect_uri": redirect, "response_type": "code", "scope": SCOPES,
            "code_challenge": challenge, "code_challenge_method": "S256", "state": state,
            "access_type": "offline", "prompt": "consent", "login_hint": address})
        print(f"\n{name} ({address}): opening Google sign-in in your browser…", flush=True)
        webbrowser.open(url)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        thread.join(300)
        server.server_close()
        if "code" not in got:
            print(f"  No answer from Google for {address}" + (f" ({got['error']})" if "error" in got else "") + ". Skipped.", flush=True)
            continue
        tok = post_form("https://oauth2.googleapis.com/token", {
            "client_id": c["client_id"], "client_secret": c.get("client_secret", ""), "code": got["code"],
            "code_verifier": verifier, "grant_type": "authorization_code", "redirect_uri": redirect})
        claims = json.loads(base64.urlsafe_b64decode(tok["id_token"].split(".")[1] + "=="))
        if claims.get("email", "").lower() != address.lower():
            print(f"  You signed in as {claims.get('email')}, not {address}. Skipped; run login again and pick {address}.", flush=True)
            continue
        granted = set(tok.get("scope", "").split())
        missing = [s.rsplit("/", 1)[-1] for s in SCOPES.split() if s.startswith("https://") and s not in granted]
        tokens[address] = {"refresh": tok["refresh_token"], "at": dt.datetime.now().isoformat(timespec="seconds"), "scope": tok.get("scope", "")}
        private_write(TOKENS, json.dumps(tokens))
        print(f"  Signed in as {address}." + (f" Not allowed: {', '.join(missing)}." if missing else " Mail and calendar, read and write."), flush=True)


_access = {}


def access_token(address):
    cached = _access.get(address)
    if cached and cached[1] > dt.datetime.now():
        return cached[0]
    entry = read_json(TOKENS, {}).get(address)
    if not entry:
        return None
    c = client()
    try:
        tok = post_form("https://oauth2.googleapis.com/token", {
            "client_id": c["client_id"], "client_secret": c.get("client_secret", ""),
            "refresh_token": entry["refresh"], "grant_type": "refresh_token"})
    except urllib.error.HTTPError:
        print(f"  {address}: the weekly sign-in has expired. Run: python3 inbox.py login {address}", flush=True)
        return None
    _access[address] = (tok["access_token"], dt.datetime.now() + dt.timedelta(seconds=tok.get("expires_in", 3600) - 120))
    return tok["access_token"]


class GoogleError(Exception):
    pass


_pace_lock = threading.Lock()
_last_call = [0.0]
PACE = 0.12  # seconds between Gmail calls: about 8 a second, well under Google's per-user limit


def _pace():
    with _pace_lock:
        wait = _last_call[0] + PACE - time.time()
        if wait > 0:
            time.sleep(wait)
        _last_call[0] = time.time()


def call(address, method, url, body=None):
    token = access_token(address)
    if not token:
        raise GoogleError(f"{address} isn't signed in. Run: python3 inbox.py login")
    data = json.dumps(body).encode() if body is not None else None
    # Reads are retried when the network is slow; a write that times out is not resent, so nothing goes out twice.
    tries = 3 if method == "GET" else 1
    quota_waits = 0
    attempt = 0
    while attempt < tries:
        _pace()
        req = urllib.request.Request(url, data, {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            try:
                detail = json.loads(detail)["error"]["message"]
            except Exception:
                pass
            # Over the per-minute limit: wait for the minute to roll over and try again (reads only, never a send).
            if method == "GET" and ("Quota exceeded" in str(detail) or e.code == 429) and quota_waits < 3:
                quota_waits += 1
                print(f"  Gmail asked us to slow down; waiting {20 * quota_waits}s.", flush=True)
                time.sleep(20 * quota_waits)
                continue
            if e.code in (500, 502, 503) and attempt < tries - 1:
                time.sleep(1.5 * (attempt + 1))
                attempt += 1
                continue
            raise GoogleError(f"Google said: {detail}")
        except (TimeoutError, urllib.error.URLError, ConnectionError) as e:
            if attempt < tries - 1:
                time.sleep(1.5 * (attempt + 1))
                attempt += 1
                continue
            raise GoogleError("Couldn't reach Google. Check the connection and try again.") from e


# ---------- mail ----------

def b64(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")


def body_text(payload):
    """Plain text if the email has it, otherwise its HTML with the tags taken out."""
    plain, rich = [], []

    def walk(part):
        mime, data = part.get("mimeType", ""), part.get("body", {}).get("data")
        if data and mime == "text/plain":
            plain.append(b64(data))
        elif data and mime == "text/html":
            rich.append(b64(data))
        for sub in part.get("parts", []) or []:
            walk(sub)

    walk(payload)
    if plain:
        text = "\n".join(plain)
    else:
        text = re.sub(r"(?is)<(script|style).*?</\1>", "", "\n".join(rich))
        text = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", text)
        text = html.unescape(re.sub(r"<[^>]+>", "", text))
    text = re.sub(r"[ \t ]+", " ", text.replace("`", "'"))
    return re.sub(r"\n\s*\n\s*\n+", "\n\n", text).strip()[:4000]


def sender(raw):
    name, addr = email.utils.parseaddr(raw or "")
    return (name or addr or "Unknown").strip(), addr


def when(ms, now):
    t = dt.datetime.fromtimestamp(int(ms) / 1000)
    if t.date() == now.date():
        return t.strftime("%-I:%M")
    if (now.date() - t.date()).days < 7:
        return t.strftime("%a")
    return t.strftime("%b %-d")


_mail_cache = None
_mail_cache_lock = threading.Lock()


def mail_cache():
    global _mail_cache
    if _mail_cache is None:
        _mail_cache = read_json(MAIL_CACHE, {})
        if not isinstance(_mail_cache, dict):
            _mail_cache = {}
    return _mail_cache


def list_ids(address, query, limit):
    ids, page = [], None
    while len(ids) < limit:
        params = {"q": query, "maxResults": min(500, limit - len(ids))}
        if page:
            params["pageToken"] = page
        listing = call(address, "GET", "https://gmail.googleapis.com/gmail/v1/users/me/messages?" + urllib.parse.urlencode(params))
        ids += [m["id"] for m in listing.get("messages", [])]
        page = listing.get("nextPageToken")
        if not page:
            break
    return ids


def message_entry(address, gid):
    """One email's list fields, fetched from Gmail once and then kept in the cache."""
    m = call(address, "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gid}?format=full")
    headers = {h["name"].lower(): h["value"] for h in m["payload"].get("headers", [])}
    name, addr = sender(headers.get("from"))
    return {"gmailId": m["id"], "threadId": m["threadId"], "from": name, "fromAddr": addr,
            "subj": headers.get("subject") or "(no subject)", "ts": int(m["internalDate"]),
            "body": body_text(m["payload"]) or html.unescape(m.get("snippet", "")), "labels": m.get("labelIds", [])}


def fetch_mail(address, key, now, next_id, query="in:inbox", limit=None):
    limit = limit or MAX_MAIL
    ids = list_ids(address, query, limit)
    # Read and starred state change often and cost little to check: two id lists instead of re-reading every email.
    unread = set(list_ids(address, f"({query}) is:unread", limit))
    starred = set(list_ids(address, f"({query}) is:starred", limit))
    cache = mail_cache()
    missing = [gid for gid in ids if f"{address}:{gid}" not in cache]
    if missing:
        print(f"  Downloading {len(missing)} new emails for {address}…", flush=True)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=3) as pool:
            for gid, entry in zip(missing, pool.map(lambda g: _safe_entry(address, g), missing)):
                if entry:
                    with _mail_cache_lock:
                        cache[f"{address}:{gid}"] = entry
        with _mail_cache_lock:
            private_write(MAIL_CACHE, json.dumps(cache))
    out = []
    for gid in ids:
        entry = cache.get(f"{address}:{gid}")
        if not entry:
            continue
        labels = [l for l in entry["labels"] if l not in ("UNREAD", "STARRED")] + (["UNREAD"] if gid in unread else []) + (["STARRED"] if gid in starred else [])
        out.append({**entry, "id": next_id(), "a": key, "time": when(entry["ts"], now),
                    "unread": gid in unread, "star": gid in starred, "labels": labels})
    return out


def _safe_entry(address, gid):
    try:
        return message_entry(address, gid)
    except GoogleError as e:
        print(f"  Skipped one email that wouldn't load ({e}).", flush=True)
        return None


# ---------- calendar ----------

def fetch_events(address, key, base, next_id):
    start = dt.datetime.combine(base, dt.time()).astimezone()
    params = {"timeMin": start.isoformat(), "timeMax": (start + dt.timedelta(days=7)).isoformat(),
              "singleEvents": "true", "orderBy": "startTime", "maxResults": 250}
    items = call(address, "GET", "https://www.googleapis.com/calendar/v3/calendars/primary/events?" + urllib.parse.urlencode(params)).get("items", [])
    return [event_out(e, key, base, address, next_id()) for e in items if e.get("status") != "cancelled"]


STATUS = {"accepted": "Going", "declined": "Declined", "tentative": "Maybe", "needsAction": "Awaiting reply"}
RSVP_IN = {"accepted": "Yes", "declined": "No", "tentative": "Maybe"}
RSVP_OUT = {"Yes": "accepted", "No": "declined", "Maybe": "tentative"}


def event_out(e, key, base, address, local_id):
    all_day = "date" in e["start"]
    if all_day:
        s_day, s_min, length = dt.date.fromisoformat(e["start"]["date"]), 0, 60
    else:
        s = dt.datetime.fromisoformat(e["start"]["dateTime"].replace("Z", "+00:00")).astimezone()
        f = dt.datetime.fromisoformat(e["end"]["dateTime"].replace("Z", "+00:00")).astimezone()
        s_day, s_min, length = s.date(), s.hour * 60 + s.minute, max(15, int((f - s).total_seconds() // 60))
    text = " ".join([e.get("location", ""), e.get("description", "")])
    zoom = re.search(r"https://[\w.-]*zoom\.us/j/(\d+)\S*", text)
    link, via, code = e.get("hangoutLink"), None, None
    if link:
        via, code = "Google Meet", link.rsplit("/", 1)[-1]
    elif zoom:
        link, via, code = zoom.group(0), "Zoom", zoom.group(1)
    people = [p for p in e.get("attendees", []) if not p.get("self")]
    mine = next((p for p in e.get("attendees", []) if p.get("self")), {})
    organizer = e.get("organizer", {})
    reminder = (e.get("reminders", {}).get("overrides") or [{}])[0].get("minutes")
    return {
        "id": local_id, "gid": e["id"], "day": (s_day - base).days, "s": s_min, "m": length, "allDay": all_day,
        "n": e.get("summary") or "(no title)", "a": key, "via": via, "link": link, "code": code,
        "guests": [{"n": f"{p.get('displayName')} <{p['email']}>" if p.get("displayName") else p.get("email"),
                    "st": STATUS.get(p.get("responseStatus"), "Awaiting reply")} for p in people],
        "loc": "" if zoom else e.get("location", ""), "desc": re.sub(r"<[^>]+>", "", e.get("description", ""))[:600],
        "org": None if organizer.get("self") or organizer.get("email") == address else (organizer.get("displayName") or organizer.get("email")),
        "rsvp": RSVP_IN.get(mine.get("responseStatus"), "Yes"),
        "busy": "free" if e.get("transparency") == "transparent" else "busy",
        "remind": str(reminder) if reminder is not None else "10",
        "invite": e.get("guestsCanInviteOthers", True), "repeat": "none"}


# ---------- ranking ----------

PROMPT = """You triage %(owner)s's email. For each email in the JSON below, return an object with:
- i: the same number
- score: 0-100, how much it needs %(owner)s personally. A real person waiting, a deadline, money, legal or government
  matters score high. Automated notices, receipts and newsletters score low. Marketing and cold pitches score lowest.
- cat: exactly one of %(cats)s. Use News for news digests about the world (Morning Brew, Axios, The Morning and similar).
- why: one short sentence on why it sits where it does, written to %(owner)s ("Picked because...", "Marketing.").
- highlights: up to 3 short phrases copied exactly from the preview that matter most (dates, amounts, deadlines).
Return only a JSON array, no prose.
""" % {"owner": OWNER, "cats": ", ".join(CATS)}


def gmail_guess(m):
    labels = m["labels"]
    if "CATEGORY_PROMOTIONS" in labels:
        return 15, "Promotions"
    if "SPAM" in labels:
        return 5, "Spam"
    if "CATEGORY_UPDATES" in labels:
        return 35, "Product"
    return (60 if m["unread"] else 45), "Newsletters" if "CATEGORY_FORUMS" in labels else "Product"


def rank_key(m):
    return m["a"] + ":" + m["gmailId"]


def read_feedback():
    notes = read_json(FEEDBACK, [])
    return [n for n in notes if isinstance(n, dict)] if isinstance(notes, list) else []


def feedback_notes():
    """Recent Not important / Important clicks, as lines for the ranking prompt."""
    notes = read_feedback()[-60:]
    if not notes:
        return ""
    lines = [f'- {"NOT important" if n["dir"] == "down" else "IMPORTANT"}: {n["from"]} <{n["fromAddr"]}>, "{n["subj"][:80]}"' for n in notes]
    return (f"\n{OWNER} has marked these by hand. Rank similar mail (same sender, same kind of email) the same way:\n"
            + "\n".join(lines) + "\n")


def sender_rules():
    """The latest verdict per sender: down caps the score, up lifts it."""
    rules = {}
    for n in read_feedback():
        if n.get("fromAddr"):
            rules[n["fromAddr"].lower()] = n["dir"]
    return rules


def rank(mail):
    cache = read_json(CACHE, {})
    # Migrate the older single-ID cache only when that ID is unambiguous across accounts.
    for m in mail:
        if rank_key(m) not in cache and m["gmailId"] in cache and sum(x["gmailId"] == m["gmailId"] for x in mail) == 1:
            cache[rank_key(m)] = cache[m["gmailId"]]
    todo = [m for m in mail if rank_key(m) not in cache]
    prompt = PROMPT + feedback_notes()
    for start in range(0, len(todo), 40):
        batch = todo[start:start + 40]
        items = [{"i": n, "from": m["from"], "subject": m["subj"], "preview": m["body"][:400]} for n, m in enumerate(batch)]
        try:
            run = subprocess.run(["claude", "-p", "--model", "haiku", prompt], input=json.dumps(items), capture_output=True, text=True, timeout=300, cwd=HERE)
            found = re.search(r"\[.*\]", run.stdout, re.S)
            for r in json.loads(found.group(0)) if found else []:
                m = batch[int(r["i"])]
                cache[rank_key(m)] = {"score": max(0, min(100, int(r.get("score", 40)))), "cat": r.get("cat") if r.get("cat") in CATS else None,
                                       "why": r.get("why") or "", "highlights": [h for h in (r.get("highlights") or [])[:3] if isinstance(h, str)]}
        except Exception as e:
            print(f"  Ranking failed for a batch ({e.__class__.__name__}); those emails use Gmail's labels.", flush=True)
    private_write(CACHE, json.dumps(cache))
    rules = sender_rules()
    for m in mail:
        guess_score, guess_cat = gmail_guess(m)
        r = cache.get(rank_key(m), {})
        m["score"] = r.get("score", guess_score)
        rule = rules.get((m.get("fromAddr") or "").lower())
        if rule == "down":
            m["score"] = min(m["score"], 25)
        elif rule == "up":
            m["score"] = max(m["score"], 80)
        m["cat"] = r.get("cat") or guess_cat
        m["why"] = r.get("why") or "Sorted by Gmail's own labels."
        for phrase in r.get("highlights", []):
            if phrase and phrase in m["body"] and "`" not in phrase:
                m["body"] = m["body"].replace(phrase, f"`{phrase}`", 1)
        m.pop("labels", None)


# Each account has its own hidden Drive file. The Mac is the sole writer; iOS reads it.
# OAuth clients must belong to the same Google Cloud project to share app data.
RANK_SCOPE = "https://www.googleapis.com/auth/drive.appdata"
RANK_FILE = "inbox-rankings-v1.json"


def publish_rankings(mail):
    tokens = read_json(TOKENS, {})
    for key, _, address in ACCOUNTS:
        if RANK_SCOPE not in tokens.get(address, {}).get("scope", "").split():
            continue  # Existing desktop credentials keep working without re-consent.
        rankings = {m["gmailId"]: {field: m.get(field) for field in ("score", "cat", "why")}
                    for m in mail if m["a"] == key}
        if not rankings:
            continue  # A transient fetch failure must not erase the phone's ranking metadata.
        document = {"version": 1, "account": address, "rankings": rankings}
        try:
            query = urllib.parse.urlencode({"spaces": "appDataFolder", "q": f"name = '{RANK_FILE}' and trashed = false",
                                            "fields": "files(id)", "orderBy": "modifiedTime desc", "pageSize": 1})
            files = call(address, "GET", "https://www.googleapis.com/drive/v3/files?" + query).get("files", [])
            if files:
                file_id = files[0]["id"]
            else:
                file_id = call(address, "POST", "https://www.googleapis.com/drive/v3/files",
                               {"name": RANK_FILE, "parents": ["appDataFolder"], "mimeType": "application/json"})["id"]
            call(address, "PATCH", f"https://www.googleapis.com/upload/drive/v3/files/{file_id}?uploadType=media", document)
        except GoogleError as e:
            print(f"  Ranking sync for {address} unavailable: {e}", flush=True)


# ---------- page ----------

PATCHES = [
    ('const ACCOUNTS = [["all","All inboxes"],',
     'const REAL = window.REAL_DATA || {base: [2026, 10, 2]};\nconst ACCOUNTS = REAL.accounts || [["all","All inboxes"],'),
    ("const GLYPHS = {", "Object.assign(ADDRESS, REAL.address || {});\nconst GLYPHS = {"),
    ("const SEED = [", "const SEED = REAL.mail || ["),
    ("unread: !ALREADY_READ.includes(m.id), star: STARRED.includes(m.id)",
     "unread: m.unread ?? !ALREADY_READ.includes(m.id), star: m.star ?? STARRED.includes(m.id)"),
    ("NOW = {day: 0, min: 14 * 60 + 5}", "NOW = REAL.now || {day: 0, min: 14 * 60 + 5}"),
    ("const SEED_EVENTS = [", "const SEED_EVENTS = (REAL.events || ["),
    ("].map(ev);", "]).map(ev);"),
    ("const PEOPLE = [", "const PEOPLE = REAL.people || ["),
    ("new Date(2026, 10, 2 + day)", "new Date(REAL.base[0], REAL.base[1], REAL.base[2] + day)"),
    ('${e.via === "Zoom" ? "https://zoom.us/join" : "https://meet.google.com/"}',
     '${e.link || (e.via === "Zoom" ? "https://zoom.us/join" : "https://meet.google.com/")}'),
    ('const m = mail.find(x => x.id === id), esc = s => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");',
     'const m = mail.find(x => x.id === id), esc = s => { const t = document.createElement("textarea"); t.innerHTML = s; return t.value.replace(/&/g, "&amp;").replace(/</g, "&lt;"); };'),
    ("<span>Sample mail · ", '<span>${REAL.live ? (window.INBOX_API ? "Live" : "Live, read-only") : "Sample mail"} · '),
]

# Wires the page's buttons to the local server. Loaded after the page's own script, so it can wrap its functions.
BRIDGE = r"""
<script>
(() => {
  if (!window.INBOX_API) return;
  let pendingWrites = 0, revision = 0;
  const call = async (path, body) => {
    const writing = !["thread", "snapshot", "refresh"].includes(path);
    if (writing) { pendingWrites++; revision++; }
    try {
    const r = await fetch("/api/" + path, {method: "POST", headers: {"Content-Type": "application/json", "X-Inbox-Token": window.INBOX_API}, body: JSON.stringify(body)});
    const out = await r.json().catch(() => ({error: "No answer from the app."}));
    if (!r.ok || out.error) throw new Error(out.error || "Something went wrong.");
    return out;
    } finally { if (writing) pendingWrites--; }
  };
  const fail = e => toast(e.message);

  window.syncFlags = (hit, field, value) => {
    const byAccount = {};
    hit.filter(m => m.gmailId).forEach(m => (byAccount[m.a] ||= []).push(m.gmailId));
    Object.entries(byAccount).forEach(([a, ids]) => call("flags", {a, ids, field, value}).catch(fail));
  };

  window.sendFeedback = (m, dir) => {
    if (!m.gmailId) return;
    call("feedback", {gmailId: m.gmailId, from: m.from, fromAddr: m.fromAddr || "", subj: m.subj, dir})
      .then(() => dir !== "undo" && toast(dir === "down" ? `Got it. Mail like this from ${html2text(m.from)} will rank lower.` : `Got it. Mail like this will rank higher.`))
      .catch(fail);
  };

  const localSend = sendComposer;
  sendComposer = async () => {
    const c = composing, to = c.to.trim();
    if (!/@/.test(to + (c.cc || "") + (c.bcc || ""))) { toast("Add an email address to send to"); return $("c-to").focus(); }
    try {
      await call("send", {a: c.from, to, cc: c.showCc ? c.cc : "", bcc: c.showCc ? (c.bcc || "") : "", subject: c.subj, body: c.body, forward: c.forward || []});
      localSend(); toast(`Sent from ${ADDRESS[c.from]}`);
    } catch (e) { fail(e); }
  };

  // The reply box: who it goes to, Reply / Reply all / Forward, and editable To, Cc and Bcc.
  const mine = () => Object.values(ADDRESS).filter(Boolean).map(a => a.toLowerCase());
  const splitList = v => String(v || "").split(",").map(x => x.trim()).filter(Boolean);
  const addrOf = v => (v.match(/<([^>]+)>/)?.[1] || v).trim().toLowerCase();
  const replies = {};
  function replyFor(m) {
    if (replies[m.id]) return replies[m.id];
    const sender = html2text(m.from) && html2text(m.fromAddr) ? `${html2text(m.from)} <${html2text(m.fromAddr)}>` : html2text(m.fromAddr || m.from);
    return replies[m.id] = {mode: "reply", to: sender, cc: "", bcc: "", open: false};
  }
  function everyone(m) {
    const last = (threads[m.a + ":" + m.threadId] || []).slice(-1)[0];
    const r = replyFor(m), skip = new Set([...mine(), addrOf(r.to)]);
    const seen = new Set();
    return [...splitList(last?.to), ...splitList(last?.cc)].filter(x => { const a = addrOf(x); if (skip.has(a) || seen.has(a)) return false; seen.add(a); return true; }).join(", ");
  }
  function paintReplyBar() {
    const form = document.getElementById("compose"), m = mail.find(x => x.id === sel);
    if (!form || !m || document.querySelector(".reader")?.classList.contains("previewing")) return;
    const r = replyFor(m);
    const names = v => splitList(v).map(x => esc(x.replace(/\s*<[^>]+>/, "") || x)).join(", ");
    let bar = form.querySelector(".replybar");
    if (!bar) { bar = document.createElement("div"); bar.className = "replybar"; form.prepend(bar); }
    bar.innerHTML = `<div class="rmodes">${["reply", "all", "forward"].map(k => `<button type="button" data-rmode="${k}" class="${r.mode === k ? "on" : ""}">${{reply: "Reply", all: "Reply all", forward: "Forward"}[k]}</button>`).join("")}</div>
      ${r.open ? `<input class="fi rto" data-rf="to" list="people-mail" placeholder="To" aria-label="To" value="${esc(r.to)}">
        <input class="fi rto" data-rf="cc" list="people-mail" placeholder="Cc" aria-label="Cc" value="${esc(r.cc)}">
        <input class="fi rto" data-rf="bcc" list="people-mail" placeholder="Bcc" aria-label="Bcc" value="${esc(r.bcc)}">`
        : `<button type="button" class="rwho" data-redit title="Change who this goes to">To ${names(r.to) || "nobody yet"}${r.cc ? ` <span>· Cc ${names(r.cc)}</span>` : ""}${r.bcc ? ` <span>· Bcc ${names(r.bcc)}</span>` : ""} <em>Edit</em></button>`}`;
  }
  document.addEventListener("click", e => {
    const b = e.target.closest?.("[data-rmode], [data-redit]");
    if (!b) return;
    const m = mail.find(x => x.id === sel); if (!m) return;
    const r = replyFor(m);
    if (b.dataset.rmode === "forward") { forwardEmail(m); return; }
    if (b.dataset.rmode) { r.mode = b.dataset.rmode; r.cc = r.mode === "all" ? everyone(m) : ""; }
    if ("redit" in b.dataset) r.open = true;
    paintReplyBar();
    if ("redit" in b.dataset) document.querySelector('[data-rf="to"]')?.focus();
  }, true);
  document.addEventListener("input", e => {
    const f = e.target.dataset?.rf; if (!f) return;
    const m = mail.find(x => x.id === sel); if (m) replyFor(m)[f] = e.target.value;
  });
  // Send the reply before the page marks the email read and moves on.
  document.addEventListener("submit", e => {
    const m = mail.find(x => x.id === sel), text = e.target.querySelector("textarea")?.value.trim();
    if (!m || !text) return;
    const r = replyFor(m);
    if (!/@/.test(r.to + r.cc + r.bcc)) { e.preventDefault(); e.stopImmediatePropagation(); toast("Add an email address to send this to"); return; }
    // Show the reply in the thread right away; it turns from "Sending…" to the time once Gmail has it.
    const key = m.a + ":" + m.threadId;
    if (!threads[key]) threads[key] = quick(m);
    const mineMsg = {id: "", from: "You", fromAddr: ADDRESS[m.a], date: "Sending…", to: r.to, cc: r.cc, html: "", text, files: []};
    threads[key] = [...threads[key], mineMsg];
    call("send", {a: m.a, replyTo: m.gmailId, to: r.to, cc: r.cc, bcc: r.bcc, body: text})
      .then(() => {
        mineMsg.date = "Just now"; delete replies[m.id];
        if (sel === m.id) render();
        toast(`Sent to ${splitList(r.to).map(x => x.replace(/\s*<[^>]+>/, "")).join(", ")}`);
      })
      .catch(err => {
        threads[key] = threads[key].filter(x => x !== mineMsg);
        m.draft = text;   // put the text back so nothing is lost
        if (sel === m.id) render();
        fail(err);
      });
  }, true);

  // Suggestions for the reply bar's To, Cc and Bcc.
  if (!document.getElementById("people-mail")) document.body.insertAdjacentHTML("beforeend", `<datalist id="people-mail">${PEOPLE.map(p => `<option value="${p}">`).join("")}</datalist>`);

  // Forward the whole conversation, with its attachments.
  forwardEmail = m => {
    const msgs = threads[m.a + ":" + m.threadId];
    const subj = html2text(m.subj), title = /^fwd?:/i.test(subj) ? subj : "Fwd: " + subj;
    const quote = (msgs || [{from: html2text(m.from), date: m.time, to: "", text: html2text(m.body), html: ""}]).map(x =>
      `---------- Forwarded message ---------\nFrom: ${x.from}${x.fromAddr ? " <" + x.fromAddr + ">" : ""}\nDate: ${x.date}\nSubject: ${subj}${x.to ? "\nTo: " + x.to : ""}\n\n${(x.text || html2text(x.html.replace(/<(br|\/p|\/div|\/tr)[^>]*>/gi, "\n").replace(/<[^>]+>/g, ""))).trim()}`).join("\n\n");
    const files = (msgs || []).reduce((n, x) => n + x.files.length, 0);
    composing = {from: m.a, to: "", cc: "", bcc: "", showCc: false, subj: title, body: "\n\n" + quote,
      forward: msgs ? msgs.filter(x => x.files.length && x.id).map(x => x.id) : [m.gmailId]};
    paintComposer(); $("c-to").focus();
    if (files) toast(`${files} attachment${files === 1 ? "" : "s"} will be forwarded too`);
  };

  // Search all of Gmail, both inboxes.
  searchAll = async q => {
    if (!q) return;
    toast("Searching all mail…");
    try {
      const out = await call("search", {q, account: acct});
      const have = new Map(mail.filter(m => m.gmailId).map(m => [m.a + ":" + m.gmailId, m]));
      let next = Math.max(0, ...mail.map(m => m.id)) + 1;
      const ids = new Set();
      out.mail.forEach(r => {
        const existing = have.get(r.a + ":" + r.gmailId);
        if (existing) { ids.add(existing.id); return; }
        const added = {...r, id: next++, fromSearch: true, deleted: false};
        mail.push(added); ids.add(added.id);
      });
      searchHits = ids;
      sel = [...ids][0] ?? sel;
      render();
      toast(ids.size ? `${ids.size} found in all mail` : "Nothing in your mail matches");
    } catch (e) { fail(e); }
  };


  const localSave = saveDraft;
  saveDraft = () => {
    addGuest();
    const d = JSON.parse(JSON.stringify(draft));
    localSave();
    call("event", {op: "save", base: REAL.base, event: d}).then(out => {
      const local = events.find(x => x.id === d.id);
      if (local) Object.assign(local, out.event, {id: d.id});
      render();
      toast(out.skipped?.length ? `Saved. Not invited (no email address): ${out.skipped.join(", ")}` : out.invited ? `Saved and invited ${out.invited}` : "Saved to Google Calendar");
    }).catch(fail);
  };

  const localDelete = deleteDraft;
  deleteDraft = () => {
    const d = draft;
    localDelete();
    if (d.gid) call("event", {op: "delete", event: {gid: d.gid, a: d.a}}).then(() => toast("Event deleted")).catch(fail);
  };

  // ---- The open email, as it really looks: the whole thread, real HTML, links, images and attachments. ----
  const style = document.createElement("style");
  style.textContent = `
    .thread { display: flex; flex-direction: column; gap: 10px; }
    /* Each message in a thread is its own tinted section, in its sender's color; yours are marked You. */
    .tmsg { display: flex; flex-direction: column; gap: 8px; padding: 10px; border-radius: 16px;
      background: oklch(62% .07 var(--h, 245) / .17); box-shadow: inset 0 .5px 0 rgba(255,255,255,.2), inset 3px 0 0 oklch(72% .11 var(--h, 245) / .75); }
    .tmsg.mine { background: rgba(99,160,255,.16); box-shadow: inset 0 .5px 0 rgba(255,255,255,.2), inset 3px 0 0 rgba(99,208,255,.8); }
    .thead { display: flex; justify-content: space-between; align-items: center; gap: 10px; width: 100%; text-align: left; font-size: 12.5px; color: var(--dim); }
    .thead .who { display: flex; align-items: center; gap: 9px; min-width: 0; }
    .tav { width: 28px; height: 28px; flex: none; display: grid; place-items: center; border-radius: 50%; font-size: 10.5px; color: #fff; background: radial-gradient(circle at 32% 28%, oklch(78% .12 var(--h, 245)), oklch(48% .12 var(--h, 245))); }
    .tmsg.mine .tav { background: radial-gradient(circle at 32% 28%, #8fd0ff, #2f6fd1); }
    .thead b { font: normal 700 13.5px/1.3 var(--head); color: var(--strong); }
    .thead .when2 { flex: none; }
    .tmsg.folded { cursor: pointer; }
    .tmsg.folded:hover { filter: brightness(1.12); }
    .tmsg.folded .thead span.snip2 { display: block; color: var(--dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 320px; }
    .tto { font-size: 12px; color: var(--dim); padding-left: 37px; margin-top: -4px; }
    .sheet { display: block; width: 100%; border: 0; border-radius: 12px; background: #1e2230; }
    [data-look="dim"] .sheet { background: #2b3242; }
    [data-look="light"] .sheet { background: #fff; }
    .quoted { align-self: flex-start; font-size: 12px; color: var(--blue); }
    .atts { display: flex; flex-wrap: wrap; gap: 6px; }
    .att { display: inline-flex; gap: 6px; align-items: center; padding: 6px 10px; border-radius: 10px; font-size: 12px; color: var(--strong); text-decoration: none; background: rgba(170,200,255,.13); box-shadow: inset 0 .5px 0 rgba(255,255,255,.22); }
    .att small { color: var(--dim); }
    .tload { margin: 0; color: var(--dim); }
    .compose { grid-template-columns: minmax(0, 1fr) auto; }
    .replybar { grid-column: 1 / -1; display: flex; flex-direction: column; gap: 6px; padding-bottom: 6px; border-bottom: 1px solid rgba(255,255,255,.08); }
    .rmodes { display: flex; gap: 4px; }
    .rmodes button { padding: 3px 10px; border-radius: 999px; font-size: 12px; color: var(--dim); }
    .rmodes button.on { color: #fff; background: rgba(170,200,255,.18); box-shadow: inset 0 .5px 0 rgba(255,255,255,.25); }
    .rwho { text-align: left; font-size: 12.5px; color: var(--ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .rwho span { color: var(--dim); }
    .rwho em { font-style: normal; color: var(--blue); margin-left: 6px; }
    .rto { font-size: 12.5px; }
    .reader .rscroll { gap: 12px; }`;
  document.head.appendChild(style);

  const esc = s => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const linkify = s => s.replace(/(https?:\/\/[^\s<>"')\]]+)/g, '<a href="$1">$1</a>');
  // Plain-text mail: quoted lines become a folded quote instead of a ">" on every line.
  function textToHtml(text) {
    const out = [], lines = String(text || "").replace(/`/g, "").split(/\r?\n/);
    let quote = [];
    const flush = () => { if (quote.length) { out.push(`<blockquote class="gmail_quote">${textToHtml(quote.join("\n"))}</blockquote>`); quote = []; } };
    for (const line of lines) {
      if (/^\s*>/.test(line)) quote.push(line.replace(/^\s*> ?/, ""));
      else { flush(); out.push(linkify(esc(line))); }
    }
    flush();
    return `<div style="white-space:pre-wrap">${out.join("\n").replace(/\n*(<blockquote)/g, "\n$1").replace(/(<\/blockquote>)\n*/g, "$1")}</div>`;
  }
  // Dark mode for the real email. Plain text gets dark colors directly. HTML mail, which brings its own light colors,
  // is flipped dark the way Gmail's dark mode does it, with photos and logos flipped back so they look right.
  // Mail that is already dark is left as it is (see darkAlready).
  const sheetDoc = (body, plain) => `<!doctype html><html class="${plain ? "plain" : "flip"} look-${emailLook}"><head><meta charset="utf-8"><base target="_blank"><style>
    html { color-scheme: dark; } html.flip { color-scheme: light; } html.look-light { color-scheme: light; }
    html, body { margin: 0; background: transparent; overflow: hidden; } body { padding: 16px 18px; font: 14px/1.55 -apple-system, "Helvetica Neue", Helvetica, Arial, sans-serif; overflow-wrap: anywhere; }
    img { max-width: 100%; height: auto; } pre { white-space: pre-wrap; }
    /* Many emails set html, body { height: 100% }, which pins them to the frame's size and crops them. */
    html[class], html[class] body { height: auto !important; min-height: 0 !important; }
    html.plain, html.plain body { background: #1e2230; color: #e6ecf8; }
    html.plain.look-dim, html.plain.look-dim body { background: #2b3242; color: #b9c3d6; }
    html.plain.look-light, html.plain.look-light body { background: #fff; color: #202124; }
    html.plain.look-light a { color: #1a73e8; }
    html.plain.look-light blockquote { border-left-color: #dadce0; color: #5f6368; }
    html.flip.look-dim { filter: invert(.8) hue-rotate(180deg) brightness(1.05); }
    html.look-light:not(.plain) { background: #fff; color: #202124; filter: none; }
    html.look-light:not(.plain) img, html.look-light:not(.plain) picture, html.look-light:not(.plain) video, html.look-light:not(.plain) svg,
    html.look-light:not(.plain) [style*="background-image"], html.look-light:not(.plain) [background] { filter: none !important; }
    html.plain a { color: #7cc4ff; }
    html.plain blockquote { margin: 8px 0 0; padding-left: 10px; border-left: 2px solid #3a4763; color: #a9b6d1; }
    html.flip { background: #fff; color: #202124; filter: invert(.9) hue-rotate(180deg); }
    html.flip a { color: #1a73e8; }
    html.flip blockquote { margin: 8px 0 0; padding-left: 10px; border-left: 2px solid #dadce0; color: #5f6368; }
    html.flip img, html.flip picture, html.flip video, html.flip svg, html.flip canvas, html.flip iframe,
    html.flip [style*="background-image"], html.flip [background] { filter: invert(1) hue-rotate(180deg); }
    .q-hidden .gmail_quote, .q-hidden blockquote[type=cite], .q-hidden .yahoo_quoted, .q-hidden #appendonsend ~ * { display: none !important; }
  </style></head><body class="q-hidden">${body}</body></html>`;
  // An email whose own background is already dark shouldn't be flipped to light.
  function darkAlready(doc) {
    const lum = el => {
      const m = getComputedStyle(el).backgroundColor.match(/[\d.]+/g);
      if (!m || (m[3] !== undefined && +m[3] < .5)) return null;
      return (.2126 * m[0] + .7152 * m[1] + .0722 * m[2]) / 255;
    };
    const candidates = [doc.body, ...doc.body.querySelectorAll(":scope > *, :scope > * > *, table")].slice(0, 12);
    const found = candidates.map(lum).find(v => v !== null);
    return found !== undefined && found < .35;
  }

  function fit(frame) {
    // Size the frame to the email without collapsing it first, so the reading pane's scroll never jumps.
    const doc = frame.contentDocument;
    if (!doc?.body) return;
    const room = frame.clientWidth;
    doc.body.style.zoom = 1;
    const wide = doc.documentElement.scrollWidth;
    if (wide > room + 2) doc.body.style.zoom = (room / wide).toFixed(3);
    const tall = contentHeight(doc);
    if (Math.abs(frame.offsetHeight - tall) > 1) frame.style.height = tall + "px";
  }
  // The email's real height: the body, or whatever its content reaches if that runs past the body.
  function contentHeight(doc) {
    const body = doc.body, box = body.getBoundingClientRect();
    const range = doc.createRange();
    range.selectNodeContents(body);
    const reach = range.getBoundingClientRect().bottom - box.top + (parseFloat(getComputedStyle(body).paddingBottom) || 0);
    return Math.ceil(Math.max(box.height, reach));
  }
  function sheet(html, holder, plain) {
    const frame = document.createElement("iframe");
    frame.className = "sheet";
    frame.title = "Email";
    frame.setAttribute("sandbox", "allow-same-origin allow-popups allow-popups-to-escape-sandbox");
    frame.srcdoc = sheetDoc(html, plain);
    frame.addEventListener("load", () => {
      const doc = frame.contentDocument;
      if (doc && !plain) {
        doc.documentElement.classList.remove("flip");
        if (emailLook !== "light" && !darkAlready(doc)) doc.documentElement.classList.add("flip");
      }
      fit(frame);
      // One scroll only: the frame never scrolls, it grows to fit, and the wheel over it scrolls the reading pane.
      if (doc) {
        // The email's frame runs no scripts and observers can't see into it, so re-check its height while it's on screen
        // (late images, fonts, a quote opening). It stops once the email is closed.
        let lastTall = 0;
        const recheck = setInterval(() => {
          if (!frame.isConnected) return clearInterval(recheck);
          const tall = contentHeight(doc);
          if (tall !== lastTall) { lastTall = tall; fit(frame); }
        }, 300);
        doc.addEventListener("wheel", e => {
          const pane = frame.closest(".rscroll");
          if (!pane || Math.abs(e.deltaX) > Math.abs(e.deltaY)) return;
          e.preventDefault();
          pane.scrollBy({top: e.deltaY * (e.deltaMode === 1 ? 16 : 1)});
        }, {passive: false});
      }
      if (doc?.querySelector(".gmail_quote, blockquote[type=cite], .yahoo_quoted")) {
        const toggle = document.createElement("button");
        toggle.className = "quoted";
        toggle.textContent = "Show quoted text";
        toggle.onclick = () => { const on = doc.body.classList.toggle("q-hidden"); toggle.textContent = on ? "Show quoted text" : "Hide quoted text"; fit(frame); };
        frame.after(toggle);
      }
    });
    holder.appendChild(frame);
  }
  const html2text = s => { const t = document.createElement("textarea"); t.innerHTML = s; return t.value; };
  const size = n => n > 1e6 ? (n / 1e6).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1e3)) + " KB";
  function paint(box, msgs) {
    box.innerHTML = "";
    msgs.forEach((msg, i) => {
      const last = i === msgs.length - 1, item = document.createElement("div");
      const mine = Object.values(ADDRESS).some(a => a && a.toLowerCase() === (msg.fromAddr || "").toLowerCase());
      const key = (msg.fromAddr || msg.from || "").toLowerCase();
      const hue = [...key].reduce((h, ch) => (h * 31 + ch.charCodeAt(0)) % 360, 7);
      item.className = "tmsg" + (last ? "" : " folded") + (mine ? " mine" : "");
      item.style.setProperty("--h", hue);
      const name = mine ? "You" : msg.from;
      const initials = (mine ? "You" : msg.from || "?").split(/\s+/).filter(Boolean).slice(0, 2).map(w => w[0]).join("").toUpperCase();
      const own = msg.text ? msg.text.split("\n").filter(line => !/^\s*>/.test(line)).join(" ") : msg.html.replace(/<blockquote[\s\S]*?<\/blockquote>|<div class="gmail_quote[\s\S]*$/gi, " ").replace(/<[^>]+>/g, " ");
      const preview = html2text(own).replace(/\s+/g, " ").trim().slice(0, 120);
      item.innerHTML = `<button class="thead" ${last ? "disabled" : ""}><span class="who"><span class="tav" aria-hidden="true">${esc(initials)}</span><span><b>${esc(name)}</b>${last || !preview ? "" : `<span class="snip2">${esc(preview)}</span>`}</span></span><span class="when2">${esc(msg.date)}</span></button>`;
      const open = () => {
        if (item.dataset.open) return;
        item.dataset.open = 1; item.classList.remove("folded");
        item.querySelector(".snip2")?.remove();
        if (msg.to) item.insertAdjacentHTML("beforeend", `<div class="tto">To ${esc(msg.to)}${msg.cc ? " · Cc " + esc(msg.cc) : ""}</div>`);
        sheet(msg.html || textToHtml(msg.text), item, !msg.html);
        if (msg.files.length) item.insertAdjacentHTML("beforeend", `<div class="atts">${msg.files.map(f => `<a class="att" href="${esc(f.url)}" target="_blank" rel="noopener" download="${esc(f.name)}">${esc(f.name)} <small>${size(f.size)}</small></a>`).join("")}</div>`);
      };
      item.querySelector(".thead").addEventListener("click", open);
      box.appendChild(item);
      if (last) open();
    });
  }
  // Full threads, fetched once each. Hovering starts the fetch, so a click usually finds it ready.
  const threads = {}, pending = {};
  const loadThread = m => {
    const key = m?.threadId ? m.a + ":" + m.threadId : null;
    if (!key || threads[key]) return Promise.resolve(key && threads[key]);
    return pending[key] ||= call("thread", {a: m.a, threadId: m.threadId})
      .then(out => (threads[key] = out.messages))
      .finally(() => { delete pending[key]; });
  };
  const quick = m => [{from: html2text(m.from), fromAddr: html2text(m.fromAddr || ""), date: m.time, html: "", text: html2text(m.body), files: []}];
  function enhanceReader() {
    const pane = document.querySelector(".reader"), body = pane?.querySelector(".body");
    if (!pane || !body) return;
    const shown = mail.find(x => x.id === sel);
    const box = document.createElement("div");
    box.className = "thread";
    body.replaceWith(box);
    const previewing = pane.classList.contains("previewing");
    const m = previewing ? mail.find(x => x.id === previewId) || shown : shown;
    if (!m) return;
    // Show the full thread if it's here; otherwise the quick copy now, and swap in the full thread when it arrives.
    paint(box, threads[m.a + ":" + m.threadId] || quick(m));
    if (!m.threadId || threads[m.a + ":" + m.threadId]) return;
    loadThread(m)
      .then(msgs => { if (box.isConnected && msgs) paint(box, msgs); })
      .catch(e => {
        if (!box.isConnected || previewing) return;
        box.insertAdjacentHTML("beforeend", `<p class="tload">Showing a text copy. Links and images didn't load (${esc(e.message)}). <button class="quoted" data-retrythread>Retry</button></p>`);
      });
  }
  const localRender = render;
  let shownSel = sel, dwell = null;
  function markShownRead() {
    clearTimeout(dwell);
    if (sel === shownSel) return;
    shownSel = sel;
    dwell = setTimeout(() => {
      const m = mail.find(x => x.id === sel);
      const pane = document.querySelector(".reader");
      if (!m || !m.unread || sel !== shownSel || !pane || pane.classList.contains("previewing") || getComputedStyle(pane).display === "none") return;
      m.unread = false; window.syncFlags([m], "unread", false);
      undoFn = () => { m.unread = true; window.syncFlags([m], "unread", true); };
      undoLabel = "Marked read"; undoAt = Date.now();
      render();
    }, 1200);
  }
  render = (...args) => { localRender(...args); enhanceReader(); paintReplyBar(); markShownRead(); };
  const localShow = showInReader;
  showInReader = id => { localShow(id); enhanceReader(); paintReplyBar(); };
  enhanceReader();
  document.addEventListener("click", e => { if (e.target.closest?.("[data-retrythread]")) render(); });
  // Resizing the reading pane re-fits each email to the new width.
  window.addEventListener("readerresize", () => document.querySelectorAll(".sheet").forEach(fit));

  // Preserve open drafts, selection, and scroll position while merging Google state.
  let syncing = false;
  const editing = () => composing || draft || drag || picks.size || searchHits || search ||
    document.activeElement?.matches("textarea, input, [contenteditable=true]") ||
    [...document.querySelectorAll(".compose textarea")].some(el => el.value.trim());
  async function syncSnapshot(manual = false) {
    if (syncing || pendingWrites || editing() || (!manual && document.hidden)) {
      if (manual) toast("Finish your edit or wait for the current action, then check again.");
      return;
    }
    syncing = true;
    const started = revision;
    try {
      const data = await call("snapshot", {});
      if (started !== revision || pendingWrites || editing()) return;
      const selected = mail.find(m => m.id === sel);
      const oldIDs = new Map(mail.filter(m => m.gmailId).map(m => [m.a + ":" + m.gmailId, m.id]));
      let nextID = Math.max(0, ...mail.map(m => m.id)) + 1;
      mail = data.mail.map(m => ({...m, id: oldIDs.get(m.a + ":" + m.gmailId) ?? nextID++, deleted: false}));
      sel = selected ? mail.find(m => m.a === selected.a && m.gmailId === selected.gmailId)?.id ?? null : null;
      events = data.events.map(ev);
      REAL.base = data.base; REAL.now = data.now;
      Object.assign(NOW, data.now);
      undoFn = null; evUndo = null;
      Object.keys(threads).forEach(key => delete threads[key]);
      render();
    } catch (error) { if (manual) fail(error); }
    finally { syncing = false; }
  }
  setInterval(() => syncSnapshot(), 60000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) syncSnapshot(); });

  const foot = document.querySelector(".sfoot");
  if (foot) {
    foot.insertAdjacentHTML("afterbegin", '<button class="act" id="refreshbtn" style="width:100%;justify-content:center;margin-bottom:6px">Check for new mail</button>');
    document.getElementById("refreshbtn").addEventListener("click", async e => {
      e.target.textContent = "Checking…";
      try { await syncSnapshot(true); } finally { e.target.textContent = "Check for new mail"; }
    });
  }
})();
</script>
"""


def build(data, api_token=None):
    with open(TEMPLATE, encoding="utf-8") as source:
        page = source.read()
    for old, new in PATCHES:
        if page.count(old) != 1:
            sys.exit(f"The template changed and this script no longer fits it (looking for: {old[:50]}…).")
        page = page.replace(old, new)
    blob = json.dumps(data).replace("</", "<\\/")
    head = f"<script>window.REAL_DATA = {blob};" + (f"window.INBOX_API = {json.dumps(api_token)};" if api_token else "") + "</script>\n"
    page = page.replace("<script>", head + "<script>", 1)
    if api_token:
        page = page.rstrip() + "\n" + BRIDGE
    return page


def week_base(today):
    return today - dt.timedelta(days=today.weekday())


def gather():
    now = dt.datetime.now()
    base = week_base(now.date())
    counter = iter(range(1, 10**9))
    next_id = lambda: next(counter)
    mail, events, accounts, address = [], [], [["all", "All inboxes"]], {}
    failures, signed_out = [], []
    for key, name, mailbox in ACCOUNTS:
        if not access_token(mailbox):
            print(f"{name}: not signed in, skipped.", flush=True)
            signed_out.append(name)
            continue
        accounts.append([key, name])
        address[key] = mailbox
        try:
            got = fetch_mail(mailbox, key, now, next_id)
        except GoogleError as e:
            print(f"{name}: mail didn't load ({e}).", flush=True)
            failures.append(f"{name}: {e}")
            got = []
        try:
            evs = fetch_events(mailbox, key, base, next_id)
        except GoogleError as e:
            print(f"{name}: calendar didn't load ({e}).", flush=True)
            failures.append(f"{name}: {e}")
            evs = []
        print(f"{name}: {len(got)} emails, {len(evs)} events this week.", flush=True)
        mail += got
        events += evs
    if len(accounts) == 1:
        raise GoogleError("No connected accounts. Run: python3 inbox.py login")
    if failures:
        raise GoogleError("Refresh incomplete; keeping the previous view. " + "; ".join(failures))
    print("Ranking new mail with Claude…", flush=True)
    rank(mail)
    publish_rankings(mail)
    mail.sort(key=lambda m: -m["ts"])
    seen, people = set(), []
    for m in mail:
        if m["fromAddr"] and not re.search(r"no-?reply|notifications?@|mailer", m["fromAddr"], re.I) and m["fromAddr"] not in seen:
            seen.add(m["fromAddr"])
            people.append(f"{m['from']} <{m['fromAddr']}>" if m["from"] != m["fromAddr"] else m["fromAddr"])
    # Email text is data, never markup: escape it before the page sees it. A sender, subject or preview that
    # contains "<" can otherwise break the page's layout or run code inside the app.
    for m in mail:
        for field in ("from", "fromAddr", "subj", "body", "why", "time"):
            if isinstance(m.get(field), str):
                m[field] = html.escape(m[field], quote=True)
    people = [html.escape(p, quote=True) for p in people]
    return {"live": True, "accounts": accounts, "address": address, "mail": mail, "events": events, "people": people[:200],
            "signedOut": signed_out, "city": CITY, "base": [base.year, base.month - 1, base.day], "now": {"day": (now.date() - base).days, "min": now.hour * 60 + now.minute}}


def sync():
    private_write(OUT, build(gather()))
    print(f"Built {OUT} (read-only copy)")
    subprocess.run(["open", OUT])


# ---------- actions ----------

LABEL = {"unread": "UNREAD", "star": "STARRED"}


def do_feedback(req):
    notes = read_feedback()
    if req.get("dir") == "undo":
        notes = [n for n in notes if n.get("gmailId") != req.get("gmailId")]
    else:
        notes = [n for n in notes if n.get("gmailId") != req.get("gmailId")]
        notes.append({"dir": "down" if req.get("dir") == "down" else "up", "gmailId": req.get("gmailId", ""),
                      "from": html.unescape(req.get("from", ""))[:120], "fromAddr": html.unescape(req.get("fromAddr", ""))[:200],
                      "subj": html.unescape(req.get("subj", ""))[:200], "at": dt.datetime.now().isoformat(timespec="seconds")})
    private_write(FEEDBACK, json.dumps(notes[-500:]))
    return {"ok": True}


_live_state = {}


def remember_flags(req):
    """Apply a successful change to the copy the page is built from."""
    data = _live_state.get("data")
    if not data:
        return
    ids = set(req.get("ids") or [])
    field, value = req.get("field"), bool(req.get("value"))
    keep = []
    for m in data["mail"]:
        if m.get("a") == req.get("a") and m.get("gmailId") in ids:
            if field in ("unread", "star"):
                m[field] = value
            elif field in ("deleted", "archived", "spam") and value:
                continue  # gone from the inbox; Undo brings it back on the next refresh
        keep.append(m)
    data["mail"] = keep
    _live_state["dirty"] = True


def do_flags(req):
    address = ADDRESS[req["a"]]
    for gid in req["ids"]:
        if req["field"] == "deleted":
            call(address, "POST", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gid}/{'trash' if req['value'] else 'untrash'}")
        elif req["field"] == "archived":
            key = "removeLabelIds" if req["value"] else "addLabelIds"
            call(address, "POST", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gid}/modify", {key: ["INBOX"]})
        elif req["field"] == "spam":
            change = {"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]} if req["value"] else {"addLabelIds": ["INBOX"], "removeLabelIds": ["SPAM"]}
            call(address, "POST", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gid}/modify", change)
        elif req["field"] in LABEL:
            key = "addLabelIds" if req["value"] else "removeLabelIds"
            call(address, "POST", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{gid}/modify", {key: [LABEL[req["field"]]]})
    return {"ok": True}


def do_send(req):
    address = ADDRESS[req["a"]]
    msg = email.message.EmailMessage()
    msg["From"] = address
    body = {"raw": None}
    subject = req.get("subject") or ""
    if req.get("replyTo"):
        original = call(address, "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{req['replyTo']}?format=metadata"
                        "&metadataHeaders=Subject&metadataHeaders=Message-ID&metadataHeaders=References&metadataHeaders=From&metadataHeaders=Reply-To")
        h = {x["name"].lower(): x["value"] for x in original["payload"].get("headers", [])}
        if not subject:
            subject = h.get("subject", "")
            subject = subject if subject.lower().startswith("re:") else f"Re: {subject}"
        if h.get("message-id"):
            msg["In-Reply-To"] = h["message-id"]
            msg["References"] = (h.get("references", "") + " " + h["message-id"]).strip()
        body["threadId"] = original["threadId"]
        to = req.get("to") or h.get("reply-to") or h.get("from")
    else:
        to = req.get("to") or ""
    if not to.strip() and not (req.get("cc") or "").strip() and not (req.get("bcc") or "").strip():
        raise GoogleError("Add someone to send this to.")
    for header, value in (("To", to), ("Cc", req.get("cc")), ("Bcc", req.get("bcc"))):
        if value and value.strip():
            msg[header] = value.strip()
    msg["Subject"] = subject
    msg.set_content(req.get("body") or "")
    # Forward: attach every file from the forwarded messages.
    for ref in req.get("forward") or []:
        m = call(address, "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{ref}?format=full")
        for part in _file_parts(m["payload"]):
            data = part["body"].get("data") or call(address, "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{ref}/attachments/{part['body']['attachmentId']}")["data"]
            maintype, _, subtype = (part.get("mimeType") or "application/octet-stream").partition("/")
            msg.add_attachment(base64.urlsafe_b64decode(data + "=="), maintype=maintype, subtype=subtype or "octet-stream", filename=part.get("filename") or "attachment")
    body["raw"] = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    call(address, "POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", body)
    return {"ok": True}


def _file_parts(part):
    found = []
    if part.get("filename") and (part.get("body", {}).get("attachmentId") or part.get("body", {}).get("data")):
        found.append(part)
    for sub in part.get("parts", []) or []:
        found += _file_parts(sub)
    return found


def do_search(req):
    """All of Gmail, not just the loaded inbox. Results come back shaped like inbox mail."""
    query = (req.get("q") or "").strip()
    if not query:
        return {"mail": []}
    now = dt.datetime.now()
    counter = iter(range(10**8, 10**9))
    found = []
    for key, _, address in ACCOUNTS:
        if req.get("account") not in (None, "all", key) or not access_token(address):
            continue
        found += fetch_mail(address, key, now, lambda: next(counter), query=query, limit=40)
    rank(found)
    found.sort(key=lambda m: -m["ts"])
    for m in found:
        for field in ("from", "fromAddr", "subj", "body", "why", "time"):
            if isinstance(m.get(field), str):
                m[field] = html.escape(m[field], quote=True)
    return {"mail": found}


def parse_message(m, address, token):
    """One message of a thread as the reader shows it: the real HTML (or the plain text), and its attachments."""
    headers = {h["name"].lower(): h["value"] for h in m["payload"].get("headers", [])}
    html_parts, text_parts, files, cids = [], [], [], {}

    def walk(part):
        mime, body = part.get("mimeType", ""), part.get("body", {})
        part_headers = {h["name"].lower(): h["value"] for h in part.get("headers", [])}
        cid = part_headers.get("content-id", "").strip("<>")
        disposition = part_headers.get("content-disposition", "").lower()
        has_file = body.get("attachmentId") or body.get("data")
        if has_file and (part.get("filename") or (body.get("attachmentId") and not mime.startswith("text/"))):
            url = (f"data:{mime};base64,{base64.b64encode(base64.urlsafe_b64decode(body['data'] + '==')).decode()}" if body.get("data")
                   else f"/attachment?" + urllib.parse.urlencode({"t": token, "a": address, "m": m["id"], "id": body.get("attachmentId", ""),
                                                                 "name": part.get("filename") or "file", "type": mime}))
            if cid:
                cids[cid] = url
            if not cid or "attachment" in disposition:
                files.append({"name": part.get("filename") or "file", "size": body.get("size", 0), "type": mime, "url": url})
        elif mime == "text/html" and body.get("data"):
            html_parts.append(b64(body["data"]))
        elif mime == "text/plain" and body.get("data"):
            text_parts.append(b64(body["data"]))
        for sub in part.get("parts", []) or []:
            walk(sub)

    walk(m["payload"])
    page = "\n".join(html_parts)
    for cid, url in cids.items():
        page = page.replace(f"cid:{cid}", url)
    name, addr = sender(headers.get("from"))
    return {"id": m["id"], "from": name, "fromAddr": addr, "to": headers.get("to", ""), "cc": headers.get("cc", ""),
            "date": dt.datetime.fromtimestamp(int(m["internalDate"]) / 1000).strftime("%a %b %-d, %-I:%M %p"),
            "html": page, "text": "\n".join(text_parts), "files": files, "unread": "UNREAD" in m.get("labelIds", [])}


def do_thread(req, token):
    address = ADDRESS[req["a"]]
    thread = call(address, "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/threads/{req['threadId']}?format=full")
    return {"messages": [parse_message(m, address, token) for m in thread.get("messages", [])]}


def attachment(query):
    address, data = query["a"], call(query["a"], "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{query['m']}/attachments/{query['id']}")
    return base64.urlsafe_b64decode(data["data"] + "==")


RRULE = {"daily": ["RRULE:FREQ=DAILY"], "weekly": ["RRULE:FREQ=WEEKLY"], "weekdays": ["RRULE:FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR"]}


def emails_in(guests):
    found, skipped = [], []
    for g in guests:
        _, addr = email.utils.parseaddr(g.get("n", ""))
        (found if "@" in addr else skipped).append(addr if "@" in addr else g.get("n", ""))
    return found, skipped


def do_event(req):
    e = req["event"]
    address = ADDRESS.get(e.get("a")) or next(iter(ADDRESS.values()))
    cal = "https://www.googleapis.com/calendar/v3/calendars/primary/events"
    if req["op"] == "delete":
        call(address, "DELETE", f"{cal}/{e['gid']}?sendUpdates=all")
        return {"ok": True}
    if e.get("org") and e.get("gid"):
        # Someone else's event: the only change you can make is your reply.
        current = call(address, "GET", f"{cal}/{e['gid']}")
        for p in current.get("attendees", []):
            if p.get("self"):
                p["responseStatus"] = RSVP_OUT.get(e.get("rsvp"), "accepted")
        updated = call(address, "PATCH", f"{cal}/{e['gid']}?sendUpdates=all", {"attendees": current.get("attendees", [])})
        base = dt.date(*[req["base"][0], req["base"][1] + 1, req["base"][2]])
        return {"ok": True, "event": event_out(updated, e["a"], base, address, e["id"])}
    base = dt.date(req["base"][0], req["base"][1] + 1, req["base"][2])
    day = base + dt.timedelta(days=e["day"])
    found, skipped = emails_in(e.get("guests", []))
    body = {"summary": e.get("n") or "Untitled", "location": e.get("loc", ""), "description": e.get("desc", ""),
            "attendees": [{"email": a} for a in found], "guestsCanInviteOthers": bool(e.get("invite", True)),
            "transparency": "transparent" if e.get("busy") == "free" else "opaque",
            "reminders": {"useDefault": False, "overrides": [] if e.get("remind") == "none" else [{"method": "popup", "minutes": int(e.get("remind") or 10)}]}}
    if e.get("allDay"):
        body["start"], body["end"] = {"date": day.isoformat()}, {"date": (day + dt.timedelta(days=1)).isoformat()}
    else:
        start = dt.datetime.combine(day, dt.time()).astimezone() + dt.timedelta(minutes=e["s"])
        body["start"], body["end"] = {"dateTime": start.isoformat()}, {"dateTime": (start + dt.timedelta(minutes=e["m"])).isoformat()}
    if e.get("repeat") in RRULE and not e.get("gid"):
        body["recurrence"] = RRULE[e["repeat"]]
    if e.get("via") == "Google Meet" and not (e.get("link") or "").startswith("https://meet.google.com/"):
        body["conferenceData"] = {"createRequest": {"requestId": uuid.uuid4().hex, "conferenceSolutionKey": {"type": "hangoutsMeet"}}}
    query = "conferenceDataVersion=1&sendUpdates=all"
    saved = call(address, "PATCH", f"{cal}/{e['gid']}?{query}", body) if e.get("gid") else call(address, "POST", f"{cal}?{query}", body)
    return {"ok": True, "event": event_out(saved, e["a"], base, address, e["id"]), "skipped": skipped, "invited": len(found)}


SESSION = os.path.join(HERE, ".session-key")


def session_key():
    """Kept across restarts, so a tab left open from an earlier run keeps working."""
    try:
        key = open(SESSION).read().strip()
        if key:
            return key
    except FileNotFoundError:
        pass
    key = secrets.token_urlsafe(24)
    private_write(SESSION, key)
    return key


def serve():
    token = session_key()
    initial = gather()
    state = _live_state
    state.update(page=build(initial, token), data=initial, at=time.time(), dirty=False)
    lock = threading.Lock()
    refresh_lock = threading.Lock()

    class App(http.server.BaseHTTPRequestHandler):
        def reply(self, code, body, kind="application/json"):
            raw = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            if url.path == "/attachment":
                q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
                if q.get("t") != token or q.get("a") not in ADDRESS.values():
                    return self.reply(403, "{}")
                if not q.get("m") or not q.get("id"):
                    return self.reply(404, json.dumps({"error": "This attachment has no file to download."}))
                try:
                    raw = attachment(q)
                except (GoogleError, KeyError) as e:
                    return self.reply(400, json.dumps({"error": str(e)}))
                self.send_response(200)
                self.send_header("Content-Type", q.get("type") or "application/octet-stream")
                if not (q.get("type") or "").startswith("image/"):
                    self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{urllib.parse.quote(q.get('name', 'file'))}")
                self.send_header("Cache-Control", "private, max-age=3600")
                self.end_headers()
                return self.wfile.write(raw)
            if url.path != "/":
                return self.reply(404, "{}")
            with lock:
                if state.get("dirty"):
                    state["page"], state["dirty"] = build(state["data"], token), False
                page = state["page"]
            self.reply(200, page, "text/html; charset=utf-8")

        def do_POST(self):
            origin = self.headers.get("Origin", "")
            if origin not in ("", f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"):
                return self.reply(403, json.dumps({"error": "Not allowed from this page."}))
            if self.headers.get("X-Inbox-Token") != token:
                return self.reply(403, json.dumps({"error": "This tab is from an older run of Inbox. Reload the page."}))
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            action = self.path.rsplit("/", 1)[-1]
            try:
                if action in ("refresh", "snapshot"):
                    # Fetching/ranking may take time. Keep the action lock free so background
                    # refresh cannot stall replies or label changes; the browser rejects stale merges.
                    # Every open tab polls; within 45 seconds they all share the same fetch.
                    with refresh_lock:
                        fresh = action == "snapshot" and time.time() - state.get("at", 0) < 45
                        data = state["data"] if fresh else gather()
                        page = state["page"] if fresh else build(data, token)
                    with lock:
                        state.update(data=data, page=page, at=state.get("at", 0) if fresh else time.time())
                    out = data if action == "snapshot" else {"ok": True}
                else:
                    with lock:
                        out = do_thread(req, token) if action == "thread" else {"flags": do_flags, "send": do_send, "event": do_event, "feedback": do_feedback, "search": do_search}[action](req)
                        if action == "flags":
                            remember_flags(req)
                print(f"  {action}: ok", flush=True)
                self.reply(200, json.dumps(out))
            except (GoogleError, KeyError, ValueError) as e:
                print(f"  {action}: {e}", flush=True)
                self.reply(400, json.dumps({"error": str(e)}))

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), App)
    url = f"http://127.0.0.1:{PORT}/"
    print(f"Inbox is running at {url} (only on this Mac). Stop it with Ctrl+C.", flush=True)
    webbrowser.open(url)
    server.serve_forever()


def demo():
    today = dt.date.today()
    base = week_base(today)
    data = {"live": False, "accounts": [["all", "All inboxes"], ["work", "Work"], ["personal", "Personal"]],
            "address": {"work": "you@work.example", "personal": "you@example.com"}, "city": CITY, "people": ["Test Person <test@example.com>"],
            "mail": [{"id": 1, "a": "work", "gmailId": "x1", "threadId": "t1", "cat": "Contracts", "score": 90, "from": "Test Sender", "time": "9:00", "subj": "Demo email",
                      "why": "Demo data.", "body": "This page was built from made-up data, due `Friday`.", "unread": True, "star": False}],
            "events": [{"id": 3, "gid": "g1", "day": (today - base).days, "s": 23 * 60, "m": 30, "n": "Demo meeting", "a": "work", "via": "Google Meet",
                        "link": "https://meet.google.com/", "code": "abc-defg-hij", "guests": []}],
            "base": [base.year, base.month - 1, base.day], "now": {"day": (today - base).days, "min": 9 * 60}}
    private_write(OUT, build(data, "demo-token"))
    print(f"Built {OUT}")


def setup():
    """Ask for the accounts, name and city, and write settings.json."""
    cfg, _ = load_settings()
    print("Inbox setup. Press Return to keep what's in [brackets].\n")
    ask = lambda q, d="": input(f"{q}{f' [{d}]' if d else ''}: ").strip() or d
    owner = ask("Your first name (Claude ranks mail by how much it needs you)", cfg.get("owner", ""))
    accounts, old = [], cfg.get("accounts", [])
    print("\nYour Google accounts, one at a time. Leave the address empty when you're done.")
    for i in range(10):
        prev = old[i] if i < len(old) else {}
        address = ask(f"  Account {i + 1} email", prev.get("email", ""))
        if not address:
            break
        name = ask("    Short name for it (shown in the sidebar)", prev.get("name", "Work" if i == 0 else "Personal" if i == 1 else f"Inbox {i + 1}"))
        key = re.sub(r"[^a-z0-9]", "", name.lower()) or f"acct{i + 1}"
        while key in [a["key"] for a in accounts] or key == "all":
            key += str(i + 1)
        accounts.append({"key": key, "name": name, "email": address})
    if not accounts:
        sys.exit("Add at least one Google account.")
    city = cfg.get("city") or {"name": "London", "lat": 51.51, "lon": -0.13}
    print("\nThe background sky follows the sun where you are.")
    name = ask("  City", city["name"])
    if name != city["name"]:
        lat = ask("  Its latitude (for example 51.51 for London)", "")
        lon = ask("  Its longitude (west is negative, for example -0.13 for London)", "")
        try:
            city = {"name": name, "lat": float(lat), "lon": float(lon)}
        except ValueError:
            print("  Those numbers didn't read as a latitude and longitude, so the sky stays on", city["name"])
    private_write(SETTINGS, json.dumps({"owner": owner, "accounts": accounts, "city": city}, indent=2))
    print(f"\nSaved settings.json. Next: python3 inbox.py login")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "serve"
    {"setup": setup, "login": lambda: login(sys.argv[2] if len(sys.argv) > 2 else None), "serve": serve, "sync": sync, "demo": demo}.get(command, lambda: sys.exit(__doc__))()
