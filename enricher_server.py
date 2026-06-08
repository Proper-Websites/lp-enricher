#!/usr/bin/env python3
"""
LP Lead Enricher — Local Server v2
One persistent Playwright browser shared across all requests.
No new browser per request — fast, cheap, reliable.
"""

import asyncio
import json
import re
import os
import sys
import ssl
import urllib.request
import urllib.parse
import threading
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime

PORT = 3773
START_INDEX = 0

def _load_secret(name):
    # Read a secret by name from ~/.secrets/creds.env (or the environment).
    # The value is never printed or logged.
    v = os.environ.get(name)
    if v:
        return v
    creds = Path.home() / '.secrets' / 'creds.env'
    if creds.exists():
        for line in creds.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, _, val = line.partition('=')
            if k.strip() == name:
                return val.strip().strip('"').strip("'")
    return None

ANTHROPIC_API_KEY = _load_secret('ANTHROPIC_API_KEY')
if not ANTHROPIC_API_KEY:
    print("\n❌ ANTHROPIC_API_KEY not found in ~/.secrets/creds.env or the environment.\n")
    sys.exit(1)

# ── Model + pricing ──────────────────────────────────────────────────────────
# Change MODEL to switch which model runs. cost() automatically uses the
# matching price below, so the displayed cost is always accurate.
MODEL = "claude-haiku-4-5"
PRICING = {  # (input $/M tokens, output $/M tokens)
    "claude-haiku-4-5":  (1.0, 5.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-opus-4-8":   (5.0, 25.0),
}
PRICE_SEARCH = 10.0 / 1000  # web search: $10 per 1,000 searches

MAILTESTER_KEY = _load_secret('MAILTESTER_KEY')  # optional; email verification skipped if absent

PAGE_TIMEOUT = 20000
NAV_TIMEOUT  = 12000

GENERIC_PREFIXES = {
    'info','hello','contact','admin','team','support','office','sales',
    'mail','noreply','no-reply','donotreply','webmaster','privacy','legal',
    'press','billing','help','service','feedback','unsubscribe','postmaster',
    'abuse','enquiries','inquiry','enquiry','media'
}
PLATFORM_DOMAINS = {
    'luxurypresence','sentry','cloudflare','amazonaws','googleapis',
    'facebook','twitter','instagram','mailchimp'
}

SCRIPT_DIR = Path(__file__).parent
# Load remaining domains (excludes already-processed ones)
with open(SCRIPT_DIR / 'domains_list.json') as f:
    ALL_DOMAINS = json.load(f)

# ── Persistent browser state ────────────────────────────────────────────────
_loop     = None   # asyncio event loop running in background thread
_browser  = None   # persistent Playwright browser instance
_pw       = None   # playwright context manager
stats     = {'in':0,'out':0,'calls':0,'searches':0,'last_in':0,'last_out':0,'last_searches':0}

# Rate limit throttle — space Claude calls 2 seconds apart
_last_claude_call = 0
_claude_lock = threading.Lock()

def throttled_claude_call(*args, **kwargs):
    global _last_claude_call
    with _claude_lock:
        import time
        now = time.time()
        elapsed = now - _last_claude_call
        if elapsed < 2.0:
            time.sleep(2.0 - elapsed)
        _last_claude_call = time.time()
    return call_claude(*args, **kwargs)

def get_loop():
    return _loop

# ── Email extraction ────────────────────────────────────────────────────────

def decode_cf_email(encoded):
    r = int(encoded[:2], 16)
    return ''.join(chr(int(encoded[i:i+2], 16) ^ r) for i in range(2, len(encoded), 2))

def extract_emails(html):
    found = set()
    found.update(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', html))
    for m in re.findall(r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', html, re.I):
        found.add(m)
    decoded = html.replace('&#64;','@').replace('&#46;','.').replace('&#x40;','@').replace('&#x2e;','.')
    found.update(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', decoded))
    for m in re.findall(r'[a-zA-Z0-9._%+\-]+\s*[\[\(]\s*at\s*[\]\)]\s*[a-zA-Z0-9.\-]+\s*[\[\(]\s*dot\s*[\]\)]\s*[a-zA-Z]{2,}', html, re.I):
        c = re.sub(r'\s*[\[\(]\s*at\s*[\]\)]\s*','@',m,flags=re.I)
        c = re.sub(r'\s*[\[\(]\s*dot\s*[\]\)]\s*','.',c,flags=re.I)
        found.add(c.replace(' ',''))
    for m in re.findall(r'data-email=["\']([^"\']+)["\']', html, re.I):
        if '@' in m: found.add(m)
    for m in re.findall(r'"email"\s*:\s*"([^"]+)"', html, re.I):
        if '@' in m: found.add(m)
    for m in re.findall(r'(?:email|mail)\s*[=:]\s*["\']([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})["\']', html, re.I):
        found.add(m)
    for enc in re.findall(r'data-cfemail="([0-9a-f]+)"', html, re.I):
        try: found.add(decode_cf_email(enc))
        except: pass
    for enc in re.findall(r'/cdn-cgi/l/email-protection#([0-9a-f]+)', html, re.I):
        try: found.add(decode_cf_email(enc))
        except: pass

    result = []
    for e in found:
        e = e.lower().strip('.,;')
        if '@' not in e or '.' not in e.split('@')[1]: continue
        prefix = e.split('@')[0]
        domain_part = e.split('@')[1]
        if any(p in domain_part for p in PLATFORM_DOMAINS): continue
        if prefix in GENERIC_PREFIXES:
            idx = html.lower().find(e)
            if idx > -1:
                ctx = html[max(0,idx-400):idx+400].lower()
                person_context = any(s in ctx for s in [
                    'email address','email:','contact email',
                    'managing broker','broker of record','lead agent',
                    'founding agent','owner','principal',
                    '/agents/','/team/','/about/','meet ',
                    'profile','bio'
                ])
                if not person_context: continue
        result.append(e)
    return list(set(result))

# Capitalized words that show up on real-estate sites but are NOT people —
# keeps "Connect With", "Our Team", "Real Estate" from looking like names.
NON_NAME_WORDS = {
    'real','estate','los','angeles','new','york','san','francisco','palm','beach',
    'santa','barbara','beverly','hills','view','all','read','more','learn','contact',
    'meet','our','team','home','homes','about','privacy','policy','rights','reserved',
    'connect','with','us','the','your','listings','properties','realty','group','company',
    'sign','log','search','menu','sell','buy','rent','find','get','call','email','phone',
    'luxury','premier','elite','top','best','trusted','local','area','county','city',
}
# Obvious role-inbox local parts — a fast reject. The real test is name-matching below.
GENERIC_LOCAL = {
    'info','contact','team','admin','sales','office','support','hello','connect',
    'inquiries','enquiries','enquiry','inquiry','mail','hi','homes','listings','realty',
    'properties','broker','agent','agents','help','service','marketing','leasing',
    'rentals','escrow','frontdesk','reception','general','company','business',
}

def email_matches_person(email, html):
    """Is this email's prefix a PERSON's name that appears on the page (vs a role word)?"""
    local = email.split('@')[0].lower()
    if local in GENERIC_LOCAL:
        return False
    local_clean = re.sub(r'[._\-]', '', local)
    text = re.sub(r'<[^>]+>', ' ', html)
    tokens = set()
    for first, last in re.findall(r'\b([A-Z][a-z]{2,})\s+([A-Z][a-z]{2,})\b', text):
        if first.lower() in NON_NAME_WORDS or last.lower() in NON_NAME_WORDS:
            continue
        f, l = first.lower(), last.lower()
        tokens.update({f, l, f+l, l+f, f[0]+l, f+l[0]})  # john / smith / johnsmith / jsmith ...
    return local in tokens or local_clean in tokens

def has_personal_email(emails, html):
    return any(email_matches_person(e, html) for e in emails)

def is_single_listing(html):
    """Heuristic: does this page look like a single-PROPERTY listing microsite (not an agent site)?"""
    t = re.sub(r'<[^>]+>', ' ', html or '').lower()
    s = 0
    if re.search(r'\b\d+\s*(bed|bd|bedroom)', t): s += 1
    if re.search(r'\b\d+\s*(bath|ba|bathroom)', t): s += 1
    if re.search(r'(sq\.?\s?ft|square feet|sqft|lot size)', t): s += 1
    if re.search(r'\$[\d,]{6,}', t): s += 1            # a property price like $1,250,000
    if re.search(r'(for sale|just listed|offered at|schedule a (tour|showing)|listing courtesy|presented by)', t): s += 1
    if re.search(r'(virtual tour|property details|floor ?plan|mls\s*#|listing agent|this (home|property))', t): s += 1
    return s >= 3

def is_js_shell(html):
    if not html: return True
    stripped = re.sub(r'<[^>]+>','',html)
    stripped = re.sub(r'\s+',' ',stripped).strip()
    return len(stripped) < 400

def extract_nav_links(html, domain):
    links = []
    for href in re.findall(r'href=["\']([^"\']+)["\']', html, re.I):
        href = href.strip()
        if href.startswith('/') and not href.startswith('//'):
            links.append(f"https://{domain}{href}")
        elif domain in href:
            links.append(href)
    return links

# ── MailTester Ninja email verification ──────────────────────────────────────

def verify_email(email):
    """Return (label, detail) from MailTester Ninja. Never raises — failures are 'Unverified'."""
    if not email or '@' not in email or not MAILTESTER_KEY:
        return ('', '')
    try:
        url = (f"https://happy.mailtester.ninja/ninja"
               f"?email={urllib.parse.quote(email)}&key={urllib.parse.quote(MAILTESTER_KEY)}")
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "LP-Enricher"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            d = json.loads(r.read())
        code = (d.get('code') or '').lower()
        msg  = d.get('message') or ''
        label = {'ok': 'Valid', 'ko': 'Invalid', 'mb': 'Unverifiable'}.get(code, code or 'Unknown')
        return (label, msg)
    except Exception as e:
        print(f"  mailtester error for {email}: {type(e).__name__}: {str(e)[:60]}")
        return ('Unverified', '')

# ── Claude API ──────────────────────────────────────────────────────────────

def call_claude(domain, html_context, use_search=False, actual_domain=None, team_hint=""):
    redirect_note = f"NOTE: {domain} redirects to {actual_domain}\n\n" if actual_domain and actual_domain != domain else ""

    system = """You are a real estate lead researcher. Your only job is to find the owner/decision maker's personal email from the page content provided.

STRICT EMAIL RULES — NO EXCEPTIONS:
- You may ONLY use emails that are LITERALLY PRESENT in the page content given to you
- NEVER construct, guess, infer, or hallucinate an email address under any circumstances
- NEVER output firstname@domain.com or any pattern you invented — only copy what is there
- If no real email exists in the content: set drop=true, email="", dropReason="No email found in page content"
- Copy emails EXACTLY character for character — never simplify or modify

WHO TO PICK (the decision maker worth reaching) — in priority order:
1. NAMESAKE: if the team/site is named after a person ("The Mack Team", "Luxury Homes by Tina",
   "Sue Bladek Real Estate"), that person IS the decision maker. Find THEIR email.
2. TITLE: otherwise pick whoever is labeled Owner, Founder, Broker/Owner, Team Lead, Principal,
   Managing Broker, or Realtor®/Owner.
3. SOLO: if it's a single agent, that's the person.
4. Among equals, the first-listed / most senior person.

WHICH EMAIL TO USE FOR THAT PERSON:
- Use their DIRECT/PERSONAL email — the one whose prefix is their name (e.g. tina@, t.mack@, freida@).
- NEVER use a shared role inbox (info@, contact@, team@, connect@, hello@, admin@, sales@,
  office@, broker@, listings@) UNLESS it is the only email AND clearly sits next to one named person.
- If the homepage only showed a role inbox but a team/about page is included below, prefer the
  named person's personal email from that page.
- ONLY use emails LITERALLY present in the content. Never invent one.

THE NAME AND THE EMAIL MUST BE THE SAME PERSON — this is critical:
- decisionMaker MUST be the actual owner of the email you return.
- If the only usable email belongs to Hilary, then decisionMaker is Hilary — do NOT return
  Darlene's name with Hilary's email. Never pair one person's name with another's email.

TWO-NAME TEAM EMAILS (jasonlaura@, johnandjane@):
- These belong to a named 2-person team. If it is a genuine SMALL team, keep it and set decisionMaker
  to one of those people (prefer the first name) — do NOT drop as "shared/generic".
- BUT if a TEAM SIZE note says LARGE (6+) or an ADDRESS-ONLY note is present below, DROP per those
  notes even though this email exists.

DECISION MAKER NAME — DO NOT LEAVE BLANK if a person is named anywhere on the page:
- Always fill decisionMaker with the person from the rules above.
- Single-listing / single-property pages: use the listing agent / main contact named on the page.
- Only leave it blank if truly NO human name appears anywhere in the content.

TEAM SIZE & WHEN TO DROP:
- A "TEAM SIZE" and/or "ADDRESS-ONLY SITE" note may appear below — trust it; it is based on the
  actual number of individual agent profile pages found on the site.
- Drop if 6+ agents (note says LARGE team) → dropReason "Team too large (6+ agents)".
- Drop address-only single-listing microsites with no clear solo owner → dropReason "Address-only site / team too large".
- Keep 1-5 agents — pick the owner/lead per the rules above; use a CANDIDATE email if one is listed.
- "Group"/"Team"/"& Associates" in the name does NOT auto-drop — go by the team-size note, not the name.

LOCATION — NEVER LEAVE BLANK:
- Extract from any address: "130 N Preston Rd, Prosper, TX 75078" → "Prosper TX"
- Check footer, contact section, address blocks anywhere on page
- Use first city mentioned in "Serving X, Y, Z" if no address found

Return ONLY valid JSON:
{"agentName":"","decisionMaker":"First Last","location":"City ST","type":"Solo Agent|Small Team","email":"","emailConfidence":"CONFIRMED — found on [page/section]|HIGH — [specific reason]","phone":"","icpNotes":"1-2 sentences","dropReason":"","drop":false}"""

    if html_context:
        clean = re.sub(r'<script[^>]*>.*?</script>',' ',html_context,flags=re.DOTALL|re.I)
        clean = re.sub(r'<style[^>]*>.*?</style>',' ',clean,flags=re.DOTALL|re.I)
        clean = re.sub(r'<[^>]+',' ',clean) # faster than full tag strip
        clean = re.sub(r'\s+',' ',clean).strip()

        found_emails = extract_emails(html_context)
        email_hint = f"EMAILS FOUND: {', '.join(found_emails[:5])}\n\n" if found_emails else ""

        if found_emails:
            idx = clean.find(found_emails[0])
            start = max(0, idx-2500) if idx > 0 else 0
            text_slice = clean[start:start+7000]
        else:
            text_slice = clean[:7000]

        # Always include footer (last 1200 chars) — contains address/phone/location
        footer = clean[-1200:]
        if footer not in text_slice:
            text_slice = text_slice + "\n\n[PAGE FOOTER — contains address/location]: " + footer

        # Pre-extract location — try multiple patterns
        location_hint = ""
        # Pattern 1: Full address with zip "City, ST 12345"
        addr_match = re.search(r'([A-Z][a-zA-Z ]{2,20}), *([A-Z]{2}) +[0-9]{5}', clean)
        if addr_match:
            city = addr_match.group(1).strip()
            # Clean up city — remove street number/name if present
            city_words = city.split()
            # Take last 1-2 words as city name (removes street address prefix)
            if len(city_words) > 2:
                city = ' '.join(city_words[-2:])
            state = addr_match.group(2)
            location_hint = f"LOCATION FOUND IN PAGE: {city}, {state}\n\n"
            print(f"  [{domain}] location extracted: {city}, {state}")

        # Keep prompt lean — email hint + focused text slice + footer
        user_msg = f"Domain: {domain}\n{redirect_note}{location_hint}{team_hint}{email_hint}PAGE TEXT:\n{text_slice}"
    else:
        user_msg = f'Find owner/founder personal email for: {domain}. Search "{domain} owner email contact". Return JSON only.'

    body = {
        "model": MODEL,
        "max_tokens": 400,
        "system": system,
        "messages": [{"role":"user","content":user_msg}]
    }
    if use_search and not html_context:
        body["tools"] = [{"type":"web_search_20250305","name":"web_search"}]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode(),
        headers={"Content-Type":"application/json","x-api-key":ANTHROPIC_API_KEY,"anthropic-version":"2023-06-01"},
        method="POST"
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                data = json.loads(resp.read())
            break  # success
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = (attempt + 1) * 20  # 20s, 40s, 60s
                print(f"  Rate limited (429) — waiting {wait}s before retry {attempt+1}/3")
                import time; time.sleep(wait)
                if attempt == 2:
                    raise
            else:
                raise
    else:
        raise RuntimeError("Max retries exceeded")

    last_in  = data.get('usage',{}).get('input_tokens',0)
    last_out = data.get('usage',{}).get('output_tokens',0)
    last_s   = sum(1 for b in data.get('content',[]) if b.get('type')=='tool_use' and b.get('name')=='web_search')
    stats['in']  += last_in
    stats['out'] += last_out
    stats['calls'] += 1
    stats['searches'] += last_s
    stats['last_in'] = last_in; stats['last_out'] = last_out; stats['last_searches'] = last_s

    text = ''.join(b.get('text','') for b in data.get('content',[]) if b.get('type')=='text')
    try:
        return json.loads(re.sub(r'```json|```','',text).strip())
    except:
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m:
            try: return json.loads(m.group(0))
            except: pass
        return {"drop":True,"dropReason":f"Parse error: {text[:80]}"}

def cost():
    pin, pout = PRICING.get(MODEL, (1.0, 5.0))
    return (stats['in']/1_000_000*pin) + (stats['out']/1_000_000*pout) + (stats['searches']*PRICE_SEARCH)

# ── Playwright fetch ─────────────────────────────────────────────────────────

async def fetch_page(page, url, timeout=PAGE_TIMEOUT):
    try:
        import random
        await page.wait_for_timeout(random.randint(500, 1500))  # human-like delay
        await page.goto(url, wait_until='domcontentloaded', timeout=timeout)
        await page.wait_for_timeout(random.randint(1000, 2000))  # let JS settle
        html = await page.content()
        return html if not is_js_shell(html) else None
    except Exception as e:
        print(f"  fetch error {url}: {type(e).__name__}: {str(e)[:80]}")
        return None

async def enrich_domain_async(domain):
    global _browser
    result = {
        "domain":domain,"status":"error","step":"—",
        "agentName":"","decisionMaker":"","location":"","type":"",
        "email":"","emailConfidence":"","phone":"","icpNotes":"",
        "dropReason":"","siteDown":False,"date":datetime.now().strftime("%Y-%m-%d"),
        "city":"","state":"","emailStatus":"","emailStatusDetail":""
    }

    context = await _browser.new_context(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        viewport={"width": 1920, "height": 1080},
        locale="en-US",
        timezone_id="America/New_York",
        extra_http_headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
        }
    )
    # Remove headless detection flags
    await context.add_init_script("""
        // Remove webdriver flag
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        delete navigator.__proto__.webdriver;
        
        // Fake plugins
        Object.defineProperty(navigator, 'plugins', {get: () => [
            {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer'},
            {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai'},
            {name: 'Native Client', filename: 'internal-nacl-plugin'}
        ]});
        
        // Languages and platform
        Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        Object.defineProperty(navigator, 'platform', {get: () => 'MacIntel'});
        Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
        Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
        
        // Chrome object
        window.chrome = {
            runtime: {id: undefined},
            app: {isInstalled: false, InstallState: {DISABLED:'disabled',INSTALLED:'installed',NOT_INSTALLED:'not_installed'}, RunningState: {CANNOT_RUN:'cannot_run',READY_TO_RUN:'ready_to_run',RUNNING:'running'}},
            loadTimes: function(){return {firstPaintTime:0,firstPaintAfterLoadTime:0,finishedLoading:true};},
            csi: function(){return {startE:Date.now(),onloadT:Date.now(),pageT:1,tran:15};}
        };
        
        // Notification permission
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
            Promise.resolve({state: Notification.permission}) :
            originalQuery(parameters)
        );
    """)
    page = await context.new_page()

    try:
        html_context = None
        step = "search"
        actual_domain = domain

        print(f"  [{domain}] loading homepage...")
        homepage_html = await fetch_page(page, f"https://{domain}")

        if homepage_html:
            current_url = page.url
            cd = re.sub(r'^https?://(www\.)?','',current_url).split('/')[0]
            if cd and cd != domain and domain not in cd:
                actual_domain = cd
                print(f"  [{domain}] redirected to {actual_domain}")

            emails = extract_emails(homepage_html)
            # Only trust a homepage email if it's a PERSON's name (not a role inbox like
            # connect@/info@). A generic homepage email means we still dig to the team page.
            if emails and has_personal_email(emails, homepage_html):
                print(f"  [{domain}] personal email on homepage: {emails[0]}")
                html_context = homepage_html
                step = "html"
                result['_emailSource'] = 'homepage'
                result['_emailUrl'] = f"https://{actual_domain}"
            else:
                if emails:
                    print(f"  [{domain}] homepage email(s) look generic ({emails[0]}) — digging to team/agent pages for the owner")
                else:
                    print(f"  [{domain}] no email on homepage, checking team/agent pages...")
                nav_links = extract_nav_links(homepage_html, actual_domain)

                PROFILE_RE = r'/(agents?|team|staff|people|member|our-team)/[^/?#]+/?$'
                JUNK_RE = r'\.(jpg|jpeg|png|gif|webp|svg|pdf|css|js)$'

                # Team/about/contact LISTING pages (not individual profiles)
                standard = [f"https://{actual_domain}/{p}" for p in
                            ('contact','about','about-us','team','meet-the-team','our-team','agents')]
                nav_matches = [l for l in nav_links if re.search(
                    r'contact|about|team|meet|agent|staff|people|founder|who|our|bio', l, re.I)
                    and not re.search(PROFILE_RE, l, re.I) and not re.search(JUNK_RE, l, re.I)][:8]
                listing_pages = list(dict.fromkeys(standard + nav_matches))

                # Individual agent PROFILE links — these hold the personal emails
                profile_links = set(l for l in nav_links
                                    if re.search(PROFILE_RE, l, re.I) and not re.search(JUNK_RE, l, re.I))

                gathered = []  # (label, url, html)
                for sub_url in listing_pages[:6]:
                    sub_html = await fetch_page(page, sub_url, NAV_TIMEOUT)
                    if not sub_html: continue
                    gathered.append((sub_url.rstrip('/').split('/')[-1] or 'page', sub_url, sub_html))
                    for l in extract_nav_links(sub_html, actual_domain):
                        if re.search(PROFILE_RE, l, re.I) and not re.search(JUNK_RE, l, re.I):
                            profile_links.add(l)

                profile_links = list(dict.fromkeys(profile_links))
                n_prof = len(profile_links)

                # Reliable team size = count of distinct agent profile pages (the old name-regex over-counted badly)
                hint = ""
                if n_prof >= 6:
                    hint += (f"TEAM SIZE: {n_prof} individual agent profile pages found — LARGE team/brokerage "
                             f"(6+ agents). DROP as 'Team too large (6+ agents)'.\n")
                    print(f"  [{domain}] {n_prof} agent profiles -> LARGE team (6+)")
                    to_open = profile_links[:2]
                else:
                    if n_prof:
                        hint += f"TEAM SIZE: {n_prof} agent profile page(s) found (small team).\n"
                    to_open = profile_links[:5]
                    print(f"  [{domain}] {n_prof} agent profiles -> opening {len(to_open)} for personal emails")

                # Open each individual profile page so we capture THAT person's personal email
                candidates = []  # (name, email)
                for prof_url in to_open:
                    p_html = await fetch_page(page, prof_url, NAV_TIMEOUT)
                    if not p_html: continue
                    nm = prof_url.rstrip('/').split('/')[-1].replace('-', ' ').replace('_', ' ').strip().title()
                    for em in extract_emails(p_html)[:2]:
                        candidates.append((nm, em))
                    gathered.append((f"profile: {nm}", prof_url, p_html))
                    print(f"  [{domain}] opened profile {nm}: {extract_emails(p_html)[:1] or 'no email'}")

                if candidates:
                    hint += ("CANDIDATE PEOPLE & THEIR PERSONAL EMAILS (each taken from that person's own profile "
                             "page — pick the OWNER/FOUNDER and use THEIR email; these are real emails from the "
                             "site, you may use them):\n")
                    for nm, em in candidates[:8]:
                        hint += f"- {nm}: {em}\n"

                # Single-property listing microsite? Only flag when we found NO reachable agent — and tell
                # the AI to find the listing agent FIRST, dropping only if there genuinely isn't one.
                first_label = domain.split('.')[0]
                if not candidates and (is_single_listing(homepage_html) or (first_label[:1].isdigit() and n_prof == 0)):
                    hint += ("SINGLE-PROPERTY LISTING PAGE: this looks like a one-property listing microsite. "
                             "FIRST identify the listing agent named on it ('Presented by'/'Listed by'/"
                             "'Listing courtesy of'/agent contact block) and use THEIR personal email if present. "
                             "ONLY if no individual agent is reachable (just a property, or it belongs to a large "
                             "team) DROP as 'Address-only site / team too large'.\n")
                    print(f"  [{domain}] single-listing microsite (no agent profiles) — find agent or drop")
                if hint:
                    result['_teamSizeHint'] = hint

                # Context = homepage + listing pages + profiles (capped). call_claude slices this, but the
                # name->email pairs above ride along UNSLICED via the hint, so the owner's email always reaches it.
                parts = [homepage_html[:60000]]
                for label, url, html in gathered:
                    parts.append(f"\n\n--- {label} ({url}) ---\n{html[:40000]}")
                html_context = "".join(parts)
                step = "html"

                # Display source: first gathered page with a personal email, else homepage
                result['_emailSource'] = 'homepage'
                result['_emailUrl'] = f"https://{actual_domain}"
                for label, url, html in gathered:
                    ems = extract_emails(html)
                    if ems and has_personal_email(ems, html):
                        result['_emailSource'] = label
                        result['_emailUrl'] = url
                        break
        else:
            result['siteDown'] = True
            step = "search"
            print(f"  [{domain}] Playwright blocked — falling back to web search")

        result['step'] = step

        print(f"  [{domain}] calling Claude (step={step})...")
        p = call_claude(domain, html_context, use_search=(step == 'search'), actual_domain=actual_domain, team_hint=result.get('_teamSizeHint',''))

        # Show exactly which page and URL the email came from
        source_page = result.get('_emailSource', '')
        source_url  = result.get('_emailUrl', '')
        confidence_with_source = p.get('emailConfidence','')
        if source_page:
            confidence_with_source = f"{confidence_with_source} · Found on: {source_page}"
            if source_url:
                confidence_with_source += f" ({source_url})"

        # Split location into city and state
        raw_loc = p.get('location','')
        city_val, state_val = '', ''
        if raw_loc:
            parts = [x.strip() for x in raw_loc.replace(',','').split()]
            if len(parts) >= 2:
                state_val = parts[-1]
                city_val = ' '.join(parts[:-1])
            elif len(parts) == 1:
                city_val = parts[0]

        result.update({
            'agentName':      p.get('agentName',''),
            'decisionMaker':  p.get('decisionMaker',''),
            'location':       raw_loc,
            'city':           city_val,
            'state':          state_val,
            'type':           p.get('type',''),
            'email':          p.get('email',''),
            'emailConfidence':confidence_with_source,
            'phone':          p.get('phone',''),
            'icpNotes':       p.get('icpNotes',''),
            'dropReason':     p.get('dropReason',''),
        })

        if p.get('drop') or not p.get('email','').strip():
            result['status'] = 'dropped'
            print(f"  [{domain}] DROPPED: {p.get('dropReason','no email')} | cost so far: ${cost():.4f}")
        elif 'CONFIRMED' in p.get('emailConfidence','').upper():
            result['status'] = 'confirmed'
            print(f"  [{domain}] CONFIRMED: {p.get('email')} | cost so far: ${cost():.4f}")
        else:
            result['status'] = 'high'
            print(f"  [{domain}] HIGH: {p.get('email')} | cost so far: ${cost():.4f}")

        # Verify deliverability with MailTester Ninja (offloaded so it doesn't block other domains)
        if result['email'] and result['status'] in ('confirmed', 'high'):
            loop = asyncio.get_event_loop()
            label, detail = await loop.run_in_executor(None, verify_email, result['email'])
            result['emailStatus'] = label
            result['emailStatusDetail'] = detail
            print(f"  [{domain}] mailtester: {label} ({detail})")

    except Exception as e:
        result['status'] = 'error'
        result['dropReason'] = str(e)[:100]
        print(f"  [{domain}] ERROR: {e}")
    finally:
        await context.close()

    return result

# ── HTTP handler ─────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args): pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',len(body))
        self.send_header('Access-Control-Allow-Origin','*')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Methods','GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers','Content-Type')
        self.end_headers()

    def do_GET(self):
        if self.path == '/':
            ui = (SCRIPT_DIR / 'enricher_ui.html').read_text()
            body = ui.encode()
            self.send_response(200)
            self.send_header('Content-Type','text/html; charset=utf-8')
            self.send_header('Content-Length',len(body))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == '/status':
            self.send_json({'running':False,'paused':False,'progress':0,'total':0,
                'confirmed':0,'high':0,'dropped':0,'html_step':0,'src_step':0,
                'cost':round(cost(),4),'log':[],'results':[]})
        elif self.path == '/domains':
            active = ALL_DOMAINS[START_INDEX:]
            self.send_json({'domains':active,'total':len(ALL_DOMAINS),'start':START_INDEX,'remaining':len(active),'model':MODEL})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length',0))
        body = json.loads(self.rfile.read(length)) if length else {}

        if self.path == '/enrich':
            domain = body.get('domain','').strip()
            if not domain:
                return self.send_json({'error':'no domain'},400)

            # Run on persistent event loop
            future = asyncio.run_coroutine_threadsafe(enrich_domain_async(domain), _loop)
            try:
                result = future.result(timeout=120)  # 2 min max per domain
            except Exception as e:
                print(f"  [{domain}] FUTURE ERROR: {e}")
                result = {"domain":domain,"status":"error","drop":True,
                    "dropReason":str(e)[:100],"step":"—","email":"",
                    "agentName":"","decisionMaker":"","location":"","type":"",
                    "emailConfidence":"","phone":"","icpNotes":"","siteDown":False}

            result['_tokensIn']   = stats.get('last_in',0)
            result['_tokensOut']  = stats.get('last_out',0)
            result['_searches']   = stats.get('last_searches',0)
            result['_costTotal']  = round(cost(), 4)   # accurate, model-aware
            result['_model']      = MODEL
            self.send_json(result)

        elif self.path == '/reset':
            stats.update({'in':0,'out':0,'calls':0,'searches':0,'last_in':0,'last_out':0,'last_searches':0})
            self.send_json({'ok':True})
        else:
            self.send_response(404); self.end_headers()

# ── Startup ──────────────────────────────────────────────────────────────────

async def start_playwright():
    global _browser, _pw
    from playwright.async_api import async_playwright
    _pw = async_playwright()
    pw = await _pw.__aenter__()
    _browser = await pw.chromium.launch(
        headless=True,
        args=[
            '--no-sandbox',
            '--disable-blink-features=AutomationControlled',
            '--disable-dev-shm-usage',
            '--disable-web-security',
            '--disable-features=IsolateOrigins,site-per-process',
            '--window-size=1920,1080',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-renderer-backgrounding',
            '--disable-ipc-flooding-protection',
            '--password-store=basic',
            '--use-mock-keychain',
        ]
    )
    print(f"  Browser ready")

def run_loop(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

if __name__ == '__main__':
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("\n❌ Run: pip3 install playwright anthropic && playwright install chromium\n")
        sys.exit(1)

    print(f"\n✅ LP Lead Enricher")
    print(f"   {len(ALL_DOMAINS)} domains loaded")
    print(f"   Starting browser...")

    # Start persistent event loop in background thread
    _loop = asyncio.new_event_loop()
    t = threading.Thread(target=run_loop, args=(_loop,), daemon=True)
    t.start()

    # Start Playwright on that loop
    future = asyncio.run_coroutine_threadsafe(start_playwright(), _loop)
    future.result(timeout=30)

    print(f"   Running at http://localhost:{PORT}")
    print(f"   Opening browser...")
    print(f"   Press Ctrl+C to stop\n")

    import time
    time.sleep(1)
    subprocess.Popen(['open', f'http://localhost:{PORT}'])

    server = HTTPServer(('localhost', PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
