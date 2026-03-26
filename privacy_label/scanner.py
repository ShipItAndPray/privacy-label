"""Scan a website for trackers, data collection, and privacy signals."""
import httpx
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from urllib.parse import urlparse
from .trackers import TRACKER_PATTERNS, COOKIE_PATTERNS, DATA_COLLECTION_SIGNALS
from .known_sites import get_known_intel


@dataclass
class Tracker:
    name: str
    category: str
    severity: int
    source: str  # "script", "pixel", "iframe", "cookie", "link"


@dataclass
class DataSignal:
    name: str
    category: str
    source: str


@dataclass
class ScanResult:
    url: str = ""
    domain: str = ""
    status_code: int = 0
    https: bool = False
    trackers: list = field(default_factory=list)
    data_signals: list = field(default_factory=list)
    cookies_set: list = field(default_factory=list)
    third_party_requests: list = field(default_factory=list)
    has_privacy_policy: bool = False
    privacy_policy_url: str = ""
    has_cookie_banner: bool = False
    has_dnf_header: bool = False  # Do Not Track response
    security_headers: dict = field(default_factory=dict)
    score: int = 0
    grade: str = ""
    errors: list = field(default_factory=list)


def _normalize_url(url: str) -> str:
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip("/")


def scan(url: str) -> ScanResult:
    """Scan a URL and return privacy analysis."""
    url = _normalize_url(url)
    result = ScanResult(url=url, domain=urlparse(url).netloc)
    result.https = url.startswith("https")

    try:
        with httpx.Client(timeout=20, follow_redirects=True, verify=False) as client:
            resp = client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "DNT": "1",
            })
            result.status_code = resp.status_code
            html = resp.text

            # Check security headers
            headers = resp.headers
            result.security_headers = {
                "strict-transport-security": "strict-transport-security" in headers,
                "content-security-policy": "content-security-policy" in headers,
                "x-content-type-options": "x-content-type-options" in headers,
                "x-frame-options": "x-frame-options" in headers,
                "referrer-policy": "referrer-policy" in headers,
                "permissions-policy": "permissions-policy" in headers,
            }

            # Check DNT response
            result.has_dnf_header = headers.get("tk") == "N" or "dnt" in headers

            # Check response headers for tracking signals
            set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
            for sc in set_cookie_headers:
                sc_lower = sc.lower()
                for pattern, name, category in COOKIE_PATTERNS:
                    if pattern.lower() in sc_lower:
                        result.cookies_set.append(Tracker(
                            name=name, category=category, severity=2, source="set-cookie-header"
                        ))

            # P3P header (legacy privacy platform)
            if "p3p" in headers:
                # Sites still sending P3P are usually doing it for IE compat with tracking cookies
                pass  # informational only

            # Report-To / NEL headers indicate telemetry
            if "report-to" in headers or "nel" in headers:
                result.data_signals.append(DataSignal(
                    name="Network Error Logging (NEL)", category="api_access", source="header"
                ))

            # Cookies
            for cookie in resp.cookies.jar:
                for pattern, name, category in COOKIE_PATTERNS:
                    if pattern in cookie.name.lower():
                        result.cookies_set.append(Tracker(
                            name=name, category=category, severity=2, source="cookie"
                        ))
                        break

            # Parse HTML
            soup = BeautifulSoup(html, "html.parser")

            # Find all script srcs, img srcs, iframe srcs, link hrefs
            external_resources = []
            for tag in soup.find_all("script", src=True):
                external_resources.append(("script", tag["src"]))
            for tag in soup.find_all("img", src=True):
                external_resources.append(("pixel", tag["src"]))
            for tag in soup.find_all("iframe", src=True):
                external_resources.append(("iframe", tag["src"]))
            for tag in soup.find_all("link", href=True):
                external_resources.append(("link", tag["href"]))

            # Check noscript tags — tracking pixels hidden for non-JS users
            for noscript in soup.find_all("noscript"):
                noscript_html = str(noscript)
                for pattern, name, category, severity in TRACKER_PATTERNS:
                    if pattern in noscript_html and name not in seen_trackers:
                        seen_trackers.add(name)
                        result.trackers.append(Tracker(
                            name=name, category=category, severity=severity, source="noscript"
                        ))

            # Also check inline scripts
            inline_scripts = " ".join(s.string or "" for s in soup.find_all("script") if s.string)

            # Match trackers against external resources
            seen_trackers = set()
            for source_type, resource_url in external_resources:
                for pattern, name, category, severity in TRACKER_PATTERNS:
                    if pattern in resource_url and name not in seen_trackers:
                        seen_trackers.add(name)
                        result.trackers.append(Tracker(
                            name=name, category=category, severity=severity, source=source_type
                        ))

            # Match trackers in inline scripts
            for pattern, name, category, severity in TRACKER_PATTERNS:
                if pattern in inline_scripts and name not in seen_trackers:
                    seen_trackers.add(name)
                    result.trackers.append(Tracker(
                        name=name, category=category, severity=severity, source="inline"
                    ))

            # Data collection signals in HTML
            seen_signals = set()
            full_html = html.lower() if len(html) < 5_000_000 else html[:5_000_000].lower()
            for pattern, name, category in DATA_COLLECTION_SIGNALS:
                if pattern.lower() in full_html and name not in seen_signals:
                    seen_signals.add(name)
                    result.data_signals.append(DataSignal(
                        name=name, category=category, source="html"
                    ))

            # Meta tag analysis — social/tracking embeds
            for meta in soup.find_all("meta"):
                name_attr = (meta.get("name") or meta.get("property") or "").lower()
                content = (meta.get("content") or "").lower()
                if "fb:app_id" in name_attr or "fb:admins" in name_attr:
                    if "Facebook App ID" not in seen_trackers:
                        seen_trackers.add("Facebook App ID")
                        result.trackers.append(Tracker(name="Facebook App ID", category="social", severity=2, source="meta"))
                if "google-site-verification" in name_attr:
                    if "Google Site Verification" not in seen_trackers:
                        seen_trackers.add("Google Site Verification")
                        result.trackers.append(Tracker(name="Google Site Verification", category="analytics", severity=1, source="meta"))
                if "msvalidate" in name_attr:
                    if "Bing Site Verification" not in seen_trackers:
                        seen_trackers.add("Bing Site Verification")
                        result.trackers.append(Tracker(name="Bing Site Verification", category="analytics", severity=1, source="meta"))

            # Privacy policy detection
            for a in soup.find_all("a", href=True):
                text = (a.get_text() or "").lower()
                href = a["href"].lower()
                if "privacy" in text or "privacy" in href:
                    result.has_privacy_policy = True
                    result.privacy_policy_url = a["href"]
                    break

            # Cookie banner detection
            for div in soup.find_all(["div", "section", "aside", "dialog"]):
                classes = " ".join(div.get("class", []))
                div_id = div.get("id", "")
                text = (div.get_text() or "")[:200].lower()
                if any(kw in (classes + " " + div_id).lower() for kw in ["cookie", "consent", "gdpr", "privacy-banner"]):
                    result.has_cookie_banner = True
                    break
                if "cookie" in text and ("accept" in text or "consent" in text):
                    result.has_cookie_banner = True
                    break

            # Third-party domain count
            base_domain = _extract_base_domain(result.domain)
            tp_domains = set()
            for _, resource_url in external_resources:
                try:
                    rd = urlparse(resource_url).netloc
                    if rd and _extract_base_domain(rd) != base_domain:
                        tp_domains.add(rd)
                except Exception:
                    pass
            result.third_party_requests = sorted(tp_domains)

    except Exception as e:
        result.errors.append(str(e))

    # Merge known site intelligence (supplements static scan)
    intel = get_known_intel(result.domain)
    if intel:
        seen_names = {t.name for t in result.trackers}
        for name, category, severity in intel.get("known_trackers", []):
            if name not in seen_names:
                result.trackers.append(Tracker(name=name, category=category, severity=severity, source="known_intel"))
                seen_names.add(name)

        seen_signals = {s.name for s in result.data_signals}
        for name, category in intel.get("known_data", []):
            if name not in seen_signals:
                result.data_signals.append(DataSignal(name=name, category=category, source="known_intel"))
                seen_signals.add(name)

        # Use known cookie/3P counts if they exceed what we detected
        known_cookies = intel.get("known_cookies", 0)
        if known_cookies > len(result.cookies_set):
            for i in range(known_cookies - len(result.cookies_set)):
                result.cookies_set.append(Tracker(name=f"Cookie #{len(result.cookies_set)+1}", category="tracking", severity=2, source="known_intel"))

        known_tp = intel.get("known_third_parties", 0)
        if known_tp > len(result.third_party_requests):
            for i in range(known_tp - len(result.third_party_requests)):
                result.third_party_requests.append(f"(known 3rd party #{len(result.third_party_requests)+1})")

    # Calculate score
    result.score, result.grade = _calculate_score(result)
    return result


def _extract_base_domain(domain: str) -> str:
    parts = domain.replace("www.", "").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _calculate_score(result: ScanResult) -> tuple[int, str]:
    """Score 0-100 (higher = more private). Grade A+ to F."""
    score = 100

    # HTTPS
    if not result.https:
        score -= 15

    # Trackers (biggest penalty)
    ad_trackers = [t for t in result.trackers if t.category == "advertising"]
    analytics_trackers = [t for t in result.trackers if t.category == "analytics"]
    fingerprinting = [t for t in result.trackers if t.category == "fingerprinting"]
    marketing = [t for t in result.trackers if t.category == "marketing"]
    social = [t for t in result.trackers if t.category == "social"]

    score -= len(ad_trackers) * 8
    score -= len(fingerprinting) * 10
    score -= len(marketing) * 5
    score -= len(analytics_trackers) * 3
    score -= len(social) * 2

    # Cookies (cap at -18)
    score -= min(len(result.cookies_set) * 3, 18)

    # Data collection signals
    high_risk = [s for s in result.data_signals if s.category in ("fingerprinting", "api_access")]
    score -= len(high_risk) * 4
    form_fields = [s for s in result.data_signals if s.category == "form_field"]
    score -= len(form_fields) * 1

    # Third party domains
    tp_count = len(result.third_party_requests)
    if tp_count > 20:
        score -= 15
    elif tp_count > 10:
        score -= 8
    elif tp_count > 5:
        score -= 3

    # Bonuses
    if result.has_privacy_policy:
        score += 5
    if result.has_cookie_banner:
        score += 3
    if result.security_headers.get("strict-transport-security"):
        score += 2
    if result.security_headers.get("content-security-policy"):
        score += 3
    if result.security_headers.get("permissions-policy"):
        score += 2
    if result.security_headers.get("referrer-policy"):
        score += 2

    score = max(0, min(100, score))

    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B+"
    elif score >= 60:
        grade = "B"
    elif score >= 50:
        grade = "C+"
    elif score >= 40:
        grade = "C"
    elif score >= 30:
        grade = "D+"
    elif score >= 20:
        grade = "D"
    else:
        grade = "F"

    return score, grade
