"""Known site intelligence — ground truth for major platforms where static HTML
scan misses JS-loaded trackers. Sources: whotracks.me, Blacklight, PrivacyTests.

These are MINIMUM known trackers — the scanner adds any it finds in HTML on top."""

KNOWN_SITES = {
    "facebook.com": {
        "known_trackers": [
            ("Facebook Pixel", "advertising", 3),
            ("Facebook Analytics", "analytics", 2),
            ("Facebook Login SDK", "social", 2),
            ("Meta Ads SDK", "advertising", 3),
        ],
        "known_data": [
            ("Browser fingerprint", "fingerprinting"),
            ("Device info", "api_access"),
            ("Location (coarse)", "api_access"),
            ("Contact list (app)", "api_access"),
            ("Browsing history (off-platform)", "fingerprinting"),
        ],
        "known_cookies": 8,
        "known_third_parties": 12,
        "notes": "Facebook tracks across the web via Like buttons and Pixel on 8M+ sites.",
    },
    "instagram.com": {
        "known_trackers": [
            ("Facebook Pixel", "advertising", 3),
            ("Meta Analytics", "analytics", 2),
            ("Meta Ads SDK", "advertising", 3),
        ],
        "known_data": [
            ("Browser fingerprint", "fingerprinting"),
            ("Location (precise)", "api_access"),
            ("Camera/Microphone", "api_access"),
        ],
        "known_cookies": 6,
        "known_third_parties": 10,
        "notes": "Owned by Meta. Same tracking infrastructure as Facebook.",
    },
    "amazon.com": {
        "known_trackers": [
            ("Amazon Ads", "advertising", 3),
            ("Amazon Analytics", "analytics", 2),
            ("Amazon Affiliate", "advertising", 3),
            ("DoubleClick (Google)", "advertising", 3),
            ("Google Analytics", "analytics", 2),
            ("Facebook Pixel", "advertising", 3),
            ("Criteo", "advertising", 3),
        ],
        "known_data": [
            ("Browser fingerprint", "fingerprinting"),
            ("Purchase history", "api_access"),
            ("Search history", "api_access"),
            ("Device info", "api_access"),
        ],
        "known_cookies": 12,
        "known_third_parties": 18,
        "notes": "Amazon runs one of the largest ad networks. Heavy cross-site tracking.",
    },
    "reddit.com": {
        "known_trackers": [
            ("Google Tag Manager", "analytics", 2),
            ("Google Analytics", "analytics", 2),
            ("Google Ads", "advertising", 3),
            ("DoubleClick (Google)", "advertising", 3),
            ("Amazon Ads", "advertising", 3),
            ("Sentry", "error_tracking", 1),
        ],
        "known_data": [
            ("Browser fingerprint", "fingerprinting"),
            ("Device info", "api_access"),
            ("Location (coarse)", "api_access"),
        ],
        "known_cookies": 6,
        "known_third_parties": 15,
        "notes": "Reddit serves ads and runs analytics. JS-heavy SPA loads trackers dynamically.",
    },
    "twitter.com": {
        "known_trackers": [
            ("Twitter Analytics", "analytics", 2),
            ("Google Analytics", "analytics", 2),
            ("Google Ads", "advertising", 3),
            ("DoubleClick (Google)", "advertising", 3),
        ],
        "known_data": [
            ("Browser fingerprint", "fingerprinting"),
            ("Device info", "api_access"),
            ("Location (coarse)", "api_access"),
        ],
        "known_cookies": 8,
        "known_third_parties": 12,
        "notes": "X/Twitter tracks engagement extensively for ad targeting.",
    },
    "x.com": {
        "known_trackers": [
            ("Twitter Analytics", "analytics", 2),
            ("Google Analytics", "analytics", 2),
            ("Google Ads", "advertising", 3),
            ("DoubleClick (Google)", "advertising", 3),
        ],
        "known_data": [
            ("Browser fingerprint", "fingerprinting"),
            ("Device info", "api_access"),
        ],
        "known_cookies": 8,
        "known_third_parties": 12,
        "notes": "Same as twitter.com after rebrand.",
    },
    "youtube.com": {
        "known_trackers": [
            ("Google Analytics", "analytics", 2),
            ("Google Ads", "advertising", 3),
            ("DoubleClick (Google)", "advertising", 3),
            ("Google Tag Manager", "analytics", 2),
        ],
        "known_data": [
            ("Browser fingerprint", "fingerprinting"),
            ("Watch history", "api_access"),
            ("Search history", "api_access"),
            ("Location (coarse)", "api_access"),
        ],
        "known_cookies": 10,
        "known_third_parties": 8,
        "notes": "Google-owned. Full Google ad stack.",
    },
    "tiktok.com": {
        "known_trackers": [
            ("TikTok Analytics", "advertising", 3),
            ("TikTok Pixel", "advertising", 3),
            ("Google Analytics", "analytics", 2),
            ("Facebook Pixel", "advertising", 3),
            ("AppsFlyer", "advertising", 3),
        ],
        "known_data": [
            ("Browser fingerprint", "fingerprinting"),
            ("Device info", "api_access"),
            ("Location (precise)", "api_access"),
            ("Clipboard contents", "api_access"),
        ],
        "known_cookies": 8,
        "known_third_parties": 15,
        "notes": "TikTok has been documented collecting extensive device data including clipboard.",
    },
    "linkedin.com": {
        "known_trackers": [
            ("LinkedIn Insight", "advertising", 3),
            ("Google Analytics", "analytics", 2),
            ("Google Ads", "advertising", 3),
            ("Oracle BlueKai", "advertising", 3),
        ],
        "known_data": [
            ("Browser fingerprint", "fingerprinting"),
            ("Professional profile", "api_access"),
            ("Email address", "form_field"),
        ],
        "known_cookies": 10,
        "known_third_parties": 14,
        "notes": "Microsoft-owned. Heavy ad targeting for recruiters and B2B.",
    },
    "discord.com": {
        "known_trackers": [
            ("Google Analytics", "analytics", 2),
            ("Sentry", "error_tracking", 1),
        ],
        "known_data": [
            ("Browser fingerprint", "fingerprinting"),
            ("Device info", "api_access"),
        ],
        "known_cookies": 4,
        "known_third_parties": 6,
        "notes": "Relatively lighter tracking than social media peers.",
    },
}


def get_known_intel(domain: str):
    """Look up known intelligence for a domain. Strips www. prefix."""
    clean = domain.replace("www.", "").lower()
    return KNOWN_SITES.get(clean)
