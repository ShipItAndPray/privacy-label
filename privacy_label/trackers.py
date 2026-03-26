"""Known tracker database — patterns matched against page resources."""

# Format: (pattern, name, category, severity)
# severity: 1=analytics, 2=marketing, 3=advertising, 4=fingerprinting, 5=surveillance
TRACKER_PATTERNS = [
    # Google
    ("google-analytics.com", "Google Analytics", "analytics", 2),
    ("googletagmanager.com", "Google Tag Manager", "analytics", 2),
    ("googlesyndication.com", "Google Ads", "advertising", 3),
    ("googleadservices.com", "Google Ad Services", "advertising", 3),
    ("doubleclick.net", "DoubleClick (Google)", "advertising", 3),
    ("google.com/recaptcha", "Google reCAPTCHA", "functionality", 1),
    ("googleapis.com/js/plusone", "Google+", "social", 2),
    ("youtube.com/iframe_api", "YouTube Embed", "social", 1),
    # Facebook / Meta
    ("facebook.net/en_US/fbevents", "Facebook Pixel", "advertising", 3),
    ("facebook.com/tr", "Facebook Tracking", "advertising", 3),
    ("connect.facebook.net", "Facebook SDK", "social", 2),
    ("facebook.com/plugins", "Facebook Social Plugin", "social", 2),
    # Amazon
    ("amazon-adsystem.com", "Amazon Ads", "advertising", 3),
    ("amazonwebservices.com", "AWS", "infrastructure", 0),
    # Microsoft
    ("clarity.ms", "Microsoft Clarity", "analytics", 2),
    ("bing.com/bat", "Bing Ads", "advertising", 3),
    ("bat.bing.com", "Bing UET", "advertising", 3),
    # Twitter / X
    ("platform.twitter.com", "Twitter Widget", "social", 2),
    ("analytics.twitter.com", "Twitter Analytics", "analytics", 2),
    ("t.co/", "Twitter Link Tracker", "analytics", 1),
    # TikTok
    ("analytics.tiktok.com", "TikTok Analytics", "advertising", 3),
    ("tiktok.com/i18n", "TikTok Pixel", "advertising", 3),
    # Snap
    ("sc-static.net/scevent", "Snapchat Pixel", "advertising", 3),
    # Pinterest
    ("pintrk", "Pinterest Tag", "advertising", 3),
    ("ct.pinterest.com", "Pinterest Tracker", "advertising", 3),
    # LinkedIn
    ("snap.licdn.com/li.lms-analytics", "LinkedIn Insight", "advertising", 3),
    ("linkedin.com/px", "LinkedIn Pixel", "advertising", 3),
    # Analytics
    ("hotjar.com", "Hotjar", "analytics", 2),
    ("segment.com", "Segment", "analytics", 2),
    ("segment.io", "Segment", "analytics", 2),
    ("cdn.segment.com", "Segment CDN", "analytics", 2),
    ("mixpanel.com", "Mixpanel", "analytics", 2),
    ("amplitude.com", "Amplitude", "analytics", 2),
    ("heapanalytics.com", "Heap", "analytics", 2),
    ("plausible.io", "Plausible", "analytics", 1),
    ("matomo", "Matomo", "analytics", 1),
    ("umami.is", "Umami", "analytics", 1),
    ("posthog.com", "PostHog", "analytics", 2),
    ("rudderstack.com", "RudderStack", "analytics", 2),
    # Error tracking
    ("sentry.io", "Sentry", "error_tracking", 1),
    ("sentry-cdn.com", "Sentry CDN", "error_tracking", 1),
    ("bugsnag.com", "Bugsnag", "error_tracking", 1),
    ("datadoghq.com", "Datadog", "monitoring", 1),
    ("newrelic.com", "New Relic", "monitoring", 1),
    ("nr-data.net", "New Relic Data", "monitoring", 1),
    # Advertising networks
    ("criteo.com", "Criteo", "advertising", 3),
    ("taboola.com", "Taboola", "advertising", 3),
    ("outbrain.com", "Outbrain", "advertising", 3),
    ("adnxs.com", "AppNexus", "advertising", 3),
    ("rubiconproject.com", "Rubicon", "advertising", 3),
    ("pubmatic.com", "PubMatic", "advertising", 3),
    ("openx.net", "OpenX", "advertising", 3),
    ("casalemedia.com", "Casale", "advertising", 3),
    ("indexexchange.com", "Index Exchange", "advertising", 3),
    ("sharethrough.com", "Sharethrough", "advertising", 3),
    ("adsrvr.org", "The Trade Desk", "advertising", 3),
    # Fingerprinting
    ("fingerprintjs", "FingerprintJS", "fingerprinting", 4),
    ("fpjs.io", "FingerprintJS Pro", "fingerprinting", 4),
    ("datadome.co", "DataDome", "fingerprinting", 4),
    # CDN / infra (low severity)
    ("cloudflare.com", "Cloudflare", "infrastructure", 0),
    ("cloudfront.net", "CloudFront (AWS)", "infrastructure", 0),
    ("fastly.net", "Fastly", "infrastructure", 0),
    ("akamai", "Akamai", "infrastructure", 0),
    # Consent managers
    ("cookiebot.com", "Cookiebot", "consent", 0),
    ("onetrust.com", "OneTrust", "consent", 0),
    ("trustarc.com", "TrustArc", "consent", 0),
    ("cookielaw.org", "CookieLaw", "consent", 0),
    # Chat / support
    ("intercom.io", "Intercom", "support", 1),
    ("drift.com", "Drift", "marketing", 2),
    ("zendesk.com", "Zendesk", "support", 1),
    ("crisp.chat", "Crisp", "support", 1),
    ("hubspot.com", "HubSpot", "marketing", 2),
    ("hs-scripts.com", "HubSpot Scripts", "marketing", 2),
    ("hs-analytics.net", "HubSpot Analytics", "marketing", 2),
    # Social
    ("addthis.com", "AddThis", "social", 2),
    ("sharethis.com", "ShareThis", "social", 2),
    ("disqus.com", "Disqus", "social", 2),
]

# Cookie patterns that indicate tracking
COOKIE_PATTERNS = [
    ("_ga", "Google Analytics", "analytics"),
    ("_gid", "Google Analytics", "analytics"),
    ("_gat", "Google Analytics", "analytics"),
    ("_fbp", "Facebook Pixel", "advertising"),
    ("_fbc", "Facebook Click", "advertising"),
    ("fr", "Facebook", "advertising"),
    ("IDE", "DoubleClick", "advertising"),
    ("NID", "Google", "advertising"),
    ("_gcl_au", "Google Ads Conversion", "advertising"),
    ("__hstc", "HubSpot", "marketing"),
    ("hubspotutk", "HubSpot", "marketing"),
    ("_hjid", "Hotjar", "analytics"),
    ("_hjSessionUser", "Hotjar", "analytics"),
    ("mp_", "Mixpanel", "analytics"),
    ("ajs_", "Segment", "analytics"),
    ("intercom-", "Intercom", "support"),
    ("__cf_bm", "Cloudflare Bot Management", "security"),
    ("cf_clearance", "Cloudflare Challenge", "security"),
]

# Data collection signals found in HTML
DATA_COLLECTION_SIGNALS = [
    ("type=\"email\"", "Email address", "form_field"),
    ("type=\"tel\"", "Phone number", "form_field"),
    ("type=\"password\"", "Password", "form_field"),
    ("autocomplete=\"name\"", "Full name", "form_field"),
    ("autocomplete=\"address\"", "Physical address", "form_field"),
    ("autocomplete=\"cc-", "Payment information", "form_field"),
    ("navigator.geolocation", "Precise location", "api_access"),
    ("getUserMedia", "Camera/Microphone", "api_access"),
    ("navigator.userAgent", "Browser fingerprint", "api_access"),
    ("canvas.toDataURL", "Canvas fingerprinting", "fingerprinting"),
    ("AudioContext", "Audio fingerprinting", "fingerprinting"),
    ("WebGLRenderingContext", "WebGL fingerprinting", "fingerprinting"),
    ("navigator.connection", "Network info", "api_access"),
    ("navigator.getBattery", "Battery status", "api_access"),
    ("Notification.requestPermission", "Push notifications", "api_access"),
    ("serviceWorker.register", "Service Worker (offline/push)", "api_access"),
    ("localStorage", "Local storage", "storage"),
    ("sessionStorage", "Session storage", "storage"),
    ("indexedDB", "IndexedDB", "storage"),
]
