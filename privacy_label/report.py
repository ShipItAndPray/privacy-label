"""Generate a standalone HTML privacy report card."""
from .scanner import ScanResult


def generate_html_report(results: list) -> str:
    """Generate a single self-contained HTML report for one or more sites."""
    cards = []
    for r in results:
        grade_color = {"A+": "#22c55e", "A": "#22c55e", "B+": "#06b6d4", "B": "#06b6d4",
                       "C+": "#eab308", "C": "#eab308", "D+": "#ef4444", "D": "#ef4444", "F": "#dc2626"}.get(r.grade, "#888")

        tracker_rows = ""
        for t in sorted(r.trackers, key=lambda x: -x.severity):
            if t.severity == 0:
                continue
            cat_color = "#ef4444" if t.severity >= 3 else "#eab308" if t.severity >= 2 else "#888"
            tracker_rows += f'<tr><td style="color:{cat_color}">{t.category}</td><td>{t.name}</td><td style="color:#888">{t.source}</td></tr>\n'

        signal_rows = ""
        for s in r.data_signals:
            cat_color = "#ef4444" if s.category == "fingerprinting" else "#eab308" if s.category == "api_access" else "#888"
            signal_rows += f'<tr><td style="color:{cat_color}">{s.category}</td><td>{s.name}</td></tr>\n'

        score_pct = r.score
        ads = len([t for t in r.trackers if t.category == "advertising"])
        fp = len([s for s in r.data_signals if s.category == "fingerprinting"])

        card = f'''
        <div class="card">
            <div class="header">
                <div class="domain">{r.domain}</div>
                <div class="grade" style="background:{grade_color}">{r.grade}</div>
            </div>
            <div class="score-bar">
                <div class="score-fill" style="width:{score_pct}%;background:{grade_color}"></div>
            </div>
            <div class="score-text">{r.score}/100</div>
            <div class="stats">
                <div class="stat"><span class="stat-num">{len(r.trackers)}</span>trackers</div>
                <div class="stat"><span class="stat-num" style="color:#ef4444">{ads}</span>ad networks</div>
                <div class="stat"><span class="stat-num">{len(r.third_party_requests)}</span>3rd parties</div>
                <div class="stat"><span class="stat-num">{len(r.cookies_set)}</span>cookies</div>
            </div>
            <div class="features">
                <span class="{"good" if r.https else "bad"}">HTTPS: {"Yes" if r.https else "No"}</span>
                <span class="{"good" if r.has_privacy_policy else "bad"}">Privacy Policy: {"Yes" if r.has_privacy_policy else "No"}</span>
                <span class="{"good" if r.has_cookie_banner else "warn"}">Cookie Banner: {"Yes" if r.has_cookie_banner else "No"}</span>
                <span class="{"good" if r.has_dnf_header else "bad"}">DNT: {"Respected" if r.has_dnf_header else "Ignored"}</span>
            </div>
            {"<table class='tracker-table'><tr><th>Category</th><th>Tracker</th><th>Source</th></tr>" + tracker_rows + "</table>" if tracker_rows else "<p class='clean'>No trackers detected</p>"}
            {"<table class='tracker-table'><tr><th>Type</th><th>Data Signal</th></tr>" + signal_rows + "</table>" if signal_rows else ""}
        </div>
        '''
        cards.append(card)

    return f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Label Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,sans-serif;background:#0d1117;color:#e6edf3;padding:24px;max-width:900px;margin:0 auto}}
h1{{color:#58a6ff;margin-bottom:4px}}
.subtitle{{color:#8b949e;margin-bottom:24px;font-size:14px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:20px}}
.header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}}
.domain{{font-size:20px;font-weight:700}}
.grade{{font-size:24px;font-weight:800;color:white;padding:4px 16px;border-radius:8px}}
.score-bar{{height:8px;background:#21262d;border-radius:4px;margin-bottom:4px}}
.score-fill{{height:100%;border-radius:4px;transition:width 0.3s}}
.score-text{{color:#8b949e;font-size:13px;margin-bottom:12px}}
.stats{{display:flex;gap:16px;margin-bottom:12px}}
.stat{{text-align:center;font-size:12px;color:#8b949e}}
.stat-num{{display:block;font-size:20px;font-weight:700;color:#e6edf3}}
.features{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}}
.features span{{padding:2px 8px;border-radius:4px;font-size:12px}}
.good{{background:#23863633;color:#3fb950}}
.warn{{background:#d2992233;color:#d29922}}
.bad{{background:#f8514933;color:#f85149}}
.tracker-table{{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}}
.tracker-table th{{text-align:left;color:#8b949e;padding:6px 8px;border-bottom:1px solid #30363d}}
.tracker-table td{{padding:6px 8px;border-bottom:1px solid #21262d}}
.clean{{color:#3fb950;margin-top:12px}}
.footer{{color:#8b949e;font-size:12px;margin-top:24px;text-align:center}}
</style></head><body>
<h1>Privacy Nutrition Label</h1>
<p class="subtitle">Generated by privacy-label (pip install privacy-label)</p>
{"".join(cards)}
<p class="footer">Scanned with privacy-label v0.4.0 | github.com/ShipItAndPray/privacy-label</p>
</body></html>'''
