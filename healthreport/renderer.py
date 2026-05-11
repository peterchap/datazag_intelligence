"""
healthreport/renderer.py
------------------------
HealthReportRenderer — produces the v8 master Trusted-Platform-Impersonation report.

Architecture
------------
- Inherits from BaseRenderer (in `renderers.py`) to reuse all the data attribute
  binding (self.domain, self.tech, self.findings, etc.).
- Overrides to_html / to_markdown / to_dict / render — does NOT use _html_shell_branded
  because the v8 design's multi-page A4 paginated structure is different enough to
  build its own shell.
- HTML is built via a single Jinja2 template constant (HEALTH_REPORT_TEMPLATE) for
  cleanliness around the page-5 vendor league-table loop.
- All hardcoded values from the v8 mockup are replaced with data bindings; placeholders
  marked TODO will resolve once the relevant pipeline modules are extended.

Pages
-----
01  Cover (page 1)
02  TOC (page 2)
03  At a glance (page 3)
04  Why this matters (page 4)
05  Your vendor footprint (page 5)
[06–10 to follow once section 04 dataset is specced]
"""

from __future__ import annotations

import json
from typing import Any

from jinja2 import Environment, BaseLoader, select_autoescape

from renderers import BaseRenderer  # parent project import
from branding import BrandConfig

from .grade import score_to_grade, TrustGrade


# ---------------------------------------------------------------------------
# Vendor / platform desirability table
# ---------------------------------------------------------------------------
# Static for v1. The intent in production is for these scores to come from a
# rolling 30-day count of certificate-issuance volume per imitated platform,
# computed by the AII pipeline. For now: hand-calibrated weights that match the
# pattern observed in the April 2026 corpus.

PLATFORM_DESIRABILITY: dict[str, dict[str, Any]] = {
    # name (lowercase substring match)        rank weight, role, reason
    "microsoft 365":      {"weight": 100, "tier": "high",
                           "role": "Email, identity, productivity · primary work environment",
                           "why": "A fake M365 login works on virtually any office worker. "
                                  "Captured credentials unlock email, files, calendar, and "
                                  "frequent SSO into other tools. The most-impersonated trusted "
                                  "platform in our certificate-issuance data globally."},
    "google workspace":   {"weight": 90, "tier": "high",
                           "role": "Search Console, calendar, productivity · secondary work environment",
                           "why": "Workspace credentials unlock email, drive, and calendar. "
                                  "Search Console access additionally lets attackers manipulate "
                                  "your search visibility — relevant to brand-impersonation "
                                  "campaigns covered in section 05."},
    "mailchimp":          {"weight": 75, "tier": "med-high",
                           "role": "Marketing email, customer mailing list · outbound channel",
                           "why": "Mailchimp credentials unlock the customer mailing list directly. "
                                  "Fastest known path from staff compromise to brand-impersonation "
                                  "at scale — attackers send convincing email from your real "
                                  "Mailchimp account to your real customer list. Recent breach "
                                  "history makes this an especially active target."},
    "apple":              {"weight": 50, "tier": "med",
                           "role": "Apple Business / device management",
                           "why": "Apple ID credentials unlock device management and App Store access."},
    "zoho":               {"weight": 45, "tier": "med",
                           "role": "CRM, productivity, campaign tooling",
                           "why": "Zoho credentials unlock CRM, support, and campaign infrastructure."},
    "citrix":             {"weight": 40, "tier": "med",
                           "role": "Mobile device management",
                           "why": "Citrix admin credentials unlock device fleet management."},
    "mailgun":            {"weight": 25, "tier": "low",
                           "role": "Transactional email infrastructure",
                           "why": "Mailgun credentials unlock outbound email sending; less directly "
                                  "actionable but enables high-volume campaigns."},
    "email signatures":   {"weight": 15, "tier": "low",
                           "role": "Email signature management",
                           "why": "Lower-value target; signature infrastructure rather than identity."},
    # additions can be appended; the lookup uses substring matching
}

DEFAULT_PLATFORM_ENTRY = {
    "weight": 30, "tier": "med",
    "role": "SaaS platform",
    "why": "Identity platform — credentials may unlock account access.",
}


# ---------------------------------------------------------------------------
# Jinja environment and template
# ---------------------------------------------------------------------------

_jinja_env = Environment(
    loader=BaseLoader(),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


HEALTH_REPORT_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Datazag Health Report — {{ domain }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --navy-deep: #0A141F; --navy: #0F1923; --navy-lift: #18283C; --navy-soft: #1E2C40;
    --rule-dark: rgba(255,255,255,0.10); --rule-soft: rgba(255,255,255,0.06);
    --white: #FFFFFF; --white-2: rgba(255,255,255,0.78); --white-3: rgba(255,255,255,0.55); --white-4: rgba(255,255,255,0.32);
    --cyan: #00C2FF; --cyan-deep: #0096CC; --cyan-glow: rgba(0,194,255,0.12);
    --warn: #F4B860; --bad: #FF6B6B; --good: #4ADE80;
    --paper: #FAFAF8; --ink: #0F172A; --ink-2: #334155; --ink-3: #64748B; --ink-4: #94A3B8;
    --rule-light: #E2E8F0; --rule-lighter: #F1F5F9; --cyan-page: #0096CC;
    --tag-context: #64748B; --tag-findings: #0096CC; --tag-action: #C2410C;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  @page { size: A4; margin: 0; }
  html, body { background: #FFFFFF; font-family: 'Inter', sans-serif; color: var(--white); -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }
  /* Page shell */
  .page { width: 794px; height: 1123px; margin: 0 auto; background: var(--navy); position: relative; overflow: hidden; display: flex; flex-direction: column; page-break-after: always; }
  .page:last-child { page-break-after: auto; }
  .page::before { content: ''; position: absolute; inset: 0; background: radial-gradient(circle at 88% 8%, rgba(0,194,255,0.10) 0%, transparent 38%), radial-gradient(circle at 8% 82%, rgba(0,194,255,0.06) 0%, transparent 42%), radial-gradient(circle at 60% 50%, rgba(255,255,255,0.02) 0%, transparent 50%); pointer-events: none; z-index: 0; }
  .page::after { content: ''; position: absolute; inset: 0; background-image: linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px); background-size: 32px 32px; pointer-events: none; z-index: 0; }
  .page > * { position: relative; z-index: 1; }
  /* Top bar */
  .topbar { display: flex; justify-content: space-between; align-items: center; padding: 28px 56px 22px; border-bottom: 1px solid var(--rule-dark); }
  .brand { display: flex; align-items: center; gap: 14px; }
  .brand-mark { width: 32px; height: 32px; border-radius: 8px; background: linear-gradient(135deg, var(--cyan) 0%, var(--cyan-deep) 100%); display: flex; align-items: center; justify-content: center; box-shadow: 0 2px 12px rgba(0,194,255,0.28); }
  .brand-mark svg { width: 18px; height: 18px; }
  .brand-wordmark { font-size: 19px; font-weight: 800; letter-spacing: -0.02em; color: var(--white); }
  .brand-divider { width: 1px; height: 22px; background: var(--rule-dark); }
  .brand-product { font-size: 11px; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; color: var(--white-3); }
  .topbar-right { text-align: right; }
  .topbar-id { font-size: 11px; font-weight: 600; color: var(--white-3); letter-spacing: 0.06em; text-transform: uppercase; }
  .topbar-id strong { color: var(--cyan); font-weight: 700; letter-spacing: 0; text-transform: none; margin-left: 8px; font-size: 12px; }
  /* Cover content */
  .cover { flex: 1; padding: 44px 56px 40px; display: flex; flex-direction: column; }
  .eyebrow { display: inline-flex; align-items: center; gap: 10px; padding: 7px 14px; background: var(--cyan-glow); border: 1px solid rgba(0,194,255,0.28); border-radius: 100px; font-size: 10.5px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: var(--cyan); align-self: flex-start; margin-bottom: 28px; }
  .eyebrow .dot { width: 5px; height: 5px; border-radius: 50%; background: var(--cyan); box-shadow: 0 0 8px var(--cyan); }
  .hero { font-size: 44px; font-weight: 800; letter-spacing: -0.028em; line-height: 1.08; color: var(--white); margin-bottom: 22px; max-width: 640px; }
  .hero .pct { color: var(--cyan); font-weight: 900; position: relative; white-space: nowrap; }
  .hero .pct::after { content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 4px; background: var(--cyan); opacity: 0.25; border-radius: 2px; }
  .hero .lead-out { display: block; font-weight: 600; color: var(--white-2); font-size: 32px; letter-spacing: -0.02em; margin-top: 14px; line-height: 1.15; }
  .deck { font-size: 14px; line-height: 1.65; color: var(--white-2); max-width: 600px; margin-bottom: 36px; }
  .deck strong { color: var(--white); font-weight: 600; }
  /* Trust grade block */
  .grade-block { display: grid; grid-template-columns: 168px 1fr; gap: 28px; align-items: center; background: linear-gradient(135deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.015) 100%); border: 1px solid var(--rule-dark); border-radius: 16px; padding: 26px 30px; margin-bottom: 28px; position: relative; overflow: hidden; }
  .grade-block::before { content: ''; position: absolute; top: -60px; right: -40px; width: 220px; height: 220px; background: radial-gradient(circle, var(--cyan-glow) 0%, transparent 60%); pointer-events: none; }
  .grade-dial { position: relative; width: 168px; height: 168px; }
  .grade-dial svg { width: 100%; height: 100%; transform: rotate(-90deg); }
  .grade-dial-letter { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .grade-letter { font-size: 76px; font-weight: 900; line-height: 1; letter-spacing: -0.04em; color: var(--white); margin-bottom: 4px; }
  .grade-caption { font-size: 9.5px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: var(--white-3); }
  .grade-text { position: relative; z-index: 1; }
  .grade-headline { font-size: 22px; font-weight: 800; letter-spacing: -0.02em; color: var(--white); line-height: 1.2; margin-bottom: 6px; }
  .grade-sub { font-size: 13px; color: var(--white-2); line-height: 1.55; margin-bottom: 18px; max-width: 460px; }
  .grade-pills { display: flex; flex-wrap: wrap; gap: 8px; }
  .pill { display: inline-flex; align-items: center; gap: 8px; padding: 7px 12px 7px 11px; background: rgba(255,255,255,0.04); border: 1px solid var(--rule-dark); border-radius: 100px; font-size: 11.5px; font-weight: 600; color: var(--white); letter-spacing: 0.005em; }
  .pill .pill-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--cyan); }
  .pill.warn .pill-dot { background: var(--warn); }
  .pill.bad .pill-dot { background: var(--bad); }
  .pill .pill-num { font-weight: 800; color: var(--cyan); margin-right: 2px; }
  .pill.warn .pill-num { color: var(--warn); }
  .pill.bad .pill-num { color: var(--bad); }
  /* Meta strip */
  .meta-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; padding: 18px 0 20px; border-top: 1px solid var(--rule-dark); border-bottom: 1px solid var(--rule-dark); margin-bottom: 24px; }
  .meta-cell { padding: 0 22px; border-right: 1px solid var(--rule-soft); }
  .meta-cell:first-child { padding-left: 0; }
  .meta-cell:last-child { padding-right: 0; border-right: none; }
  .meta-label { font-size: 9.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--cyan); margin-bottom: 7px; }
  .meta-value { font-size: 13.5px; font-weight: 600; color: var(--white); line-height: 1.35; }
  .meta-value .meta-sub { display: block; font-size: 10.5px; font-weight: 500; color: var(--white-3); margin-top: 3px; letter-spacing: 0.01em; }
  /* Corpus line */
  .corpus { display: flex; align-items: center; gap: 12px; margin-bottom: auto; padding-bottom: 20px; }
  .corpus-bar { flex: 1; height: 1px; background: linear-gradient(90deg, var(--rule-dark) 0%, rgba(0,194,255,0.18) 50%, var(--rule-dark) 100%); }
  .corpus-text { font-size: 10.5px; font-weight: 600; color: var(--white-3); letter-spacing: 0.06em; text-transform: uppercase; white-space: nowrap; }
  .corpus-text strong { color: var(--cyan); font-weight: 700; margin-right: 4px; }
  .corpus-pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--cyan); }
  /* Footer */
  .cover-footer { display: flex; justify-content: space-between; align-items: center; padding: 18px 56px 24px; border-top: 1px solid var(--rule-dark); font-size: 10px; font-weight: 600; color: var(--white-4); letter-spacing: 0.1em; text-transform: uppercase; }
  .cover-footer .right { color: var(--white-3); }
  /* Light interior pages */
  .page.light { background: var(--paper); color: var(--ink); }
  .page.light::before { background: radial-gradient(circle at 92% 4%, rgba(0,150,204,0.05) 0%, transparent 35%), radial-gradient(circle at 4% 96%, rgba(0,150,204,0.03) 0%, transparent 40%); }
  .page.light::after { background-image: linear-gradient(rgba(15,23,42,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(15,23,42,0.025) 1px, transparent 1px); background-size: 36px 36px; }
  .page.light .topbar { border-bottom-color: var(--rule-light); }
  .page.light .brand-wordmark { color: var(--ink); }
  .page.light .brand-product { color: var(--ink-3); }
  .page.light .brand-divider { background: var(--rule-light); }
  .page.light .topbar-id { color: var(--ink-3); }
  .page.light .topbar-id strong { color: var(--cyan-page); }
  .page.light .cover-footer { color: var(--ink-4); border-top-color: var(--rule-light); }
  .page.light .cover-footer .right { color: var(--ink-3); }
  .page.light .toc-spacer { flex: 1; }
  /* TOC */
  .toc-header { padding: 44px 56px 24px; }
  .toc-eyebrow { display: inline-flex; align-items: center; gap: 8px; font-size: 10.5px; font-weight: 700; color: var(--cyan-page); letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 14px; }
  .toc-eyebrow::before { content: ''; width: 18px; height: 1.5px; background: var(--cyan-page); }
  .toc-title { font-size: 32px; font-weight: 800; letter-spacing: -0.025em; color: var(--ink); line-height: 1.15; margin-bottom: 12px; max-width: 600px; }
  .toc-lede { font-size: 13.5px; color: var(--ink-2); line-height: 1.6; max-width: 600px; }
  .toc-list { padding: 8px 56px 0; list-style: none; }
  .toc-item { display: grid; grid-template-columns: 56px 1fr auto; gap: 18px; align-items: start; padding: 14px 0; border-bottom: 1px solid var(--rule-lighter); }
  .toc-item:last-child { border-bottom: none; }
  .toc-num { font-size: 22px; font-weight: 800; color: var(--cyan-page); letter-spacing: -0.02em; line-height: 1; padding-top: 2px; font-variant-numeric: tabular-nums; }
  .toc-content { padding-right: 12px; }
  .toc-content h4 { font-size: 14.5px; font-weight: 700; color: var(--ink); letter-spacing: -0.01em; margin-bottom: 3px; line-height: 1.3; }
  .toc-content p { font-size: 12px; color: var(--ink-3); line-height: 1.5; margin: 0; }
  .toc-tag { display: inline-flex; align-items: center; gap: 6px; padding: 5px 11px 5px 9px; border-radius: 100px; font-size: 9.5px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; border: 1px solid; white-space: nowrap; margin-top: 2px; }
  .toc-tag .tag-dot { width: 5px; height: 5px; border-radius: 50%; }
  .toc-tag.context { color: var(--tag-context); border-color: rgba(100,116,139,0.3); background: rgba(100,116,139,0.06); }
  .toc-tag.context .tag-dot { background: var(--tag-context); }
  .toc-tag.findings { color: var(--tag-findings); border-color: rgba(0,150,204,0.32); background: rgba(0,150,204,0.06); }
  .toc-tag.findings .tag-dot { background: var(--tag-findings); }
  .toc-tag.action { color: var(--tag-action); border-color: rgba(194,65,12,0.32); background: rgba(194,65,12,0.06); }
  .toc-tag.action .tag-dot { background: var(--tag-action); }
  .toc-callout { margin: 16px 56px 0; background: linear-gradient(135deg, rgba(0,150,204,0.06) 0%, rgba(0,150,204,0.02) 100%); border: 1px solid rgba(0,150,204,0.22); border-radius: 12px; padding: 18px 22px; display: grid; grid-template-columns: auto 1fr; gap: 16px; align-items: start; }
  .toc-callout-icon { width: 36px; height: 36px; border-radius: 10px; background: var(--cyan-page); color: white; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 16px; }
  .toc-callout h5 { font-size: 12.5px; font-weight: 700; color: var(--ink); margin-bottom: 4px; letter-spacing: 0.02em; }
  .toc-callout p { font-size: 12px; color: var(--ink-2); line-height: 1.55; margin: 0; }
  .toc-callout p strong { color: var(--ink); font-weight: 600; }
  /* Section identifier */
  .section-id-bar { padding: 36px 56px 0; }
  .section-num-row { display: flex; align-items: baseline; gap: 12px; margin-bottom: 14px; }
  .section-num { font-size: 11px; font-weight: 700; letter-spacing: 0.18em; color: var(--cyan-page); text-transform: uppercase; }
  .section-rule { flex: 1; height: 1px; background: var(--rule-light); }
  .section-tag { font-size: 9.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; padding: 4px 10px; border-radius: 100px; background: rgba(100,116,139,0.08); border: 1px solid rgba(100,116,139,0.22); color: var(--ink-3); }
  .section-title-h1 { font-size: 30px; font-weight: 800; letter-spacing: -0.025em; color: var(--ink); line-height: 1.1; margin-bottom: 10px; }
  .section-headline { font-size: 14.5px; color: var(--ink-2); line-height: 1.6; max-width: 620px; margin-bottom: 24px; }
  .section-headline strong { color: var(--ink); font-weight: 600; }
  /* At-a-glance */
  .grade-band { margin: 0 56px 24px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 18px 22px; display: grid; grid-template-columns: 60px 1fr; gap: 22px; align-items: center; }
  .grade-band-letter { width: 60px; height: 60px; border-radius: 12px; background: linear-gradient(135deg, var(--ink) 0%, #1E293B 100%); color: var(--white); display: flex; align-items: center; justify-content: center; font-size: 32px; font-weight: 900; letter-spacing: -0.03em; box-shadow: 0 2px 10px rgba(15,23,42,0.18); }
  .grade-band-body { display: grid; grid-template-rows: auto auto; gap: 8px; }
  .grade-band-scale { position: relative; height: 24px; margin-top: 2px; }
  .grade-scale-track { position: absolute; top: 50%; left: 0; right: 0; height: 6px; transform: translateY(-50%); background: linear-gradient(90deg, #4ADE80 0%, #A3E635 22%, #FACC15 45%, #FB923C 65%, #EF4444 88%, #B91C1C 100%); border-radius: 3px; opacity: 0.85; }
  .grade-scale-marks { position: absolute; top: 50%; left: 0; right: 0; transform: translateY(-50%); display: flex; justify-content: space-between; pointer-events: none; }
  .grade-scale-mark { width: 2px; height: 14px; background: var(--paper); border-radius: 1px; }
  .grade-scale-pin { position: absolute; top: 50%; transform: translate(-50%, -50%); width: 22px; height: 22px; border-radius: 50%; background: var(--ink); border: 3px solid var(--paper); box-shadow: 0 2px 8px rgba(15,23,42,0.35); z-index: 2; }
  .grade-band-text { font-size: 12.5px; color: var(--ink-2); line-height: 1.55; }
  .grade-band-text strong { color: var(--ink); font-weight: 600; }
  .scorecards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin: 0 56px 22px; }
  .scorecard { background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 18px 18px 16px; border-top: 3px solid var(--ink-4); }
  .scorecard.bad { border-top-color: #EF4444; }
  .scorecard.warn { border-top-color: #F59E0B; }
  .scorecard.neutral { border-top-color: var(--cyan-page); }
  .scorecard-label { font-size: 9.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--ink-3); margin-bottom: 10px; display: flex; align-items: center; gap: 6px; }
  .scorecard-label .scorecard-icon { width: 14px; height: 14px; border-radius: 4px; background: var(--ink-4); display: inline-flex; align-items: center; justify-content: center; color: white; font-size: 9px; font-weight: 800; }
  .scorecard.bad .scorecard-icon { background: #EF4444; }
  .scorecard.warn .scorecard-icon { background: #F59E0B; }
  .scorecard.neutral .scorecard-icon { background: var(--cyan-page); }
  .scorecard-state { font-size: 22px; font-weight: 800; letter-spacing: -0.02em; line-height: 1.1; margin-bottom: 10px; color: var(--ink); }
  .scorecard.bad .scorecard-state { color: #B91C1C; }
  .scorecard.warn .scorecard-state { color: #B45309; }
  .scorecard.neutral .scorecard-state { color: var(--cyan-deep); }
  .scorecard-text { font-size: 11.5px; color: var(--ink-2); line-height: 1.5; }
  .scorecard-text strong { color: var(--ink); font-weight: 600; }
  .assessment-strip { margin: 0 56px 22px; padding: 12px 18px; background: rgba(100,116,139,0.05); border: 1px solid rgba(100,116,139,0.15); border-radius: 10px; font-size: 11.5px; color: var(--ink-3); display: flex; align-items: center; gap: 10px; }
  .assessment-strip-icon { width: 20px; height: 20px; border-radius: 50%; background: var(--ink-3); color: white; display: inline-flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 800; flex-shrink: 0; }
  .assessment-strip strong { color: var(--ink); font-weight: 600; }
  .priorities-header { margin: 0 56px 12px; display: flex; align-items: baseline; gap: 14px; }
  .priorities-header h3 { font-size: 16px; font-weight: 800; letter-spacing: -0.015em; color: var(--ink); }
  .priorities-header .sub { font-size: 11.5px; color: var(--ink-3); }
  .priority-list { margin: 0 56px; }
  .priority-card { display: grid; grid-template-columns: 40px 1fr 110px; gap: 16px; padding: 14px 18px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; margin-bottom: 8px; align-items: start; }
  .priority-card:last-child { margin-bottom: 0; }
  .priority-num { font-size: 26px; font-weight: 900; color: var(--ink-4); letter-spacing: -0.03em; line-height: 1; padding-top: 2px; font-variant-numeric: tabular-nums; }
  .priority-body { padding-right: 8px; }
  .priority-pills { display: flex; gap: 6px; margin-bottom: 5px; flex-wrap: wrap; }
  .pri-pill { font-size: 9px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; padding: 3px 8px; border-radius: 4px; }
  .pri-pill.crit { background: #FEE2E2; color: #991B1B; }
  .pri-pill.high { background: #FEF3C7; color: #92400E; }
  .pri-pill.med { background: #DBEAFE; color: #1E40AF; }
  .pri-pill.vendor { background: rgba(239,68,68,0.08); color: #B91C1C; border: 1px solid rgba(239,68,68,0.25); }
  .pri-pill.brand { background: rgba(245,158,11,0.08); color: #B45309; border: 1px solid rgba(245,158,11,0.25); }
  .pri-pill.infra { background: rgba(0,150,204,0.08); color: var(--cyan-deep); border: 1px solid rgba(0,150,204,0.25); }
  .priority-title { font-size: 13.5px; font-weight: 700; color: var(--ink); letter-spacing: -0.005em; line-height: 1.3; margin-bottom: 3px; }
  .priority-action { font-size: 11.5px; color: var(--ink-2); line-height: 1.5; margin-bottom: 6px; }
  .priority-why { font-size: 10.5px; color: var(--ink-3); line-height: 1.5; font-style: italic; }
  .priority-why::before { content: 'Why · '; font-style: normal; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--ink-4); font-size: 9.5px; }
  .priority-meta { font-size: 10px; color: var(--ink-3); line-height: 1.6; text-align: right; border-left: 1px solid var(--rule-light); padding-left: 14px; align-self: stretch; }
  .priority-meta-row { display: flex; justify-content: space-between; margin-bottom: 4px; }
  .priority-meta-key { font-weight: 700; color: var(--ink-4); letter-spacing: 0.06em; text-transform: uppercase; font-size: 8.5px; }
  .priority-meta-val { font-weight: 600; color: var(--ink); font-size: 10.5px; }
  /* Why this matters */
  .data-panel { margin: 0 56px 26px; background: linear-gradient(135deg, var(--ink) 0%, #1E293B 100%); border-radius: 14px; padding: 22px 26px; color: var(--white); position: relative; overflow: hidden; }
  .data-panel::before { content: ''; position: absolute; top: -40px; right: -40px; width: 220px; height: 220px; background: radial-gradient(circle, rgba(0,194,255,0.18) 0%, transparent 60%); pointer-events: none; }
  .data-panel-inner { position: relative; z-index: 1; }
  .data-panel-eyebrow { font-size: 9.5px; font-weight: 700; letter-spacing: 0.16em; text-transform: uppercase; color: var(--cyan); margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
  .data-panel-eyebrow::after { content: ''; flex: 1; height: 1px; background: rgba(0,194,255,0.25); }
  .data-panel-row { display: grid; grid-template-columns: auto 1fr; gap: 22px; align-items: center; margin-bottom: 14px; }
  .data-panel-pct { font-size: 56px; font-weight: 900; color: var(--cyan); line-height: 1; letter-spacing: -0.04em; }
  .data-panel-bar { height: 24px; border-radius: 6px; overflow: hidden; display: flex; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.08); }
  .data-panel-bar-fill { background: linear-gradient(90deg, var(--cyan-deep) 0%, var(--cyan) 100%); width: 87.5%; display: flex; align-items: center; justify-content: flex-start; padding-left: 12px; font-size: 10.5px; font-weight: 700; color: var(--ink); letter-spacing: 0.04em; text-transform: uppercase; }
  .data-panel-bar-rest { flex: 1; display: flex; align-items: center; justify-content: flex-end; padding-right: 10px; font-size: 10px; font-weight: 600; color: var(--white-3); letter-spacing: 0.04em; text-transform: uppercase; }
  .data-panel-claim { font-size: 13px; color: rgba(255,255,255,0.85); line-height: 1.6; max-width: 580px; margin-top: 14px; }
  .data-panel-claim strong { color: var(--white); font-weight: 600; }
  .surfaces-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin: 0 56px 24px; }
  .surface-panel { background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 20px 22px; }
  .surface-panel.inbound { border-top: 3px solid #EF4444; }
  .surface-panel.outbound { border-top: 3px solid #F59E0B; }
  .surface-eyebrow { font-size: 9.5px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; margin-bottom: 4px; display: flex; align-items: center; gap: 7px; }
  .surface-panel.inbound .surface-eyebrow { color: #B91C1C; }
  .surface-panel.outbound .surface-eyebrow { color: #B45309; }
  .surface-eyebrow .surface-icon { width: 16px; height: 16px; border-radius: 4px; display: inline-flex; align-items: center; justify-content: center; color: white; font-size: 9px; font-weight: 800; }
  .surface-panel.inbound .surface-icon { background: #EF4444; }
  .surface-panel.outbound .surface-icon { background: #F59E0B; }
  .surface-title { font-size: 18px; font-weight: 800; color: var(--ink); letter-spacing: -0.02em; line-height: 1.2; margin-bottom: 6px; }
  .surface-thesis { font-size: 12px; color: var(--ink-2); line-height: 1.55; margin-bottom: 14px; font-style: italic; }
  .surface-attrs { display: grid; gap: 8px; padding-top: 12px; border-top: 1px solid var(--rule-light); }
  .surface-attr { display: grid; grid-template-columns: 76px 1fr; gap: 12px; align-items: baseline; font-size: 11.5px; }
  .surface-attr-key { font-size: 9px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-4); padding-top: 2px; }
  .surface-attr-val { color: var(--ink-2); line-height: 1.45; }
  .surface-attr-val strong { color: var(--ink); font-weight: 600; }
  .vol-badge { display: inline-flex; align-items: center; gap: 5px; padding: 2px 7px; border-radius: 4px; font-size: 10.5px; font-weight: 700; letter-spacing: 0.02em; }
  .surface-panel.inbound .vol-badge { background: #FEE2E2; color: #991B1B; }
  .surface-panel.outbound .vol-badge { background: #FEF3C7; color: #92400E; }
  .causal-section { margin: 0 56px 0; }
  .causal-header { display: flex; align-items: baseline; gap: 14px; margin-bottom: 14px; }
  .causal-header h3 { font-size: 15px; font-weight: 800; letter-spacing: -0.015em; color: var(--ink); }
  .causal-header .sub { font-size: 11.5px; color: var(--ink-3); line-height: 1.5; }
  .causal-example-eyebrow { display: inline-flex; align-items: center; gap: 8px; font-size: 9.5px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-3); margin-bottom: 10px; padding: 5px 12px; background: rgba(100,116,139,0.06); border: 1px dashed rgba(100,116,139,0.32); border-radius: 4px; }
  .causal-example-eyebrow::before { content: 'For example'; font-weight: 800; color: var(--ink); padding-right: 8px; margin-right: 4px; border-right: 1px solid rgba(100,116,139,0.3); }
  .causal-chain { display: grid; grid-template-columns: 1fr auto 1fr auto 1fr auto 1fr; gap: 0; align-items: stretch; }
  .causal-step { background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; padding: 12px 14px; display: flex; flex-direction: column; gap: 4px; min-height: 72px; }
  .causal-step.start { border-left: 3px solid #EF4444; }
  .causal-step.end { border-left: 3px solid #F59E0B; }
  .causal-step-num { font-size: 8.5px; font-weight: 800; color: var(--ink-4); letter-spacing: 0.14em; text-transform: uppercase; }
  .causal-step.start .causal-step-num { color: #B91C1C; }
  .causal-step.end .causal-step-num { color: #B45309; }
  .causal-step-title { font-size: 11.5px; font-weight: 700; color: var(--ink); line-height: 1.3; letter-spacing: -0.005em; }
  .causal-step-detail { font-size: 10px; color: var(--ink-3); line-height: 1.4; }
  .causal-arrow { display: flex; align-items: center; justify-content: center; color: var(--ink-4); padding: 0 4px; font-size: 18px; }
  .causal-tags { display: flex; justify-content: space-between; margin-top: 10px; padding: 0 4px; font-size: 9.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; }
  .causal-tags .tag-vendor { color: #B91C1C; }
  .causal-tags .tag-brand { color: #B45309; }
  /* Vendor footprint */
  .footprint-summary { margin: 0 56px 22px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; padding: 14px 0; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; }
  .footprint-stat { padding: 0 22px; border-right: 1px solid var(--rule-lighter); }
  .footprint-stat:last-child { border-right: none; }
  .footprint-stat-num { font-size: 24px; font-weight: 800; color: var(--ink); letter-spacing: -0.03em; line-height: 1; margin-bottom: 4px; font-variant-numeric: tabular-nums; }
  .footprint-stat-num.accent { color: var(--cyan-deep); }
  .footprint-stat-num.alert { color: #B91C1C; }
  .footprint-stat-label { font-size: 9.5px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--ink-3); line-height: 1.3; }
  .top-vendors { margin: 0 56px 18px; display: grid; gap: 10px; }
  .vendor-card { background: var(--white); border: 1px solid var(--rule-light); border-radius: 12px; padding: 16px 18px 14px; display: grid; grid-template-columns: 56px 1fr 130px; gap: 16px; align-items: start; }
  .vendor-card.high { border-left: 3px solid #EF4444; }
  .vendor-card.med-high { border-left: 3px solid #F59E0B; }
  .vendor-rank { display: flex; flex-direction: column; align-items: center; padding-top: 2px; }
  .vendor-rank-num { font-size: 30px; font-weight: 900; color: var(--ink); line-height: 1; letter-spacing: -0.04em; font-variant-numeric: tabular-nums; }
  .vendor-rank-label { font-size: 7.5px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-4); margin-top: 4px; }
  .vendor-body { padding-right: 4px; }
  .vendor-name { font-size: 16px; font-weight: 800; color: var(--ink); letter-spacing: -0.02em; line-height: 1.2; margin-bottom: 2px; }
  .vendor-role { font-size: 11.5px; color: var(--ink-3); margin-bottom: 10px; font-weight: 500; }
  .vendor-evidence { display: flex; flex-wrap: wrap; gap: 5px 6px; margin-bottom: 10px; }
  .vendor-evi { font-family: 'JetBrains Mono', monospace; font-size: 9.5px; font-weight: 500; color: var(--ink-2); background: rgba(15,23,42,0.04); border: 1px solid rgba(15,23,42,0.08); padding: 3px 7px; border-radius: 4px; letter-spacing: -0.01em; }
  .vendor-evi-key { color: var(--cyan-deep); font-weight: 700; margin-right: 3px; }
  .vendor-quote { font-size: 11.5px; color: var(--ink-2); line-height: 1.5; font-style: italic; padding-left: 10px; border-left: 2px solid var(--rule-light); }
  .vendor-quote strong { color: var(--ink); font-weight: 600; font-style: normal; }
  .vendor-meta { display: flex; flex-direction: column; gap: 6px; align-items: flex-end; }
  .vendor-desirability { display: inline-flex; align-items: center; gap: 6px; padding: 5px 10px; border-radius: 100px; font-size: 9.5px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; border: 1px solid; white-space: nowrap; }
  .vendor-desirability.high { color: #B91C1C; background: rgba(239,68,68,0.08); border-color: rgba(239,68,68,0.32); }
  .vendor-desirability.med-high { color: #B45309; background: rgba(245,158,11,0.08); border-color: rgba(245,158,11,0.32); }
  .vendor-desirability .des-dot { width: 6px; height: 6px; border-radius: 50%; }
  .vendor-desirability.high .des-dot { background: #EF4444; }
  .vendor-desirability.med-high .des-dot { background: #F59E0B; }
  .vendor-evidence-count { font-size: 9.5px; font-weight: 700; color: var(--ink-4); letter-spacing: 0.08em; text-transform: uppercase; }
  .vendor-evidence-count strong { color: var(--ink); font-size: 11.5px; font-weight: 800; margin-right: 3px; }
  .vendor-table-wrap { margin: 0 56px 18px; background: var(--white); border: 1px solid var(--rule-light); border-radius: 10px; overflow: hidden; }
  .vendor-table-header { padding: 10px 18px; background: rgba(15,23,42,0.02); border-bottom: 1px solid var(--rule-light); font-size: 11px; font-weight: 700; color: var(--ink); letter-spacing: -0.01em; }
  .vendor-table-header span { font-size: 9.5px; font-weight: 600; color: var(--ink-3); letter-spacing: 0.04em; text-transform: none; }
  .vendor-table { width: 100%; border-collapse: collapse; }
  .vendor-table thead th { text-align: left; padding: 8px 14px; font-size: 8.5px; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--ink-4); border-bottom: 1px solid var(--rule-light); background: rgba(15,23,42,0.015); }
  .vendor-table tbody td { padding: 9px 14px; font-size: 11.5px; color: var(--ink-2); border-bottom: 1px solid var(--rule-lighter); vertical-align: middle; }
  .vendor-table tbody tr:last-child td { border-bottom: none; }
  .vendor-table .rank-cell { font-weight: 800; color: var(--ink-3); font-variant-numeric: tabular-nums; font-size: 13px; width: 36px; }
  .vendor-table .name-cell { font-weight: 700; color: var(--ink); font-size: 12px; white-space: nowrap; }
  .vendor-table .role-cell { color: var(--ink-3); }
  .vendor-table .evi-cell { font-family: 'JetBrains Mono', monospace; font-size: 9.5px; color: var(--ink-3); }
  .vendor-table .des-cell { text-align: right; width: 88px; }
  .des-mini { display: inline-flex; align-items: center; gap: 5px; padding: 3px 8px; border-radius: 100px; font-size: 8.5px; font-weight: 800; letter-spacing: 0.1em; text-transform: uppercase; border: 1px solid; }
  .des-mini.med { color: #92400E; background: rgba(245,158,11,0.06); border-color: rgba(245,158,11,0.28); }
  .des-mini.low { color: var(--ink-3); background: rgba(100,116,139,0.06); border-color: rgba(100,116,139,0.22); }
  .des-mini .des-dot { width: 5px; height: 5px; border-radius: 50%; }
  .des-mini.med .des-dot { background: #F59E0B; }
  .des-mini.low .des-dot { background: var(--ink-4); }
  .next-section-cta { margin: 0 56px 0; padding: 14px 18px; background: linear-gradient(135deg, rgba(0,150,204,0.05) 0%, rgba(0,150,204,0.015) 100%); border: 1px solid rgba(0,150,204,0.22); border-radius: 10px; display: grid; grid-template-columns: 1fr auto; gap: 14px; align-items: center; }
  .next-section-cta-text { font-size: 12px; color: var(--ink-2); line-height: 1.5; }
  .next-section-cta-text strong { color: var(--ink); font-weight: 700; }
  .next-section-cta-arrow { display: inline-flex; align-items: center; gap: 8px; font-size: 10.5px; font-weight: 800; color: var(--cyan-deep); letter-spacing: 0.1em; text-transform: uppercase; white-space: nowrap; }
</style>
</head>
<body>

{# ============ MACROS ============ #}
{% macro brand_block(light=False) -%}
  <div class="brand">
    <div class="brand-mark">
      <svg viewBox="0 0 24 24" fill="none">
        <path d="M4 7L12 3L20 7L12 11L4 7Z" fill="white" opacity="0.95"/>
        <path d="M4 12L12 16L20 12" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" opacity="0.7"/>
        <path d="M4 17L12 21L20 17" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" opacity="0.45"/>
      </svg>
    </div>
    <div class="brand-wordmark">DATAZAG</div>
    <div class="brand-divider"></div>
    <div class="brand-product">Health Report</div>
  </div>
{%- endmacro %}

{# ============ PAGE 1 — COVER ============ #}
<div class="page">
  <div class="topbar">
    {{ brand_block() }}
    <div class="topbar-right">
      <div class="topbar-id">
        {{ quarter_label }} · Confidential
        <strong>{{ domain }}</strong>
      </div>
    </div>
  </div>

  <div class="cover">
    <span class="eyebrow">
      <span class="dot"></span>
      Trusted platform &amp; brand impersonation exposure
    </span>

    <h1 class="hero">
      <span class="pct">85&ndash;90%</span> of impersonation attacks target the trusted platforms your team logs into every day.
      <span class="lead-out">This report shows which of yours.</span>
    </h1>

    <p class="deck">
      A point-in-time exposure assessment for <strong>{{ domain }}</strong>: the technology platforms your stack depends on, the active attacker infrastructure currently imitating them, and how your own brand authentication holds up in return. Derived from continuous certificate-issuance, BGP and DNS telemetry across a 320-million-domain corpus.
    </p>

    <div class="grade-block">
      <div class="grade-dial">
        <svg viewBox="0 0 168 168">
          <circle cx="84" cy="84" r="74" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"/>
          <circle cx="84" cy="84" r="74" fill="none" stroke="url(#dialGrad)" stroke-width="10"
                  stroke-dasharray="465" stroke-dashoffset="{{ (465 * (1 - grade.arc_fill)) | round(0) }}" stroke-linecap="round"/>
          <defs>
            <linearGradient id="dialGrad" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stop-color="#00C2FF"/>
              <stop offset="100%" stop-color="#0096CC"/>
            </linearGradient>
          </defs>
        </svg>
        <div class="grade-dial-letter">
          <div class="grade-letter">{{ grade.letter }}</div>
          <div class="grade-caption">Trust Grade</div>
        </div>
      </div>
      <div class="grade-text">
        <h2 class="grade-headline">{{ grade.headline }} — {{ grade.description }}</h2>
        <p class="grade-sub">
          {# TODO(section-04-data): pillar counts use placeholder logic until per-platform exposure dataset exists #}
          {{ pill_platforms_at_risk }} platforms in your stack are being actively impersonated, and your own brand authentication has gaps that let the same attackers send convincingly as you. Items to address by priority over the quarter.
        </p>
        <div class="grade-pills">
          <span class="pill bad"><span class="pill-dot"></span><span class="pill-num">{{ pill_platforms_at_risk }}</span>platforms at risk</span>
          <span class="pill warn"><span class="pill-dot"></span><span class="pill-num">{{ pill_brand_exposures }}</span>brand exposures</span>
          <span class="pill"><span class="pill-dot"></span><span class="pill-num">{{ pill_defence_gaps }}</span>defence gaps</span>
        </div>
      </div>
    </div>

    <div class="meta-strip">
      <div class="meta-cell"><div class="meta-label">Prepared for</div><div class="meta-value">{{ org_name }}<span class="meta-sub">{{ org_locale }}</span></div></div>
      <div class="meta-cell"><div class="meta-label">Domain</div><div class="meta-value">{{ domain }}<span class="meta-sub">{{ subdomain_count }} subdomains observed</span></div></div>
      <div class="meta-cell"><div class="meta-label">Snapshot</div><div class="meta-value">{{ snapshot_date_pretty }}<span class="meta-sub">{{ quarter_label }}</span></div></div>
      <div class="meta-cell"><div class="meta-label">Corpus</div><div class="meta-value">320M domains<span class="meta-sub">Hourly refresh</span></div></div>
    </div>

    <div class="corpus">
      <div class="corpus-pulse"></div>
      <div class="corpus-text"><strong>Live</strong> — cross-referenced against 40+ threat feeds &middot; updated continuously</div>
      <div class="corpus-bar"></div>
    </div>
  </div>

  <div class="cover-footer">
    <span>Datazag Health Report · Confidential</span>
    <span class="right">Page 1 of {{ total_pages }}</span>
  </div>
</div>

{# ============ PAGE 2 — TOC ============ #}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Inside this report<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="toc-header">
    <div class="toc-eyebrow">A guided tour</div>
    <h2 class="toc-title">Ten sections, three kinds of section.</h2>
    <p class="toc-lede">Each section is one of three kinds. <strong>Context</strong> orients you. <strong>Findings</strong> tell you what we observed. <strong>Action</strong> tells you what to do about it. The report is designed to be read in order, but each section also stands alone &mdash; if you only have ten minutes, sections 01, 02 and 09 are the spine.</p>
  </div>
  <ol class="toc-list">
    {% for item in toc_items %}
    <li class="toc-item">
      <span class="toc-num">{{ "%02d"|format(loop.index) }}</span>
      <div class="toc-content">
        <h4>{{ item.title }}</h4>
        <p>{{ item.desc | safe }}</p>
      </div>
      <span class="toc-tag {{ item.kind }}"><span class="tag-dot"></span>{{ item.kind | capitalize }}</span>
    </li>
    {% endfor %}
  </ol>
  <div class="toc-callout">
    <div class="toc-callout-icon">★</div>
    <div>
      <h5>How to read this report</h5>
      <p>If you have <strong>ten minutes</strong>, read sections 01, 02 and 09. If you have <strong>thirty minutes</strong>, add 03 and 04 &mdash; the platform surface where most attacks now originate. The full report is designed for technical and non-technical readers in parallel: every section opens with plain-English context before the technical detail.</p>
    </div>
  </div>
  <div class="toc-spacer"></div>
  <div class="cover-footer">
    <span>Datazag Health Report · Confidential</span>
    <span class="right">Page 2 of {{ total_pages }}</span>
  </div>
</div>

{# ============ PAGE 3 — AT A GLANCE ============ #}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section 01 · At a glance<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section 01</span><span class="section-rule"></span><span class="section-tag">● Context</span></div>
    <h1 class="section-title-h1">At a glance.</h1>
    <p class="section-headline"><strong>{{ org_name }} sits at {{ grade.headline | lower }}.</strong> Trusted platform-impersonation activity is currently elevated against the platforms you depend on; brand-impersonation exposure is moderate but contained; your own outbound posture is the weakest of the three surfaces and the easiest to repair. Most of the work is in the next 90 days.</p>
  </div>
  <div class="grade-band">
    <div class="grade-band-letter">{{ grade.letter }}</div>
    <div class="grade-band-body">
      <div class="grade-band-scale">
        <div class="grade-scale-track"></div>
        <div class="grade-scale-marks">
          {% for _ in range(6) %}<span class="grade-scale-mark"></span>{% endfor %}
        </div>
        <div class="grade-scale-pin" style="left: {{ (grade.scale_position * 100) | round(1) }}%;"></div>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:9.5px;font-weight:700;color:var(--ink-4);letter-spacing:0.05em;padding:0 2px;">
        {% for L in ['A','B','C','D','E','F'] %}<span{% if L == grade.letter %} style="color:var(--ink);"{% endif %}>{{ L }}</span>{% endfor %}
      </div>
      <div class="grade-band-text" style="margin-top:4px;">Most {{ grade.letter }}-grade organisations move toward a higher grade within a quarter by completing the items in section 09. The grade reflects trusted-platform exposure (the active risk), brand exposure (the watchlist), and outbound posture (the fixable item).</div>
    </div>
  </div>
  <div class="scorecards">
    <div class="scorecard bad">
      <div class="scorecard-label"><span class="scorecard-icon">▲</span>Trusted platform impersonation</div>
      <div class="scorecard-state">Elevated</div>
      <div class="scorecard-text"><strong>{{ pill_platforms_at_risk }} of your detected platforms</strong> are being actively impersonated by attacker infrastructure issued in the last 30 days. <em>The active risk.</em></div>
    </div>
    <div class="scorecard warn">
      <div class="scorecard-label"><span class="scorecard-icon">◆</span>Brand impersonation</div>
      <div class="scorecard-state">Moderate</div>
      <div class="scorecard-text"><strong>{{ pill_brand_exposures }} lookalike domains</strong> targeting <code style="font-family:'JetBrains Mono',monospace;font-size:10px;background:rgba(15,23,42,0.05);padding:1px 4px;border-radius:3px;">{{ domain_root }}</code> observed in certificate logs. <em>The watchlist.</em></div>
    </div>
    <div class="scorecard neutral">
      <div class="scorecard-label"><span class="scorecard-icon">◉</span>Outbound posture</div>
      <div class="scorecard-state">{{ outbound_state }}</div>
      <div class="scorecard-text"><strong>{{ outbound_summary | safe }}</strong>. <em>The fixable item.</em></div>
    </div>
  </div>
  <div class="assessment-strip">
    <span class="assessment-strip-icon">i</span>
    <span><strong>First assessment.</strong> No quarter-on-quarter delta in this report. From the next snapshot onward, this strip will surface what changed since the last assessment &mdash; new platforms detected, posture changes, new lookalike registrations.</span>
  </div>
  <div class="priorities-header">
    <h3>Three things to address first.</h3>
    <span class="sub">One per surface — platform, brand, infrastructure.</span>
  </div>
  <div class="priority-list">
    {% for p in priorities %}
    <div class="priority-card">
      <div class="priority-num">{{ "%02d"|format(loop.index) }}</div>
      <div class="priority-body">
        <div class="priority-pills">
          <span class="pri-pill {{ p.severity }}">{{ p.severity_label }}</span>
          <span class="pri-pill {{ p.surface }}">{{ p.surface_glyph }} {{ p.surface_label }}</span>
        </div>
        <div class="priority-title">{{ p.title }}</div>
        <div class="priority-action">{{ p.action | safe }}</div>
        <div class="priority-why">{{ p.why }}</div>
      </div>
      <div class="priority-meta">
        <div class="priority-meta-row"><span class="priority-meta-key">Owner</span><span class="priority-meta-val">{{ p.owner }}</span></div>
        <div class="priority-meta-row"><span class="priority-meta-key">Effort</span><span class="priority-meta-val">{{ p.effort }}</span></div>
        <div class="priority-meta-row"><span class="priority-meta-key">When</span><span class="priority-meta-val">{{ p.when }}</span></div>
      </div>
    </div>
    {% endfor %}
  </div>
  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page 3 of {{ total_pages }}</span></div>
</div>

{# ============ PAGE 4 — WHY THIS MATTERS ============ #}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section 02 · Why this matters<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section 02</span><span class="section-rule"></span><span class="section-tag">● Context</span></div>
    <h1 class="section-title-h1">Why attackers prefer trusted platforms.</h1>
    <p class="section-headline">Imitating a single company gives an attacker access to that company&rsquo;s customers. <strong>Imitating a platform your staff already trusts gives them access to every company&rsquo;s staff.</strong> The asymmetry is the entire reason this report exists &mdash; and the reason it&rsquo;s structured around two impersonation surfaces rather than one.</p>
  </div>
  <div class="data-panel">
    <div class="data-panel-inner">
      <div class="data-panel-eyebrow">Datazag certificate-issuance observation · {{ research_month }}</div>
      <div class="data-panel-row">
        <div><span class="data-panel-pct">85&ndash;90%</span></div>
        <div class="data-panel-bar">
          <div class="data-panel-bar-fill">Trusted platforms · 85&ndash;90%</div>
          <div class="data-panel-bar-rest">Everything else · 10&ndash;15%</div>
        </div>
      </div>
      <p class="data-panel-claim">Of all suspicious certificate registrations Datazag observed in {{ research_month }}, <strong>between 85 and 90 per cent imitated a trusted technology platform</strong> &mdash; Microsoft 365, Google Workspace, Apple, DocuSign, Mailchimp, PayPal, Amazon, Cloudflare, and the rest of the platforms most companies log into every day. Single-company brand impersonation accounted for the remainder. One phishing kit imitating Microsoft 365 can be used against thousands of tenants; a kit imitating any single company only works against that company&rsquo;s customers. Attackers follow the volume.</p>
    </div>
  </div>
  <div class="surfaces-grid">
    <div class="surface-panel inbound">
      <div class="surface-eyebrow"><span class="surface-icon">▲</span>Surface 1 · Inbound</div>
      <h2 class="surface-title">Trusted platform impersonation</h2>
      <p class="surface-thesis">Attackers imitate the platforms your staff trusts, to capture credentials.</p>
      <div class="surface-attrs">
        <div class="surface-attr"><span class="surface-attr-key">Lure</span><span class="surface-attr-val">A trusted platform login or notification &mdash; Microsoft 365, Google Workspace, Mailchimp, DocuSign.</span></div>
        <div class="surface-attr"><span class="surface-attr-key">Target</span><span class="surface-attr-val"><strong>Your staff.</strong> The credentials they use every day.</span></div>
        <div class="surface-attr"><span class="surface-attr-key">Volume</span><span class="surface-attr-val"><span class="vol-badge">85&ndash;90% of observed activity</span></span></div>
        <div class="surface-attr"><span class="surface-attr-key">Defence</span><span class="surface-attr-val">Awareness of active campaigns, MFA enforcement on platform tenants, platform-side phish reporting.</span></div>
        <div class="surface-attr"><span class="surface-attr-key">In report</span><span class="surface-attr-val">Sections <strong>03</strong> &amp; <strong>04</strong> &mdash; your vendor footprint, then per-platform exposure.</span></div>
      </div>
    </div>
    <div class="surface-panel outbound">
      <div class="surface-eyebrow"><span class="surface-icon">◆</span>Surface 2 · Outbound</div>
      <h2 class="surface-title">Brand impersonation</h2>
      <p class="surface-thesis">Attackers imitate your brand, to get to your customers.</p>
      <div class="surface-attrs">
        <div class="surface-attr"><span class="surface-attr-key">Lure</span><span class="surface-attr-val">Your own domain, logo, brand language &mdash; lookalikes, typosquats, fraudulent certificates.</span></div>
        <div class="surface-attr"><span class="surface-attr-key">Target</span><span class="surface-attr-val"><strong>Your customers.</strong> Their trust in your name.</span></div>
        <div class="surface-attr"><span class="surface-attr-key">Volume</span><span class="surface-attr-val"><span class="vol-badge">10&ndash;15% of observed activity</span></span></div>
        <div class="surface-attr"><span class="surface-attr-key">Defence</span><span class="surface-attr-val">DMARC, SPF, BIMI, CAA, lookalike monitoring, takedown workflow.</span></div>
        <div class="surface-attr"><span class="surface-attr-key">In report</span><span class="surface-attr-val">Sections <strong>05</strong> &amp; <strong>06</strong> &mdash; brand exposure, then your outbound posture.</span></div>
      </div>
    </div>
  </div>
  <div class="causal-section">
    <div class="causal-header"><h3>How they connect.</h3><span class="sub">Trusted platform impersonation is often upstream of brand impersonation. The path below shows one common example &mdash; there are others.</span></div>
    <div class="causal-example-eyebrow">A Microsoft 365-led attack chain</div>
    <div class="causal-chain">
      <div class="causal-step start"><span class="causal-step-num">Step 1</span><span class="causal-step-title">Cloned M365 login</span><span class="causal-step-detail">Attacker registers a lookalike domain and sends a phishing email. Office manager clicks and enters credentials.</span></div>
      <div class="causal-arrow">→</div>
      <div class="causal-step"><span class="causal-step-num">Step 2</span><span class="causal-step-title">Tenant compromise</span><span class="causal-step-detail">Credentials work. Attacker is inside your real Microsoft 365 tenant.</span></div>
      <div class="causal-arrow">→</div>
      <div class="causal-step"><span class="causal-step-num">Step 3</span><span class="causal-step-title">Email from your domain</span><span class="causal-step-detail">Attacker sends a real email from <code style="font-family:'JetBrains Mono',monospace;font-size:9.5px;">@{{ domain }}</code>. DMARC, SPF and DKIM all pass.</span></div>
      <div class="causal-arrow">→</div>
      <div class="causal-step end"><span class="causal-step-num">Step 4</span><span class="causal-step-title">Customer fraud</span><span class="causal-step-detail">A genuine-looking 'updated invoice' lands in your customer&rsquo;s inbox. They pay an attacker bank account.</span></div>
    </div>
    <div class="causal-tags"><span class="tag-vendor">▲ Trusted platform impersonation</span><span class="tag-brand">◆ Brand impersonation</span></div>
  </div>
  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page 4 of {{ total_pages }}</span></div>
</div>

{# ============ PAGE 5 — VENDOR FOOTPRINT ============ #}
<div class="page light">
  <div class="topbar">
    {{ brand_block(light=True) }}
    <div class="topbar-right"><div class="topbar-id">Section 03 · Your vendor footprint<strong>{{ domain }}</strong></div></div>
  </div>
  <div class="section-id-bar">
    <div class="section-num-row"><span class="section-num">Section 03</span><span class="section-rule"></span><span class="section-tag" style="color:var(--cyan-deep);border-color:rgba(0,150,204,0.32);background:rgba(0,150,204,0.06);">● Findings</span></div>
    <h1 class="section-title-h1">Your stack, ordered by attacker preference.</h1>
    <p class="section-headline">Attackers don&rsquo;t imitate platforms at random. They imitate the ones that <em>work</em> &mdash; platforms with universal staff recognition, credentials that unlock other systems, or customer lists that monetise quickly. Below: <strong>the SaaS we detected in your stack</strong>, ordered by how often each platform is impersonated in our certificate-issuance observations.</p>
  </div>
  <div class="footprint-summary">
    <div class="footprint-stat"><div class="footprint-stat-num">{{ vendors | length }}</div><div class="footprint-stat-label">Platforms detected</div></div>
    <div class="footprint-stat"><div class="footprint-stat-num alert">{{ vendors_high_count }}</div><div class="footprint-stat-label">High desirability</div></div>
    <div class="footprint-stat"><div class="footprint-stat-num accent">{{ total_evidence_signals }}</div><div class="footprint-stat-label">Evidence signals</div></div>
    <div class="footprint-stat"><div class="footprint-stat-num">DNS, SPF, TXT</div><div class="footprint-stat-label">Detection sources</div></div>
  </div>

  <div class="top-vendors">
    {% for v in vendors_top %}
    <div class="vendor-card {{ v.tier }}">
      <div class="vendor-rank"><div class="vendor-rank-num">{{ loop.index }}</div><div class="vendor-rank-label">Rank</div></div>
      <div class="vendor-body">
        <h3 class="vendor-name">{{ v.name }}</h3>
        <p class="vendor-role">{{ v.role }}</p>
        <div class="vendor-evidence">
          {% for e in v.evidence %}<span class="vendor-evi"><span class="vendor-evi-key">{{ e.key }}</span>{{ e.val }}</span>{% endfor %}
        </div>
        <div class="vendor-quote"><strong>Why attackers prefer it:</strong> {{ v.why }}</div>
      </div>
      <div class="vendor-meta">
        <span class="vendor-desirability {{ v.tier }}"><span class="des-dot"></span>{{ v.tier_label }} desirability</span>
        <span class="vendor-evidence-count"><strong>{{ v.evidence | length }}</strong>signals</span>
      </div>
    </div>
    {% endfor %}
  </div>

  {% if vendors_rest %}
  <div class="vendor-table-wrap">
    <div class="vendor-table-header">Remaining platforms <span>&middot; ranks {{ vendors_top | length + 1 }}–{{ vendors | length }} by attacker desirability</span></div>
    <table class="vendor-table">
      <thead><tr><th>Rank</th><th>Platform</th><th>Role in your stack</th><th>Evidence</th><th class="des-cell">Desirability</th></tr></thead>
      <tbody>
        {% for v in vendors_rest %}
        <tr>
          <td class="rank-cell">{{ vendors_top | length + loop.index }}</td>
          <td class="name-cell">{{ v.name }}</td>
          <td class="role-cell">{{ v.role }}</td>
          <td class="evi-cell">{{ v.evidence_short }}</td>
          <td class="des-cell"><span class="des-mini {{ v.tier_short }}"><span class="des-dot"></span>{{ v.tier_label }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <div class="next-section-cta">
    <div class="next-section-cta-text"><strong>The next section</strong> shows the active attacker infrastructure currently imitating each of your top three trusted platforms &mdash; what those campaigns look like and what your staff are likely to encounter.</div>
    <div class="next-section-cta-arrow">Section 04 →</div>
  </div>

  <div class="toc-spacer"></div>
  <div class="cover-footer"><span>Datazag Health Report · Confidential</span><span class="right">Page 5 of {{ total_pages }}</span></div>
</div>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

class HealthReportRenderer(BaseRenderer):
    """
    Master Trusted-Platform-Impersonation Health Report (v8 design).

    Inherits all data-attribute binding from BaseRenderer; overrides render
    methods to produce the new multi-page A4 design.
    """

    AUDIENCE = "health"
    REPORT_TITLE = "Datazag Health Report"
    TOTAL_PAGES = 5  # placeholder; will grow to ~24 once all sections exist

    # ----- Public API ------------------------------------------------------

    def render(self, fmt: str = "html", brand: BrandConfig | None = None) -> str:
        if fmt == "html":     return self.to_html(brand=brand)
        if fmt == "json":     return json.dumps(self.to_dict(), indent=2, default=str)
        if fmt == "markdown": return self.to_markdown(brand=brand)
        raise ValueError(f"Unknown format: {fmt}")

    def to_dict(self) -> dict:
        """Structured representation of what's rendered into the HTML.
        Useful for debugging and for downstream JSON consumers."""
        return {
            "report_type":   "trusted_platform_health_report",
            "version":       "v8",
            "domain":        self.domain,
            "generated_at":  self.o["generated_at"],
            "trust_grade":   {
                "letter":      self._grade.letter,
                "headline":    self._grade.headline,
                "description": self._grade.description,
                "score":       self.display_score,
            },
            "platform_footprint": self._build_vendor_list(),
            "surface_counts": {
                "platforms_at_risk": self._pill_platforms_at_risk(),  # TODO(section-04-data)
                "brand_exposures":   self._pill_brand_exposures(),    # TODO(brand-pipeline)
                "defence_gaps":      self._pill_defence_gaps(),
            },
            "priorities":     self._build_priorities(),
            "narrative":      self.narrative,
        }

    def to_html(self, brand: BrandConfig | None = None) -> str:
        brand = brand or BrandConfig.default()
        ctx = self._build_context(brand)
        template = _jinja_env.from_string(HEALTH_REPORT_TEMPLATE)
        return template.render(**ctx)

    def to_markdown(self, brand: BrandConfig | None = None) -> str:
        """Markdown variant for grep/diff workflows. Minimal — the HTML is the
        canonical output. Markdown carries the structured findings only."""
        g = self._grade
        lines = [
            f"# Datazag Health Report — {self.domain}",
            f"",
            f"**Trust Grade:** {g.letter} — {g.headline}",
            f"**Score:** {self.display_score}/100",
            f"**Snapshot:** {self.o['generated_at'][:10]}",
            "",
            "## Platform footprint (ordered by attacker desirability)",
            "",
        ]
        for i, v in enumerate(self._build_vendor_list(), 1):
            lines.append(f"{i}. **{v['name']}** — {v['role']} ({v['tier_label']} desirability)")
        lines.append("")
        lines.append("## Three things to address first")
        lines.append("")
        for i, p in enumerate(self._build_priorities(), 1):
            lines.append(f"{i}. **{p['title']}** ({p['severity_label']} · {p['surface_label']})")
            lines.append(f"   {p['action']}")
            lines.append("")
        return "\n".join(lines)

    # ----- Cached lazy properties ------------------------------------------

    @property
    def _grade(self) -> TrustGrade:
        if not hasattr(self, "_grade_cache"):
            self._grade_cache = score_to_grade(self.display_score)
        return self._grade_cache

    # ----- Context assembly ------------------------------------------------

    def _build_context(self, brand: BrandConfig) -> dict[str, Any]:
        gen_iso = self.o.get("generated_at", "")
        snapshot_date = gen_iso[:10] if gen_iso else ""
        snapshot_pretty = self._pretty_date(snapshot_date)
        quarter = self._quarter_label(snapshot_date)

        vendors = self._build_vendor_list()
        vendors_top = vendors[:3]
        vendors_rest = vendors[3:]

        return {
            # Identity
            "domain":            self.domain,
            "domain_root":       self.domain.split(".")[0],
            "org_name":          self._org_display_name(),
            "org_locale":        self._org_locale(),  # TODO(rdap-locale)
            # Snapshot meta
            "snapshot_date_pretty": snapshot_pretty,
            "quarter_label":     quarter,
            "research_month":    "April 2026",  # TODO(research-publishing): pull from config when published
            "subdomain_count":   len(self.subdomains),
            "total_pages":       self.TOTAL_PAGES,
            # Trust grade
            "grade":             self._grade,
            # Surface pill counts
            "pill_platforms_at_risk": self._pill_platforms_at_risk(),
            "pill_brand_exposures":   self._pill_brand_exposures(),
            "pill_defence_gaps":      self._pill_defence_gaps(),
            # At-a-glance scorecards
            "outbound_state":    self._outbound_state(),
            "outbound_summary":  self._outbound_summary(),
            # Priorities
            "priorities":        self._build_priorities(),
            # Vendor footprint
            "vendors":              vendors,
            "vendors_top":          vendors_top,
            "vendors_rest":         vendors_rest,
            "vendors_high_count":   sum(1 for v in vendors if v["tier"] == "high"),
            "total_evidence_signals": sum(len(v["evidence"]) for v in vendors),
            # TOC
            "toc_items":         self._toc_items(),
        }

    # ----- Display helpers -------------------------------------------------

    def _org_display_name(self) -> str:
        rdap_org = (self.rdap or {}).get("registrant_name") or ""
        if rdap_org:
            return rdap_org
        # Fallback: prettify the domain root
        return self.domain.split(".")[0].replace("-", " ").title()

    def _org_locale(self) -> str:
        # TODO(rdap-locale): registrant country + industry classification
        country = (self.rdap or {}).get("registrant_country", "") or ""
        return country if country else "—"

    @staticmethod
    def _pretty_date(iso_date: str) -> str:
        try:
            from datetime import datetime
            dt = datetime.strptime(iso_date, "%Y-%m-%d")
            return dt.strftime("%d %b %Y")
        except (ValueError, TypeError):
            return iso_date or "—"

    @staticmethod
    def _quarter_label(iso_date: str) -> str:
        try:
            from datetime import datetime
            dt = datetime.strptime(iso_date, "%Y-%m-%d")
            q = (dt.month - 1) // 3 + 1
            return f"Q{q} {dt.year}"
        except (ValueError, TypeError):
            return "—"

    # ----- Surface counts (TODO placeholders) ------------------------------

    def _pill_platforms_at_risk(self) -> int:
        """TODO(section-04-data): currently a placeholder. Once the AII pipeline
        produces per-platform exposure (active attacker certs imitating each
        detected platform), replace with the real count."""
        return min(len(self._build_vendor_list()), 4)

    def _pill_brand_exposures(self) -> int:
        """TODO(brand-pipeline): lookalike-domain detection for the customer's
        own brand. Detection logic exists upstream but isn't surfaced into the
        output dict yet. Placeholder: 0 if no signal, else heuristic."""
        return 0

    def _pill_defence_gaps(self) -> int:
        """Defence gaps = critical+high posture findings. Real value, no placeholder."""
        return sum(1 for f in self.findings if f.get("severity") in ("critical", "high"))

    def _outbound_state(self) -> str:
        if self.ea.get("is_spoofable"):
            sev = self.ea.get("spoofing_severity", "high")
            return {"high": "Weak", "medium": "Mixed"}.get(sev, "Mixed")
        return "Configured"

    def _outbound_summary(self) -> str:
        ea = self.ea
        bits = []
        dmarc = ea.get("dmarc_policy") or "missing"
        bits.append(f"DMARC at p={dmarc}")
        if not self.flags.get("has_caa"):
            bits.append("no CAA")
        if "BIMI" in (ea.get("missing_layers") or []):
            bits.append("no BIMI")
        return ", ".join(bits) + (". Your domain remains spoofable" if ea.get("is_spoofable") else "")

    # ----- Priorities ------------------------------------------------------

    def _build_priorities(self) -> list[dict[str, Any]]:
        """Three priorities spanning the three surfaces.

        TODO(section-04-data): the platform-priority is currently synthesised
        from the highest-tier detected vendor. Once per-platform exposure data
        exists, this will reference an actual active campaign."""
        priorities = []

        # 1. Platform priority — synthesised from top vendor
        vendors = self._build_vendor_list()
        if vendors:
            top = vendors[0]
            priorities.append({
                "severity": "crit",
                "severity_label": "Critical",
                "surface": "vendor",
                "surface_label": "Platform",
                "surface_glyph": "▲",
                "title": f"Active impersonation campaign against {top['name']} likely",
                "action": (f"Brief staff who use the {top['name']} tenant on the active phishing wave; "
                           "verify MFA enforcement on the tenant and review session timeouts."),
                "why": (f"{top['name']} is the most-impersonated trusted platform in our certificate-issuance "
                        "data. Tenants matching your profile are routinely targeted."),
                "owner": "Marketing/IT ops",
                "effort": "< 1 day",
                "when": "Fortnight",
            })

        # 2. Brand priority — DMARC if spoofable
        if self.ea.get("is_spoofable") and self.ea.get("dmarc_policy") in (None, "none", ""):
            priorities.append({
                "severity": "high",
                "severity_label": "High",
                "surface": "brand",
                "surface_label": "Brand",
                "surface_glyph": "◆",
                "title": "Move DMARC from p=none to p=quarantine",
                "action": ("Escalate the existing p=none policy to p=quarantine after a 30-day reporting "
                           "validation window confirming all legitimate senders are authenticated."),
                "why": (f"Your @{self.domain} is currently spoofable by anyone. Brand-impersonation campaigns "
                        "against your customers can be sent from real-looking addresses with no infrastructure cost."),
                "owner": "DNS / email",
                "effort": "30 min",
                "when": "Quarter",
            })

        # 3. Infra priority — top critical/high posture finding
        infra_finding = next(
            (f for f in self.findings if f.get("severity") in ("critical", "high")),
            None,
        )
        if infra_finding:
            title = infra_finding.get("title") or infra_finding.get("finding", "Critical posture finding")
            action = infra_finding.get("remediation") or infra_finding.get("fix") or "See full finding detail."
            priorities.append({
                "severity": "crit" if infra_finding.get("severity") == "critical" else "high",
                "severity_label": (infra_finding.get("severity") or "high").capitalize(),
                "surface": "infra",
                "surface_label": "Infra",
                "surface_glyph": "◉",
                "title": title[:80],
                "action": action[:200],
                "why": (infra_finding.get("detail") or infra_finding.get("description") or "")[:200],
                "owner": "Infrastructure",
                "effort": "varies",
                "when": "Fortnight",
            })

        return priorities[:3]

    # ----- Vendor footprint ------------------------------------------------

    def _build_vendor_list(self) -> list[dict[str, Any]]:
        """Detected platforms ranked by attacker desirability.

        Sources:
        - txt_intelligence['saas_platforms'/'identity_providers'/etc.] from the
          existing technographics module
        - mx_provider, isp from infrastructure
        - SPF includes parsed from dns_records['txt']

        TODO(technographics-2.0): the technographics module needs updating to
        emit a per-vendor record with structured evidence (rather than just a
        list of names). When that lands, this method becomes a pass-through.
        """
        ti = self.txt_intel or {}
        evidence_map: dict[str, list[dict[str, str]]] = {}

        # Categorised platforms from txt_intelligence
        for category in ("saas_platforms", "identity_providers", "payment_processors",
                         "ai_infrastructure", "security_tooling", "email_marketing"):
            for svc in ti.get(category, []):
                key = self._normalise_vendor_name(svc)
                evidence_map.setdefault(key, []).append({"key": "TXT", "val": category})

        # MX provider
        mx_provider = self.infra.get("mx_provider")
        if mx_provider:
            key = self._normalise_vendor_name(mx_provider)
            mx_records = self.dns.get("mx", []) or []
            mx_host = (mx_records[0]["host"] if mx_records and isinstance(mx_records[0], dict)
                       else (mx_records[0] if mx_records else mx_provider))
            evidence_map.setdefault(key, []).append({"key": "MX", "val": str(mx_host)})

        # SPF includes
        for txt in self.dns.get("txt", []) or []:
            if isinstance(txt, str) and txt.startswith("v=spf1"):
                for token in txt.split():
                    if token.startswith("include:"):
                        host = token.split(":", 1)[1]
                        key = self._spf_to_vendor_key(host)
                        if key:
                            evidence_map.setdefault(key, []).append({"key": "SPF", "val": host})

        # Build vendor records, applying desirability lookup
        vendors = []
        for name_key, evidence in evidence_map.items():
            entry = self._lookup_platform(name_key)
            tier = entry["tier"]
            tier_label = {"high": "High", "med-high": "Med-high", "med": "Med", "low": "Low"}[tier]
            tier_short = {"high": "med", "med-high": "med", "med": "med", "low": "low"}[tier]
            vendors.append({
                "name":             self._display_name(name_key),
                "name_key":         name_key,
                "role":             entry["role"],
                "why":              entry["why"],
                "tier":             tier,
                "tier_label":       tier_label,
                "tier_short":       tier_short,
                "weight":           entry["weight"],
                "evidence":         evidence,
                "evidence_short":   ", ".join(f"{e['key']}: {e['val']}" for e in evidence[:2]),
            })

        vendors.sort(key=lambda v: -v["weight"])
        return vendors

    @staticmethod
    def _normalise_vendor_name(raw: str) -> str:
        """Lowercase, strip, collapse common aliases."""
        s = (raw or "").strip().lower()
        if "outlook" in s or "office 365" in s or "ms 365" in s:
            return "microsoft 365"
        if "google" in s and ("workspace" in s or "search console" in s):
            return "google workspace"
        if "google" in s:
            return "google workspace"
        if "mailchimp" in s:
            return "mailchimp"
        if "apple" in s:
            return "apple"
        if "zoho" in s:
            return "zoho"
        if "citrix" in s:
            return "citrix"
        if "mailgun" in s:
            return "mailgun"
        if "emailsignatures" in s.replace(" ", "") or "email signatures 365" in s:
            return "email signatures"
        return s

    @staticmethod
    def _spf_to_vendor_key(spf_host: str) -> str | None:
        h = spf_host.lower()
        if "outlook" in h or "protection.outlook" in h:
            return "microsoft 365"
        if "google.com" in h or "_spf.google" in h:
            return "google workspace"
        if "mcsv.net" in h or "mailchimp" in h:
            return "mailchimp"
        if "mailgun" in h:
            return "mailgun"
        if "zoho" in h:
            return "zoho"
        if "emailsignatures365" in h:
            return "email signatures"
        return None

    @staticmethod
    def _lookup_platform(name_key: str) -> dict[str, Any]:
        for k, v in PLATFORM_DESIRABILITY.items():
            if k in name_key or name_key in k:
                return v
        return DEFAULT_PLATFORM_ENTRY

    @staticmethod
    def _display_name(name_key: str) -> str:
        return {
            "microsoft 365":    "Microsoft 365",
            "google workspace": "Google Workspace",
            "mailchimp":        "Mailchimp",
            "apple":            "Apple",
            "zoho":             "Zoho",
            "citrix":           "Citrix",
            "mailgun":          "Mailgun",
            "email signatures": "Email Signatures 365",
        }.get(name_key, name_key.title())

    # ----- TOC -------------------------------------------------------------

    @staticmethod
    def _toc_items() -> list[dict[str, str]]:
        return [
            {"title": "At-a-glance", "kind": "context",
             "desc": "Your overall Trust Grade, what changed since last quarter, and the three things to address first."},
            {"title": "Why this matters", "kind": "context",
             "desc": "Why 85&ndash;90% of impersonation attacks target trusted technology platforms, and how to read both the inbound (platform) and outbound (brand) sides of impersonation exposure."},
            {"title": "Your vendor footprint", "kind": "findings",
             "desc": "The technology platforms your stack actually depends on, ordered by attacker desirability rather than internal priority."},
            {"title": "Trusted platform-impersonation exposure", "kind": "findings",
             "desc": "For each detected platform: the active attacker infrastructure imitating it, recently observed lures, and what those campaigns look like to your staff. <em>Highest-volume threat surface.</em>"},
            {"title": "Brand-impersonation exposure", "kind": "findings",
             "desc": "Lookalike domains, suspicious certificates, and typosquats targeting your own brand &mdash; the campaigns aimed at your customers, not your staff."},
            {"title": "Outbound posture", "kind": "findings",
             "desc": "Your domain authentication: DMARC, SPF, BIMI, CAA, MTA-STS. The technical defences that constrain how far a brand-impersonation campaign can travel."},
            {"title": "Hidden infrastructure", "kind": "findings",
             "desc": "Forgotten subdomains, dormant services, certificate hygiene across your wider estate &mdash; the assets attackers find that you may not know exist."},
            {"title": "Twelve-month timeline", "kind": "findings",
             "desc": "Every infrastructure change observed in the past year &mdash; including any that look unusual against your baseline."},
            {"title": "Your remediation roadmap", "kind": "action",
             "desc": "What to address this fortnight, this quarter, and this year &mdash; with effort estimates and ownership recommendations against your current Trust Grade."},
            {"title": "Glossary &amp; methodology", "kind": "context",
             "desc": "Plain-English definitions of every technical term used, plus how the evidence behind each finding was gathered."},
        ]
