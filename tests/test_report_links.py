"""Shipped-artefact link guards.

Reports are emailed and forwarded as standalone HTML/PDF — every CTA must be an
absolute URL, never a placeholder. The free report's page-5 seam must land on
the /reports Cross-Estate anchor with the src attribution param (WU19; WU20
re-points it at the scope flow when that ships).
"""
from estatereport.renderer import ESTATE_TEMPLATE, UPGRADE_CONTACT_URL
from freereport.renderer import FREE_REPORT_TEMPLATE, SEAM_CROSS_ESTATE_URL, WATCH_URL


def test_no_placeholder_links_in_templates():
    assert 'href="#"' not in FREE_REPORT_TEMPLATE
    assert 'href="#"' not in ESTATE_TEMPLATE


def test_seam_lands_on_cross_estate_anchor():
    assert SEAM_CROSS_ESTATE_URL == "https://www.datazag.com/reports?src=free-report#cross-estate"
    assert f'href="{SEAM_CROSS_ESTATE_URL}"' in FREE_REPORT_TEMPLATE


def test_cta_urls_are_absolute():
    for url, template in (
        (WATCH_URL, FREE_REPORT_TEMPLATE),
        (UPGRADE_CONTACT_URL, ESTATE_TEMPLATE),
    ):
        assert url.startswith("https://"), url
        assert f'href="{url}"' in template
