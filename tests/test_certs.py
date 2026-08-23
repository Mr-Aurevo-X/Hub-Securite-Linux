# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core import certs


def test_parse_openssl_and_not_after() -> None:
    parsed = certs.parse_openssl_text(
        "subject=CN = demo\nissuer=CN = ca\nnotAfter=Jan  1 00:00:00 2099 GMT\n"
    )
    assert parsed["subject"] == "CN = demo"
    assert parsed["issuer"] == "CN = ca"
    expiry = certs.parse_not_after(parsed["not_after"])
    assert expiry is not None
    assert expiry.year == 2099
    assert expiry.tzinfo == timezone.utc


def test_parse_expired() -> None:
    expiry = certs.parse_not_after("Jan 1 00:00:00 2020 GMT")
    assert expiry is not None
    assert expiry < datetime.now(timezone.utc)


def test_inventory_uses_openssl(tmp_path: Path, monkeypatch) -> None:
    pem = tmp_path / "demo.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", encoding="utf-8")

    class _Out:
        returncode = 0
        stdout = "subject=CN = demo\nissuer=CN = ca\nnotAfter=Jan  1 00:00:00 2099 GMT\n"

    monkeypatch.setattr(certs.host, "which", lambda name: "/usr/bin/openssl" if name == "openssl" else None)
    monkeypatch.setattr(certs.host, "run", lambda *a, **k: _Out())
    monkeypatch.setattr(certs, "nss_store_paths", lambda: [])
    report = certs.inventory([tmp_path])
    assert report["count"] == 1
    assert report["certs"][0]["subject"] == "CN = demo"
    assert report["certs"][0]["severity"] == "ok"


def test_html_and_csv_standalone() -> None:
    report = {
        "generated_at": "2026-08-23 20:00:00",
        "warn": 1,
        "count": 1,
        "certs": [
            {
                "subject": '<script>x</script>',
                "issuer": "ca",
                "not_after": "Jan 1 00:00:00 2020 GMT",
                "days_left": -10,
                "severity": "warn",
                "path": "/tmp/demo.pem",
            }
        ],
    }
    html = certs.build_html(report)
    assert "<script>x" not in html
    assert "&lt;script&gt;" in html
    assert "http://" not in html
    assert "https://" not in html
    assert "src=" not in html.lower()
    csv_text = certs.build_csv(report)
    assert "ca" in csv_text
    assert "/tmp/demo.pem" in csv_text
