from models import SessionLocal, Finding, Scan, init_db


init_db()

db = SessionLocal()

try:
    # Add a demo scan
    scan = Scan(
        target_url="http://127.0.0.1:5001",
        scan_name="Local Demo Scan",
        status="Completed"
    )

    db.add(scan)

    # Add demo findings
    findings = [
        Finding(
            vulnerability="Missing Security Header",
            severity="HIGH",
            url="http://127.0.0.1:5001",
            description="A recommended security header is missing.",
            status="Open"
        ),
        Finding(
            vulnerability="Potential XSS Indicator",
            severity="MEDIUM",
            url="http://127.0.0.1:5001/search",
            description="A potential client-side script indicator was detected.",
            status="Open"
        ),
        Finding(
            vulnerability="CSRF Protection Review",
            severity="MEDIUM",
            url="http://127.0.0.1:5001/login",
            description="A form should be reviewed for CSRF protection.",
            status="Open"
        ),
        Finding(
            vulnerability="Information Disclosure",
            severity="LOW",
            url="http://127.0.0.1:5001",
            description="The application exposes potentially useful informational data.",
            status="Open"
        ),
        Finding(
            vulnerability="Missing Content Security Policy",
            severity="CRITICAL",
            url="http://127.0.0.1:5001",
            description="Content Security Policy should be reviewed and configured.",
            status="Open"
        )
    ]

    db.add_all(findings)
    db.commit()

    print("Demo scan and findings inserted successfully.")

finally:
    db.close()