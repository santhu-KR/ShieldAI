from flask import Flask, jsonify, request
from flask_cors import CORS
from sqlalchemy import func
import threading

from models import (
    SessionLocal,
    Finding,
    Scan,
    init_db,
)

from scanner.validator import validate_target_url
from scanner.safe_scanner import scan_target


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

CORS(app)

init_db()


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def home():
    return jsonify({
        "name": "ShieldAI",
        "message": "Web Application Penetration Testing Toolkit API",
        "status": "running"
    })


# ============================================================
# HEALTH
# ============================================================

@app.get("/api/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "ShieldAI Backend",
        "version": "1.0.0"
    })


# ============================================================
# DASHBOARD
# ============================================================

@app.get("/api/dashboard")
def dashboard():

    db = SessionLocal()

    try:

        # ----------------------------------------------------
        # FINDING COUNTS
        # ----------------------------------------------------

        critical = (
            db.query(Finding)
            .filter(
                func.upper(Finding.severity) == "CRITICAL"
            )
            .count()
        )

        high = (
            db.query(Finding)
            .filter(
                func.upper(Finding.severity) == "HIGH"
            )
            .count()
        )

        medium = (
            db.query(Finding)
            .filter(
                func.upper(Finding.severity) == "MEDIUM"
            )
            .count()
        )

        low = (
            db.query(Finding)
            .filter(
                func.upper(Finding.severity) == "LOW"
            )
            .count()
        )

        total = (
            critical +
            high +
            medium +
            low
        )

        # ----------------------------------------------------
        # SCAN STATUS
        # ----------------------------------------------------

        completed = (
            db.query(Scan)
            .filter(
                func.upper(Scan.status) == "COMPLETED"
            )
            .count()
        )

        running = (
            db.query(Scan)
            .filter(
                func.upper(Scan.status) == "RUNNING"
            )
            .count()
        )

        queued = (
            db.query(Scan)
            .filter(
                func.upper(Scan.status) == "QUEUED"
            )
            .count()
        )

        # ----------------------------------------------------
        # RECENT FINDINGS
        # ----------------------------------------------------

        recent_records = (
            db.query(Finding)
            .order_by(
                Finding.created_at.desc()
            )
            .limit(5)
            .all()
        )

        recent_findings = []

        for finding in recent_records:

            recent_findings.append({
                "id":
                    finding.id,

                "scan_id":
                    finding.scan_id,

                "vulnerability":
                    finding.vulnerability,

                "severity":
                    finding.severity,

                "url":
                    finding.url,

                "description":
                    finding.description,

                "status":
                    finding.status,

                "created_at":
                    finding.created_at.isoformat()
                    if finding.created_at
                    else None
            })

        # ----------------------------------------------------
        # TOP VULNERABILITIES
        # ----------------------------------------------------

        grouped_rows = (
            db.query(
                Finding.vulnerability,
                Finding.severity,
                func.count(Finding.id)
            )
            .group_by(
                Finding.vulnerability,
                Finding.severity
            )
            .order_by(
                func.count(Finding.id).desc()
            )
            .limit(5)
            .all()
        )

        top_vulnerabilities = []

        for name, severity, count in grouped_rows:

            top_vulnerabilities.append({
                "name":
                    name,

                "severity":
                    severity,

                "count":
                    count
            })

        # ----------------------------------------------------
        # FINDINGS TREND
        # ----------------------------------------------------

        recent_scans = (
            db.query(Scan)
            .order_by(
                Scan.created_at.desc()
            )
            .limit(7)
            .all()
        )

        findings_trend = []

        for scan in reversed(recent_scans):

            scan_findings = (
                db.query(Finding)
                .filter(
                    Finding.scan_id == scan.id
                )
                .count()
            )

            findings_trend.append({
                "scan_id":
                    scan.id,

                "scan_name":
                    scan.scan_name,

                "findings":
                    scan_findings,

                "created_at":
                    scan.created_at.isoformat()
                    if scan.created_at
                    else None
            })

        # ----------------------------------------------------
        # ENDPOINT COVERAGE
        # ----------------------------------------------------

        endpoint_rows = (
            db.query(Finding.url)
            .filter(
                Finding.url.isnot(None)
            )
            .distinct()
            .all()
        )

        discovered = len(endpoint_rows)

        scanned = discovered

        pending = 0

        # ----------------------------------------------------
        # RESPONSE
        # ----------------------------------------------------

        return jsonify({

            "critical":
                critical,

            "high":
                high,

            "medium":
                medium,

            "low":
                low,

            "total":
                total,

            "scan_status": {

                "completed":
                    completed,

                "running":
                    running,

                "queued":
                    queued
            },

            "endpoint_coverage": {

                "discovered":
                    discovered,

                "scanned":
                    scanned,

                "pending":
                    pending
            },

            "recent_findings":
                recent_findings,

            "top_vulnerabilities":
                top_vulnerabilities,

            "findings_trend":
                findings_trend

        })

    finally:

        db.close()


# ============================================================
# CREATE NEW SCAN
# ============================================================

@app.post("/api/scans")
def create_scan():

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    target_url = (
        data.get(
            "target_url",
            ""
        )
        .strip()
    )

    scan_name = (
        data.get(
            "scan_name",
            "ShieldAI Scan"
        )
        .strip()
    )

    # --------------------------------------------------------
    # VALIDATE TARGET
    # --------------------------------------------------------

    valid, result = validate_target_url(
        target_url
    )

    if not valid:

        return jsonify({
            "success": False,
            "error": result
        }), 400

    # --------------------------------------------------------
    # CREATE SCAN
    # --------------------------------------------------------

    db = SessionLocal()

    try:

        scan = Scan(
            target_url=result,
            scan_name=scan_name,
            status="Queued"
        )

        db.add(scan)

        db.commit()

        db.refresh(scan)

        scan_id = scan.id

        saved_target_url = scan.target_url

        print(
            f"[ShieldAI] Scan #{scan_id} queued: "
            f"{saved_target_url}"
        )

    finally:

        db.close()

    # --------------------------------------------------------
    # START BACKGROUND SCAN
    # --------------------------------------------------------

    thread = threading.Thread(
        target=run_scan,
        args=(
            scan_id,
            saved_target_url
        ),
        daemon=True
    )

    thread.start()

    print(
        f"[ShieldAI] Scan #{scan_id} "
        f"background thread started"
    )

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return jsonify({

        "success":
            True,

        "message":
            "Scan created successfully.",

        "scan": {

            "id":
                scan_id,

            "target_url":
                saved_target_url,

            "scan_name":
                scan_name,

            "status":
                "Queued"
        }

    }), 201


# ============================================================
# GET ALL SCANS
# ============================================================

@app.get("/api/scans")
def get_scans():

    db = SessionLocal()

    try:

        scans = (
            db.query(Scan)
            .order_by(
                Scan.created_at.desc()
            )
            .all()
        )

        result = []

        for scan in scans:

            result.append({

                "id":
                    scan.id,

                "target_url":
                    scan.target_url,

                "scan_name":
                    scan.scan_name,

                "status":
                    scan.status,

                "created_at":
                    scan.created_at.isoformat()
                    if scan.created_at
                    else None
            })

        return jsonify({

            "success":
                True,

            "scans":
                result

        })

    finally:

        db.close()


# ============================================================
# GET SINGLE SCAN
# ============================================================

@app.get("/api/scans/<int:scan_id>")
def get_scan(scan_id):

    db = SessionLocal()

    try:

        scan = (
            db.query(Scan)
            .filter(
                Scan.id == scan_id
            )
            .first()
        )

        if not scan:

            return jsonify({

                "success":
                    False,

                "error":
                    "Scan not found."

            }), 404

        return jsonify({

            "success":
                True,

            "scan": {

                "id":
                    scan.id,

                "target_url":
                    scan.target_url,

                "scan_name":
                    scan.scan_name,

                "status":
                    scan.status,

                "created_at":
                    scan.created_at.isoformat()
                    if scan.created_at
                    else None
            }

        })

    finally:

        db.close()


# ============================================================
# GET ALL FINDINGS
# ============================================================

@app.get("/api/findings")
def get_findings():

    db = SessionLocal()

    try:

        findings = (
            db.query(Finding)
            .order_by(
                Finding.created_at.desc()
            )
            .all()
        )

        result = []

        for finding in findings:

            result.append({

                "id":
                    finding.id,

                "scan_id":
                    finding.scan_id,

                "vulnerability":
                    finding.vulnerability,

                "severity":
                    finding.severity,

                "url":
                    finding.url,

                "description":
                    finding.description,

                "status":
                    finding.status,

                "created_at":
                    finding.created_at.isoformat()
                    if finding.created_at
                    else None
            })

        return jsonify({

            "success":
                True,

            "findings":
                result

        })

    finally:

        db.close()


# ============================================================
# GET FINDINGS FOR SPECIFIC SCAN
# ============================================================

@app.get("/api/scans/<int:scan_id>/findings")
def get_scan_findings(scan_id):

    db = SessionLocal()

    try:

        scan = (
            db.query(Scan)
            .filter(
                Scan.id == scan_id
            )
            .first()
        )

        if not scan:

            return jsonify({

                "success":
                    False,

                "error":
                    "Scan not found."

            }), 404

        findings = (
            db.query(Finding)
            .filter(
                Finding.scan_id == scan_id
            )
            .order_by(
                Finding.created_at.desc()
            )
            .all()
        )

        result = []

        for finding in findings:

            result.append({

                "id":
                    finding.id,

                "scan_id":
                    finding.scan_id,

                "vulnerability":
                    finding.vulnerability,

                "severity":
                    finding.severity,

                "url":
                    finding.url,

                "description":
                    finding.description,

                "status":
                    finding.status,

                "created_at":
                    finding.created_at.isoformat()
                    if finding.created_at
                    else None
            })

        return jsonify({

            "success":
                True,

            "scan": {

                "id":
                    scan.id,

                "target_url":
                    scan.target_url,

                "scan_name":
                    scan.scan_name,

                "status":
                    scan.status,

                "created_at":
                    scan.created_at.isoformat()
                    if scan.created_at
                    else None
            },

            "findings":
                result
        })

    finally:

        db.close()


# ============================================================
# BACKGROUND SCANNER
# ============================================================

def run_scan(scan_id, target_url):

    db = SessionLocal()

    try:

        scan = (
            db.query(Scan)
            .filter(
                Scan.id == scan_id
            )
            .first()
        )

        if not scan:

            print(
                f"[ShieldAI] Scan #{scan_id} "
                f"not found"
            )

            return

        # ----------------------------------------------------
        # RUNNING
        # ----------------------------------------------------

        scan.status = "Running"

        db.commit()

        print(
            f"[ShieldAI] Starting scan "
            f"#{scan_id}: {target_url}"
        )

        # ----------------------------------------------------
        # SAFE SCANNER
        # ----------------------------------------------------

        result = scan_target(
            target_url
        )

        # ----------------------------------------------------
        # FAILED
        # ----------------------------------------------------

        if not result.get(
            "success",
            False
        ):

            scan.status = "Failed"

            db.commit()

            print(
                f"[ShieldAI] Scan "
                f"#{scan_id} failed: "
                f"{result.get('error')}"
            )

            return

        # ----------------------------------------------------
        # FINDINGS
        # ----------------------------------------------------

        findings = result.get(
            "findings",
            []
        )

        # ----------------------------------------------------
        # SAVE FINDINGS
        # ----------------------------------------------------

        for item in findings:

            finding = Finding(

                scan_id=
                    scan_id,

                vulnerability=
                    item.get(
                        "vulnerability",
                        "Unknown"
                    ),

                severity=
                    item.get(
                        "severity",
                        "LOW"
                    ),

                url=
                    item.get(
                        "url",
                        target_url
                    ),

                description=
                    item.get(
                        "description",
                        ""
                    ),

                status=
                    item.get(
                        "status",
                        "Open"
                    )
            )

            db.add(finding)

        # ----------------------------------------------------
        # COMPLETED
        # ----------------------------------------------------

        scan.status = "Completed"

        db.commit()

        print(
            f"[ShieldAI] Scan "
            f"#{scan_id} completed. "
            f"Findings: {len(findings)}"
        )

    except Exception as error:

        print(
            f"[ShieldAI] Scan "
            f"#{scan_id} error: "
            f"{error}"
        )

        try:

            scan = (
                db.query(Scan)
                .filter(
                    Scan.id == scan_id
                )
                .first()
            )

            if scan:

                scan.status = "Failed"

                db.commit()

        except Exception:

            db.rollback()

    finally:

        db.close()


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )