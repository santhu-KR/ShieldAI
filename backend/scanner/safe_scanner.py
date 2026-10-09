import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


# ============================================================
# SHIELDAI SAFE SCANNER
# ============================================================
# This scanner performs non-destructive checks against an
# authorized local target.
#
# Current checks:
# 1. Basic HTTP reconnaissance
# 2. Security headers
# 3. HTML forms / CSRF review indicators
# 4. Basic endpoint discovery
#
# It does NOT:
# - exploit vulnerabilities
# - submit destructive requests
# - brute force credentials
# - dump databases
# - execute shell commands
# ============================================================


TIMEOUT = 8

RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "Content Security Policy",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer-Policy",
}


def scan_target(url):
    """
    Perform a safe, read-only scan against an authorized
    local web application.
    """

    findings = []

    endpoints = []

    try:

        # ----------------------------------------------------
        # HTTP GET
        # ----------------------------------------------------

        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={
                "User-Agent": "ShieldAI-SafeScanner/1.0"
            }
        )

        final_url = response.url

        # ----------------------------------------------------
        # RECONNAISSANCE
        # ----------------------------------------------------

        endpoints.append(final_url)

        # ----------------------------------------------------
        # SECURITY HEADERS
        # ----------------------------------------------------

        headers = response.headers

        for header, display_name in RECOMMENDED_HEADERS.items():

            if header not in headers:

                severity = "MEDIUM"

                # Missing CSP gets HIGH in our academic
                # demonstration rules.
                if header == "Content-Security-Policy":
                    severity = "HIGH"

                findings.append({
                    "vulnerability": f"Missing {display_name}",
                    "severity": severity,
                    "url": final_url,
                    "description": (
                        f"The recommended security header "
                        f"'{header}' was not observed in "
                        f"the HTTP response."
                    ),
                    "status": "Open"
                })

        # ----------------------------------------------------
        # SERVER INFORMATION
        # ----------------------------------------------------

        server_header = headers.get("Server")

        if server_header:

            findings.append({
                "vulnerability": "Server Information Disclosure",
                "severity": "LOW",
                "url": final_url,
                "description": (
                    "The HTTP response exposes a Server "
                    "header that may disclose server "
                    "implementation information."
                ),
                "status": "Open"
            })

        # ----------------------------------------------------
        # HTML ANALYSIS
        # ----------------------------------------------------

        content_type = headers.get(
            "Content-Type",
            ""
        ).lower()

        if "text/html" in content_type:

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            # ------------------------------------------------
            # FORM DISCOVERY
            # ------------------------------------------------

            forms = soup.find_all("form")

            for form in forms:

                action = form.get("action") or final_url

                form_url = urljoin(
                    final_url,
                    action
                )

                method = (
                    form.get("method")
                    or "GET"
                ).upper()

                inputs = form.find_all(
                    ["input", "textarea", "select"]
                )

                has_csrf_indicator = False

                for field in inputs:

                    field_name = (
                        field.get("name")
                        or ""
                    ).lower()

                    field_id = (
                        field.get("id")
                        or ""
                    ).lower()

                    csrf_words = [
                        "csrf",
                        "xsrf",
                        "token",
                        "authenticity"
                    ]

                    if any(
                        word in field_name
                        or word in field_id
                        for word in csrf_words
                    ):
                        has_csrf_indicator = True

                # Only flag potentially state-changing
                # POST forms.
                if method == "POST" and not has_csrf_indicator:

                    findings.append({
                        "vulnerability": (
                            "CSRF Protection Review"
                        ),
                        "severity": "MEDIUM",
                        "url": form_url,
                        "description": (
                            "A POST form was identified "
                            "without an obvious CSRF token "
                            "field. Manual verification is "
                            "recommended."
                        ),
                        "status": "Needs Verification"
                    })

            # ------------------------------------------------
            # LINK DISCOVERY
            # ------------------------------------------------

            links = soup.find_all(
                "a",
                href=True
            )

            for link in links:

                href = link.get("href")

                if not href:
                    continue

                endpoint = urljoin(
                    final_url,
                    href
                )

                # Keep only HTTP(S) endpoints.
                if endpoint.startswith(
                    ("http://", "https://")
                ):

                    if endpoint not in endpoints:
                        endpoints.append(endpoint)

        # ----------------------------------------------------
        # SAFE XSS INDICATOR
        # ----------------------------------------------------
        # We only inspect the returned HTML.
        # We do not inject a payload.
        # ----------------------------------------------------

        response_text_lower = (
            response.text.lower()
        )

        script_indicators = [
            "<script>",
            "javascript:",
            "onclick="
        ]

        if any(
            indicator in response_text_lower
            for indicator in script_indicators
        ):

            findings.append({
                "vulnerability": (
                    "Potential Client-Side Script Indicator"
                ),
                "severity": "MEDIUM",
                "url": final_url,
                "description": (
                    "Client-side script indicators were "
                    "observed in the returned HTML. "
                    "This is an indicator only and requires "
                    "manual verification; no payload was "
                    "injected."
                ),
                "status": "Needs Verification"
            })

        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        return {
            "success": True,
            "final_url": final_url,
            "status_code": response.status_code,
            "endpoints": endpoints,
            "findings": findings
        }

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "error": "Target request timed out.",
            "endpoints": endpoints,
            "findings": []
        }

    except requests.exceptions.ConnectionError:

        return {
            "success": False,
            "error": "Unable to connect to target.",
            "endpoints": endpoints,
            "findings": []
        }

    except requests.exceptions.RequestException as error:

        return {
            "success": False,
            "error": str(error),
            "endpoints": endpoints,
            "findings": []
        }

    except Exception as error:

        return {
            "success": False,
            "error": str(error),
            "endpoints": endpoints,
            "findings": []
        }