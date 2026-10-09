from urllib.parse import urlparse


def validate_target_url(url: str):
    """
    Validate a target URL before scanning.

    ShieldAI only accepts HTTP/HTTPS URLs.
    """

    if not url:
        return False, "Target URL is required."

    url = url.strip()

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS URLs are allowed."

    if not parsed.netloc:
        return False, "Invalid target URL."

    hostname = parsed.hostname

    if not hostname:
        return False, "Invalid hostname."

    # Academic/local testing targets
    allowed_local_hosts = {
        "127.0.0.1",
        "localhost",
        "::1"
    }

    if hostname not in allowed_local_hosts:
        return False, (
            "For this academic build, scans are restricted "
            "to authorized local targets."
        )

    return True, url