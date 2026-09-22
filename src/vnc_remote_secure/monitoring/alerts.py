"""Alert dispatch for VNC Remote Secure.

Sends notifications to the channels configured via environment:

- ``DISCORD_ENABLED`` / ``DISCORD_WEBHOOK_URL`` — Discord webhook.
- ``ALERT_WEBHOOK_URL`` — generic JSON webhook.
- ``ALERT_EMAIL_*`` / ``ALERT_SMTP_*`` — email via SMTP.

All channels are best-effort: a failing channel is logged and skipped
without affecting the caller or the other channels. Nothing is sent
unless ``ALERTS_ENABLED=true`` (force=True bypasses this gate, e.g. for
explicit ``vnc-remote`` invocations).
"""
import json
import logging
import os
import smtplib
import urllib.request
from email.message import EmailMessage

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 10


def _env_flag(name, default='false'):
    return os.environ.get(name, default).lower() in ('true', '1', 'yes')


def send_discord_alert(title, message, severity='info'):
    """Post an embed to the configured Discord webhook."""
    url = os.environ.get('DISCORD_WEBHOOK_URL', '')
    if not url:
        return False
    colors = {'info': 0x3498DB, 'warning': 0xF1C40F, 'error': 0xE74C3C, 'success': 0x2ECC71}
    payload = {'embeds': [{'title': title, 'description': message,
                           'color': colors.get(severity, 0x3498DB)}]}
    return _post_json(url, payload)


def send_webhook_alert(title, message, severity='info'):
    """POST a JSON payload to the generic alert webhook."""
    url = os.environ.get('ALERT_WEBHOOK_URL', '')
    if not url:
        return False
    return _post_json(url, {'title': title, 'message': message,
                            'severity': severity,
                            'source': 'vnc-remote-secure'})


def _redact_url(url):
    """Return a log-safe form of a webhook URL (scheme + host only).

    Webhook URLs embed their credential in the path (e.g. Discord's
    ``/api/webhooks/<id>/<token>``) or in the query string. A generic
    webhook may carry the token as the FIRST path segment, so showing
    even one segment can leak the secret — redact the whole path.
    """
    from urllib.parse import urlparse
    try:
        p = urlparse(url)
        return f'{p.scheme}://{p.netloc}/…'
    except ValueError:
        return '<invalid-url>'


def _post_json(url, payload):
    """POST JSON to a webhook URL. Returns True on HTTP 2xx."""
    # Webhook URLs are operator-configured, but restrict the scheme so a
    # config mistake (or tampered .env) cannot turn the alerter into a
    # file:// or gopher:// reader.
    if not url.lower().startswith(('https://', 'http://')):
        logger.warning("Webhook URL rejected — non-HTTP scheme: %s",
                       _redact_url(url))
        return False
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        # nosec rationale: scheme validated before dispatch
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # nosec B310
            ok = 200 <= resp.status < 300
            if not ok:
                logger.warning("Webhook %s returned HTTP %s",
                               _redact_url(url), resp.status)
            return ok
    except Exception as exc:  # noqa: BLE001 - alerting must never crash callers
        logger.warning("Webhook POST to %s failed: %s",
                       _redact_url(url), exc)
        return False


def send_email_alert(title, message):
    """Send an alert email via the configured SMTP server."""
    to_addr = os.environ.get('ALERT_EMAIL_TO', '')
    smtp_server = os.environ.get('ALERT_SMTP_SERVER', '')
    if not to_addr or not smtp_server:
        return False

    host, _, port = smtp_server.partition(':')
    try:
        # Inside the try: header assignment rejects CR/LF (ValueError)
        # and must not crash the caller.
        msg = EmailMessage()
        msg['Subject'] = f"[VNC Remote Secure] {title}"
        msg['From'] = os.environ.get(
            'ALERT_EMAIL_FROM', 'vnc-remote-secure@localhost')
        msg['To'] = to_addr
        msg.set_content(message)

        with smtplib.SMTP(host, int(port or 25), timeout=_HTTP_TIMEOUT) as smtp:
            # TLS protects the message body too, not just credentials —
            # attempt it whenever supported. When the operator asked for
            # TLS (the default) a failed STARTTLS must abort the send:
            # continuing would transmit credentials and the alert body
            # in cleartext. Set ALERT_SMTP_TLS=false only for a known
            # plaintext relay.
            if os.environ.get('ALERT_SMTP_TLS', 'true').lower() in (
                    'true', '1', 'yes'):
                try:
                    smtp.starttls()
                except smtplib.SMTPException as exc:
                    logger.warning(
                        "SMTP STARTTLS failed and ALERT_SMTP_TLS=true — "
                        "refusing to send cleartext: %s", exc)
                    return False
            user = os.environ.get('ALERT_SMTP_USER', '')
            password = os.environ.get('ALERT_SMTP_PASS', '')
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        logger.info("Alert email sent to %s", to_addr)
        return True
    except Exception as exc:  # noqa: BLE001 - alerting must never crash callers
        logger.warning("Alert email failed: %s", exc)
        return False


# Dedup window: identical (title, message, severity) alerts within
# this interval are dropped so a flapping caller cannot spam the
# configured channels (Discord/webhook rate limits, email floods).
_DEDUP_WINDOW_S = 60
_last_sent: dict = {}


def notify(title, message, severity='info', force=False):
    """Dispatch an alert to every configured channel.

    Args:
        title: Short headline (e.g. 'Service failure').
        message: Human-readable body.
        severity: 'info' | 'warning' | 'error' | 'success'.
        force: Send even when ALERTS_ENABLED is false (manual triggers).

    Returns:
        Number of channels that accepted the alert.
    """
    if not (force or _env_flag('ALERTS_ENABLED')):
        return 0

    import time as _time
    key = (title, message, severity)
    now = _time.monotonic()
    if now - _last_sent.get(key, -_DEDUP_WINDOW_S) < _DEDUP_WINDOW_S:
        logger.debug("Alert deduplicated (sent < %ds ago): %s",
                     _DEDUP_WINDOW_S, title)
        return 0
    _last_sent[key] = now

    sent = 0
    if _env_flag('DISCORD_ENABLED') and send_discord_alert(title, message, severity):
        sent += 1
    if send_webhook_alert(title, message, severity):
        sent += 1
    if send_email_alert(title, message):
        sent += 1
    if sent == 0:
        logger.debug("No alert channel configured or reachable for: %s", title)
    return sent
