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
from email.message import EmailMessage

from vnc_remote_secure.core.config import env_flag
from vnc_remote_secure.security.http_client import (
    redact_url as _redact_url,
)
from vnc_remote_secure.security.http_client import (
    secure_post,
)
from vnc_remote_secure.security.http_client import (
    validate_url as _validate_webhook_url,
)

logger = logging.getLogger(__name__)

_HTTP_TIMEOUT = 10


def _alert_id() -> str:
    """Return a short correlation id for an alert dispatch.

    Lets the receiver (or the operator cross-referencing the audit
    log) tie an inbound notification back to one event — without it
    two deduped incidents are indistinguishable on the channel.
    """
    import uuid
    return uuid.uuid4().hex[:12]


def send_discord_alert(title, message, severity='info', alert_id=''):
    """Post an embed to the configured Discord webhook."""
    url = os.environ.get('DISCORD_WEBHOOK_URL', '')
    if not url:
        return False
    colors = {'info': 0x3498DB, 'warning': 0xF1C40F, 'error': 0xE74C3C, 'success': 0x2ECC71}
    desc = message + (f'\n`id: {alert_id}`' if alert_id else '')
    payload = {'embeds': [{'title': title, 'description': desc,
                           'color': colors.get(severity, 0x3498DB)}]}
    return _post_json(url, payload)


def send_webhook_alert(title, message, severity='info', alert_id=''):
    """POST a JSON payload to the generic alert webhook."""
    url = os.environ.get('ALERT_WEBHOOK_URL', '')
    if not url:
        return False
    return _post_json(url, {'title': title, 'message': message,
                            'severity': severity,
                            'source': 'vnc-remote-secure',
                            'id': alert_id})


def _post_pinned(url, body, headers) -> bool:
    """POST via a DNS-pinned connection. Returns True on HTTP 2xx.

    The request dials the exact IP that passed the public-address
    check — validation and connect cannot see different answers.
    Redirects are never followed (we issue exactly one request).
    Retried once on transport errors by ``secure_post``; a transport
    failure (no public address, refused, timeout) returns False —
    alerting must never crash callers.
    """
    import httpx
    try:
        status = secure_post(url, body, headers)
    except (httpx.TransportError, OSError):
        return False
    ok = 200 <= status < 300
    if not ok:
        logger.warning("Webhook %s returned HTTP %s",
                       _redact_url(url), status)
    return ok


def _post_json(url, payload):
    """POST JSON to a webhook URL. Returns True on HTTP 2xx."""
    # Webhook URLs are operator-configured, but a config mistake (or
    # tampered .env) must not turn the alerter into an SSRF primitive
    # against loopback/LAN/metadata endpoints or a file:// reader.
    err = _validate_webhook_url(url)
    if err:
        logger.warning("Webhook URL rejected (%s): %s",
                       err, _redact_url(url))
        from vnc_remote_secure.monitoring.prometheus import inc_counter
        inc_counter('vnc_remote_alerts_dropped_total',
                    'reason=url_rejected')
        return False
    body = json.dumps(payload).encode('utf-8')
    headers = {'Content-Type': 'application/json'}
    # HMAC signature (ALERT_WEBHOOK_SECRET): lets the receiver verify
    # the alert came from this deployment — a leaked webhook URL alone
    # cannot forge notifications (GitHub-style `sha256=` scheme).
    secret = os.environ.get('ALERT_WEBHOOK_SECRET', '')
    if secret:
        import hashlib
        import hmac as _hmac
        sig = _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers['X-VncRemote-Signature'] = f'sha256={sig}'
    try:
        return _post_pinned(url, body, headers)
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
            if env_flag('ALERT_SMTP_TLS', 'true'):
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
    if not (force or env_flag('ALERTS_ENABLED')):
        return 0

    import time as _time
    key = (title, message, severity)
    now = _time.monotonic()
    if now - _last_sent.get(key, -_DEDUP_WINDOW_S) < _DEDUP_WINDOW_S:
        logger.debug("Alert deduplicated (sent < %ds ago): %s",
                     _DEDUP_WINDOW_S, title)
        from vnc_remote_secure.monitoring.prometheus import inc_counter
        inc_counter('vnc_remote_alerts_dropped_total',
                    'reason=dedup')
        return 0
    _last_sent[key] = now

    alert_id = _alert_id()
    sent = 0
    if env_flag('DISCORD_ENABLED') and send_discord_alert(
            title, message, severity, alert_id=alert_id):
        sent += 1
    if send_webhook_alert(title, message, severity, alert_id=alert_id):
        sent += 1
    if send_email_alert(
            title, f'{message}\n\n(alert id: {alert_id})'):
        sent += 1
    if sent == 0:
        logger.debug("No alert channel configured or reachable for: %s", title)
        from vnc_remote_secure.monitoring.prometheus import inc_counter
        inc_counter('vnc_remote_alerts_dropped_total',
                    'reason=no_channel')
    else:
        # The id lands in the local log so an inbound alert can be
        # correlated back to the event that raised it.
        logger.info("Alert dispatched (id=%s, channels=%d): %s",
                    alert_id, sent, title)
    return sent
