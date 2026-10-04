import type { Messages } from './es';

export const en: Messages = {
  'common.cancel': 'Cancel',
  'common.confirm': 'Confirm',
  'common.loading': 'Loading…',
  'common.error': 'Operation failed',
  'common.search': 'Search…',
  'common.delete': 'Delete',
  'common.create': 'Create',
  'common.close': 'Close',
  'common.more': 'More',
  'common.undo': 'Undo',
  'common.actions': 'Actions',
  'common.enabled': 'enabled',
  'common.disabled': 'disabled',
  'common.detail': 'Detail',
  'err.generic': 'Something failed. Please try again.',
  'err.network': 'Cannot reach the service — check the network.',

  'nav.summary': 'Summary',
  'nav.sessions': 'Access links',
  'nav.users': 'Operators',
  'nav.security': 'Security',
  'nav.audit': 'Audit',
  'nav.doctor': 'Diagnostics',
  'nav.backups': 'Backups',
  'nav.config': 'Configuration',
  'nav.jobs': 'Tasks',
  'nav.backToPortal': '← Portal',
  'nav.backToSummary': 'Back to summary',
  'nav.skipToContent': 'Skip to content',
  'nav.logout': 'Log out',
  'nav.adminPanel': 'administration panel',
  'nav.group.access': 'Remote sessions',
  'nav.group.identities': 'Administration',
  'nav.group.operations': 'System',
  'nav.connect': 'Connection center',
  'nav.files': 'Files',
  'nav.notFound': 'Page not found.',
  'nav.sessionError': 'Could not verify the session.',
  'nav.sessionErrorNet': 'Network error — the service may be down.',
  'common.retry': 'Retry',
  'role.viewer': 'View only',
  'role.support': 'Support',
  'role.administrator': 'Administrator',
  'role.operator': 'Operator',
  'role.admin': 'Administrator',
  // Capability enums (security/ephemeral_model.py ALL_PERMISSIONS)
  'perm.view': 'view desktop',
  'perm.control': 'remote control',
  'perm.keyboard': 'keyboard',
  'perm.pointer': 'pointer',
  'perm.clipboard': 'clipboard',
  'perm.clipboard_write': 'clipboard (write)',
  'perm.clipboard_read': 'clipboard (read)',
  'perm.file_transfer': 'file transfer',
  'perm.terminal': 'terminal',
  'perm.terminal_view': 'terminal (view)',
  'perm.terminal_write': 'terminal (execute)',
  'perm.audio': 'audio',
  'perm.gamepad': 'gamepad',
  'perm.admin': 'administration',
  'perm.admin_users': 'administration · operators',
  'perm.admin_config': 'administration · config',
  'perm.admin_audit': 'administration · audit',
  'perm.admin_sessions': 'administration · sessions',
  'perm.admin:*': 'full administration',
  'common.noResults': 'No results for this filter.',
  'common.open': 'Open',

  'login.title': 'Operator console',
  'login.username': 'Username',
  'login.password': 'Password',
  'login.totp': 'MFA code',
  'login.submit': 'Sign in',
  'login.submitting': 'Signing in…',
  'login.passkey': 'Sign in with passkey',
  'login.mfaRequired': 'MFA required — enter your code.',

  'stepup.title': 'Elevated confirmation',
  'stepup.verify': 'Verify and continue',
  'stepup.reason': 'This operation requires re-authentication:',
  'stepup.onResource': 'on',
  'stepup.password': 'Password',
  'stepup.failed': 'Password verification failed',
  'stepup.boundNote':
    'Verification binds to this exact operation and resource, ' +
    'usable once (~2 min).',
  'stepup.genericNote':
    'Verification stays linked to your session for ~5 minutes.',

  'confirm.typeToConfirm': 'Type {{name}} to confirm',

  'jobs.title': 'Tasks',
  'jobs.subtitle':
    'Persistent operation ledger: lifecycle, restores and upgrades ' +
    'executed by the runner — they survive a portal restart.',
  'jobs.loadError': 'Could not load the job ledger.',
  'jobs.empty': 'No operations recorded yet.',
  'jobs.col.job': 'Job',
  'jobs.col.op': 'Operation',
  'jobs.col.resource': 'Resource',
  'jobs.col.actor': 'Actor',
  'jobs.col.start': 'Started',
  'jobs.col.state': 'State',
  'jobs.state': 'State',
  'jobs.st.queued': 'queued',
  'jobs.st.claimed': 'claimed',
  'jobs.st.running': 'running',
  'jobs.st.done': 'done',
  'jobs.st.failed': 'failed',
  'jobs.progress': 'Progress',
  'jobs.detailLabel': 'Detail',
  'jobs.error': 'Error',

  'nav.recordings': 'Recordings',
  'nav.remote': 'Remote desktop',
  'nav.menu': 'Administration menu',
  'nav.filter': 'Go to… (filter)',
  'nav.palette': 'Go to… (Ctrl+K)',
  'nav.paletteEmpty': 'No results.',
  'crash.title': 'Something failed in this view',
  'crash.desc': 'The section crashed. Reload or try again — your session is still active.',
  'nav.help': 'Help',
  'config.levels': 'Configuration level',
  'config.level.basic': 'Basic',
  'config.level.advanced': 'Advanced',
  'rec.mark': 'Bookmark',
  'rec.marks': 'Markers',
  'rec.markSeek': 'Jump to marker',
  'rec.marksExport': 'Export markers (JSON)',
  'rec.marksClear': 'Clear markers',
  'sessions.detail.tab.desktop': 'Desktop',
  'help.title': 'Help',
  'help.subtitle': 'Quick guide to the remote support flow.',
  'help.flow.title': 'How it works',
  'help.flow.invite.title': '1. Create an invitation',
  'help.flow.invite.desc': 'In «Access links» pick the resource, permissions and expiry. The link only reveals what it grants.',
  'help.flow.share.title': '2. Share the link',
  'help.flow.share.desc': 'Copy the link, the QR, or send it by email. The guest needs no account.',
  'help.flow.consent.title': '3. Consent',
  'help.flow.consent.desc': 'The guest sees exactly what you will be able to do — view or control, terminal, files — and accepts explicitly.',
  'help.flow.supervise.title': '4. Supervise the session',
  'help.flow.supervise.desc': 'From the session detail: live desktop, active connections, chat and timeline.',
  'help.flow.close.title': '5. Close',
  'help.flow.close.desc': 'The session expires on its own or you can revoke it at any time. Revocation is audited.',
  'help.glossary': 'Concepts',
  'help.term.session': 'Session',
  'help.term.session.desc': 'An ephemeral connection between a guest and this machine.',
  'help.term.invite': 'Invitation',
  'help.term.invite.desc': 'The not-yet-used link that grants access.',
  'help.term.grant': 'Temporary grant',
  'help.term.grant.desc': 'What the link authorises: resources, control and limits.',
  'help.term.stepup': 'Identity verification',
  'help.term.stepup.desc': 'Critical actions (power, deleting recordings, revoking all) ask for your password again.',
  'help.term.audit': 'Audit',
  'help.term.audit.desc': 'Hash-chained log of everything that happens; verify its integrity under Security → Audit.',
  'help.term.sharelink': 'Access link',
  'help.term.sharelink.desc': 'A single-purpose credential delivered as a fragment URL — it never reaches the server.',
  'help.term.opsession': 'Operator session',
  'help.term.opsession.desc': 'Your own console session (cookie + Basic auth); not the same thing as an access link.',
  'help.term.connection': 'Live connection',
  'help.term.connection.desc': 'A socket open right now under an activated link — visible on each session detail.',
  'help.term.job': 'Job',
  'help.term.job.desc': 'A destructive operation queued on the shared ledger (restore, restart, upgrade).',
  'help.term.label': 'Label',
  'help.term.label.desc': 'Free-text inventory tag to group links by case; it never influences permissions.',
  'help.links': 'Go to…',
  'theme.auto': 'Theme: system',
  'theme.dark': 'Theme: dark',
  'theme.light': 'Theme: light',
  'theme.switch': 'Switch theme',
  'density.normal': 'Density: normal',
  'density.compact': 'Density: compact',
  'density.switch': 'Switch density',
  'jobs.badge': '{{count}} task(s) running',
  'status.strip': 'System status',
  'status.healthy': 'Healthy · {{up}}/{{total}} services',
  'status.degraded': 'Degraded · {{up}}/{{total}} services',
  'status.down': 'Down · {{up}}/{{total}} services',
  'status.unknown': 'Status unknown',
  'status.stale': 'stale',
  'status.staleHint': 'Last check failed — this data may be out of date',
  'status.sessions_one': '{{count}} session',
  'status.sessions_other': '{{count}} sessions',
  'status.jobs': '{{count}} job(s)',
  'status.criticals': '{{count}} critical',
  'nav.activity': 'Activity',
  'activity.title': 'Activity',
  'activity.subtitle': 'Audit events and tasks in one feed.',
  'activity.filter.kind': 'Kind',
  'activity.kind.all': 'All',
  'activity.kind.audit': 'Audit',
  'activity.kind.jobs': 'Jobs',
  'activity.filter.severity': 'Severity',
  'activity.sev.all': 'All',
  'activity.sev.info': 'Info',
  'activity.sev.warn': 'Warning',
  'activity.sev.error': 'Error',
  'activity.filter.text': 'Search events…',
  'activity.filter.user': 'User',
  'activity.empty': 'No events match these filters.',
  'activity.col.when': 'When',
  'activity.col.what': 'Event',
  'activity.col.who': 'Actor',
  'activity.col.result': 'Result',
  'activity.loadMore': 'Load more',
  'remote.title': 'Remote console',
  'remote.chat': 'Chat',
  'remote.fullscreen': 'Fullscreen',
  'remote.popout': 'Pop out',
  'remote.immersive': 'Immersive mode',
  'remote.immersiveExit': 'Exit immersive',
  'remote.group.capture': 'Capture',
  'remote.group.view': 'View',
  'remote.frameTitle': 'Remote desktop',
  'remote.offline': 'The remote desktop service is down',
  'remote.offlineHint':
    'The frame loaded but there is no framebuffer behind it — ' +
    'start the VNC service from Operations.',
  'guest.console': 'Remote desktop',
  'rec.title': 'Desktop recordings',
  'rec.subtitle':
    'Forensic desktop capture: one-shot PNG screenshots or a ' +
    'replayable framebuffer stream. Every action is audited.',
  'rec.screenshot': 'Take screenshot',
  'rec.record': 'Record desktop',
  'rec.runningHint': 'A recording is in progress — stop it before starting another.',
  'rec.stop': 'Stop',
  'rec.play': 'Play',
  'rec.close': 'Close',
  'rec.pause': 'Pause',
  'rec.seek': 'Position',
  'rec.speed': 'Speed',
  'rec.playerAria': 'Recording player',
  'rec.download': 'Download',
  'rec.delete': 'Delete',
  'rec.live': 'Recording',
  'rec.ended': 'Complete',
  'rec.truncated': 'Interrupted',
  'rec.empty': 'No recordings yet.',
  'rec.loading': 'Loading…',
  'rec.loadError': 'Could not load the recording.',
  'rec.started': 'Recording started.',
  'rec.stopped': 'Recording stopped.',
  'rec.deleted': 'Recording deleted.',
  'rec.startError': 'Could not start the recording.',
  'rec.stopError': 'Could not stop the recording.',
  'rec.deleteError': 'Could not delete the recording.',
  'rec.stepup.delete': 'Delete a recording (forensic material)',
  'rec.deleteConfirmTitle': 'Delete recording',
  'rec.deleteConfirmBody':
    'Recording {{id}} will be permanently deleted — there is no ' +
    'way to recover it.',
  'rec.col.created': 'Started',
  'rec.col.resolution': 'Resolution',
  'rec.col.operator': 'Operator',
  'rec.col.size': 'Size',
  'rec.col.state': 'State',

  'overview.title': 'Summary',
  'overview.actions.newInvite': 'New invitation',
  'overview.actions.console': 'Open remote desktop',
  'overview.actions.activity': 'Review activity',
  'overview.actions.diag': 'Diagnostics',
  'overview.systemControl': 'System control',
  'overview.customize': 'Customize dashboard',
  'overview.widget.banner': 'Banners',
  'overview.widget.actions': 'Quick actions',
  'overview.widget.metrics': 'Metrics',
  'overview.widget.services': 'Services',
  'overview.widget.lan': 'LAN access',
  'overview.widget.system': 'System control',
  'overview.recentJobs': 'Recent jobs',
  'overview.power.title': 'Host power',
  'overview.power.shutdown': 'Shut down host',
  'overview.power.restart': 'Restart host',
  'overview.power.sleep': 'Sleep host',
  'overview.power.accepted':
    '{{action}} accepted — executes in ~1 s.',
  'overview.power.stepup': 'host power action',
  'overview.power.wolMac': 'MAC of the host to wake',
  'overview.power.wolMacInvalid': 'Invalid format — use AA:BB:CC:DD:EE:FF',
  'overview.power.wolSend': 'Wake (WoL)',
  'overview.power.wolSent': 'Wake-on-LAN packet sent to {{mac}}',
  'overview.power.confirmTitle': '{{action}} the host',
  'overview.power.confirmLabel': 'Execute',
  'overview.power.confirmBody':
    'The {{action}} action will run on this remote host. ' +
    'Active sessions will be interrupted.',
  'overview.col.job': 'Job',
  'overview.col.op': 'Operation',
  'overview.col.actor': 'Actor',
  'overview.col.state': 'State',
  'overview.col.detail': 'Detail',
  'overview.lifecycle.title': 'Lifecycle',
  'overview.lifecycle.stop': 'Stop all',
  'overview.lifecycle.restart': 'Restart all',
  'overview.lifecycle.start': 'Start stopped',
  'overview.lifecycle.stopping':
    'Stopping (job {{job}}) — this UI will stop responding. ' +
    'Restart with "vnc-remote start".',
  'overview.lifecycle.restarting':
    'Restarting (job {{job}}) — the UI will return once the portal ' +
    'is back up.',
  'overview.lifecycle.starting':
    'Starting (job {{job}}) the stopped services.',
  'overview.lifecycle.confirm.stop': 'stopping all services',
  'overview.lifecycle.confirm.restart': 'restarting all services',
  'overview.lifecycle.confirm.start': 'starting services',
  'overview.upgrade.run': 'Upgrade',
  'overview.upgrade.rollback': 'Rollback',
  'overview.upgrade.queued':
    'Upgrade queued (job {{job}}) — track progress under ' +
    'Operations → Jobs; restart when done.',
  'overview.upgrade.rollbackQueued':
    'Rollback queued (job {{job}}) — check its progress under ' +
    'Operations → Jobs.',
  'overview.upgrade.confirm': 'updating the installed package',
  'overview.upgrade.confirmRollback': 'rollback to the previous version',
  'overview.upgrade.placeholder':
    'Source (wheel/URL; empty = PyPI latest)',
  'overview.upgrade.running': 'Upgrading…',
  'overview.lifecycle.unavailable':
    'Service control is not available with this role.',
  'overview.version.installed': 'Installed version',
  'overview.version.available': 'available',
  'overview.security.score': 'Security: {{score}}/100',
  'overview.security.posture.excellent': 'Excellent security posture',
  'overview.security.posture.good': 'Good security posture with minor gaps',
  'overview.security.posture.moderate': 'Moderate security posture — several improvements needed',
  'overview.security.posture.poor': 'Poor security posture — immediate action required',
  'overview.health.healthy': 'Health: healthy',
  'overview.health.degraded': 'Health: degraded',
  'overview.health.down': 'Health: down',
  'overview.health.unknown': 'Health: no data',
  'overview.services': 'Services',
  'overview.services.error': 'Could not load the service list.',
  'overview.lanAccess': 'LAN access',
  'overview.dialog.stopTitle': 'Stop all services',
  'overview.dialog.restartTitle': 'Restart all services',
  'overview.dialog.stop': 'Stop',
  'overview.dialog.restart': 'Restart',
  'overview.dialog.stopBody':
    'All services will stop — including this portal. ' +
    'The UI will stop responding until they are started ' +
    'from the CLI or the service manager.',
  'overview.dialog.restartBody':
    'The services will restart — including this portal. ' +
    'The UI will be back in a few seconds.',

  'backups.title': 'Backups',
  'backups.subtitle':
    'Full parity with the CLI (vnc-remote backup | restore | verify ' +
    'backup). Create and restore require step-up; restore launches ' +
    'a persistent job.',
  'backups.created': 'Backup created: {{name}}',
  'backups.restoreQueued':
    'Restore of {{name}} queued — job {{job}}.',
  'backups.listError': 'Could not list backups.',
  'backups.create': 'New backup',
  'backups.creating': 'Creating…',
  'backups.loading': 'Loading…',
  'backups.col.file': 'File',
  'backups.col.size': 'Size',
  'backups.col.encrypted': 'Encrypted',
  'backups.col.date': 'Date',
  'backups.col.actions': 'Actions',
  'backups.encrypted': 'ENCRYPTED',
  'backups.plain': 'PLAINTEXT',
  'backups.restore': 'Restore…',
  'backups.empty':
    'No backups. Use "New backup" or vnc-remote backup.',
  'backups.stepup.create': 'backup creation',
  'backups.stepup.restore': 'restoring backup {{name}}',
  'backups.verify.error': 'Could not queue the restore',
  'backups.jobLink': 'track progress in Jobs →',

  'wizard.title': 'Restore backup',
  'wizard.steps': 'Steps',
  'wizard.verify': '1. Verification',
  'wizard.impact': '2. Impact',
  'wizard.confirm': '3. Confirmation',
  'wizard.verifying': 'Verifying integrity of {{name}}…',
  'wizard.verifyFailed': 'Could not verify the file.',
  'wizard.corrupt':
    'Backup {{name}} is CORRUPT{{msg}} — it cannot be restored.',
  'wizard.integrity':
    '{{name}} is intact ({{members}} entries). The restore will ' +
    'overwrite:',
  'wizard.note':
    'The restore runs as a persistent job — it survives a portal ' +
    'restart. Restored passwords invalidate active sessions.',
  'wizard.continue': 'Continue',
  'wizard.typeName':
    'Type {{name}} to launch the restore. The server will require ' +
    'step-up bound to this exact file.',
  'wizard.typeLabel': 'Type the backup name',
  'wizard.launch': 'Restore',
  'wizard.launching': 'Queueing…',
  'wizard.impact.env': '.env — credentials and config flags',
  'wizard.impact.ssl': 'ssl/ — live TLS certificates',
  'wizard.impact.config': 'config/ — profiles and effective values',
  'wizard.impact.data': 'data/ — application state',
  'wizard.impact.run':
    'run/ — signing secrets, ephemeral sessions and shared_state.db',

  'config.migrate.dry': 'config migration preview',
  'config.migrate.apply': 'migrating the .env file',

  'security.stepup.rotate': 'rotation of secret {{name}}',
  'security.stepup.signing': 'signing key rotation',
  'security.stepup.recovery': 'MFA recovery-code generation',


  // --- Security ---------------------------------------------------------------
  'security.title': 'Security',
  'security.posture.error': 'Could not load the security posture.',
  'security.score': 'Score',
  'security.deployment': 'Deployment',
  'security.deployment.allowed': 'deployment allowed',
  'security.deployment.blocked': 'deployment blocked',
  'security.overview.error': 'The security overview is unavailable.',
  'security.overview.score': 'Score',
  'security.overview.blocking': '{{count}} blocking finding(s)',
  'security.overview.noBlocking': 'No blocking findings',
  'security.overview.authFails': 'Auth failures (24h)',
  'security.overview.actors': 'actors: {{list}}',
  'security.overview.none': 'no actors with failures',
  'security.overview.denied': 'Denied (24h)',
  'security.overview.sessions': '{{count}} active sessions',
  'security.overview.state': 'State',
  'security.overview.maint': 'Maintenance',
  'security.overview.normal': 'Operational',
  'security.overview.jobs': '{{count}} running jobs',
  'security.overview.recent': 'Recent failures',
  'security.blockingFindings': 'Blocking findings',
  'security.findings': 'Findings',
  'security.check.tls.name': 'HTTPS/TLS enabled',
  'security.check.tls.warn': 'TLS disabled — traffic is unencrypted',
  'security.check.tls.fail': 'TLS disabled — all traffic is unencrypted',
  'security.check.ssl_cert.name': 'SSL certificate configured',
  'security.check.ssl_cert.warn': 'TLS disabled or no SSL certificate path configured',
  'security.check.mfa.name': 'MFA enabled',
  'security.check.mfa.warn': 'MFA not configured — single-factor auth only',
  'security.check.strong_creds.name': 'Strong credentials configured',
  'security.check.strong_creds.warn': 'Credentials may be weak or missing',
  'security.check.strong_creds.fail': 'No credentials configured',
  'security.check.rate_limit.name': 'Rate limiting configured',
  'security.check.rate_limit.warn': 'No rate limiting configured',
  'security.check.session_secret.name': 'Persistent session secret (FLASK_SECRET_KEY)',
  'security.check.session_secret.warn': 'FLASK_SECRET_KEY not set — sessions invalidated on restart',
  'security.check.session_secret.ok':
    'Development profile — ephemeral secret acceptable',
  'security.check.health_endpoint_pub.name': 'Health endpoint protected',
  'security.check.health_endpoint_pub.warn':
    'Health endpoint has no auth token',
  'security.check.health_endpoint_priv.name': 'Health endpoint protected',
  'security.check.health_endpoint_priv.warn':
    'Health endpoint has no auth token (loopback-only — acceptable, ' +
    'but set HEALTH_AUTH_TOKEN before exposing)',
  'security.check.no_placeholder_secrets.name': 'No placeholder secrets',
  'security.check.no_placeholder_secrets.warn': 'Placeholder value in DISCORD_WEBHOOK_URL',
  'security.check.bind_localhost.name': 'Services bound to localhost',
  'security.check.bind_localhost.warn': 'Services bind to {{bind}} (exposed to network)',
  'security.check.nginx_proxy.name': 'Reverse proxy (nginx) enabled',
  'security.check.nginx_proxy.warn': 'No reverse proxy — services exposed directly',
  'security.check.domain.name': 'Domain configured (DuckDNS)',
  'security.check.domain.warn': 'No domain configured — local access only',
  'security.check.session_idle.name': 'Session idle timeout configured',
  'security.check.session_idle.warn': 'Session idle timeout is {{idle}}s (consider ≤1800s)',
  'security.check.temp_user_cleanup.name': 'Temp user removed on exit',
  'security.check.temp_user_cleanup.warn': 'KEEP_TEMP_USER=true — temp user persists after exit',
  'security.check.shared_state.name': 'Shared-state backend (cross-process auth)',
  'security.check.shared_state.warn': 'SHARED_STATE_BACKEND={{backend}} — revocation/single-use/rate-limit guarantees are per-process only',
  'security.check.shared_state_degraded.name': 'Shared-state backend (cross-process auth)',
  'security.check.shared_state_degraded.warn': 'SHARED_STATE_BACKEND={{backend}} degraded to in-memory fallback — revocation/single-use/rate-limit guarantees are per-process only',
  'security.check.session_idle_unconfigured.name': 'Session idle timeout',
  'security.check.session_idle_unconfigured.warn': 'Not configured',
  'security.check.attack_surface.name': 'Optional services (attack surface)',
  'security.col.check': 'Check',
  'security.col.severity': 'Severity',
  'security.col.status': 'Status',
  'security.col.evidence': 'Evidence',
  'security.secrets.title': 'Secrets',
  'security.secrets.forbidden':
    'Secret management is not available with this role (requires admin:*).',
  'security.secrets.col.secret': 'Secret',
  'security.secrets.col.status': 'Status',
  'security.secrets.col.actions': 'Actions',
  'security.secrets.showMasked': 'Show masked',
  'security.secrets.rotate': 'Rotate',
  'security.secrets.rotateTitle': 'Rotate secret',
  'security.secrets.rotateBody':
    'A new value will be generated for {{name}} and persisted to ' +
    '.env. Services pick it up on restart; the value is never shown.',
  'security.secrets.rotated':
    'Rotated {{name}} (fp {{fingerprint}}) — restart services to ' +
    'apply it{{extra}}.',
  'security.secrets.rotatedRevoked':
    '; operator sessions revoked',
  'security.secrets.signingTitle': 'Rotate signing key',
  'security.secrets.signingBody':
    'The HMAC signing key will be rotated with a 7-day coexistence ' +
    'window: existing tokens keep verifying with the previous key ' +
    'during that period.',
  'security.secrets.signingRotated':
    'Signing key rotated — 7-day coexistence window active.',
  'security.secrets.rotateSigning': 'Rotate signing key',
  'security.secrets.recovery': 'Recovery codes',
  'security.secrets.codesOnce':
    'New codes (shown ONCE — store them offline):',
  'security.secrets.copyCodes': 'Copy all codes',
  'security.secrets.fixPerms': 'Check and fix permissions',
  'security.secrets.permsFixed':
    'Permissions fixed on {{count}} file(s).',
  'security.secrets.permsNone':
    'Secret permissions are already correct — nothing to fix.',
  'security.secrets.checkTitle': 'Secret check',

  // --- Audit ------------------------------------------------------------------
  'audit.title': 'Audit',
  'audit.chain': 'Integrity chain:',
  'audit.chain.intact': 'intact',
  'audit.chain.intactDetail': '{{n}} entries verified',
  'audit.chain.broken': 'BROKEN',
  'audit.filter.event': 'Filter by event',
  'audit.filter.user': 'Filter by user',
  'audit.user': 'User',
  'audit.filter.result': 'Filter by result',
  'audit.result.all': 'All',
  'audit.result.success': 'Success',
  'audit.result.failure': 'Failure',
  'audit.result.denied': 'Denied',
  'audit.filter.rows': 'Rows to load',
  'audit.rows': '{{n}} rows',
  'audit.refresh': 'Refresh',
  'audit.loadError': 'Could not load the audit log.',
  'audit.caption': 'Audit events (newest first)',
  'audit.empty': 'No events to show.',
  'audit.loadMore': 'Load more',
  'audit.col.seq': '#',
  'audit.col.timestamp': 'Timestamp',
  'audit.col.event': 'Event',
  'audit.col.user': 'User',
  'audit.col.result': 'Result',
  'audit.col.detail': 'Detail',

  // --- Doctor -----------------------------------------------------------------
  'doctor.title': 'Diagnostics',
  'doctor.run': 'Run doctor',
  'doctor.running': 'Running…',
  'doctor.healthy': 'all healthy',
  'doctor.unhealthy': 'issues found',
  'doctor.maintenance': 'Maintenance',
  'doctor.maintenance.reason':
    'Scheduled maintenance — please check back soon.',
  'doctor.maintenance.by': '— by {{by}}',
  'doctor.maintenance.activate': 'Enable maintenance',
  'doctor.maintenance.deactivate': 'Disable maintenance',
  'doctor.maintenance.forbidden':
    'Maintenance control is not available with this role (admin:*).',
  'doctor.failed': 'Doctor failed',
  'doctor.failedDetail': 'detail: {{msg}}',
  'doctor.col.check': 'Check',
  'doctor.col.status': 'Status',
  'doctor.col.message': 'Message',
  'doctor.jobs.title': 'Recent jobs',
  'doctor.jobs.recent': '{{count}} recorded operation(s).',
  'doctor.jobs.open': 'Open in Jobs',
  'doctor.stepup.maintenance': 'changing maintenance mode',

  // Human names for doctor checks — fixed keys translate fully and
  // dynamic prefixes (dirs./ports./deps.) fall back to the suffix:
  // `dirs.tls` → "Directory (tls)".
  'doctor.check.config.blockers': 'Blocking security findings',
  'doctor.check.config.consistency': 'Profile consistency',
  'doctor.check.deps': 'System dependency',
  'doctor.check.deps.py': 'Python module',
  'doctor.check.deps.psutil': 'psutil',
  'doctor.check.deps.uvicorn': 'uvicorn',
  'doctor.check.deps.vnc_server': 'VNC server',
  'doctor.check.dirs': 'Directory',
  'doctor.check.firewall.rules': 'Firewall rules',
  'doctor.check.gamepad.capability': 'Gamepad capability',
  'doctor.check.ports': 'Port',
  'doctor.check.ports.nginx': 'nginx port',
  'doctor.check.secrets.auth_secret': 'Auth secret',
  'doctor.check.secrets.flask_key': 'Flask secret key',
  'doctor.check.secrets.vnc_password': 'VNC password',
  'doctor.check.security.public_listeners': 'Public listeners',
  'doctor.check.state.backend': 'Shared state backend',
  'doctor.check.state.backend.effective': 'Effective backend',
  'doctor.check.state.integrity': 'State integrity',
  'doctor.check.terminal.isolation': 'Terminal isolation',
  'doctor.check.tls.certificates': 'TLS certificates',
  'doctor.check.webauthn': 'WebAuthn',
  'doctor.check.webauthn.credentials': 'Registered passkeys',
  'doctor.check.webauthn.origin': 'WebAuthn origin',

  // Doctor finding messages — keyed by msg_key emitted by doctor.py;
  // the server-side English message remains the fallback.
  'doctor.msg.config_blockers': '{{n}} blocking finding(s): {{details}}',
  'doctor.msg.config_blockers_ok': 'No blocking security findings',
  'doctor.msg.config_consistency_ok': 'Profile configuration is consistent',
  'doctor.msg.dirs_missing': 'Directory does not exist: {{path}}',
  'doctor.msg.secret_ok_nondefault': 'Set and non-default',
  'doctor.msg.secret_set': 'Set',
  'doctor.msg.vnc_password_fail': 'VNC_PASSWORD is empty or default',
  'doctor.msg.flask_key_warn': 'FLASK_SECRET_KEY not set',
  'doctor.msg.auth_secret_warn': 'AUTH_SECRET not set',
  'doctor.msg.tls_missing': 'TLS enabled but certificate files not found',
  'doctor.msg.tls_disabled': 'TLS disabled',
  'doctor.msg.webauthn_unavailable': 'module unavailable',
  'doctor.msg.webauthn_hardened':
    'disabled — hardened profile enforces phishing-resistant policies ' +
    'no method can satisfy',
  'doctor.msg.webauthn_disabled': 'disabled',
  'doctor.msg.webauthn_pkg_missing':
    'WEBAUTHN_ENABLED=true but the webauthn package is not installed ' +
    '(pip install vnc-remote-secure[webauthn])',
  'doctor.msg.webauthn_origin_ok': 'origin/RP ID explicit or deployment is direct',
  'doctor.msg.webauthn_creds_missing':
    'Hardened profile enforces phishing-resistant auth policies but ' +
    'no passkey is registered — register an admin credential before ' +
    'relying on this profile',
  'doctor.msg.webauthn_creds_ok': '{{n}} passkey(s) registered',
  'doctor.msg.webauthn_store_unreadable': 'store unreadable',
  'doctor.msg.state_sqlite_ok': 'SQLite shared state (cross-process guarantees)',
  'doctor.msg.state_memory_dev':
    'In-memory backend — single-use claims, revocation and rate ' +
    'limiting are process-local (dev only)',
  'doctor.msg.state_memory_hardened':
    'In-memory backend in a hardened profile — revoked sessions and ' +
    'TOTP claims do not propagate across service processes. ' +
    'Set SHARED_STATE_BACKEND=sqlite',
  'doctor.msg.state_unknown': "Unknown backend '{{backend}}' — falling back to memory",
  'doctor.msg.state_fallback_fail':
    'SQLite backend failed to initialize — running on in-memory ' +
    'fallback. Revocations and single-use claims do NOT propagate ' +
    'across processes. Check logs for the SQLite init error.',
  'doctor.msg.state_effective_ok': 'Effective backend: {{backend}}',
  'doctor.msg.state_probe_fail': 'Could not probe effective backend: {{err}}',
  'doctor.msg.integrity_ok': 'shared_state.db integrity_check ok',
  'doctor.msg.integrity_fail':
    'shared_state.db corrupt: {{err}} — see docs/runbook/recovery.md §2',
  'doctor.msg.integrity_probe_fail': 'Could not run integrity_check: {{err}}',
  'doctor.msg.psutil_ok': 'psutil present — stale-process reaping enabled',
  'doctor.msg.psutil_missing':
    'psutil not installed — orphaned service processes are not reaped ' +
    'on restart. Install with: pip install "vnc-remote-secure[ops]"',
  'doctor.msg.uvicorn_ok': 'uvicorn present — web surfaces served by the ASGI server',
  'doctor.msg.uvicorn_missing':
    'uvicorn not installed — the web services cannot start. ' +
    'Install with: pip install "vnc-remote-secure"',
  'doctor.msg.term_sandbox_off':
    'TERMINAL_WINDOWS_SANDBOX=off — terminal shells can read the ' +
    'service data dir (auth_secret.key, shared_state.db)',
  'doctor.msg.term_appcontainer':
    'AppContainer sandbox ({{mode}}) — terminal shells cannot read ' +
    'the user profile or service secrets',
  'doctor.msg.term_sid_fail':
    'AppContainer SID derivation failed — terminal shells run unsandboxed',
  'doctor.msg.term_sandbox_unknown':
    'Could not verify AppContainer sandbox availability',
  'doctor.msg.term_webterm_user':
    'WEBTERM_USER={{user}} — shell drops privileges',
  'doctor.msg.term_root_warn':
    'Running as root without WEBTERM_USER — terminal shells spawn ' +
    'as root. Set WEBTERM_USER to an unprivileged user',
  'doctor.msg.term_bwrap_ok':
    'bubblewrap sandbox active — secret dirs (run, config, ssl, ' +
    'data, log) are masked from terminal shells',
  'doctor.msg.term_bwrap_ns':
    'bubblewrap installed but unprivileged user namespaces are ' +
    'disabled — terminal shells can read the service state dirs ' +
    '(auth_secret.key, shared_state.db)',
  'doctor.msg.term_no_isolation':
    'Not running as root and no bubblewrap — terminal shells run ' +
    'as the service account and can read auth_secret.key / write ' +
    'shared_state.db. Install bubblewrap, set ' +
    'TERMINAL_COMMAND_ALLOWLIST, or restrict terminal access',
  'doctor.msg.gamepad_vigem':
    'ViGEm available — real X360 XInput virtual controller ' +
    '(works even without an interactive session)',
  'doctor.msg.gamepad_session0':
    'GAMEPAD_ENABLED but no interactive console session and no ' +
    'ViGEmBus driver — SendInput cannot inject from Session 0. ' +
    'Install ViGEmBus + `pip install vgamepad` or run the service ' +
    'in the user session',
  'doctor.msg.gamepad_sendinput':
    'SendInput injection only (interactive session present) — ' +
    'injects keyboard/mouse events, NOT an XInput gamepad. Install ' +
    'ViGEmBus + `pip install vgamepad` for real controller emulation',
  'doctor.msg.gamepad_verify_fail':
    'Could not verify interactive session for SendInput',
  'doctor.msg.gamepad_no_evdev':
    'GAMEPAD_ENABLED but evdev not installed — gamepad forwarding ' +
    'disabled. pip install evdev',
  'doctor.msg.gamepad_uinput_ok': 'uinput available — virtual gamepad can be created',
  'doctor.msg.gamepad_no_uinput':
    '/dev/uinput missing — load the uinput module (modprobe uinput) ' +
    'or gamepad injection will fail',
  'doctor.msg.fw_rules_ok': '{{n}} VncRemoteSecure rule(s) found',
  'doctor.msg.fw_rules_missing':
    'No VncRemoteSecure firewall rules found (public bind {{host}} configured)',
  'doctor.msg.fw_not_needed': 'Not needed (loopback-only deployment)',
  'doctor.msg.fw_unavailable': 'Firewall check unavailable: {{err}}',
  'doctor.msg.listeners_skip': 'Could not enumerate listening sockets',
  'doctor.msg.pl_websockify':
    'websockify bridge listening on {{addr}} — the auth gateway ' +
    'can be bypassed directly',
  'doctor.msg.pl_rfb_fail':
    'RFB port {{port}} listening publicly — the 8-char DES ' +
    'credential is the only barrier; set LoopbackOnly or keep the ' +
    'profile honest',
  'doctor.msg.pl_ports_nginx':
    'Backend ports public while nginx is the entry point — ' +
    'gateway bypass possible: {{ports}}',
  'doctor.msg.pl_ports_warn': 'Backend ports bound publicly (no nginx): {{ports}}',
  'doctor.msg.pl_rfb_warn':
    'RFB port public on {{addr}} — direct VNC clients rely on an ' +
    '8-char DES password; prefer nginx+websockify',
  'doctor.msg.pl_ok': 'No internal service port bound publicly',
  'doctor.msg.port_disabled': 'Disabled via {{env}}=false',
  'doctor.msg.port_listening': 'Listening on {{addr}}',
  'doctor.msg.port_not_listening': 'Not listening on {{addr}}',
  'doctor.msg.nginx_down':
    'NGINX_ENABLED=true but nothing listens on {{port}} — the ' +
    'public entry point is down',
  'doctor.msg.bin_found': 'Found',
  'doctor.msg.bin_missing': 'Not found on PATH',
  'doctor.msg.vnc_server_missing_win': 'winvnc.exe not found (may still work)',
  'doctor.msg.vnc_server_missing': 'vncserver not on PATH (may still work)',
  'doctor.msg.mod_installed': 'Installed',
  'doctor.msg.mod_missing': 'Missing — install with: pip install {{pip}}',

  // --- Config page --------------------------------------------------------------
  'config.page.title': 'Configuration',
  'config.page.subtitle':
    'Parity with vnc-remote config: effective view with provenance, ' +
    'validation, profile diff and migration.',
  'config.profile': 'Profile',
  'config.profile.live': 'Live environment',
  'config.filter': 'Filter variables',
  'config.vars': '{{count}} variables',
  'config.loadError': 'Could not load configuration.',
  'config.col.var': 'Variable',
  'config.col.value': 'Value',
  'config.col.source': 'Source',
  'config.col.actions': 'Actions',
  'config.explain': 'Explain {{name}}',
  'config.explainLive': 'Showing the «{{profile}}» profile value; above is the live provenance.',
  'config.ops.title': 'Operations',
  'config.ops.valid': 'Configuration is valid',
  'config.ops.findings': '{{count}} validation finding(s)',
  'config.ops.diff': 'Profile diff',
  'config.ops.preview': 'Preview',
  'config.ops.apply': 'Apply migration',
  'config.ops.noDiffs': 'No differences between profiles.',
  'config.ops.noMigrations': 'No pending migrations.',
  'config.ops.migrationsApplied': 'Applied {{count}} migration(s):',
  'config.ops.migrationsWould': '{{count}} migration(s) would apply:',
  'config.ops.migrateFailed': 'The migration failed',
  'config.history.title': 'Configuration history',
  'config.history.unavailable': 'History unavailable.',
  'config.history.empty':
    'No snapshots yet — the first is taken before the next .env mutation.',
  'config.history.col.when': 'When',
  'config.history.col.snapshot': 'Snapshot',
  'config.history.col.actor': 'Actor',
  'config.history.col.reason': 'Reason',
  'config.history.col.changes': 'Changes',
  'config.history.col.file': 'File',
  'config.history.restore': 'Restore',
  'config.history.keysChanged': 'Keys: {{keys}}',
  'config.history.restartAfter':
    'Restart services after restoring (same step-up)',
  'config.history.restartQueued': 'restart queued · job {{id}}',
  'config.history.restored':
    'Snapshot {{id}} restored',
  'config.history.error': 'The rollback failed',
  'config.history.stepup':
    'Restoring this snapshot overwrites the live config — confirm your identity.',
  'config.history.confirmTitle': 'Restore config snapshot',
  'config.history.confirmBody':
    'This overwrites {{source}} with snapshot {{id}}. The current state is snapshotted first, so the rollback is reversible.',

  // --- Portal ----------------------------------------------------------------
  'portal.metrics.host': 'Host',
  'portal.metrics.os': 'OS',
  'portal.metrics.uptime': 'Uptime',
  'portal.metrics.cpu': 'CPU',
  'portal.metrics.ram': 'RAM',
  'portal.metrics.disk': 'Disk',
  // Metric formats — the backend emits <name>_fmt {key,params}
  // alongside the composed English string; the SPA localizes with
  // these templates.
  'metrics.fmt.cpu_load': 'Load: {{load}}',
  'metrics.fmt.cpu_pct': '{{pct}}%',
  'metrics.fmt.mem_usage': '{{pct}}% ({{used}} MB / {{total}} MB)',
  'metrics.fmt.disk_linux': '/ {{size}} ({{used}} used, {{pct}} full)',
  'metrics.fmt.disk_win': '{{drive}} {{pct}}% ({{free}} GB free)',
  'metrics.fmt.uptime': '{{h}}h {{m}}m',
  'portal.lan.title': 'LAN access',
  'portal.lan.desc': 'Local addresses of this machine.',
  'portal.services.title': 'Services',
  'portal.services.port': 'Port',
  'portal.services.link': 'Open',
  'portal.status.online': 'ONLINE',
  'portal.status.offline': 'OFFLINE',
  'portal.vncDirect.title': 'Direct VNC',
  'portal.vncDirect.desc':
    'Native VNC access (no browser) available on loopback.',
  'portal.vncDirect.loopback': 'Loopback only',
  'portal.banner.title': 'Guest session active',
  'portal.banner.role': 'Permission',
  'portal.banner.expiresIn': 'Expires in',
  'portal.banner.viewOnly': 'View only',
  'portal.banner.noTerminal': 'No terminal',
  'portal.banner.singleUse': 'Single use',
  'portal.sessions.title': 'Active sessions',
  'portal.sessions.empty': 'No active ephemeral sessions.',
  'portal.sessions.role': 'Permission',
  'portal.sessions.expires': 'Expires',
  'portal.sessions.uses': 'Uses',
  'portal.sessions.revoke': 'Revoke',
  'portal.sessions.revokeError': 'Could not revoke the session.',
  'portal.gamepad.desc': 'Live gamepad forwarding for games.',
  'portal.gamepad.resume': 'Resume gamepad',
  'portal.gamepad.stop': 'Stop',
  'portal.error.restricted': 'Access restricted to operators.',
  'portal.error.load': 'Could not load the portal.',
  'portal.adminLink': 'Administration panel →',
  'portal.shell.system': 'system shell',
  'portal.skipLink': 'Skip to content',
  'portal.tagline': 'Service access portal',
  'portal.sysinfo': 'System information',
  'portal.maintenance.title': 'Maintenance',
  'portal.maintenance.desc':
    'Access is temporarily limited to administrators.',
  'portal.features.title': 'Features',
  'portal.features.desktop.title': 'Remote desktop',
  'portal.features.desktop.desc':
    'Full VNC session in the browser via noVNC on {{os}}.',
  'portal.features.terminal.title': 'Web terminal',
  'portal.features.terminal.desc':
    'Interactive system shell in the browser ({{os}} · {{shell}}).',
  'portal.features.monitoring.title': 'Monitoring',
  'portal.features.monitoring.desc':
    'Health dashboard with live host metrics.',
  'portal.features.vnc.title': 'VNC access',
  'portal.features.vnc.desc':
    'VNC server listening on port {{port}} (native client).',
  'portal.features.tls.title': 'TLS',
  'portal.features.tls.secure': 'Encryption active — valid certificate.',
  'portal.features.tls.insecure': 'No certificate — plain HTTP.',
  'portal.features.lan.title': 'Local network',
  'portal.features.lan.desc':
    'The portal is reachable from other machines on your LAN.',
  'portal.creds.title': 'Credentials',
  'portal.creds.desc1': 'Credentials live in ',
  'portal.creds.desc2': ' and in ',
  'portal.creds.desc3':
    ' — they are never shown in this interface.',
  'portal.firewall.title': 'Firewall ({{os}})',
  'portal.firewall.desc':
    'Rules required for external access:',
  'portal.ssl.title': 'SSL certificate',
  'portal.ssl.desc': 'Portal TLS certificate status.',

  // --- Share link ---------------------------------------------------------------
  'share.error.network': 'Network error — please try again.',
  'share.error.expired': 'Link expired or already used.',
  'share.error.noToken': 'Incomplete link — the token is missing.',
  'share.flag.viewOnly': 'view only',
  'share.flag.singleUse': 'single use',
  'share.flag.noTerminal': 'no terminal',
  'share.flag.maxUses': 'max {{n}} uses',
  'share.title': 'Shared access',
  'share.discarded':
    'For security, the token was removed from the address bar.',
  'share.checking': 'Checking the link…',
  'share.grantPre': 'This link grants you',
  'share.action.view': 'view access',
  'share.action.viewControl': 'view and control access',
  'share.grantPost': 'to this machine.',
  'share.role': 'Permission',
  'share.expiresIn': 'Expires in',
  'share.restrictions': 'Restrictions',
  'share.activating': 'Activating session…',
  'share.accept': 'Accept and enter',
  'share.capTitle': 'This link will let the remote operator:',
  'share.cap.viewDesktop': 'See your desktop',
  'share.cap.controlDesktop': 'Control your keyboard and mouse',
  'share.cap.terminal': 'Open a terminal on your machine',
  'share.cap.audio': 'Hear your machine audio',
  'share.cap.gamepad': 'Use a gamepad on your machine',
  'share.cap.files': 'Access your files',
  'share.cap.chat': 'Chat with you',
  'share.cap.controlWarn':
    'Remote control lets them type and act on the machine as if ' +
    'they were sitting in front of it.',
  'share.expiresAuto':
    'The session closes automatically in {{time}}.',
  'share.endAnytime':
    'You can end it at any time from the guest portal.',
  'share.details': 'Technical details',
  'share.boundResource': 'Bound resource',

  // --- Audio ------------------------------------------------------------------
  'audio.title': 'Remote audio',
  'audio.connect': 'Connect',
  'audio.disconnect': 'Disconnect',
  'audio.volume': 'Volume',
  'audio.info.initial':
    'Press Connect to receive audio from the remote machine.',
  'audio.error.conn': 'Could not connect the audio.',
  'audio.state.streaming': 'streaming',
  'audio.state.connecting': 'connecting',
  'audio.state.error': 'error',
  'audio.state.disconnected': 'disconnected',
  'audio.bt.title': 'Bluetooth speaker',
  'audio.bt.desc':
    'Audio plays through the browser\'s default playback device.',

  // --- Gamepad ------------------------------------------------------------------
  'gamepad.title': 'Remote gamepad',
  'gamepad.connect': 'Connect',
  'gamepad.disconnect': 'Disconnect',
  'gamepad.scan': 'Scan for pads',
  'gamepad.info.initial':
    'Press Connect then Scan for pads to bind your local gamepad ' +
    'to the remote game.',
  'gamepad.info.connected': 'Gamepad channel open.',
  'gamepad.error.conn': 'Could not connect the gamepad channel.',
  'gamepad.pad.none': 'No gamepad detected.',
  'gamepad.pad.connected': 'Pad {{id}} sending.',
  'gamepad.pad.disconnected': 'Pad disconnected.',
  'gamepad.pad.found': 'Pad detected: {{id}}.',
  'gamepad.pad.notFound':
    'No gamepad found — press a button on the pad and retry.',
  'gamepad.state.connected': 'connected',
  'gamepad.state.connecting': 'connecting',
  'gamepad.state.error': 'error',
  'gamepad.state.disconnected': 'disconnected',
  'gamepad.bt.title': 'Bluetooth gamepad',
  'gamepad.bt.desc':
    'The browser exposes the pad via the Gamepad API; events are ' +
    'forwarded to the host over WebSocket.',
  'gamepad.stick.left': 'Left stick',
  'gamepad.stick.right': 'Right stick',

  // --- Audio/Gamepad short aliases (as used by the pages) ---------------------------
  'audio.unauthorized': 'Session is not authorized for audio.',
  'audio.noService':
    'This link does not grant access to the remote machine audio.',
  'audio.connectingTo': 'Connecting to {{url}}…',
  'audio.receiving': 'Receiving audio…',
  'audio.status':
    '{{clients}} listener(s) · device {{device}} · {{bitrate}} kbps',
  'audio.closed': 'Connection closed by the server.',
  'audio.error': 'Error: {{msg}}',
  'gamepad.unauthorized': 'Session is not authorized for gamepad.',
  'gamepad.serviceOff':
    'The gamepad service is not running on the host, or your ' +
    'session does not include that permission.',
  'gamepad.closed': 'Connection closed by the server.',
  'gamepad.revoked': 'Session revoked.',
  'gamepad.error': 'Error: {{msg}}',
  'portal.error.adminLink': 'Administration panel →',

  // --- Terminal -------------------------------------------------------------------
  'terminal.unauthorized': 'Session is not authorized for the terminal.',
  'terminal.reconnect': 'Reconnect',
  'terminal.find': 'Search the scrollback (Enter: next, Shift+Enter: previous)',
  'terminal.findPrev': 'Previous match',
  'terminal.findNext': 'Next match',
  'terminal.download': 'Download session transcript',
  'terminal.state.connected': 'connected',
  'terminal.state.connecting': 'connecting',
  'terminal.state.error': 'error',
  'terminal.state.disconnected': 'disconnected',

  // --- Login (extra) ----------------------------------------------------------------
  'login.networkError': 'Network error — the service may be down.',
  'login.passkeyFailed': 'Passkey authentication failed.',
  'webauthn.cancelled': 'Ceremony cancelled.',
  'login.passkeyWaiting': 'Waiting for your device…',
  'login.auditNote':
    'Sign-in attempts are recorded in the audit log.',

  // --- Sessions ----------------------------------------------------------------
  'sessions.title': 'Access links',
  'sessions.createTitle': 'New shared session',
  'sessions.role': 'Permission',
  'sessions.ttl': 'Duration (TTL)',
  'sessions.maxUses': 'Max uses',
  'sessions.resource': 'Resource',
  'sessions.ipRestriction': 'IP restriction',
  'sessions.ipPlaceholder': 'e.g. 192.168.1.10',
  // Finding severities — readable label; rank/colour still come
  // from the backend token.
  'security.sev.critical': 'Critical',
  'security.sev.high': 'High',
  'security.sev.medium': 'Medium',
  'security.sev.low': 'Low',
  'security.sev.warn': 'Warn',
  'security.sev.info': 'Info',
  'sessions.viewOnly': 'View only',
  'sessions.noTerminal': 'No terminal',
  'sessions.singleUse': 'Single use',
  'sessions.createLink': 'Create link',
  'sessions.createdTitle': 'Link created',
  'sessions.createdOnce':
    'This link is shown ONCE — share it now.',
  'sessions.copy': 'Copy',
  'sessions.createError': 'Could not create the session.',
  'sessions.revokeError': 'Could not revoke the session.',
  'sessions.revokeAllError': 'Could not revoke all sessions.',
  'sessions.inventory': 'Session inventory',
  'sessions.viewsAria': 'Session views',
  'sessions.revokeAll': 'Close all',
  'sessions.revokeAllConfirm': 'CLOSE ALL',
  'sessions.loadError': 'Could not load sessions.',
  'sessions.col.ref': 'Ref',
  'sessions.col.state': 'State',
  'sessions.col.role': 'Permission',
  'sessions.col.perms': 'Scope',
  'sessions.col.resource': 'Resource',
  'sessions.col.label': 'Label',
  'sessions.col.expires': 'Expires',
  'sessions.col.flags': 'Flags',
  'sessions.col.creator': 'Creator',
  'sessions.stateActive': 'active',
  'sessions.stateRevoked': 'revoked',
  'sessions.permCount_one': '{{count}} permission',
  'sessions.permCount_other': '{{count}} permissions',
  'sessions.revoke': 'Revoke',
  'sessions.revokeUndo':
    'Session {{id}} will be revoked in 10 seconds.',
  'sessions.revokeTitle': 'Revoke session',
  'sessions.revokeBody':
    'Session {{id}} ({{role}}{{resource}}) will be ' +
    'invalidated immediately.',
  'sessions.revokeBodyResource': ' on {{resource}}',
  'sessions.revokeAllTitle': 'Close all sessions',
  'sessions.revokeAllBody':
    'All {{count}} active sessions will be revoked. Connected ' +
    'guests lose access immediately.',
  'sessions.selectRow': 'Select link {{id}}…',
  'sessions.revokeSelected': 'Revoke selected ({{count}})',
  'sessions.bulkTitle': 'Revoke {{count}} sessions',
  'sessions.bulkBody':
    'The {{count}} selected links will stop being valid. Guests ' +
    'who have not joined yet will lose access.',
  'sessions.bulkRevokeUndo':
    '{{count}} sessions will be revoked in 10 seconds.',
  'sessions.revokeSomeFailed':
    '{{ok}} sessions revoked; {{failed}} failed.',
  'sessions.loadMore': 'Load more',
  'sessions.stepup.revokeAll': 'closing all active sessions',

  // --- Session creation wizard ---------------------------------------------------------
  'sessions.wizard.resources': 'Resource',
  'sessions.wizard.permissions': 'Permissions',
  'sessions.wizard.limits': 'Duration & restrictions',
  'sessions.wizard.review': 'Review',
  'sessions.wizard.next': 'Next',
  'sessions.wizard.back': 'Back',
  'sessions.wizard.resourceHint':
    'Recommended: bind the link to a single resource. Unbound ' +
    'tokens reach every resource their permissions allow.',
  'sessions.wizard.roleHint':
    'viewer = view only; support = assistance; operator = control ' +
    'and session management; administrator = full control.',
  'sessions.wizard.summaryTitle': 'Access summary',
  'sessions.wizard.ttlQuick': 'Quick duration',
  'sessions.wizard.custom': 'custom',
  'sessions.wizard.restrictions': 'Restrictions',
  'sessions.wizard.restrictionsNone':
    'None — reusable from any IP until it expires.',
  'sessions.wizard.riskUnbound':
    'No resource binding: the link will reach every resource its ' +
    'role allows.',
  'sessions.wizard.riskAdmin':
    'Administrator permission: full control of the remote system.',
  'sessions.wizard.maxUsesN': 'max {{count}} uses',
  'sessions.wizard.ipOnly': 'only from {{ip}}',
  'sessions.wizard.permission': 'Permission',
  'sessions.wizard.duration': 'Duration',
  'sessions.wizard.ttlInvalid': 'Between 60 seconds and 7 days (604800 s).',
  'sessions.wizard.maxUsesInvalid': 'Between 0 (unlimited) and 1000.',
  'sessions.wizard.ipInvalid':
    'A valid IP or CIDR (e.g. 192.168.1.10 or 10.0.0.0/24), ' +
    'or "first-observed".',
  'sessions.wizard.emailInvalid': 'Does not look like a valid email address.',
  'sessions.res.desktop': 'Remote desktop',
  'sessions.res.terminal': 'Terminal',
  'sessions.res.audio': 'Audio',
  'sessions.res.gamepad': 'Gamepad',
  'sessions.res.all': 'All allowed resources',
  'sessions.res.files': 'Files',
  'sessions.qrAlt': 'QR code for the share link',
  'sessions.emailTo': 'Email the link to (optional)',
  'sessions.emailPlaceholder': 'recipient@example.com',
  'sessions.label': 'Label (optional)',
  'sessions.labelPh': 'e.g. Juan support, Q3 demo',
  'sessions.labelEditAria': 'Edit label (Enter saves, Esc cancels)',
  'sessions.labelAdd': 'Add label',
  'sessions.labelError': 'Could not save the label.',
  'sessions.emailedOk': 'Link emailed to {{to}}.',
  'sessions.emailedFail':
    'Email delivery failed — copy the link manually.',
  'sessions.access.view': 'View only',

  // --- Access lifecycle split + detail -----------------------------------------
  'sessions.tab.invitations': 'Invitations',
  'sessions.tab.connections': 'Connections',
  'sessions.tab.history': 'History',
  'sessions.empty.invitations': 'No pending invitations.',
  'sessions.empty.createCta': '↑ Create a new link',
  'sessions.empty.connections': 'No connections in use.',
  'sessions.empty.history': 'No finished accesses.',
  'sessions.stateExpired': 'expired',
  'sessions.stateUsed': 'in use',
  'sessions.stateInvitation': 'invitation',
  'sessions.detail.title': 'Access',
  'sessions.detail.created': 'Created',
  'sessions.detail.createdBy': 'Created by',
  'sessions.detail.uses': 'Uses',
  'sessions.detail.notFound':
    'Access not found — it may have expired or been reaped.',
  'sessions.detail.back': '← Back to accesses',
  'sessions.detail.lastUsed': 'Last used',
  'sessions.detail.lastIp': 'Last used IP',
  'sessions.detail.lastConnected': 'Last connected',
  'sessions.detail.lastDisconnected': 'Last disconnected',
  'sessions.detail.connectionCount': 'Total connections',
  'sessions.detail.duration': 'Duration',
  'sessions.detail.liveConnections': 'Live connections now',
  'sessions.tl.title': 'Timeline',
  'sessions.tl.created': 'Invite created',
  'sessions.tl.activated': 'Link used',
  'sessions.tl.connected': 'Connection started',
  'sessions.tl.disconnected': 'Connection closed',
  'sessions.tl.revoked': 'Session revoked',
  'sessions.detail.tabsAria': 'Session sections',
  'sessions.detail.tab.summary': 'Summary',
  'sessions.detail.tab.activity': 'Activity',
  'sessions.detail.tab.chat': 'Chat',
  'sessions.detail.noActivity': 'No live connections.',
  'sessions.detail.chatEnded':
    'The session is no longer active — chat is closed.',
  'sessions.detail.exportAudit': 'Export audit (JSON)',

  // --- Entity detail pages ----------------------------------------------------
  'users.detail.title': 'Operator',
  'users.detail.back': '← Back to operators',
  'jobs.detail.title': 'Job',
  'jobs.detail.notFound': 'Job not found.',
  'jobs.detail.back': '← Back to jobs',
  'jobs.detail.started': 'Started',
  'jobs.detail.finished': 'Finished',
  'jobs.detail.claimedBy': 'Runner',
  'jobs.detail.payload': 'Payload',

  // --- Guest portal (/guest) -------------------------------------------------
  'guest.title': 'Guest portal',
  'guest.subtitle':
    'The resources your shared link grants access to.',
  'guest.role': 'Permission',
  'guest.expires': 'Expires',
  'guest.resources': 'Available resources',
  'guest.endSession': 'End session',
  'guest.none':
    'No active guest session — this page is for share-link ' +
    'recipients.',
  'guest.expired': 'The session has expired or was revoked.',
  'guest.expiringSoon': 'Less than 10 minutes left — ask the operator for a new invite if you need more time.',
  'guest.portalLink': 'Back to portal',
  'guest.resDesc.desktop': 'Remote desktop in the browser',
  'guest.resDesc.terminal': 'Web terminal',
  'guest.resDesc.audio': 'Live audio receiver',
  'guest.resDesc.gamepad': 'Gamepad forwarding',
  'guest.resDesc.files': 'Shared file folder',
  'chat.title': 'Session chat',
  'chat.placeholder': 'Type a message…',
  'chat.send': 'Send',
  'chat.sendError': 'Message could not be sent',
  'chat.empty': 'No messages yet.',
  'chat.unavailable': 'Chat unavailable.',
  'chat.notify': 'Notify on new messages',
  'files.title': 'Shared files',
  'files.subtitle': 'Shared folder on the remote host.',
  'files.dropHint': 'Drop files onto this page to upload them.',
  'files.breadcrumb': 'Current path',
  'files.rootDir': 'Root folder',
  'files.upload': 'Upload',
  'files.queue': 'Transfers',
  'files.clearDone': 'Clear finished',
  'files.st.queued': 'queued',
  'files.st.uploading': 'uploading…',
  'files.st.done': 'done',
  'files.st.error': 'error',
  'files.st.cancelled': 'cancelled',
  'files.cancelUpload': 'Cancel this upload',
  'files.newDir': 'new-folder',
  'files.mkdir': 'Create folder',
  'files.download': 'Download',
  'files.col.name': 'Name',
  'files.col.size': 'Size',
  'files.col.mtime': 'Modified',
  'files.empty': 'Empty folder.',
  'files.truncated': 'Listing truncated: too many entries.',
  'files.loadError': 'Could not list the folder.',
  'files.uploadError': 'Upload failed.',
  'files.mkdirError': 'Could not create the folder.',
  'files.tooBig': 'File exceeds the allowed size limit.',

  // --- Connection center (/admin/connect) ------------------------------------
  'connect.title': 'Connections',
  'connect.subtitle':
    'Direct access to the remote system and shared links.',
  'connect.direct': 'Direct access',
  'connect.directDesc':
    'Connection surfaces available on this host.',
  'connect.grants': 'Active links',
  'connect.grantsDesc':
    'Currently valid shared access — full management under Sessions.',
  'connect.newLink': 'Create link',
  'connect.manage': 'Manage',
  'connect.guestView': 'Guest view',
  'connect.empty': 'No active links.',

  // --- Recovery (/recovery) ----------------------------------------------------
  'recovery.title': 'Emergency access',
  'recovery.subtitle':
    'Use a single-use recovery code if you lost your second factor.',
  'recovery.username': 'Username',
  'recovery.password': 'Password',
  'recovery.code': 'Recovery code',
  'recovery.submit': 'Sign in',
  'recovery.busy': 'Verifying…',
  'recovery.error': 'Invalid credentials.',
  'recovery.usedNote':
    'Each recovery code is single-use: it is consumed on sign-in.',
  'recovery.where':
    'No codes? An administrator can generate them under ' +
    'Security → Secrets or with "vnc-remote secrets recovery-codes".',
  'recovery.back': '← Back to portal',

  // --- Users (operators) --------------------------------------------------------------
  'users.title': 'Operators',
  'users.confirmDeleteWord': 'DELETE',
  'users.subtitle':
    'Operator accounts, permissions, sessions and passkeys.',
  'users.loadError': 'Could not load operators.',
  'users.newOperator': 'New operator',
  'users.username': 'Username',
  'users.role': 'Role',
  'users.state': 'State',
  'users.perms': 'Permissions',
  'users.created': 'Created',
  'users.actions': 'Actions',
  'users.empty': 'No operators registered.',
  'users.systemTitle': 'System users',
  'users.systemSubtitle':
    'OS accounts managed by the application.',
  'users.sessionsRevoked':
    'Sessions of operator {{name}} revoked.',
  'users.stepup.delete': 'deleting operator {{name}}',
  'users.stepup.revoke':
    'revoking sessions of operator {{name}}',
  'users.revokeTitle': 'Revoke sessions',
  'users.revokeAll': 'Revoke sessions',
  'users.revokeBody':
    'All active sessions of operator {{name}} will be invalidated.',
  'users.deleteTitle': 'Delete operator',
  'users.deleteBody':
    'Operator {{name}} will be marked as deleted ' +
    '(soft delete, recorded in the audit log).',
  'users.tempPassword': 'Temporary password:',
  'users.createFailed': 'Could not create the operator.',
  'users.creating': 'Creating…',
  'users.statusActive': 'active',
  'users.statusDisabled': 'disabled',
  'users.permCount_one': '{{count}} permission',
  'users.permCount_other': '{{count}} permissions',
  'users.enable': 'Enable',
  'users.disable': 'Disable',
  'users.revokeSessions': 'Revoke sessions',
  'users.detailError': 'Could not load operator details.',
  'users.passkeyCount_one': '{{count}} passkey',
  'users.passkeyCount_other': '{{count}} passkeys',
  'users.protected': 'protected',
  'users.passkeys': 'Passkeys',
  'users.noPasskeys': 'No passkeys registered.',
  'users.passkeyName': 'Name',
  'users.passkeyRegistered': 'Passkey registered.',
  'users.passkeySigns': 'Sign count',
  'users.passkeyRenameAria': 'Rename passkey',
  'users.rename': 'Rename',
  'users.revoke': 'Revoke',
  'users.registerFailed': 'Could not register the passkey.',
  'users.passkeyNameAria': 'Passkey name',
  'users.passkeyNamePlaceholder': 'Work laptop',
  'users.registering': 'Registering…',
  'users.registerPasskey': 'Register passkey',
  'users.webauthnUnsupported':
    'This browser does not support WebAuthn.',
  'users.passkeysUnavailable':
    'Passkeys are unavailable: WebAuthn is not enabled on this ' +
    'server (missing the webauthn extra or RP configuration).',
  'users.stepup.passkey': 'registering a passkey',
  'users.passkeyRevokeTitle': 'Revoke passkey',
  'users.passkeyRevokeBody':
    'Passkey {{ref}} will no longer be able to authenticate.',

  // --- System users ----------------------------------------------------------------
  'systemUsers.loadError': 'Could not load system users.',
  'systemUsers.opCreate': 'creating a system user',
  'systemUsers.opDelete': 'deleting system user {{name}}',
  'systemUsers.username': 'Username',
  'systemUsers.usernameAria': 'System user name',
  'systemUsers.usernamePlaceholder': 'e.g. vnc-operator',
  'systemUsers.passwordAria': 'System user password',
  'systemUsers.passwordPlaceholder': 'secure password',
  'systemUsers.create': 'Create system user',
  'systemUsers.home': 'Home',
  'systemUsers.actions': 'Actions',
  'systemUsers.empty': 'No managed system users.',
  'systemUsers.deleteTitle': 'Delete system user',
  'systemUsers.confirmWord': 'DELETE',
  'systemUsers.deleteBody':
    'User {{name}} will be removed from the system. This does ' +
    'not affect panel operators.',

  // --- Deleted operators ---------------------------------------------------------
  'deletedOps.title': 'Deleted operators',
  'deletedOps.subtitle':
    'Soft delete: restorable while the record persists.',
  'deletedOps.username': 'Username',
  'deletedOps.role': 'Role',
  'deletedOps.deletedAt': 'Deleted',
  'deletedOps.actions': 'Actions',
  'deletedOps.restore': 'Restore',
  'deletedOps.restoreTitle': 'Restore operator',
  'deletedOps.restoreBody':
    'Operator {{name}} will be active again with their ' +
    'previous permissions.',
  'deletedOps.stepup.restore': 'restoring operator {{name}}',
  'deletedOps.restoreFailed': 'Could not restore the operator.',

  // --- DataTable / bits -----------------------------------------------------------
  'table.errorText': 'Failed to load data.',
  'table.emptyText': 'No data to show.',
  'table.selectAll': 'Select all rows',
  'table.selectRow': 'Select row',
  'bits.expired': 'expired',
  'bits.ago': '{{d}} ago',
  'bits.copyRef': 'Copy reference {{id}}',
  'bits.copied': 'Copied to clipboard.',
  'bits.copyFail': 'Could not copy to the clipboard.',
  'keys.title': 'Keyboard shortcuts',
  'keys.palette': 'Command palette — jump to any section',
  'keys.this': 'This help',
  'keys.esc': 'Closes dialogs, panels and immersive mode',
  'keys.tab': 'Cycles through dialog controls',
  'lang.label': 'Language',
};
