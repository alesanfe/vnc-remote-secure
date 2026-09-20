# 🔒 Security Guide

This project includes multiple security features to protect your Raspberry Pi remote access system.

## 🛡️ Built-in Security Features

### Network Security
- **SSL/TLS Encryption**: All traffic encrypted between browser and Raspberry Pi
- **Rate Limiting**: Application-layer auth lockouts and per-IP endpoint throttling protect against brute force
- **Fail2ban Integration**: Automatic IP blocking for failed login attempts

### Application Security
- **Input Sanitization**: All inputs validated to prevent command injection
- **Temporary User Isolation**: Remote access uses dedicated user with limited privileges
- **Session Management**: Automatic cleanup when sessions end
- **Security Headers**: HTTP headers prevent web-based attacks

### System Security
- **Process Isolation**: Services run with minimal privileges
- **Automatic Cleanup**: Resources removed when sessions end
- **Certificate Management**: Let's Encrypt certificates renew via
  certbot's own timer (the app symlinks the live certs, so renewals are
  picked up automatically). Self-signed certificates do NOT auto-renew —
  the TLS validation warns 30 days before expiry so the operator can
  regenerate them.

## 🔐 Authentication

### Password Requirements
- **Length**: 8+ characters (enforced by `validate_password` via `MIN_PASSWORD_LENGTH`)
- **Complexity**: Uppercase, lowercase, numbers, symbols
- **Different passwords** for VNC and terminal access

> Note: VNC's legacy DES protocol truncates the password to 8 characters, so
> longer passwords do not increase VNC auth strength. Use HTTPS/VPN/SSH
> tunneling for transport security.

### User Management
The project creates a temporary user for remote sessions:
- Limited privileges (no sudo by default)
- Isolated home directory
- Automatic cleanup on session end
- Separate from system accounts

### Session Features
- Automatic timeout after inactivity
- IP tracking for access monitoring
- All authentication attempts logged
- Resources removed when sessions end

## 🛡️ Network Security

### SSL/TLS
- **Automatic certificates** from Let's Encrypt when `DUCK_DOMAIN` +
  `EMAIL` are configured (certbot renews; live certs are symlinked)
- **Expiry warnings**: TLS validation flags certificates expiring in
  under 30 days; self-signed certs must be regenerated manually
- **TLS 1.2/1.3** protocols only
- **HSTS support** for enhanced security

### Rate Limiting and DDoS Protection

**Built-in Rate Limiting:**
Authentication and per-endpoint rate limiting is enforced at the
application layer (`security/rate_limit.py`), backed by the shared-state
store so limits hold across service processes:

- **Auth attempts**: `AUTH_MAX_ATTEMPTS` failures inside
  `AUTH_WINDOW_SECONDS` trigger an `AUTH_LOCKOUT_SECONDS` lockout,
  tracked per IP and per username.
- **Endpoint throttling**: unauthenticated endpoints (e.g.
  `/health/live`) are rate-limited per IP.
- **WebSocket upgrades**: rejected connections are counted against the
  same limiter.

> Note: the bundled `nginx.conf` template does not define `limit_req`
> zones; request-rate limits live in the application so they apply with
> or without the reverse proxy. Operators who want edge-level limiting
> can add `limit_req_zone`/`limit_req` directives to their nginx config.

**Protection Benefits:**
- **Brute Force Prevention**: failed logins lock the source IP/account
- **DDoS Mitigation**: open endpoints cannot be hammered without cost
- **Resource Protection**: auth flood cannot exhaust worker capacity
- **Cross-process coverage**: limits hold even when services run as
  separate processes (SQLite shared-state backend)

## 🔍 Monitoring and Detection

Effective security requires continuous monitoring and threat detection capabilities.

### Health Monitoring and Anomaly Detection

**System Health Monitoring:**
The built-in health check system monitors various security-relevant metrics:

```bash
# Security monitoring via the health service (authenticated endpoints)
curl -sf -H "Authorization: Bearer $HEALTH_AUTH_TOKEN" \
    http://127.0.0.1:8080/health/all   # CPU, memory, disk, services
vnc-remote status                     # per-service health summary
vnc-remote doctor                     # readiness + security findings
```

**Anomaly Detection:**
- **Resource Spikes**: Unusual CPU or memory usage may indicate attacks
- **Access Patterns**: Monitor for abnormal access times or frequencies
- **Failed Attempts**: Track and analyze failed authentication attempts
- **Certificate Issues**: Alert for SSL certificate problems

### Logging and Audit Trail

**Comprehensive Logging:**
All security-relevant events are logged for analysis and forensics:

```bash
# Security logging locations
/var/log/nginx/access.log     # Web access logs
/var/log/nginx/error.log      # Web server errors
/var/log/auth.log            # Authentication attempts
/var/log/syslog              # System security events
```

**Log Analysis:**
- **Access Patterns**: Identify suspicious access patterns or times
- **Failed Logins**: Monitor for brute force attempts
- **Geographic Analysis**: Detect access from unusual locations
- **Traffic Analysis**: Identify unusual traffic patterns or volumes

### Alerting and Notification

**Automated Security Alerts:**
The system can send notifications for security events:

```bash
# Alert configuration
ALERTS_ENABLED=true
ALERT_EMAIL_TO=your-email@your-domain.duckdns.org
DISCORD_ENABLED=true
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

**Alert Types:**
- **Security Events**: Failed authentication, suspicious activity
- **System Issues**: Resource exhaustion, service failures
- **Certificate Problems**: Expiration warnings, renewal failures
- **Access Anomalies**: Unusual access patterns or locations

## 🚀 Advanced Security Configuration

For enhanced security in production environments, consider these advanced configurations.

### Firewall Configuration

**UFW Configuration:**
```bash
# Simplified firewall with UFW
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw deny 6080/tcp
ufw deny 5000/tcp
ufw enable
```

### Intrusion Detection and Prevention

**Fail2ban Configuration:**
Enhance Fail2ban rules for specific protection:

```bash
# Fail2ban jail configuration
[sshd]
enabled = true
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
maxretry = 5
bantime = 7200
```

**Custom Security Rules:**
- **Geographic Blocking**: Restrict access from specific countries
- **Time-based Access**: Limit access to specific hours
- **IP Whitelisting**: Only allow access from trusted IP addresses
- **Rate Limiting**: Custom limits for different user types

### Security Hardening

**System Hardening:**
```bash
# Security hardening steps
# 1. Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups

# 2. Secure SSH configuration
sudo nano /etc/ssh/sshd_config
# PermitRootLogin no
# PasswordAuthentication no
# PubkeyAuthentication yes

# 3. Update system regularly
sudo apt update && sudo apt upgrade -y

# 4. Install security updates automatically
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades
```

**Application Security:**
- **Regular Updates**: Keep all software updated with security patches
- **Minimal Services**: Run only necessary services to reduce attack surface
- **Secure Defaults**: Use secure default configurations
- **Regular Audits**: Periodically review and update security settings

## 📋 Security Checklist

Use this comprehensive checklist to ensure your system remains secure:

### Daily Security Tasks
- [ ] Review access logs for suspicious activity
- [ ] Check system resource usage for anomalies
- [ ] Verify SSL certificate status
- [ ] Monitor failed authentication attempts

### Weekly Security Tasks
- [ ] Update system packages and security patches
- [ ] Review and rotate passwords if needed
- [ ] Check firewall rules and configurations
- [ ] Backup security configurations and logs

### Monthly Security Tasks
- [ ] Conduct comprehensive security audit
- [ ] Review and update security policies
- [ ] Test backup and recovery procedures
- [ ] Update documentation and procedures

### Quarterly Security Tasks
- [ ] Perform penetration testing (if applicable)
- [ ] Review and update threat models
- [ ] Update incident response procedures
- [ ] Conduct security training and awareness

## 🚨 Incident Response

Even with strong security measures, incidents can occur. Having a response plan ensures quick and effective handling.

### Security Incident Types

**Common Incidents:**
- **Brute Force Attacks**: Repeated failed login attempts
- **Unauthorized Access**: Successful login by unauthorized users
- **Denial of Service**: Service unavailability due to overload
- **Data Breach**: Unauthorized access to sensitive information

### Response Procedures

**Immediate Response:**
1. **Assess Impact**: Determine scope and severity of the incident
2. **Contain Threat**: Isolate affected systems or services
3. **Preserve Evidence**: Collect logs and system state for analysis
4. **Notify Stakeholders**: Inform relevant parties about the incident

**Recovery Actions:**
1. **Eliminate Threat**: Remove malicious access or software
2. **Restore Services**: Bring systems back online securely
3. **Monitor Systems**: Watch for continued suspicious activity
4. **Post-Incident Review**: Analyze what happened and improve defenses

### Prevention Measures

**After Incident:**
- **Update Security**: Strengthen protections based on lessons learned
- **Update Procedures**: Improve incident response procedures
- **Training**: Educate users on security best practices
- **Monitoring**: Enhance monitoring and detection capabilities

## 📚 Security Resources

Stay informed about security best practices and emerging threats:

### Documentation and Guides
- **[Configuration](configuration.md)**: Detailed security settings
- **[Troubleshooting Guide](../user-guide/troubleshooting.md)**: Security-related issues
- **[Architecture Overview](overview.md)**: Security architecture details

### External Resources
- **OWASP Guidelines**: Web application security best practices
- **NIST Cybersecurity Framework**: Comprehensive security framework
- **CIS Benchmarks**: Security configuration benchmarks
- **Security Blogs**: Stay updated on latest threats and protections

---

**Remember**: Security is an ongoing process, not a one-time configuration. Regular monitoring, updates, and awareness are essential for maintaining a secure remote access system.
