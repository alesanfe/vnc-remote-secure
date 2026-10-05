# Operations

Runbooks y procedimientos operativos de la instancia desplegada.

| Documento | Contenido |
|---|---|
| [../runbook](../runbook) | Runbooks por incidente (servicio caído, cert caducado, disco lleno…) |
| [../installation](../installation) | Instalación por plataforma (Linux/Pi/Windows) |
| [../migration](../migration) | Migraciones de versión y config |
| [../FEATURE_FLAGS.md](../FEATURE_FLAGS.md) | Flags y knobs de `.env` |
| [../policies](../policies) | Políticas de retención/seguridad |

## Procedimientos habituales

```bash
vnc-remote doctor        # diagnóstico completo (config, puertos, certs, firewall)
vnc-remote status        # estado de servicios
vnc-remote backup        # backup cifrado
vnc-remote restore       # restauración con auto-rollback
vnc-remote session list  # sesiones activas
vnc-remote session revoke <id>
```

Ver también `../user-guide/troubleshooting.md` para diagnóstico
paso a paso.
