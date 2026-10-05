# Deprecations — vnc-remote-secure

Política: los endpoints `/api/v1/*` y los knobs de `.env` están
versionados y son estables — los cambios incompatibles se anuncian
en CHANGELOG con una release de solapamiento.

## Activas

*(ninguna actualmente)*

## Aplicadas

| Elemento | Sustituto | Notas |
|---|---|---|
| Share links `?session=` legacy | `/share#t=` (token en fragmento) | El token ya no llega al servidor — anunciado en CHANGELOG |
| `docs/adr/` | `docs/decisions/` | Renombrado por consistencia con el resto de repos |
| Plantillas de issue `.yml` | `.md` (bug/feature/security_report) | Paridad de formato en el workspace |
