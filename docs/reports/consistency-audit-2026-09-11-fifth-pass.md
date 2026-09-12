# Fifth-Pass Consistency Audit — vnc-remote-secure

**Date:** 2026-09-11 (fifth pass)
**Scope:** Full 9-category inconsistency review using the user's pattern.
**Method:** 4 parallel subagents covering categories 1-2, 3-4, 5-6, 7-8-9.
**Previous audits:**
- `docs/reports/consistency-audit-2026-09-11.md` (35 findings, pass 1)
- `docs/reports/consistency-audit-2026-09-11-second-pass.md` (18 findings, pass 2)
- `docs/reports/consistency-audit-2026-09-11-third-pass.md` (12 findings, pass 3)
- `docs/reports/consistency-audit-2026-09-11-fourth-pass.md` (6 findings, pass 4)

---

## Summary

42 raw findings from 4 parallel subagents. After deduplication, 39 unique inconsistencies identified, renumbered INC-072 through INC-110.

| Category | Count |
|---|---|
| 1 — Requisitos vs comportamiento | 4 |
| 2 — Documentación vs código | 10 |
| 3 — Arquitectura y estructura | 6 |
| 4 — API y modelos de datos | 4 |
| 5 — Configuración y despliegue | 3 |
| 6 — Seguridad | 5 |
| 7 — Errores y observabilidad | 3 |
| 8 — Pruebas | 3 |
| 9 — Calidad y mantenibilidad | 3 |
| **Duplicates merged** | 3 |

| Severity | Count |
|---|---|
| Crítica | 2 |
| Alta | 13 |
| Media | 17 |
| Baja | 7 |

| Type | Count |
|---|---|
| Error confirmado | 22 |
| Inconsistencia probable | 10 |
| Riesgo potencial | 5 |
| Mejora opcional | 2 |

---

## INC-072: Rutas de firewall incorrectas en documentación
- Categoría: 2 — Documentación
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: README.md:67, docs/installation/windows.md:58-61, docs/installation/uninstall.md:52, native/windows/README.md:37-40
- Evidencia: README y docs citan `scripts/Manage-Firewall.ps1` que no existe. El archivo real es `native/windows/Firewall.ps1`.
- Esperado: Documentos citan `.\native\windows\Firewall.ps1 -Action Create|List|Verify|Remove`.
- Actual: Ejemplos apuntan a script inexistente.
- Impacto: Usuarios Windows no pueden configurar firewall siguiendo la docs.
- Solución: Sustituir `scripts\Manage-Firewall.ps1` por `native\windows\Firewall.ps1` en toda la docs.
- Esfuerzo: Pequeño
- Prueba: `Test-Path native/windows/Firewall.ps1` → True; `Test-Path scripts/Manage-Firewall.ps1` → False.

## INC-073: Rutas de Duck DNS incorrectas en README
- Categoría: 2 — Documentación
- Severidad: Media | Confianza: Alta | Tipo: Error confirmado
- Archivos: README.md:296-298
- Evidencia: README cita `scripts/duckdns_update.sh` pero el archivo está en `scripts/utilities/duckdns_update.sh`.
- Solución: Actualizar rutas a `scripts/utilities/duckdns_update.*`.
- Esfuerzo: Pequeño
- Prueba: `ls scripts/utilities/duckdns_update.*` existe.

## INC-074: Variables VNC_REMOTE_PROFILE y TLS_ENABLED documentadas pero no consumidas
- Categoría: 2 — Documentación
- Severidad: Media | Confianza: Alta | Tipo: Inconsistencia probable
- Archivos: .env.example:319-323, launch.sh, VncRemote.ps1, cli.py
- Evidencia: `.env.example` documenta ambas variables pero `launch.sh` y `VncRemote.ps1` no las leen.
- Solución: Implementar soporte o eliminar de `.env.example`.
- Esfuerzo: Medio/Pequeño

## INC-075: Ejemplos de audio/gamepad con nombres de script inexistentes
- Categoría: 2 — Documentación
- Severidad: Media | Confianza: Alta | Tipo: Error confirmado
- Archivos: .env.example:365, services/audio.py:17-18, services/gamepad.py:17
- Evidencia: Docstrings y `.env.example` citan `audio_stream_server.py` y `gamepad_server.py` que no existen.
- Solución: Usar `python3 -m vnc_remote_secure.services.audio --list-devices`.
- Esfuerzo: Pequeño

## INC-076: README promete certificados autofirmados automáticos en Linux
- Categoría: 2 — Documentación
- Severidad: Media | Confianza: Alta | Tipo: Inconsistencia probable
- Archivos: README.md:453, src/lib/security/ssl.sh:123-128
- Evidencia: README dice "Self-signed certificates generated automatically (Linux)" pero `ssl.sh` deshabilita SSL si falta `DUCK_DOMAIN`.
- Solución: Aclarar que Linux requiere `DUCK_DOMAIN` para Let's Encrypt.
- Esfuerzo: Pequeño

## INC-077: CHANGELOG no refleja la versión actual del proyecto
- Categoría: 2 — Documentación
- Severidad: Baja | Confianza: Alta | Tipo: Inconsistencia probable
- Archivos: CHANGELOG.md:10, pyproject.toml:7, cli.py:34, constants.py:5
- Evidencia: CHANGELOG en 0.1.0 pero versión real es 0.2.0.
- Solución: Añadir sección `## [0.2.0]`.
- Esfuerzo: Pequeño

## INC-078: Variables USER_UI_SESSION_TIMEOUT y TRUSTED_PROXY usadas pero no documentadas
- Categoría: 2 — Documentación
- Severidad: Media | Confianza: Alta | Tipo: Inconsistencia probable
- Archivos: src/lib/web/user_ui_app.py:31,71, .env.example
- Evidencia: Código lee ambas variables pero `.env.example` no las documenta.
- Solución: Añadir a `.env.example`.
- Esfuerzo: Pequeño

## INC-079: VncRemote.ps1 depende de launch.sh aunque está deprecated
- Categoría: 2 — Documentación
- Severidad: Media | Confianza: Alta | Tipo: Inconsistencia probable
- Archivos: launch.sh:1-5, VncRemote.ps1:224,251, AGENTS.md:24-25
- Evidencia: `launch.sh` marcado como deprecated pero `VncRemote.ps1` lo invoca.
- Solución: Migrar a `vnc-remote install/start`.
- Esfuerzo: Medio

## INC-080: FLASK_SECRET_KEY duplicado en .env.example
- Categoría: 2 — Documentación
- Severidad: Baja | Confianza: Alta | Tipo: Mejora opcional
- Archivos: .env.example:196-198, .env.example:281-284
- Evidencia: La clave aparece dos veces.
- Solución: Eliminar la segunda aparición.
- Esfuerzo: Pequeño

## INC-081: Instalador Windows no crea reglas de firewall
- Categoría: 1 — Requisitos
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: docs/installation/windows.md:56-61, VncRemote.ps1:182-225
- Evidencia: Docs dicen "installer creates firewall rule" pero `Install-VncRemote` nunca invoca `Firewall.ps1`.
- Solución: Llamar a `Firewall.ps1 -Action Create` en `Install-VncRemote`.
- Esfuerzo: Medio

## INC-082: Makefile win-run-nossl no inicia en modo HTTP
- Categoría: 1 — Requisitos
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: Makefile:134-136, launch.sh:23-26, cli.py:126-136
- Evidencia: `win-run-nossl` ejecuta `vnc-remote start` sin `--no-ssl`; `cli.py` no acepta `--no-ssl`.
- Solución: Hacer que `vnc-remote start` acepte `--no-ssl`.
- Esfuerzo: Medio

## INC-083: README requiere binarios UltraVNC sin mecanismo de provisión
- Categoría: 1 — Requisitos
- Severidad: Alta | Confianza: Alta | Tipo: Riesgo potencial
- Archivos: README.md:159, launch.sh:147-152, third_party/manifests/ultravnc.json:10-17
- Evidencia: `managed_by: manual` — sin descarga automática, la instalación Windows falla.
- Solución: Descarga automática o advertencia explícita en docs.
- Esfuerzo: Medio/Grande

## INC-084: VncRemote.ps1 no encuentra bash.exe en Git for Windows típico
- Categoría: 1 — Requisitos
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: VncRemote.ps1:209-221
- Evidencia: Busca `bash.exe` en el mismo dir que `git.exe` (`cmd/`), pero está en `bin/`.
- Solución: `Join-Path (Split-Path $gitDir -Parent) 'bin\bash.exe'`.
- Esfuerzo: Pequeño

## INC-085: Lógica de plataforma directa en services/landing.py
- Categoría: 3 — Arquitectura
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: services/landing.py:98-305
- Evidencia: `if platform.system() == 'Windows':` con PowerShell, wmic, `ip addr`, `free -m`, `df -h` directamente en services/.
- Solución: Extraer a `platform/{linux,windows}/metrics.py`.
- Esfuerzo: Medio

## INC-086: Lógica de plataforma directa en monitoring/health.py
- Categoría: 3 — Arquitectura
- Severidad: Media | Confianza: Alta | Tipo: Error confirmado
- Archivos: monitoring/health.py:31-48
- Evidencia: `wmic` y `/proc/loadavg` directamente en el módulo común.
- Solución: Delegar a `platform/{linux,windows}/metrics.py`.
- Esfuerzo: Pequeño

## INC-087: services/vnc.py gestiona binarios específicos de OS
- Categoría: 3 — Arquitectura
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: services/vnc.py:50-84
- Evidencia: `shutil.which('winvnc')` / `tigervncserver` / `taskkill` directamente en services/.
- Solución: Añadir `start_vnc()`/`stop_vnc()` al `PlatformAdapter`.
- Esfuerzo: Medio

## INC-088: services/audio.py y gamepad.py implementan lógica específica de plataforma
- Categoría: 3 — Arquitectura
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: services/audio.py:71-147, services/gamepad.py:49-226
- Evidencia: `pactl`, `arecord`, `dshow`, `evdev`, `ctypes.windll.user32` directamente en services/.
- Solución: Mover inyectores a `platform/{linux,windows}/input.py`.
- Esfuerzo: Grande

## INC-089: services/terminal.py usa CREATE_NO_WINDOW incondicionalmente
- Categoría: 3 — Arquitectura
- Severidad: Crítica | Confianza: Alta | Tipo: Error confirmado
- Archivos: services/terminal.py:557-565
- Evidencia: `creationflags=subprocess.CREATE_NO_WINDOW` se pasa en todos los SO. En Linux, `CREATE_NO_WINDOW` no existe → `AttributeError`.
- Solución: Condicionar `if is_windows(): creationflags=...`.
- Esfuerzo: Pequeño
- Prueba: Ejecutar terminal en Linux sin `AttributeError`.

## INC-090: Responsabilidades duplicadas entre Bash/lib y paquete Python
- Categoría: 3 — Arquitectura
- Severidad: Media | Confianza: Alta | Tipo: Riesgo potencial
- Archivos: src/lib/monitoring/health_web_server.py, services/health.py, src/lib/web/user_ui_app.py, web/routes/users.py
- Evidencia: Dos stacks paralelos (Bash y Python) implementan health server y user UI.
- Solución: Deprecar Bash versions a favor del paquete Python.
- Esfuerzo: Grande

## INC-091: Contrato del endpoint /health no coincide con implementación Flask
- Categoría: 4 — API
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: docs/user-guide/health.md:8-21, web/routes/health.py:13-24, services/health.py:74-103
- Evidencia: Docs dicen HTML dashboard; Flask devuelve JSON.
- Solución: Unificar o actualizar docs.
- Esfuerzo: Medio

## INC-092: Modelos de sesión inconsistentes entre las dos UIs
- Categoría: 4 — API
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: src/lib/web/user_ui_app.py:30-39, web/routes/users.py:30-109
- Evidencia: Bash UI usa `session['logged_in']`; Flask usa `session['user']`. Listas de usuarios reservados difieren (`pi` vs `www-data`).
- Solución: Unificar en `security/authentication.py`.
- Esfuerzo: Medio

## INC-093: Códigos y métodos HTTP inconsistentes en web/routes/users.py
- Categoría: 4 — API
- Severidad: Media | Confianza: Alta | Tipo: Inconsistencia probable
- Archivos: web/routes/users.py:51-55,72-109
- Evidencia: `/logout` es GET sin CSRF; `POST /api/users` devuelve 201 sin crear; `GET /api/users` devuelve lista vacía estática.
- Solución: POST+CSRF para logout; 204 en DELETE; poblar GET.
- Esfuerzo: Medio

## INC-094: Esquema de configuración no cubre todas las variables
- Categoría: 4 — API
- Severidad: Media | Confianza: Alta | Tipo: Inconsistencia probable
- Archivos: config/schema/config.schema.json, .env.example
- Evidencia: Schema no define `USER_UI_PASSWORD`, `HEALTH_AUTH_TOKEN`, `LANDING_PASSWORD`, `USER_UI_PORT`, `TTYD_HOST`.
- Solución: Sincronizar schema con `.env.example`.
- Esfuerzo: Medio

## INC-095: get_config() y defaults Python/Bash no alineados con .env.example
- Categoría: 5 — Configuración
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: .env.example, core/config.py:88-153, src/lib/core/config.sh:51-161, core/constants.py
- Evidencia: Python omite `USER_UI_PORT`, `FLASK_SECRET_KEY`, `AUTH_SECRET`, `LANDING_HOST`, `LANDING_PASSWORD`, `VNC_HTTP_PORT`. Bash usa `VNC_DISPLAY=:2`/`1920x1080` vs Python/`.env.example` `:1`/`1280x720`. `config.sh` ignora `SSL_CERT`/`SSL_KEY` del entorno.
- Solución: Extender `get_config()`; alinear defaults; respetar `SSL_CERT`/`SSL_KEY` en `config.sh`.
- Esfuerzo: Medio
- Nota: Absorbe INC-075 (VNC_HTTP_PORT) e INC-079 (VNC_GEOMETRY/DISPLAY) del subagent 1.

## INC-096: config/defaults/common.env fuerza puertos de Windows en Linux
- Categoría: 5 — Configuración
- Severidad: Media | Confianza: Alta | Tipo: Error confirmado
- Archivos: config/defaults/common.env:5,8, config/defaults/linux.env, README.md:250-253
- Evidencia: `common.env` define `VNC_PORT=5900`/`HEALTH_WEB_PORT=8090` (Windows); `linux.env` no sobrescribe.
- Solución: Mover puertos a `linux.env`/`windows.env`.
- Esfuerzo: Pequeño

## INC-097: Dependencias declaradas no usadas y usadas no declaradas
- Categoría: 5 — Configuración
- Severidad: Media | Confianza: Alta | Tipo: Error confirmado
- Archivos: pyproject.toml:38, src/lib/web/user_ui_app.py:17
- Evidencia: `pycryptodome` declarado pero sin imports. `werkzeug` importado pero no declarado.
- Solución: Eliminar `pycryptodome`; añadir `werkzeug`.
- Esfuerzo: Pequeño

## INC-098: Autenticación desigual en servicios y rutas Flask
- Categoría: 6 — Seguridad
- Severidad: Crítica | Confianza: Alta | Tipo: Error confirmado
- Archivos: web/routes/health.py:13-18, web/routes/landing.py:12-13, src/lib/monitoring/health_web_server.py:543-555
- Evidencia: `require_auth` definido en `http_auth.py` pero no usado en blueprints Flask. Health server Bash sin auth. Landing routes Flask abiertas.
- Solución: Aplicar `@require_auth` en blueprints; añadir auth en health server Bash.
- Esfuerzo: Medio

## INC-099: Runtime Python no valida contraseñas, a diferencia de Bash
- Categoría: 6 — Seguridad
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: core/config.py:88-98, core/validation.py:67-104, launch.sh:58-69
- Evidencia: `get_config()` lee/genera contraseñas sin llamar `validate_password`. `launch.sh` tampoco valida.
- Solución: Llamar `validate_password` en `get_config()` y `launch.sh`.
- Esfuerzo: Medio

## INC-100: Fallback de config.sh puede generar la contraseña prohibida "ChangeMe!"
- Categoría: 6 — Seguridad
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: src/lib/core/config.sh:17-43, src/lib/core/validation.sh:61-68
- Evidencia: Fallback genera `ChangeMe!<5dígitos>` que `validate_password` rechaza.
- Solución: Usar fallback que no contenga patrones débiles.
- Esfuerzo: Pequeño

## INC-101: launch.sh fuerza KEEP_TEMP_USER=true ignorando el default
- Categoría: 6 — Seguridad
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: launch.sh:299, .env.example:386
- Evidencia: `export KEEP_TEMP_USER=true` incondicional; default es `false`.
- Solución: `export KEEP_TEMP_USER="${KEEP_TEMP_USER:-false}"`.
- Esfuerzo: Pequeño

## INC-102: print() sin migrar a logging en services/
- Categoría: 7 — Errores/Observabilidad
- Severidad: Media | Confianza: Alta | Tipo: Error confirmado
- Archivos: services/audio.py (28), gamepad.py (17), terminal.py (10), landing.py (3), novnc.py (4), health.py (2)
- Evidencia: 64 llamadas `print()` en services/ que ignoran `LOG_LEVEL` y filtros.
- Solución: Reemplazar por `logger.<nivel>()`.
- Esfuerzo: Grande
- Nota: Duplicado entre subagents 3 y 4; consolidado aquí.

## INC-103: Excepciones genéricas capturadas y silenciadas
- Categoría: 7 — Errores/Observabilidad
- Severidad: Alta | Confianza: Alta | Tipo: Error confirmado
- Archivos: platform/windows/installer.py:52-56, web/routes/users.py:64-68
- Evidencia: `except Exception: pass` sin logging en instalador y validación de sesión.
- Solución: `log_exception` antes de `pass`; capturar excepciones específicas.
- Esfuerzo: Pequeño

## INC-104: Formatos de respuesta de error no unificados en health.py
- Categoría: 7 — Errores/Observabilidad
- Severidad: Media | Confianza: Alta | Tipo: Inconsistencia probable
- Archivos: services/health.py:88-103, core/errors.py:12,32
- Evidencia: `health.py` incrusta JSON a mano (`b'{"error": true, ...}'`) en vez de usar `error_json()`.
- Solución: Importar y usar `error_json` en health.py.
- Esfuerzo: Pequeño

## INC-105: Servicios sin pruebas unitarias
- Categoría: 8 — Pruebas
- Severidad: Alta | Confianza: Alta | Tipo: Riesgo potencial
- Archivos: services/audio.py, gamepad.py, terminal.py, novnc.py
- Evidencia: No existen `test_audio.py`, `test_gamepad.py`, `test_terminal.py`, `test_novnc.py`.
- Solución: Añadir tests con mocks de asyncio, websockets, subprocess.
- Esfuerzo: Grande

## INC-106: Tests que solo comprueban tipo o no-nulidad
- Categoría: 8 — Pruebas
- Severidad: Media | Confianza: Alta | Tipo: Inconsistencia probable
- Archivos: tests/unit/services/test_health.py:24,38, tests/unit/services/test_landing.py:76,115, tests/unit/core/test_config.py:14,34
- Evidencia: Muchas aserciones son `isinstance` o `is not None` sin validar contenido.
- Solución: Añadir aserciones sobre valores concretos.
- Esfuerzo: Medio

## INC-107: Tests condicionales por plataforma
- Categoría: 8 — Pruebas
- Severidad: Baja | Confianza: Alta | Tipo: Riesgo potencial
- Archivos: tests/e2e/{linux,windows}/test_cli.py:8, tests/integration/{linux,windows}/test_platform_detection.py:11
- Evidencia: `@pytest.mark.skipif` hace que tests Windows no corran en Linux y viceversa.
- Solución: Parametrizar con `monkeypatch` de `platform.system()`.
- Esfuerzo: Medio

## INC-108: Nombres duplicados para contraseña de terminal
- Categoría: 9 — Calidad
- Severidad: Media | Confianza: Alta | Tipo: Inconsistencia probable
- Archivos: services/landing.py:60-62, services/terminal.py:552-554, security/authentication.py:55, security/http_auth.py:63
- Evidencia: Se mezclan `TTYD_PASSWD`, `TTYD_PASSWORD`, `USER_UI_PASSWORD` para el mismo concepto.
- Solución: Unificar a `TTYD_PASSWD` con alias documentado.
- Esfuerzo: Medio

## INC-109: Constantes mágicas y puertos hardcodeados
- Categoría: 9 — Calidad
- Severidad: Media | Confianza: Alta | Tipo: Riesgo potencial
- Archivos: services/novnc.py:13, services/vnc.py:19-23, services/landing.py:562, services/audio.py:54-120
- Evidencia: Puertos `6080`, `5900`, `5000`, `7777`, `7788` y timeouts como literales dispersos.
- Solución: Usar constantes de `core/constants.py`.
- Esfuerzo: Medio

## INC-110: Variables y módulo sin uso tras refactorización
- Categoría: 9 — Calidad
- Severidad: Baja | Confianza: Media | Tipo: Riesgo potencial
- Archivos: services/landing.py:45,60,62, src/vnc_remote_secure/constants.py
- Evidencia: `PROJECT_DIR`, `VNC_PASSWORD`, `TTYD_PASSWORD` en landing.py se asignan y nunca se leen. `constants.py` duplica `core.constants` sin consumidores.
- Solución: Eliminar variables muertas; fusionar/eliminar `constants.py`.
- Esfuerzo: Pequeño

---

## Duplicates merged

1. **INC-075 (VNC_HTTP_PORT)** del subagent 1 → absorbido en **INC-095** (subagent 3).
2. **INC-079 (VNC_GEOMETRY/DISPLAY defaults)** del subagent 1 → absorbido en **INC-095** (subagent 3).
3. **INC-072 (print() en services)** del subagent 4 = **INC-079 (print() en services)** del subagent 3 → consolidado en **INC-102**.

---

## Priority action plan

### Crítica (2) — fix inmediato
- INC-089: `CREATE_NO_WINDOW` en Linux → `AttributeError`
- INC-098: Rutas Flask sin autenticación

### Alta (13) — fix prioritario
- INC-072: Docs firewall path incorrecto
- INC-081: Instalador no crea firewall rules
- INC-082: `win-run-nossl` no funciona
- INC-083: UltraVNC sin provisión automática
- INC-084: `bash.exe` no encontrado en Git for Windows
- INC-085: Lógica plataforma en landing.py
- INC-087: Lógica plataforma en vnc.py
- INC-088: Lógica plataforma en audio/gamepad
- INC-091: Contrato /health no coincide
- INC-092: Modelos sesión inconsistentes
- INC-095: get_config() incompleto
- INC-099: Python no valida contraseñas
- INC-100: Fallback genera contraseña prohibida
- INC-101: `KEEP_TEMP_USER=true` forzado
- INC-103: Excepciones silenciadas
- INC-105: Servicios sin tests
