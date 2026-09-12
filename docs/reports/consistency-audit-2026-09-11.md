# Informe de Auditoría de Inconsistencias — vnc-remote-secure

**Fecha:** 2026-09-11
**Método:** Inspección estática de archivos + verificación con `git ls-files`, `Test-Path`, y lectura directa de código. No se ejecutaron tests ni se modificó código.
**Alcance:** Repositorio completo en `C:\Users\alex0\PycharmProjects\vnc-remote-secure`

## Clasificación de hallazgos

Cada hallazgo se clasifica como:
- **Error confirmado**: evidencia verificada en múltiples archivos; el comportamiento difiere del esperado.
- **Inconsistencia probable**: evidencia sólida pero no se ejecutó para confirmar el fallo en runtime.
- **Riesgo potencial**: condición que podría causar problemas bajo ciertas circunstancias.
- **Mejora opcional**: no es un error, pero mejorararía mantenibilidad.

---

## INC-001: Credenciales reales en `.runtime_credentials.json` sin protección de gitignore

- **Categoría:** Seguridad
- **Severidad:** Crítica
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `.runtime_credentials.json` (raíz), `.gitignore`
- **Evidencia:** El archivo `.runtime_credentials.json` existe en el árbol de trabajo y contiene:
  ```json
  {
      "VNC_PASSWORD":  "S3kszS5uEu7q",
      "TTYD_USERNAME":  "alex0",
      "TTYD_PASSWD":  "j:G\\i^T]MpcJ_[]O"
  }
  ```
  `git check-ignore -v .runtime_credentials.json` no devuelve coincidencia (no está ignorado). `git ls-files` no lo lista (no está trackeado actualmente), pero al no estar en `.gitignore`, un `git add .` lo commitearía.
- **Comportamiento esperado:** Los archivos de credenciales runtime deben estar en `.gitignore` y nunca ser commiteados.
- **Comportamiento actual:** El archivo existe con credenciales reales y no está protegido por `.gitignore`.
- **Impacto:** Si un desarrollador ejecuta `git add .` o `git add -A`, las credenciales reales (VNC y terminal) se commitean al repositorio. Fuga de credenciales.
- **Solución propuesta:** Añadir `.runtime_credentials.json` y `*.runtime_credentials.json` a `.gitignore`. Considerar rotar las credenciales expuestas.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `git check-ignore -v .runtime_credentials.json` debe devolver una coincidencia. `git add --dry-run .` no debe listar el archivo.

---

## INC-002: CLI Python `start` en Linux ejecuta `launch.sh` (launcher Windows) en lugar de `src/rpi-vnc-remote.sh`

- **Categoría:** Arquitectura / CLI
- **Severidad:** Crítica
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `src/vnc_remote_secure/cli.py:133-136`, `launch.sh:1-6`
- **Evidencia:**
  `cli.py` líneas 133-136:
  ```python
  if _is_windows():
      return _run_powershell(project_root, 'VncRemote.ps1', ['Start'])
  else:
      return _run_bash_script(project_root, 'launch.sh')
  ```
  `launch.sh` línea 1-2:
  ```bash
  # VNC Remote Secure - Windows launcher (compatibility wrapper)
  # DEPRECATED: Use 'vnc-remote start' instead.
  ```
  `launch.sh` invoca `winvnc.exe`, `cygpath`, `ipconfig`, `taskkill` (comandos Windows).
- **Comportamiento esperado:** En Linux, `vnc-remote start` debe ejecutar `src/rpi-vnc-remote.sh start` (como hace el wrapper Bash `vnc-remote` y el `Makefile`).
- **Comportamiento actual:** En Linux, el CLI Python ejecuta `launch.sh`, que es un launcher Windows/Git-Bash. Fallará en Linux real.
- **Impacto:** `vnc-remote start` (vía Python CLI) no funciona en Linux. El wrapper Bash `vnc-remote` sí funciona, pero quien use el entrypoint Python `vnc-remote = vnc_remote_secure.cli:main` en Linux obtendrá un fallo.
- **Solución propuesta:** Cambiar la rama `else` a `_run_bash_script(project_root, 'src/rpi-vnc-remote.sh', ['start'])`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** En Linux, ejecutar `python -m vnc_remote_secure start --dry-run` y verificar que referencia `src/rpi-vnc-remote.sh`, no `launch.sh`.

---

## INC-003: `kill_all.sh` referenciado por CLI/PowerShell pero no existe en el repositorio

- **Categoría:** Arquitectura / Rutas
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `src/vnc_remote_secure/cli.py:149-151`, `VncRemote.ps1:268-274`, `native/windows/VncRemote.psm1:268-274`, `.gitignore:96`
- **Evidencia:**
  `cli.py` líneas 149-151:
  ```python
  kill_script = os.path.join(project_root, 'kill_all.sh')
  if os.path.exists(kill_script):
      return _run_bash_script(project_root, 'kill_all.sh')
  ```
  `Test-Path kill_all.sh` → `False`. `find_file_by_name` no encontró ningún `kill_all.sh`. `.gitignore:96` lo ignora (línea residual de cuando existía).
- **Comportamiento esperado:** El comando `stop` debe tener un script de limpieza funcional.
- **Comportamiento actual:** `kill_all.sh` no existe. En Linux, `vnc-remote stop` (Python CLI) imprime "No stop script found" y devuelve código 1.
- **Impacto:** El comando `stop` no funciona vía Python CLI en Linux.
- **Solución propuesta:** Crear `scripts/maintenance/stop.sh` (o restaurar `kill_all.sh`) y actualizar las referencias en `cli.py`, `VncRemote.ps1`, y `VncRemote.psm1`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `vnc-remote stop` (Python CLI) debe encontrar y ejecutar el script de parada.

---

## INC-004: Scripts de mantenimiento referenciados en ruta incorrecta (`scripts/` en vez de `scripts/maintenance/`)

- **Categoría:** Arquitectura / Rutas
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:**
  - `src/vnc_remote_secure/cli.py:219,236,249`
  - `vnc-remote` (raíz Bash) líneas 469, 489, 505
  - `VncRemote.ps1:51-53,598,628`
  - `VncRemote.psm1:51-53`
- **Evidencia:**
  `cli.py`:
  ```python
  return _run_bash_script(project_root, 'scripts/backup.sh')      # línea 219
  return _run_bash_script(project_root, 'scripts/restore.sh', ...) # línea 236
  return _run_bash_script(project_root, 'scripts/uninstall.sh')   # línea 249
  ```
  Archivos reales (verificado con `Get-ChildItem scripts/maintenance`):
  - `scripts/maintenance/backup.sh`
  - `scripts/maintenance/restore.sh`
  - `scripts/maintenance/uninstall.sh`
  Los archivos `scripts/backup.sh`, `scripts/restore.sh`, `scripts/uninstall.sh` NO existen.
- **Comportamiento esperado:** Los CLIs deben apuntar a `scripts/maintenance/`.
- **Comportamiento actual:** Apuntan a `scripts/` (raíz de scripts), donde no existen.
- **Impacto:** Los comandos `backup`, `restore`, `uninstall` fallan en Python CLI, Bash wrapper y PowerShell.
- **Solución propuesta:** Actualizar todas las referencias a `scripts/maintenance/backup.sh`, `scripts/maintenance/restore.sh`, `scripts/maintenance/uninstall.sh`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `vnc-remote backup --dry-run` debe encontrar el script en `scripts/maintenance/`.

---

## INC-005: `src/rpi-vnc-remote.sh` llama a `scripts/duckdns_update.sh` (ruta incorrecta)

- **Categoría:** Arquitectura / Rutas
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `src/rpi-vnc-remote.sh:197`
- **Evidencia:**
  ```bash
  if bash "$PROJECT_DIR/scripts/duckdns_update.sh"; then
  ```
  `Test-Path scripts/duckdns_update.sh` → `False`.
  `Test-Path scripts/utilities/duckdns_update.sh` → `True`.
  El `Makefile` (líneas 310-323) y `launch.sh:101` usan la ruta correcta `scripts/utilities/duckdns_update.sh`.
- **Comportamiento esperado:** Usar `scripts/utilities/duckdns_update.sh`.
- **Comportamiento actual:** Usa `scripts/duckdns_update.sh` que no existe.
- **Impacto:** La actualización de DuckDNS falla en Linux cuando se ejecuta vía `src/rpi-vnc-remote.sh`.
- **Solución propuesta:** Cambiar la línea 197 a `scripts/utilities/duckdns_update.sh`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `bash -n src/rpi-vnc-remote.sh` pasa y la ruta del script existe.

---

## INC-006: `VncRemote.ps1` referencia `scripts\Manage-Firewall.ps1` que no existe

- **Categoría:** Arquitectura / Rutas
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `VncRemote.ps1:649-651`, `VncRemote.psm1:649-651`, `README.md:67`, `docs/installation/windows.md:58-60`, `docs/installation/uninstall.md:52`, `tests/powershell/VncRemote.Tests.ps1:22,160`, `tests/windows/VncRemote.Tests.ps1:22,160`
- **Evidencia:**
  `VncRemote.ps1:649`:
  ```powershell
  $fwScript = Join-Path $script:ProjectDir 'scripts\Manage-Firewall.ps1'
  if (Test-Path $fwScript) {
      & $fwScript -Action Remove
  }
  ```
  `Test-Path scripts/Manage-Firewall.ps1` → `False`.
  `Test-Path native/windows/Firewall.ps1` → `True`.
- **Comportamiento esperado:** Referenciar `native/windows/Firewall.ps1`.
- **Comportamiento actual:** Referencia un script inexistente. El bloque `if (Test-Path ...)` no se ejecuta, así que el firewall no se limpia en `stop`/`uninstall`.
- **Impacto:** Reglas de firewall no se eliminan al desinstalar. Acumulación de reglas obsoletas.
- **Solución propuesta:** Cambiar la ruta a `native/windows/Firewall.ps1` y actualizar docs y tests.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `Test-Path` de la ruta referenciada devuelve `True`.

---

## INC-007: `native/linux/bin/vnc-remote` usa variable `SCRIPT_ROOT` indefinida

- **Categoría:** Calidad / Empaquetado Linux
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `native/linux/bin/vnc-remote:7-8`
- **Evidencia:**
  ```bash
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  PROJECT_ROOT="$(cd "$SCRIPT_ROOT/../.." && pwd)"
  ```
  `SCRIPT_ROOT` nunca se define; solo se define `SCRIPT_DIR`. Con `set -euo pipefail`, la variable indefinida causa salida inmediata.
- **Comportamiento esperado:** `PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"`.
- **Comportamiento actual:** El script falla inmediatamente por variable indefinida.
- **Impacto:** El wrapper Linux nativo no funciona en absoluto.
- **Solución propuesta:** Reemplazar `SCRIPT_ROOT` por `SCRIPT_DIR` en la línea 8.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `bash native/linux/bin/vnc-remote status` no falla por variable indefinida.

---

## INC-008: Makefile pasa flags `--profile` y `--force` no soportados por los CLIs

- **Categoría:** Build / Makefile
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `Makefile:134-139`, `src/vnc_remote_secure/cli.py:288-294,309-312`, `vnc-remote` (raíz) líneas 520-538
- **Evidencia:**
  `Makefile`:
  ```makefile
  win-run-nossl:
      @./vnc-remote start --profile local
  win-stop:
      @./vnc-remote stop --force
  ```
  Los subparsers de `cli.py` solo soportan `--dry-run`, `--json`, `--verbose`, `--quiet`.
  El wrapper Bash `vnc-remote` solo soporta `--verbose`, `--quiet`, `--json`, `--dry-run`.
- **Comportamiento esperado:** Los flags del Makefile deben ser reconocidos por el CLI.
- **Comportamiento actual:** `make win-run-nossl` y `make win-stop` fallan con "unrecognized arguments".
- **Impacto:** Targets del Makefile rotos.
- **Solución propuesta:** Eliminar los flags no soportados del Makefile o añadir soporte en los parsers.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `make win-stop` no devuelve error de argumentos.

---

## INC-009: Defaults de puertos `VNC_PORT` y `HEALTH_WEB_PORT` no son platform-aware

- **Categoría:** Configuración / Cross-platform
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Inconsistencia probable
- **Archivos afectados:**
  - `.env.example:42` (`VNC_PORT=5901`), `:162` (`HEALTH_WEB_PORT=8080`)
  - `src/vnc_remote_secure/core/constants.py:4` (`DEFAULT_VNC_PORT = 5900`), `:7` (`DEFAULT_HEALTH_PORT = 8090`)
  - `src/vnc_remote_secure/core/config.py:87,90`
  - `config/defaults/common.env:3,5,8`
  - `vnc-remote` (raíz) líneas 230,233,240,243
  - `README.md:250,253`
- **Evidencia:**
  | Variable | `.env.example` | Python/constants | `common.env` | Bash `vnc-remote` | README |
  |---|---|---|---|---|---|
  | `VNC_PORT` | 5901 | 5900 | 5900 | 5901 (Linux) | 5900 Win / 5901 Linux |
  | `HEALTH_WEB_PORT` | 8080 | 8090 | 8090 | 8080 (Linux) | 8090 Win / 8080 Linux |

  Los comentarios en `.env.example` indican que Linux usa 5901/8080 y Windows 5900/8090, pero el código Python siempre defaulta a 5900/8090 sin distinguir plataforma.
- **Comportamiento esperado:** Los defaults Python deben ser platform-aware: Linux 5901/8080, Windows 5900/8090.
- **Comportamiento actual:** Python siempre usa 5900/8090. En Linux sin `.env` explícito, los puertos no coinciden con la documentación.
- **Impacto:** En Linux, si no se setea `.env`, los servicios Python usan puertos distintos a los que la documentación y el wrapper Bash esperan. Conflicto de puertos y confusión operativa.
- **Solución propuesta:** Hacer que `core/constants.py` o `core/config.py` detecten la plataforma y usen defaults distintos.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** En Linux sin `.env`, `python -c "from vnc_remote_secure.core.config import get_config; print(get_config().vnc_port)"` devuelve 5901.

---

## INC-010: Variables de entorno leídas por Python pero ausentes de `.env.example`

- **Categoría:** Documentación / Configuración
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:**
  - `.env.example` (ausencias)
  - `src/vnc_remote_secure/services/landing.py:38-40,55` (`LANDING_HOST`, `SSL_CERT`, `SSL_KEY`, `LANDING_PASSWORD`)
  - `src/vnc_remote_secure/services/health.py:105` (`HEALTH_WEB_HOST`)
  - `src/vnc_remote_secure/services/terminal.py:39,46-48,313` (`TTYD_USERNAME`, `TTYD_PASSWD`, `WEBTERM_SHELL`, `SSL_CERT`, `SSL_KEY`, `ALLOWED_LAN_IPS`)
  - `src/vnc_remote_secure/security/authentication.py:34` (`AUTH_SECRET`)
  - `src/vnc_remote_secure/web/application.py:43` (`SESSION_COOKIE_SECURE`)
  - `src/vnc_remote_secure/services/novnc.py:28` (`SERVE_NOVNC_HOST`)
  - `src/lib/web/user_ui_app.py:26,31,71` (`SESSION_COOKIE_SECURE`, `USER_UI_SESSION_TIMEOUT`, `TRUSTED_PROXY`)
- **Evidencia:** Estas variables se leen vía `os.environ.get`/`os.getenv` en código Python pero no aparecen en `.env.example`. Solo `SSL_DIR` (comentado) y `SSL_RENEW_DAYS` aparecen; `SSL_CERT`/`SSL_KEY` no.
- **Comportamiento esperado:** `.env.example` debe documentar todas las variables que el código lee.
- **Comportamiento actual:** Variables configurables no documentadas. El usuario no sabe que existen.
- **Impacto:** Configuración incompleta. El usuario no puede configurar SSL, hosts de binding, shell del terminal, ni seguridad de cookies desde `.env.example`.
- **Solución propuesta:** Añadir todas las variables faltantes a `.env.example` con comentarios explicativos.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `grep` de cada variable Python en `.env.example` devuelve coincidencia.

---

## INC-011: Nombres de toggles inconsistentes: `*_ENABLED` (runtime) vs `ENABLE_*` (defaults/schema)

- **Categoría:** Configuración / Nomenclatura
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:**
  - `config/defaults/common.env:12-15` → `ENABLE_RECORDING`, `ENABLE_AUDIO`, `ENABLE_GAMEPAD`, `ENABLE_USER_UI`
  - `config/schema/config.schema.json:86-98` → `ENABLE_RECORDING`, `ENABLE_AUDIO`, `ENABLE_GAMEPAD`, `ENABLE_USER_UI`
  - `.env.example:169,268,286,182` → `RECORDING_ENABLED`, `AUDIO_STREAM_ENABLED`, `GAMEPAD_ENABLED`, `USER_UI_ENABLED`
  - `src/lib/core/config.sh:116,121` → exporta `RECORDING_ENABLED`, `USER_UI_ENABLED`
  - `src/lib/features/recording.sh`, `src/lib/web/user_ui.sh` → usan `*_ENABLED`
- **Evidencia:** El código Bash runtime y `.env.example` usan `*_ENABLED`. Los archivos `config/defaults/common.env` y el schema JSON usan `ENABLE_*`. Como el loader Bash exporta `*_ENABLED`, un usuario que setee `ENABLE_*` en `common.env` será ignorado.
- **Comportamiento esperado:** Una sola convención de nombres.
- **Comportamiento actual:** Dos convenciones conflictivas. Los valores en `common.env` con `ENABLE_*` no tienen efecto.
- **Impacto:** Configuraciones de recording/audio/gamepad/user-ui en `common.env` se ignoran silenciosamente.
- **Solución propuesta:** Renombrar `ENABLE_*` en `common.env` y `config.schema.json` a `*_ENABLED`, o hacer que el loader acepte ambas.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** Setear `ENABLE_RECORDING=true` en `common.env` y verificar que el recording se activa (o que el loader advierte del nombre incorrecto).

---

## INC-012: `VNC_GEOMETRY` y `VNC_DISPLAY` tienen defaults distintos entre Python y Bash

- **Categoría:** Configuración / Defaults
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Inconsistencia probable
- **Archivos afectados:**
  - `VNC_GEOMETRY`: `.env.example:229` (1920x1080), `config/defaults/common.env:3` (1280x720), `core/constants.py:9` (1280x720), `src/lib/core/config.sh:140` (1920x1080)
  - `VNC_DISPLAY`: `.env.example:226` (:2), `config/defaults/common.env:2` (1), `src/lib/core/config.sh:139` (:2), `src/vnc_remote_secure/services/vnc.py:26` (:1)
- **Evidencia:**
  | Variable | `.env.example` | `common.env` | Python constants | Bash config.sh |
  |---|---|---|---|---|
  | `VNC_GEOMETRY` | 1920x1080 | 1280x720 | 1280x720 | 1920x1080 |
  | `VNC_DISPLAY` | :2 | 1 | :1 (en vnc.py) | :2 |
- **Comportamiento esperado:** Un default consistente o platform-aware documentado.
- **Comportamiento actual:** Defaults contradictorios. La resolución VNC y el display number cambian según qué launcher se use.
- **Impacto:** Experiencia inconsistente. En Linux vía Bash se obtiene 1920x1080 en display :2; vía Python se obtiene 1280x720 en display :1.
- **Solución propuesta:** Unificar defaults en `core/constants.py` y `config/defaults/common.env`, alineados con `.env.example`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** Los defaults de Python y Bash coinciden para las mismas variables.

---

## INC-013: `LANDING_HOST` y `HEALTH_WEB_HOST` tienen defaults conflictivos (`0.0.0.0` vs `127.0.0.1`)

- **Categoría:** Seguridad / Configuración
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Inconsistencia probable
- **Archivos afectados:**
  - `src/vnc_remote_secure/services/landing.py:38` → `os.environ.get('LANDING_HOST', '0.0.0.0')`
  - `src/vnc_remote_secure/services/health.py:105` → `os.environ.get('HEALTH_WEB_HOST', '0.0.0.0')`
  - `src/vnc_remote_secure/core/config.py:104-105` → `0.0.0.0`
  - `src/lib/monitoring/health_web_server.py:621` → `os.environ.get('HEALTH_WEB_HOST', '127.0.0.1')`
  - `launch.sh:80-81` → `127.0.0.1`
  - `src/lib/core/config.sh:63` → `127.0.0.1`
  - `README.md:255-256` → `127.0.0.1`
- **Evidencia:** Los servicios Python (`vnc_remote_secure.services.*`) defaultan a `0.0.0.0` (bind todas las interfaces). El launcher Bash, la lib legacy y la documentación defaultan a `127.0.0.1` (solo localhost).
- **Comportamiento esperado:** Default seguro (`127.0.0.1`) con opt-in explícito para exponer en LAN.
- **Comportamiento actual:** Python expone servicios en `0.0.0.0` por defecto, contradiciendo la documentación y el principio de menor privilegio.
- **Impacto:** Los servicios Python (landing, health) se exponen en todas las interfaces sin configuración explícita. Riesgo de exposición no intencionada en redes no confiables.
- **Solución propuesta:** Cambiar defaults Python a `127.0.0.1` y requerir opt-in explícito (`0.0.0.0`) para LAN.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** Sin `.env`, los servicios Python hacen bind en `127.0.0.1`.

---

## INC-014: Ruta del binario UltraVNC inconsistente entre `launch.sh` y `VncRemote.ps1`

- **Categoría:** Calidad / Windows
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:**
  - `launch.sh:139` → `bin/ultravnc/x64/winvnc.exe`
  - `scripts/utilities/configure_ultravnc_gui.py:109,117` → `bin/ultravnc/x64/winvnc.exe`
  - `VncRemote.ps1:445` → `bin\ultravnc\winvnc.exe` (sin `x64`)
  - `VncRemote.psm1:445` → `bin\ultravnc\winvnc.exe` (sin `x64`)
  - `third_party/manifests/ultravnc.json:13` → `bin/winvnc.exe`
- **Evidencia:** Verificado que `bin/ultravnc/x64/winvnc.exe` SÍ existe en el árbol de trabajo. Pero `VncRemote.ps1` busca `bin\ultravnc\winvnc.exe` (sin subdirectorio `x64`), que NO existe. El manifest del downloader usa `bin/winvnc.exe` (tercera ruta distinta).
- **Comportamiento esperado:** Una ruta canónica para el binario UltraVNC.
- **Comportamiento actual:** Tres rutas distintas. `VncRemote.ps1` y el downloader no encontrarán el binario.
- **Impacto:** `VncRemote.ps1 Start` no encuentra `winvnc.exe`. El downloader lo coloca en una ruta que ningún launcher usa.
- **Solución propuesta:** Estandarizar a `bin/ultravnc/x64/winvnc.exe` (que es donde está) y actualizar `VncRemote.ps1`, `VncRemote.psm1`, y `ultravnc.json`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `Test-Path` de la ruta referenciada por `VncRemote.ps1` devuelve `True`.

---

## INC-015: `pycryptodome` importado pero no declarado en `pyproject.toml`

- **Categoría:** Dependencias
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `scripts/utilities/generate_vnc_password.py:43-49`, `pyproject.toml:32-39`
- **Evidencia:**
  `generate_vnc_password.py:43`:
  ```python
  from Crypto.Cipher import DES
  ```
  `pyproject.toml` declara: `Flask`, `tornado`, `websockify`, `cryptography`, `websockets`, `websocket-client`. No declara `pycryptodome` ni `pycryptodomex`.
- **Comportamiento esperado:** Toda dependencia importada debe estar declarada.
- **Comportamiento actual:** `generate_vnc_password.py` falla con `ImportError` si `pycryptodome` no está instalado manualmente.
- **Impacto:** La generación de password UltraVNC no funciona en una instalación limpia.
- **Solución propuesta:** Añadir `pycryptodome>=3.20` a `pyproject.toml` (en dependencias o `optional-dependencies`).
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** En un venv limpio, `python scripts/utilities/generate_vnc_password.py --help` no falla por `ImportError`.

---

## INC-016: `websocket-client` declarado en `pyproject.toml` pero no usado en el código

- **Categoría:** Dependencias
- **Severidad:** Baja
- **Confianza:** Alta
- **Tipo:** Mejora opcional
- **Archivos afectados:** `pyproject.toml:38`
- **Evidencia:** `grep` de `websocket-client`, `websocket_client`, `from websocket` en `src/` solo coincide con la declaración en `pyproject.toml`. El código usa `tornado.websocket` y `websockets` (paquete distinto), no `websocket-client`.
- **Comportamiento esperado:** Solo declarar dependencias usadas.
- **Comportamiento actual:** Dependencia declarada sin uso.
- **Impacto:** Superficie de ataque y tamaño de instalación innecesarios.
- **Solución propuesta:** Eliminar `websocket-client` de `pyproject.toml`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `pip install -e .` no instala `websocket-client`. Los tests siguen pasando.

---

## INC-017: Versión de `VncRemote.ps1` (0.1.0) no coincide con el resto del proyecto (0.2.0)

- **Categoría:** Calidad / Versionado
- **Severidad:** Baja
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `VncRemote.ps1:46`, `VncRemote.psm1:46`, `pyproject.toml:7`, `src/vnc_remote_secure/cli.py:34`, `src/vnc_remote_secure/core/constants.py:2`
- **Evidencia:**
  `VncRemote.ps1:46`: `$script:Version = '0.1.0'`
  `pyproject.toml:7`: `version = "0.2.0"`
  `cli.py:34`: `__version__ = "0.2.0"`
- **Comportamiento esperado:** Versión consistente en todos los entrypoints.
- **Comportamiento actual:** PowerShell reporta 0.1.0, Python reporta 0.2.0.
- **Impacto:** Confusión sobre qué versión está ejecutándose. Scripts de diagnóstico pueden reportar versiones equivocadas.
- **Solución propuesta:** Actualizar `VncRemote.ps1` y `VncRemote.psm1` a `0.2.0`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `.\VncRemote.ps1 Get-Version` devuelve `0.2.0`.

---

## INC-018: Terminal web ejecuta comandos shell arbitrarios del usuario sin validación

- **Categoría:** Seguridad
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Riesgo potencial (comportamiento intencional pero arriesgado)
- **Archivos afectados:** `src/vnc_remote_secure/services/terminal.py:524-559`
- **Evidencia:**
  `_execute_command` toma `msg.get('cmd')` y lo pasa a:
  ```python
  args = ['...powershell.exe', '-NoProfile', '-NonInteractive', '-Command', cmd]
  # o
  args = ['...cmd.exe', '/c', cmd]
  subprocess.Popen(args, ...)
  ```
  El comentario en líneas 526-529 reconoce este comportamiento.
- **Comportamiento esperado:** Si es intencional (es un terminal web), debe documentarse claramente como característica y protegerse con autenticación fuerte. Si no es intencional, debe validarse/whitelistarse.
- **Comportamiento actual:** Cualquier cliente WebSocket autenticado ejecuta comandos shell arbitrarios, incluyendo encadenamiento (`;`, `&&`, `|`).
- **Impacto:** Si la autenticación se compromete, el atacante tiene shell remoto completo. Esto es inherente a un terminal web, pero debe asegurarse que la autenticación es robusta y está documentada.
- **Solución propuesta:** Documentar explícitamente el riesgo. Asegurar que la autenticación WebSocket requiere credenciales fuertes. Considerar rate-limiting y logging de comandos.
- **Esfuerzo estimado:** Pequeño (documentación) / Mediano (endurecimiento)
- **Prueba para verificar la corrección:** Sin credenciales, el WebSocket rechaza la conexión. Con credenciales, los comandos se loguean.

---

## INC-019: Health monitor deshabilita validación de certificados SSL

- **Categoría:** Seguridad / SSL
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Riesgo potencial
- **Archivos afectados:** `src/lib/monitoring/health_web_server.py:96-98`
- **Evidencia:**
  ```python
  ctx.check_hostname = False
  ctx.verify_mode = ssl.CERT_NONE
  ```
- **Comportamiento esperado:** Validar certificados o al menos pinear al certificado self-signed local.
- **Comportamiento actual:** Toda validación SSL deshabilitada para `http_check`.
- **Impacto:** Un health check a un endpoint HTTPS podría aceptar certificados falsos. Man-in-the-middle posible en checks remotos.
- **Solución propuesta:** Usar el certificado local self-signed para validación, o al menos documentar por qué se deshabilita.
- **Esfuerzo estimado:** Mediano
- **Prueba para verificar la corrección:** Un health check a un endpoint con certificado inválido falla (o se documenta la excepción).

---

## INC-020: `test_secret_exposure.py` no cubre `.runtime_credentials.json`

- **Categoría:** Pruebas / Seguridad
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `tests/security/test_secret_exposure.py:6-22`
- **Evidencia:** El test solo verifica `git ls-files .env` y `*.pem` / `data/ssl/`. No verifica que `.runtime_credentials.json` no esté trackeado.
- **Comportamiento esperado:** El test de exposición de secretos debe cubrir todos los archivos de credenciales.
- **Comportamiento actual:** El test pasa mientras `.runtime_credentials.json` existe con credenciales reales y no está en `.gitignore`.
- **Impacto:** Falsa sensación de seguridad. El test no detecta el hallazgo INC-001.
- **Solución propuesta:** Añadir assertions para `.runtime_credentials.json` y patrones `*credentials*.json`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** El test falla si `.runtime_credentials.json` está trackeado o no está en `.gitignore`.

---

## INC-021: `run_tests.sh` solo descubre `test_*.sh`, ignorando tests Python, Bats y PowerShell

- **Categoría:** Pruebas
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `tests/run_tests.sh:100-106`, `Makefile:150-177`
- **Evidencia:**
  `run_tests.sh` usa:
  ```bash
  find "$level_dir" -name "test_*.sh" -type f
  ```
  Esto ignora archivos `.bats` en `tests/shell/`, tests `.py` en `tests/unit/`, y tests `.ps1` en `tests/powershell/` y `tests/windows/`.
  `make test-all` solo ejecuta `cd tests && bash run_tests.sh`.
- **Comportamiento esperado:** `make test-all` debe ejecutar Bash, Bats, Python y Pester como describe `AGENTS.md`.
- **Comportamiento actual:** Solo se ejecutan tests `test_*.sh`. Los tests Python (25 `def test_`), Bats (6 `@test`) y Pester (22 `It`/`Describe`) no se ejecutan.
- **Impacto:** Falsa confianza. `make test-all` pasa sin ejecutar la mayoría de tests. Cobertura real mucho menor a la documentada.
- **Solución propuesta:** Añadir discovery y ejecución de `.bats`, `.py`, y `.ps1` en `run_tests.sh` o `Makefile`.
- **Esfuerzo estimado:** Mediano
- **Prueba para verificar la corrección:** `make test-all` ejecuta y reporta tests de Bash, Python y PowerShell.

---

## INC-022: Conteos de tests en `AGENTS.md` no coinciden con los archivos reales

- **Categoría:** Pruebas / Documentación
- **Severidad:** Baja
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `AGENTS.md:120`
- **Evidencia:** `AGENTS.md` declara "140 tests passing (116 Bash + 24 PowerShell)" y una pirámide con 116 tests (14+63+6+15+18). Conteo estático real:
  - `run_test "` (Bash): 117
  - `@test` (Bats): 6
  - `def test_` (Python): 25
  - `It`/`Describe` (Pester): 22
  Existe además `tests/windows/VncRemote.Tests.ps1` no listado en la documentación.
- **Comportamiento esperado:** Los conteos documentados deben reflejar los tests reales.
- **Comportamiento actual:** Conteos desactualizados y estructura de directorios distinta a la documentada.
- **Impacto:** Confusión sobre la cobertura real. Planificación de QA basada en datos incorrectos.
- **Solución propuesta:** Actualizar `AGENTS.md` con conteos reales tras ejecutar `make test-all` corregido (INC-021).
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** Los conteos en `AGENTS.md` coinciden con la salida de `make test-list`.

---

## INC-023: Tests Python solo cubren VNC; otros servicios sin tests unitarios

- **Categoría:** Pruebas / Cobertura
- **Severidad:** Baja
- **Confianza:** Alta
- **Tipo:** Mejora opcional
- **Archivos afectados:** `tests/unit/services/test_vnc.py` (único archivo en `tests/unit/services/`)
- **Evidencia:** `src/vnc_remote_secure/services/` contiene `terminal.py`, `landing.py`, `audio.py`, `gamepad.py`, `health.py`, `novnc.py`, pero solo `test_vnc.py` existe.
- **Comportamiento esperado:** Cada servicio Python tiene tests unitarios.
- **Comportamiento actual:** Solo VNC está cubierto.
- **Impacto:** Regresiones en terminal, landing, health, audio, gamepad, novnc no se detectan.
- **Solución propuesta:** Añadir tests unitarios para cada servicio.
- **Esfuerzo estimado:** Grande
- **Prueba para verificar la corrección:** `pytest tests/unit/services/ --collect-only` lista tests para cada servicio.

---

## INC-024: Patrones `except Exception: pass` silencian errores en múltiples servicios

- **Categoría:** Manejo de errores / Observabilidad
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** 53 ocurrencias de `except Exception:` en código Python. Ejemplos:
  - `src/vnc_remote_secure/services/landing.py:66,83,107,125,172,183,199,235,252,262,267,289,771`
  - `src/vnc_remote_secure/services/terminal.py:291,337,368,434,489,512,611,643`
  - `src/lib/monitoring/health_web_server.py:46,56,75,87,135,146,166,213,223,237,245,259`
  - `src/vnc_remote_secure/core/config.py:52`
  - `tools/doctor.py:322,342,361,382,502`
- **Evidencia:** Muchos bloques `except Exception: pass` o `except Exception: return` ocultan el fallo original sin loguear.
- **Comportamiento esperado:** Capturar excepciones específicas, loguear el error, y re-lanzar o retornar un mensaje significativo.
- **Comportamiento actual:** Fallos silenciosos. Debugging y monitoreo difíciles.
- **Impacto:** Errores en runtime no se detectan. El sistema puede degradarse sin señales.
- **Solución propuesta:** Reemplazar `except Exception: pass` por capturas específicas con logging. Añadir logging estructurado.
- **Esfuerzo estimado:** Mediano
- **Prueba para verificar la corrección:** `grep -r "except Exception: pass" src/` no devuelve resultados.

---

## INC-025: Formatos de respuesta de error inconsistentes entre servicios

- **Categoría:** Manejo de errores / API
- **Severidad:** Media
- **Confianza:** Media
- **Tipo:** Inconsistencia probable
- **Archivos afectados:**
  - `src/vnc_remote_secure/services/landing.py:781-784,825-828` → texto plano `Error: {e}`
  - `src/vnc_remote_secure/services/landing.py:830` → `log_message` es no-op
  - `src/lib/web/user_ui_app.py:202` → `except Exception` devuelve `Internal Server Error` genérico
  - `src/lib/web/user_ui_app.py:241-242` → `except Exception` con solo `flash()`
  - `src/vnc_remote_secure/services/terminal.py:611-612` → `except Exception: pass` en WebSocket
- **Evidencia:** Diferentes servicios responden a errores en formatos distintos (texto plano, JSON, WebSocket, Flask flash) y varias rutas críticas no loguean la excepción original.
- **Comportamiento esperado:** Formato de error unificado y logging proper para todos los servicios.
- **Comportamiento actual:** Formatos mixtos, logs faltantes.
- **Impacto:** Clientes no pueden parsear errores consistentemente. Operadores no pueden diagnosticar fallos.
- **Solución propuesta:** Definir un formato de error estándar (JSON con `error`, `message`, `code`) y un helper de logging.
- **Esfuerzo estimado:** Mediano
- **Prueba para verificar la corrección:** Todos los endpoints de error devuelven el mismo schema JSON.

---

## INC-026: `VNC_HTTP_PORT` (5800) hardcoded y no documentado

- **Categoría:** Configuración / Calidad
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Mejora opcional
- **Archivos afectados:**
  - `src/vnc_remote_secure/services/landing.py:46` → `VNC_HTTP_PORT = 5800`
  - `src/vnc_remote_secure/core/config.py:92` → `'vnc_http_port': 5800`
  - `launch.sh:87,159` → `5800`
- **Evidencia:** El puerto HTTP de UltraVNC está hardcoded a 5800 en Python y `launch.sh`. No hay variable `VNC_HTTP_PORT` en `.env.example` ni en el schema.
- **Comportamiento esperado:** Puerto configurable o al menos documentado.
- **Comportamiento actual:** Hardcoded. Si 5800 está ocupado, no se puede cambiar.
- **Impacto:** Conflicto de puertos no resoluble sin editar código.
- **Solución propuesta:** Añadir `VNC_HTTP_PORT` a `.env.example` y leerlo en config.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** Setear `VNC_HTTP_PORT=5801` y verificar que el servicio usa ese puerto.

---

## INC-027: `core/constants.py` incompleto y con magic numbers dispersos

- **Categoría:** Calidad / Mantenibilidad
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Mejora opcional
- **Archivos afectados:**
  - `src/vnc_remote_secure/core/constants.py:1-13`
  - `docs/architecture/security-model.md:27`
  - `src/vnc_remote_secure/core/config.py:92`
  - `launch.sh:87,159,369-372,319,338,374,377`
- **Evidencia:**
  - `constants.py` define `MIN_PASSWORD_LENGTH = 8` pero `security-model.md:27` documenta 12+ caracteres.
  - `constants.py` solo cubre puertos `5900, 6080, 5000, 8090, 8000`; faltan `DEFAULT_VNC_HTTP_PORT`, `DEFAULT_AUDIO_STREAM_PORT`, `DEFAULT_GAMEPAD_PORT`, `DEFAULT_WEBTERM_SHELL`.
  - `core/config.py:92` hardcodea `vnc_http_port=5800` y `webterm_shell='cmd.exe'`. `launch.sh` hardcodea `5800`, `7777`, `7788` en vez de importar constants.
- **Comportamiento esperado:** Constantes centralizadas en `core/constants.py` y docs alineadas.
- **Comportamiento actual:** Magic numbers dispersos, constante de password contradictoria con docs.
- **Impacto:** Cambios requieren editar múltiples archivos. Riesgo de desincronización.
- **Solución propuesta:** Centralizar todas las constantes en `core/constants.py` y alinear docs.
- **Esfuerzo estimado:** Mediano
- **Prueba para verificar la corrección:** `grep` de números mágicos de puertos en `src/` y `launch.sh` no encuentra literales fuera de `constants.py`.

---

## INC-028: `TTYD_USERNAME=$(whoami)` en `.env.example` no es parseado por el loader Python

- **Categoría:** Configuración / Cross-loader
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:** `.env.example:20`, `src/vnc_remote_secure/core/config.py:47-48,78`, `src/vnc_remote_secure/services/terminal.py:40`
- **Evidencia:**
  `.env.example:20`: `TTYD_USERNAME=$(whoami)`
  `config.py:47-48`: `load_env_file()` salta valores que empiezan con `$(`.
  `config.py:78`: `os.environ.get('TTYD_USERNAME', 'admin')` → defaulta a `admin`.
  `terminal.py:40`: mismo default `admin`.
  Bash `launch.sh` sí hace source de `.env` vía shell y obtiene el usuario real.
- **Comportamiento esperado:** `.env.example` debe funcionar con ambos loaders, o el loader Python debe soportar sustitución shell.
- **Comportamiento actual:** Si un usuario copia `.env.example` y ejecuta un servicio Python directamente, `TTYD_USERNAME` se ignora y defaulta a `admin`.
- **Impacto:** Usuario de terminal incorrecto en Python vs Bash.
- **Solución propuesta:** Usar un valor plano en `.env.example` (ej. `TTYD_USERNAME=` vacío con comentario) o que el loader Python resuelva `$(whoami)`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** Copiar `.env.example` a `.env`, ejecutar servicio Python, y verificar que `TTYD_USERNAME` no es `admin`.

---

## INC-029: Plantillas nginx duplicadas con sintaxis de placeholder distinta

- **Categoría:** Configuración / Duplicación
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Riesgo potencial
- **Archivos afectados:**
  - `src/config/nginx.conf` → placeholders `${...}`, usado por `src/lib/web/nginx.sh:31`
  - `config/nginx/vnc-remote.conf.template` → placeholders `{{...}}`, incluye `LANDING_PORT`
  - `src/lib/web/nginx.sh:71` → `envsubst` para `src/config/nginx.conf`
- **Evidencia:** Dos plantillas nginx. La activa es `src/config/nginx.conf` con `${...}`. `config/nginx/vnc-remote.conf.template` no es referenciada por ningún script, usa sintaxis `{{}}` distinta, y define `LANDING_PORT` que la activa no tiene.
- **Comportamiento esperado:** Una plantilla en una ubicación.
- **Comportamiento actual:** Dos plantillas con sintaxis y alcance distintos. Una está muerta.
- **Impacto:** Confusión sobre cuál editar. Cambios en la plantilla muerta no tienen efecto.
- **Solución propuesta:** Eliminar o fusionar `config/nginx/vnc-remote.conf.template` en `src/config/nginx.conf`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** Solo existe una plantilla nginx y es la que usa `nginx.sh`.

---

## INC-030: `VNC_REMOTE_PROFILE` y `TLS_ENABLED` en examples/Windows pero no consumidos por Python

- **Categoría:** Configuración
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Inconsistencia probable
- **Archivos afectados:**
  - `config/examples/local.env.example:2` → `VNC_REMOTE_PROFILE=local`
  - `config/examples/public-https.env.example:2` → `VNC_REMOTE_PROFILE=public-https`
  - `config/examples/vpn.env.example:2` → `VNC_REMOTE_PROFILE=vpn`
  - `native/windows/commands/Start-VncRemote.ps1:15,19` → setea `TLS_ENABLED` y `VNC_REMOTE_PROFILE`
  - `src/` → grep de `TLS_ENABLED` y `VNC_REMOTE_PROFILE` no devuelve resultados
- **Evidencia:** Los examples `.env` y el wrapper Windows setean estas variables, pero ningún módulo Python bajo `src/` las lee.
- **Comportamiento esperado:** Las variables seteadas en examples deben ser consumidas por el runtime.
- **Comportamiento actual:** Se escriben pero se ignoran.
- **Impacto:** Perfiles de despliegue (local, public-https, vpn) no tienen efecto en Python. `TLS_ENABLED` no controla el comportamiento.
- **Solución propuesta:** Implementar consumo de `VNC_REMOTE_PROFILE` y `TLS_ENABLED` en Python, o eliminar de examples y documentar que son Bash/PowerShell-only.
- **Esfuerzo estimado:** Mediano
- **Prueba para verificar la corrección:** Setear `VNC_REMOTE_PROFILE=public-https` y verificar que Python cambia el comportamiento (o que docs clarifican que es Bash-only).

---

## INC-031: Manifests de third-party con checksums placeholder `TBD`

- **Categoría:** Seguridad / Dependencias
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:**
  - `third_party/manifests/ultravnc.json:14` → `"sha256": "TBD"`
  - `third_party/manifests/tightvnc.json:14` → `"sha256": "TBD"`
  - `third_party/manifests/ttyd.json:14` → `"sha256": "TBD"`
  - `third_party/checksums/SHA256SUMS:1-3` → stub sin checksums reales
  - `tools/download_dependencies.py:48-50` → salta verificación si `sha256` es `TBD`
  - `tools/verify_dependencies.py:53-62` → reporta "no checksum to verify" para `TBD`
- **Evidencia:** Todos los manifests JSON tienen `"sha256": "TBD"`. `SHA256SUMS` es un stub. El downloader salta la verificación. El verifier reporta "no checksum to verify".
- **Comportamiento esperado:** Hashes SHA-256 reales y verificación obligatoria.
- **Comportamiento actual:** Sin verificación de integridad. Un binario manipulado no se detectaría.
- **Impacto:** Riesgo de supply-chain attack. Binarios manipulados pasan desapercibidos.
- **Solución propuesta:** Calcular y fijar hashes SHA-256 reales en los manifests y `SHA256SUMS`.
- **Esfuerzo estimado:** Pequeño
- **Prueba para verificar la corrección:** `python tools/verify_dependencies.py` verifica todos los manifests y no reporta `TBD`.

---

## INC-032: `download_dependencies.py` no soporta tipos de manifest reales (git-clone, zip, msi)

- **Categoría:** Dependencias / Tooling
- **Severidad:** Alta
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:**
  - `third_party/manifests/novnc.json:11-13` → `managed_by: git-clone`, solo `clone_url`
  - `third_party/manifests/ttyd.json:12-13` → release `.zip`
  - `third_party/manifests/tightvnc.json:12-13` → installer `.msi`
  - `tools/download_dependencies.py:44-84`
- **Evidencia:**
  - `novnc.json` es `git-clone` con `clone_url`, pero el downloader solo lee `download_url`; noVNC no se descarga.
  - `ttyd.json` apunta a `.zip` pero el downloader lo guarda como `ttyd.exe` sin extraer.
  - `tightvnc.json` apunta a `.msi` pero lo guarda como `tvnserver.exe` sin ejecutar/extraer.
- **Comportamiento esperado:** El downloader soporta git-clone, archivos y installers como documentan los manifests.
- **Comportamiento actual:** Solo descarga archivos raw. noVNC no se clona, zips no se extraen, MSIs no se instalan.
- **Impacto:** Las dependencias no se preparan correctamente. Setup automatizado roto.
- **Solución propuesta:** Implementar handlers para `git-clone`, extracción de zip, y ejecución de MSI en `download_dependencies.py`.
- **Esfuerzo estimado:** Mediano
- **Prueba para verificar la corrección:** `python tools/download_dependencies.py --dry-run` muestra acciones correctas para cada tipo.

---

## INC-033: `uvnc_service` Windows service referenciado pero no implementado

- **Categoría:** Arquitectura / Windows
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Inconsistencia probable
- **Archivos afectados:**
  - `native/windows/service/service-config.xml:11-17` → define servicio `vnc-remote-secure` que ejecuta `python -m vnc_remote_secure service --run`
  - `src/vnc_remote_secure/cli.py:363-385` → no existe subcomando `service` ni flag `--run`
  - `docs/installation/windows.md:1-30` → no documenta el servicio Windows
- **Evidencia:** `service-config.xml` define un servicio Windows que ejecuta `python -m vnc_remote_secure service --run`, pero `cli.py` no tiene subcomando `service` ni maneja `--run`.
- **Comportamiento esperado:** Un servicio Windows documentado e instalable, o que el config coincida con un comando CLI soportado.
- **Comportamiento actual:** El config referencia un comando inexistente.
- **Impacto:** Si se instala el servicio, fallará al arrancar porque el subcomando no existe.
- **Solución propuesta:** Implementar `service` subcommand en `cli.py` o actualizar `service-config.xml` para usar un comando existente.
- **Esfuerzo estimado:** Mediano
- **Prueba para verificar la corrección:** `python -m vnc_remote_secure service --run` no devuelve "unrecognized command".

---

## INC-034: Documentación de arquitectura describe layout obsoleto (`raspberrypinoVNC/`, `doc/`, `requirements.txt`)

- **Categoría:** Documentación / Arquitectura
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Error confirmado
- **Archivos afectados:**
  - `docs/architecture/components.md:12-87,161-175` → documenta `src/lib/...`, `scripts/backup.sh` en raíz, `requirements.txt`, `doc/`, `data/ssl/`
  - `docs/architecture/overview.md:1-113` → linkea a `developer/architecture.md` y `PROJECT_STRUCTURE.md` que no existen
  - `docs/architecture/components.md:78` → `├── doc/`
  - `docs/architecture/components.md:85,139,251` → referencia `requirements.txt` (no existe)
  - `CONTRIBUTING.md:159` → `doc/`
  - `docs/archive/README-original.md:11-20,187,207,245,294-308` → `doc/`
- **Evidencia:** La docs de arquitectura describe el layout anterior (`raspberrypinoVNC/`, `doc/`, `requirements.txt`) en vez del actual (`src/vnc_remote_secure/`, `docs/`, `pyproject.toml`). `overview.md` linkea archivos inexistentes.
- **Comportamiento esperado:** La docs refleja el layout actual del repo.
- **Comportamiento actual:** Describe estructura removida. Links rotos.
- **Impacto:** Desorientación para nuevos contribuidores. Instrucciones que no funcionan.
- **Solución propuesta:** Actualizar `components.md`, `overview.md`, `CONTRIBUTING.md` al layout actual.
- **Esfuerzo estimado:** Mediano
- **Prueba para verificar la corrección:** Todos los paths en docs existen en el repo. Los links no están rotos.

---

## INC-035: Duplicación funcional entre implementaciones Bash y Python

- **Categoría:** Arquitectura
- **Severidad:** Media
- **Confianza:** Alta
- **Tipo:** Riesgo potencial (puede ser intencional pero no justificado explícitamente)
- **Archivos afectados:**
  - UI de gestión de usuarios: `src/lib/web/user_ui_app.py` vs `src/vnc_remote_secure/web/application.py` + `web/routes/users.py`
  - Health web server: `src/lib/monitoring/health_web_server.py` vs `src/vnc_remote_secure/services/health.py`
  - Terminal web: `src/vnc_remote_secure/services/terminal.py` (Tornado) vs `src/lib/core/services.sh` (ttyd)
- **Evidencia:** Dos implementaciones Flask de UI de usuarios. Dos health web servers. Terminal web en Python/Tornado vs ttyd en Bash.
- **Comportamiento esperado:** Cada feature tiene una implementación o un adapter claro, con la coexistencia justificada explícitamente en docs/ADR.
- **Comportamiento actual:** Implementaciones paralelas sin ADR que justifique la duplicación ni defina cuál es canónica.
- **Impacto:** Divergencia, mantenimiento duplicado, bugs en una implementación pero no la otra.
- **Solución propuesta:** Documentar en un ADR cuál implementación es canónica por plataforma, o consolidar.
- **Esfuerzo estimado:** Grande
- **Prueba para verificar la corrección:** Existe un ADR que justifica la coexistencia Bash/Python y define cuál usar cuándo.

---

## Resumen ejecutivo

| ID | Categoría | Severidad | Tipo | Esfuerzo |
|---|---|---|---|---|
| INC-001 | Seguridad | Crítica | Error confirmado | Pequeño |
| INC-002 | Arquitectura | Crítica | Error confirmado | Pequeño |
| INC-003 | Arquitectura | Alta | Error confirmado | Pequeño |
| INC-004 | Arquitectura | Alta | Error confirmado | Pequeño |
| INC-005 | Arquitectura | Alta | Error confirmado | Pequeño |
| INC-006 | Arquitectura | Media | Error confirmado | Pequeño |
| INC-007 | Calidad | Alta | Error confirmado | Pequeño |
| INC-008 | Build | Alta | Error confirmado | Pequeño |
| INC-009 | Configuración | Alta | Inconsistencia probable | Pequeño |
| INC-010 | Documentación | Media | Error confirmado | Pequeño |
| INC-011 | Configuración | Alta | Error confirmado | Pequeño |
| INC-012 | Configuración | Media | Inconsistencia probable | Pequeño |
| INC-013 | Seguridad | Media | Inconsistencia probable | Pequeño |
| INC-014 | Calidad | Media | Error confirmado | Pequeño |
| INC-015 | Dependencias | Alta | Error confirmado | Pequeño |
| INC-016 | Dependencias | Baja | Mejora opcional | Pequeño |
| INC-017 | Calidad | Baja | Error confirmado | Pequeño |
| INC-018 | Seguridad | Alta | Riesgo potencial | Pequeño/Mediano |
| INC-019 | Seguridad | Media | Riesgo potencial | Mediano |
| INC-020 | Pruebas | Media | Error confirmado | Pequeño |
| INC-021 | Pruebas | Media | Error confirmado | Mediano |
| INC-022 | Pruebas | Baja | Error confirmado | Pequeño |
| INC-023 | Pruebas | Baja | Mejora opcional | Grande |
| INC-024 | Errores | Media | Error confirmado | Mediano |
| INC-025 | Errores | Media | Inconsistencia probable | Mediano |
| INC-026 | Configuración | Media | Mejora opcional | Pequeño |
| INC-027 | Calidad | Media | Mejora opcional | Mediano |
| INC-028 | Configuración | Media | Error confirmado | Pequeño |
| INC-029 | Configuración | Media | Riesgo potencial | Pequeño |
| INC-030 | Configuración | Media | Inconsistencia probable | Mediano |
| INC-031 | Seguridad | Alta | Error confirmado | Pequeño |
| INC-032 | Dependencias | Alta | Error confirmado | Mediano |
| INC-033 | Arquitectura | Media | Inconsistencia probable | Mediano |
| INC-034 | Documentación | Media | Error confirmado | Mediano |
| INC-035 | Arquitectura | Media | Riesgo potencial | Grande |

### Hallazgos por severidad
- **Crítica:** 2 (INC-001, INC-002)
- **Alta:** 8 (INC-003, 004, 005, 007, 008, 009, 011, 015, 018, 031, 032)
- **Media:** 16
- **Baja:** 4

### Hallazgos por tipo
- **Error confirmado:** 22
- **Inconsistencia probable:** 6
- **Riesgo potencial:** 4
- **Mejora opcional:** 4

### Prioridad recomendada de remediación
1. **Inmediata (crítica/alta, bajo esfuerzo):** INC-001, INC-002, INC-003, INC-004, INC-005, INC-007, INC-008, INC-015
2. **Corta (alta/media, bajo esfuerzo):** INC-006, INC-009, INC-011, INC-014, INC-017, INC-020, INC-026, INC-028, INC-031
3. **Media (requiere diseño):** INC-013, INC-018, INC-019, INC-021, INC-024, INC-025, INC-030, INC-032, INC-033, INC-034
4. **Larga (mejora continua):** INC-016, INC-022, INC-023, INC-027, INC-029, INC-035

---

## Notas metodológicas

- No se ejecutaron tests ni se modificó código. Todos los hallazgos se basan en inspección estática y verificación de existencia de archivos.
- Se verificó con `git ls-files`, `Test-Path`, y `git check-ignore` que:
  - `.runtime_credentials.json` no está trackeado pero tampoco ignorado (INC-001).
  - `.env` está ignorado correctamente.
  - `kill_all.sh`, `scripts/backup.sh`, `scripts/duckdns_update.sh`, `scripts/Manage-Firewall.ps1` no existen.
  - `d3des.py` SÍ existe en `src/vnc_remote_secure/vendor/` (un subagent reportó que faltaba; verificación directa lo desmiente).
  - `bin/ultravnc/x64/winvnc.exe` SÍ existe (la ruta de `launch.sh` es correcta; la de `VncRemote.ps1` no).
- No se encontraron secretos hardcoded adicionales en código Python trackeado, salvo `.runtime_credentials.json`.
- No se detectaron importaciones circulares Python en la revisión estática.
- La coexistencia Bash/Python (INC-035) puede ser intencional (migración gradual), pero no hay ADR que lo justifique explícitamente.
