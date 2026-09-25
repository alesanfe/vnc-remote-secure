import {
  createContext,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react';

/** Lightweight i18n — two dictionaries, localStorage persistence,
    {{placeholder}} interpolation. Add a string ONCE here, use it via
    useI18n().t(key). */

const es = {
  'common.cancel': 'Cancelar',
  'common.confirm': 'Confirmar',
  'common.loading': 'Cargando…',
  'common.error': 'Operación fallida',
  'common.delete': 'Eliminar',
  'common.create': 'Crear',
  'common.save': 'Guardar',
  'common.close': 'Cerrar',
  'common.enabled': 'activo',
  'common.disabled': 'inactivo',
  'common.yes': 'sí',
  'common.no': 'no',
  'common.detail': 'Detalle',
  'common.errorBox': 'No se pudo cargar la información.',
  'lang.label': 'Idioma',

  'nav.summary': 'Resumen',
  'nav.sessions': 'Sesiones',
  'nav.users': 'Usuarios',
  'nav.security': 'Seguridad',
  'nav.audit': 'Auditoría',
  'nav.doctor': 'Operación',
  'nav.backups': 'Backups',
  'nav.config': 'Configuración',
  'nav.jobs': 'Jobs',
  'nav.backToPortal': '← Portal',
  'nav.logout': 'Cerrar sesión',
  'nav.adminPanel': 'panel de administración',
  'nav.notFound': 'Página no encontrada.',
  'nav.sessionError': 'No se pudo verificar la sesión.',
  'nav.sessionErrorNet': 'Error de red — el servicio puede estar caído.',
  'common.retry': 'Reintentar',
  'common.open': 'Abrir',

  'login.title': 'Panel del operador',
  'login.subtitle':
    'Acceso de administración. Esta área queda registrada.',
  'login.username': 'Usuario',
  'login.password': 'Contraseña',
  'login.totp': 'Código MFA',
  'login.totpHint':
    '6 dígitos del autenticador o un código de recuperación.',
  'login.submit': 'Entrar',
  'login.submitting': 'Entrando…',
  'login.passkey': 'Entrar con passkey',
  'login.failed': 'Inicio de sesión fallido',
  'login.mfaRequired': 'MFA requerido — introduce tu código.',

  'stepup.title': 'Confirmación reforzada',
  'stepup.verify': 'Verificar y continuar',
  'stepup.reason': 'Esta operación requiere re-autenticación:',
  'stepup.onResource': 'sobre',
  'stepup.password': 'Contraseña',
  'stepup.failed': 'No se pudo verificar la contraseña',
  'stepup.boundNote':
    'La verificación queda vinculada a esta operación y recurso, ' +
    'una sola vez (~2 min).',
  'stepup.genericNote':
    'La verificación queda vinculada a tu sesión durante ~5 minutos.',

  'confirm.confirming': 'Confirmando…',
  'confirm.typeToConfirm': 'Escribe {{name}} para confirmar',

  'jobs.title': 'Jobs',
  'jobs.subtitle':
    'Registro persistente de operaciones: lifecycle, restores y ' +
    'upgrades ejecutados por el runner — sobreviven al reinicio del ' +
    'portal.',
  'jobs.loadError': 'No se pudo cargar el registro de jobs.',
  'jobs.loading': 'Cargando…',
  'jobs.empty': 'Sin operaciones registradas todavía.',
  'jobs.col.job': 'Job',
  'jobs.col.op': 'Operación',
  'jobs.col.resource': 'Recurso',
  'jobs.col.actor': 'Actor',
  'jobs.col.start': 'Inicio',
  'jobs.col.state': 'Estado',
  'jobs.col.detail': 'Detalle',
  'jobs.state': 'Estado',
  'jobs.progress': 'Progreso',
  'jobs.detailLabel': 'Detalle',
  'jobs.error': 'Error',

  'overview.title': 'Resumen',
  'overview.recentJobs': 'Jobs recientes',
  'overview.col.job': 'Job',
  'overview.col.op': 'Operación',
  'overview.col.actor': 'Actor',
  'overview.col.state': 'Estado',
  'overview.col.detail': 'Detalle',
  'overview.lifecycle.title': 'Ciclo de vida',
  'overview.lifecycle.stop': 'Parar todo',
  'overview.lifecycle.restart': 'Reiniciar todo',
  'overview.lifecycle.start': 'Arrancar parados',
  'overview.lifecycle.stopping':
    'Parada en curso (job {{job}}) — esta interfaz dejará de ' +
    'responder. Reinicia con `vnc-remote start`.',
  'overview.lifecycle.restarting':
    'Reinicio en curso (job {{job}}) — la interfaz volverá cuando ' +
    'el portal esté arriba de nuevo.',
  'overview.lifecycle.starting':
    'Arranque en curso (job {{job}}) de los servicios parados.',
  'overview.lifecycle.confirm.stop': 'parada de todos los servicios',
  'overview.lifecycle.confirm.restart': 'reinicio de todos los servicios',
  'overview.lifecycle.confirm.start': 'arranque de servicios',
  'overview.upgrade.check': 'Buscar actualización',
  'overview.upgrade.run': 'Actualizar',
  'overview.upgrade.rollback': 'Rollback',
  'overview.upgrade.queued':
    'Upgrade encolado (job {{job}}) — sigue el progreso en ' +
    'Operación → Jobs; reinicia al terminar.',
  'overview.upgrade.rollbackQueued':
    'Rollback encolado (job {{job}}) — consulta su progreso en ' +
    'Operación → Jobs.',
  'overview.upgrade.confirm': 'actualización del paquete instalado',
  'overview.upgrade.confirmRollback': 'rollback a la versión anterior',
  'overview.upgrade.placeholder':
    'Fuente (wheel/URL; vacío = PyPI latest)',
  'overview.upgrade.running': 'Actualizando…',
  'overview.lifecycle.unavailable':
    'Control de servicios no disponible con este rol.',
  'overview.version.installed': 'Versión instalada',
  'overview.version.available': 'disponible',
  'overview.security.score': 'Seguridad: {{score}}/100',
  'overview.services': 'Servicios',
  'overview.services.error': 'No se pudo cargar la lista de servicios.',
  'overview.lanAccess': 'Acceso LAN',
  'overview.dialog.stopTitle': 'Parar todos los servicios',
  'overview.dialog.restartTitle': 'Reiniciar todos los servicios',
  'overview.dialog.stop': 'Parar',
  'overview.dialog.restart': 'Reiniciar',
  'overview.dialog.stopBody':
    'Todos los servicios se pararán — incluido este portal. ' +
    'La interfaz dejará de responder hasta que se arranquen ' +
    'desde CLI o el gestor de servicios.',
  'overview.dialog.restartBody':
    'Los servicios se reiniciarán — incluido este portal. ' +
    'La interfaz volverá en unos segundos.',

  'backups.title': 'Backups',
  'backups.subtitle':
    'Paridad total con el CLI (vnc-remote backup | restore | verify ' +
    'backup). Crear y restaurar requieren step-up; restaurar lanza ' +
    'un job persistente.',
  'backups.created': 'Backup creado: {{name}}',
  'backups.restoreQueued':
    'Restauración de {{name}} encolada — job {{job}}.',
  'backups.listError': 'No se pudo listar los backups.',
  'backups.create': 'Nuevo backup',
  'backups.creating': 'Creando…',
  'backups.loading': 'Cargando…',
  'backups.col.file': 'Archivo',
  'backups.col.size': 'Tamaño',
  'backups.col.encrypted': 'Cifrado',
  'backups.col.date': 'Fecha',
  'backups.col.actions': 'Acciones',
  'backups.encrypted': 'CIFRADO',
  'backups.plain': 'PLANO',
  'backups.restore': 'Restaurar…',
  'backups.restoring': 'Encolando…',
  'backups.empty':
    'No hay backups. Usa «Nuevo backup» o vnc-remote backup.',
  'backups.stepup.create': 'creación de un backup',
  'backups.stepup.restore': 'restauración del backup {{name}}',
  'backups.verify.error': 'No se pudo encolar la restauración',
  'backups.jobLink': 'ver progreso en Jobs →',

  'wizard.title': 'Restaurar backup',
  'wizard.steps': 'Pasos',
  'wizard.verify': '1. Verificación',
  'wizard.impact': '2. Impacto',
  'wizard.confirm': '3. Confirmación',
  'wizard.verifying': 'Verificando integridad de {{name}}…',
  'wizard.verifyFailed': 'No se pudo verificar el archivo.',
  'wizard.corrupt':
    'El backup {{name}} está CORRUPTO{{msg}} — no se puede restaurar.',
  'wizard.integrity':
    '{{name}} íntegro ({{members}} entradas). La restauración ' +
    'sobrescribirá:',
  'wizard.note':
    'La restauración corre como job persistente — sobrevive a un ' +
    'reinicio del portal. Las contraseñas restauradas invalidan las ' +
    'sesiones activas.',
  'wizard.continue': 'Continuar',
  'wizard.typeName':
    'Escribe {{name}} para lanzar la restauración. El servidor ' +
    'pedirá step-up ligado a este archivo concreto.',
  'wizard.typeLabel': 'Escribe el nombre del backup',
  'wizard.launch': 'Restaurar',
  'wizard.launching': 'Encolando…',
  'wizard.impact.env': '.env — credenciales y flags de configuración',
  'wizard.impact.ssl': 'ssl/ — certificados TLS en servicio',
  'wizard.impact.config': 'config/ — perfiles y valores efectivos',
  'wizard.impact.data': 'data/ — estado de aplicación',
  'wizard.impact.run':
    'run/ — secretos firmados, sesiones efímeras y shared_state.db',

  'config.title': 'Configuración',
  'config.migrate.dry': 'vista previa de migración de configuración',
  'config.migrate.apply': 'migración del .env',

  'security.stepup.rotate': 'rotación del secreto {{name}}',
  'security.stepup.signing': 'rotación de la clave de firma',
  'security.stepup.recovery':
    'generación de códigos de recuperación MFA',

  'portal.title': 'VNC Remote Secure',
  'portal.subtitle': 'Acceso remoto seguro desde el navegador.',

  // --- Security ---------------------------------------------------------------
  'security.title': 'Seguridad',
  'security.posture.error': 'No se pudo cargar la postura de seguridad.',
  'security.score': 'Puntuación: {{score}}/100',
  'security.deployment': 'Despliegue',
  'security.deployment.allowed': 'despliegue permitido',
  'security.deployment.blocked': 'despliegue bloqueado',
  'security.blockingFindings': 'Hallazgos bloqueantes',
  'security.findings': 'Hallazgos',
  'security.col.check': 'Check',
  'security.col.status': 'Estado',
  'security.secrets.title': 'Secretos',
  'security.secrets.forbidden':
    'Gestión de secretos no disponible con este rol (requiere admin:*).',
  'security.secrets.col.secret': 'Secreto',
  'security.secrets.col.status': 'Estado',
  'security.secrets.col.actions': 'Acciones',
  'security.secrets.rotate': 'Rotar',
  'security.secrets.rotateTitle': 'Rotar secreto',
  'security.secrets.rotateBody':
    'Se generará un valor nuevo para {{name}} y se persistirá en .env. ' +
    'Los servicios lo recogen al reiniciar; no se muestra el valor.',
  'security.secrets.rotated':
    'Rotado {{name}} (fp {{fingerprint}}) — reinicia los servicios ' +
    'para aplicarlo{{extra}}.',
  'security.secrets.rotatedRevoked':
    '; sesiones de operador revocadas',
  'security.secrets.signingTitle': 'Rotar clave de firma',
  'security.secrets.signingBody':
    'La clave de firma HMAC se rotará con una ventana de coexistencia ' +
    'de 7 días: los tokens existentes siguen verificando con la clave ' +
    'anterior durante ese plazo.',
  'security.secrets.signingRotated':
    'Clave de firma rotada — ventana de coexistencia de 7 días activa.',
  'security.secrets.rotateSigning': 'Rotar clave de firma',
  'security.secrets.recovery': 'Códigos de recuperación',
  'security.secrets.codesOnce':
    'Códigos nuevos (se muestran UNA vez — guárdalos fuera):',
  'security.secrets.fixPerms': 'Revisar y corregir permisos',
  'security.secrets.permsFixed':
    'Permisos corregidos en {{count}} archivo(s).',
  'security.secrets.permsNone':
    'Permisos de secretos correctos — nada que corregir.',
  'security.secrets.checkTitle': 'Verificación de secretos',

  // --- Audit ------------------------------------------------------------------
  'audit.title': 'Auditoría',
  'audit.chain': 'Cadena de integridad:',
  'audit.chain.intact': 'íntegra',
  'audit.chain.broken': 'ROTA',
  'audit.filter.event': 'Filtrar por evento',
  'audit.filter.user': 'Filtrar por usuario',
  'audit.user': 'Usuario',
  'audit.filter.result': 'Filtrar por resultado',
  'audit.result.all': 'Todos',
  'audit.filter.rows': 'Filas a cargar',
  'audit.rows': '{{n}} filas',
  'audit.refresh': 'Actualizar',
  'audit.loadError': 'No se pudo cargar la auditoría.',
  'audit.caption': 'Eventos de auditoría (más recientes primero)',
  'audit.empty': 'Sin eventos que mostrar.',
  'audit.loadMore': 'Cargar más',

  // --- Doctor -----------------------------------------------------------------
  'doctor.title': 'Operación',
  'doctor.run': 'Ejecutar doctor',
  'doctor.running': 'Ejecutando…',
  'doctor.healthy': 'todo correcto',
  'doctor.unhealthy': 'hay problemas',
  'doctor.maintenance': 'Mantenimiento',
  'doctor.maintenance.reason':
    'Mantenimiento programado — vuelve pronto.',
  'doctor.maintenance.by': '— por {{by}}',
  'doctor.maintenance.activate': 'Activar mantenimiento',
  'doctor.maintenance.deactivate': 'Desactivar mantenimiento',
  'doctor.maintenance.forbidden':
    'Gestión de mantenimiento no disponible con este rol (admin:*).',
  'doctor.failed': 'Doctor falló',
  'doctor.failedDetail': 'detalle: {{msg}}',
  'doctor.col.check': 'Check',
  'doctor.col.status': 'Estado',
  'doctor.col.message': 'Mensaje',
  'doctor.jobs.title': 'Jobs recientes',
  'doctor.jobs.col.time': 'Hora',
  'doctor.jobs.col.op': 'Operación',
  'doctor.jobs.col.actor': 'Actor',
  'doctor.jobs.col.target': 'Recurso',
  'doctor.jobs.col.state': 'Estado',
  'doctor.stepup.maintenance': 'cambio del modo mantenimiento',

  // --- Config page --------------------------------------------------------------
  'config.page.title': 'Configuración',
  'config.page.subtitle':
    'Paridad con vnc-remote config: vista efectiva con provenance, ' +
    'validación, diff de perfiles y migración.',
  'config.filter': 'Filtrar variables',
  'config.vars': '{{count}} variables',
  'config.loadError': 'No se pudo cargar la configuración.',
  'config.col.var': 'Variable',
  'config.col.value': 'Valor',
  'config.col.source': 'Origen',
  'config.ops.title': 'Operaciones',
  'config.ops.valid': 'Configuración válida',
  'config.ops.findings': '{{count}} hallazgo(s) de validación',
  'config.ops.diff': 'Diff de perfiles',
  'config.ops.preview': 'Vista previa',
  'config.ops.apply': 'Aplicar migración',
  'config.ops.noDiffs': 'Sin diferencias entre perfiles.',
  'config.ops.noMigrations': 'Sin migraciones pendientes.',
  'config.ops.migrationsApplied': 'Aplicadas {{count}} migración(es):',
  'config.ops.migrationsWould': 'Se aplicarían {{count}} migración(es):',
  'config.ops.migrateFailed': 'La migración falló',

  // --- Portal ----------------------------------------------------------------
  'portal.metrics.host': 'Host',
  'portal.metrics.os': 'SO',
  'portal.metrics.uptime': 'Uptime',
  'portal.metrics.cpu': 'CPU',
  'portal.metrics.ram': 'RAM',
  'portal.metrics.disk': 'Disco',
  'portal.lan.title': 'Acceso LAN',
  'portal.lan.desc': 'Direcciones locales del equipo.',
  'portal.services.title': 'Servicios',
  'portal.services.port': 'Puerto',
  'portal.services.link': 'Abrir',
  'portal.status.online': 'ONLINE',
  'portal.status.offline': 'OFFLINE',
  'portal.vncDirect.title': 'VNC directo',
  'portal.vncDirect.desc':
    'Acceso VNC nativo (sin navegador) disponible en loopback.',
  'portal.vncDirect.loopback': 'Solo loopback',
  'portal.banner.title': 'Sesión invitada activa',
  'portal.banner.role': 'Permiso',
  'portal.banner.expiresIn': 'Expira en',
  'portal.banner.viewOnly': 'Solo visualización',
  'portal.banner.noTerminal': 'Sin terminal',
  'portal.banner.singleUse': 'Uso único',
  'portal.sessions.title': 'Sesiones activas',
  'portal.sessions.empty': 'No hay sesiones efímeras activas.',
  'portal.sessions.role': 'Permiso',
  'portal.sessions.expires': 'Expira',
  'portal.sessions.uses': 'Usos',
  'portal.sessions.revoke': 'Revocar',
  'portal.sessions.revokeError': 'No se pudo revocar la sesión.',
  'portal.gamepad.desc': 'Reenvío de mando en directo para juegos.',
  'portal.gamepad.resume': 'Reanudar audio',
  'portal.gamepad.stop': 'Detener',
  'portal.error.restricted': 'Acceso restringido a operadores.',
  'portal.error.load': 'No se pudo cargar el portal.',
  'portal.adminLink': 'Panel de administración →',
  'portal.shell.system': 'shell del sistema',
  'portal.skipLink': 'Saltar al contenido',
  'portal.tagline': 'Portal de acceso a servicios',
  'portal.maintenance.title': 'Mantenimiento',
  'portal.maintenance.desc':
    'El acceso está temporalmente limitado a administradores.',
  'portal.features.title': 'Funcionalidades',
  'portal.features.desktop.title': 'Escritorio remoto',
  'portal.features.desktop.desc':
    'Sesión VNC completa en el navegador vía noVNC sobre {{os}}.',
  'portal.features.terminal.title': 'Terminal web',
  'portal.features.terminal.desc':
    'Shell interactivo del sistema en el navegador ({{os}} · {{shell}}).',
  'portal.features.monitoring.title': 'Monitorización',
  'portal.features.monitoring.desc':
    'Panel de salud con métricas en vivo del host.',
  'portal.features.vnc.title': 'Acceso VNC',
  'portal.features.vnc.desc':
    'Servidor VNC escuchando en el puerto {{port}} (cliente nativo).',
  'portal.features.tls.title': 'TLS',
  'portal.features.tls.secure': 'Cifrado activo — certificado válido.',
  'portal.features.tls.insecure': 'Sin certificado — HTTP plano.',
  'portal.features.lan.title': 'Red local',
  'portal.features.lan.desc':
    'El portal es accesible desde otros equipos de tu LAN.',
  'portal.creds.title': 'Credenciales',
  'portal.creds.desc1': 'Las credenciales viven en ',
  'portal.creds.desc2': ' y en ',
  'portal.creds.desc3':
    ' — nunca se muestran en esta interfaz.',
  'portal.firewall.title': 'Firewall ({{os}})',
  'portal.firewall.desc':
    'Reglas necesarias para acceso externo:',
  'portal.ssl.title': 'Certificado SSL',
  'portal.ssl.desc': 'Estado del certificado TLS del portal.',

  // --- Share link ---------------------------------------------------------------
  'share.error.network': 'Error de red — inténtalo de nuevo.',
  'share.error.expired': 'Enlace expirado o ya utilizado.',
  'share.error.noToken': 'Enlace incompleto — falta el token.',
  'share.flag.viewOnly': 'solo visualización',
  'share.flag.singleUse': 'uso único',
  'share.flag.noTerminal': 'sin terminal',
  'share.flag.maxUses': 'máx. {{n}} usos',
  'share.title': 'Acceso compartido',
  'share.discarded':
    'Por seguridad, el token se eliminó de la barra de dirección.',
  'share.checking': 'Comprobando el enlace…',
  'share.grantPre': 'Este enlace te concede acceso',
  'share.action.view': 'de visualización',
  'share.action.viewControl': 'de visualización y control',
  'share.grantPost': 'a esta máquina.',
  'share.role': 'Permiso',
  'share.expiresIn': 'Expira en',
  'share.restrictions': 'Restricciones',
  'share.activating': 'Activando sesión…',
  'share.accept': 'Aceptar y entrar',

  // --- Audio ------------------------------------------------------------------
  'audio.title': 'Audio remoto',
  'audio.connect': 'Conectar',
  'audio.disconnect': 'Desconectar',
  'audio.volume': 'Volumen',
  'audio.info.initial':
    'Pulsa Conectar para recibir el audio del equipo remoto.',
  'audio.info.unauthorized': 'Sesión no autorizada para audio.',
  'audio.info.connectingTo': 'Conectando a {{url}}…',
  'audio.info.receiving': 'Recibiendo audio…',
  'audio.info.status':
    '{{clients}} oyente(s) · dispositivo {{device}} · {{bitrate}} kbps',
  'audio.info.closed': 'Conexión cerrada por el servidor.',
  'audio.info.error': 'Error: {{msg}}',
  'audio.error.conn': 'No se pudo conectar el audio.',
  'audio.state.streaming': 'emitiendo',
  'audio.state.connecting': 'conectando',
  'audio.state.error': 'error',
  'audio.state.disconnected': 'desconectado',
  'audio.bt.title': 'Altavoz Bluetooth',
  'audio.bt.desc':
    'El audio sale por el dispositivo de reproducción por defecto ' +
    'del navegador.',

  // --- Gamepad ------------------------------------------------------------------
  'gamepad.title': 'Gamepad remoto',
  'gamepad.connect': 'Conectar',
  'gamepad.disconnect': 'Desconectar',
  'gamepad.scan': 'Buscar mandos',
  'gamepad.info.initial':
    'Pulsa Conectar y después Buscar mandos para vincular tu gamepad ' +
    'local al juego remoto.',
  'gamepad.info.connected': 'Canal de gamepad abierto.',
  'gamepad.info.unauthorized': 'Sesión no autorizada para gamepad.',
  'gamepad.info.closed': 'Conexión cerrada por el servidor.',
  'gamepad.info.revoked': 'Sesión revocada.',
  'gamepad.info.error': 'Error: {{msg}}',
  'gamepad.error.conn': 'No se pudo conectar el canal de gamepad.',
  'gamepad.pad.none': 'Ningún mando detectado.',
  'gamepad.pad.connected': 'Mando {{id}} enviando.',
  'gamepad.pad.disconnected': 'Mando desconectado.',
  'gamepad.pad.found': 'Mando detectado: {{id}}.',
  'gamepad.pad.notFound':
    'No se encontró ningún mando — pulsa un botón en el mando y ' +
    'reintenta.',
  'gamepad.state.connected': 'conectado',
  'gamepad.state.connecting': 'conectando',
  'gamepad.state.error': 'error',
  'gamepad.state.disconnected': 'desconectado',
  'gamepad.bt.title': 'Mando Bluetooth',
  'gamepad.bt.desc':
    'El navegador expone el mando vía la Gamepad API; los eventos se ' +
    'reenvían al host por WebSocket.',
  'gamepad.stick.left': 'Stick izquierdo',
  'gamepad.stick.right': 'Stick derecho',

  // --- Audio/Gamepad short aliases (as used by the pages) ---------------------------
  'audio.unauthorized': 'Sesión no autorizada para audio.',
  'audio.connectingTo': 'Conectando a {{url}}…',
  'audio.receiving': 'Recibiendo audio…',
  'audio.status':
    '{{clients}} oyente(s) · dispositivo {{device}} · {{bitrate}} kbps',
  'audio.closed': 'Conexión cerrada por el servidor.',
  'audio.error': 'Error: {{msg}}',
  'gamepad.unauthorized': 'Sesión no autorizada para gamepad.',
  'gamepad.closed': 'Conexión cerrada por el servidor.',
  'gamepad.revoked': 'Sesión revocada.',
  'gamepad.error': 'Error: {{msg}}',
  'portal.error.adminLink': 'Panel de administración →',

  // --- Terminal -------------------------------------------------------------------
  'terminal.unauthorized': 'Sesión no autorizada para el terminal.',
  'terminal.state.connected': 'conectado',
  'terminal.state.connecting': 'conectando',
  'terminal.state.error': 'error',
  'terminal.state.disconnected': 'desconectado',

  // --- Login (extra) ----------------------------------------------------------------
  'login.networkError': 'Error de red — el servicio puede estar caído.',
  'login.passkeyFailed': 'Falló la autenticación con passkey.',
  'login.passkeyWaiting': 'Esperando el dispositivo…',
  'login.auditNote':
    'Los intentos de acceso quedan registrados en la auditoría.',

  // --- Sessions ----------------------------------------------------------------
  'sessions.title': 'Sesiones',
  'sessions.createTitle': 'Nueva sesión compartida',
  'sessions.role': 'Permiso',
  'sessions.ttl': 'Duración (TTL)',
  'sessions.maxUses': 'Usos máximos',
  'sessions.resource': 'Recurso',
  'sessions.allResources': 'Todos los recursos',
  'sessions.ipRestriction': 'Restricción por IP',
  'sessions.ipPlaceholder': 'p. ej. 192.168.1.10',
  'sessions.viewOnly': 'Solo visualización',
  'sessions.noTerminal': 'Sin terminal',
  'sessions.singleUse': 'Uso único',
  'sessions.createLink': 'Crear enlace',
  'sessions.createdTitle': 'Enlace creado',
  'sessions.createdOnce':
    'Este enlace se muestra UNA vez — compártelo ahora.',
  'sessions.copy': 'Copiar',
  'sessions.createError': 'No se pudo crear la sesión.',
  'sessions.revokeError': 'No se pudo revocar la sesión.',
  'sessions.revokeAllError': 'No se pudieron revocar todas las sesiones.',
  'sessions.inventory': 'Inventario de sesiones',
  'sessions.viewsAria': 'Vista de sesiones',
  'sessions.tabActive': 'Activas',
  'sessions.tabRevoked': 'Revocadas/expiradas',
  'sessions.revokeAll': 'Cerrar todo',
  'sessions.loadError': 'No se pudieron cargar las sesiones.',
  'sessions.emptyActive': 'No hay sesiones activas.',
  'sessions.emptyRevoked': 'No hay sesiones revocadas o expiradas.',
  'sessions.col.ref': 'Ref',
  'sessions.col.state': 'Estado',
  'sessions.col.role': 'Permiso',
  'sessions.col.perms': 'Alcance',
  'sessions.col.resource': 'Recurso',
  'sessions.col.expires': 'Expira',
  'sessions.col.flags': 'Flags',
  'sessions.col.creator': 'Creador',
  'sessions.stateActive': 'activa',
  'sessions.stateRevoked': 'revocada',
  'sessions.permCount': '{{count}} permiso(s)',
  'sessions.revoke': 'Revocar',
  'sessions.revokeTitle': 'Revocar sesión',
  'sessions.revokeBody':
    'La sesión {{id}} ({{role}} sobre {{resource}}) quedará ' +
    'invalidada inmediatamente.',
  'sessions.revokeBodyResource': 'Recurso afectado: {{resource}}.',
  'sessions.revokeAllTitle': 'Cerrar todas las sesiones',
  'sessions.revokeAllBody':
    'Las {{count}} sesiones activas quedarán revocadas. Los ' +
    'invitados conectados perderán acceso de inmediato.',
  'sessions.loadMore': 'Cargar más',
  'sessions.stepup.revokeAll': 'cierre de todas las sesiones activas',

  // --- Users (operators) --------------------------------------------------------------
  'users.title': 'Operadores',
  'users.subtitle':
    'Cuentas de operador, permisos, sesiones y passkeys.',
  'users.loadError': 'No se pudieron cargar los operadores.',
  'users.newOperator': 'Nuevo operador',
  'users.username': 'Usuario',
  'users.role': 'Rol',
  'users.state': 'Estado',
  'users.perms': 'Permisos',
  'users.created': 'Creado',
  'users.actions': 'Acciones',
  'users.empty': 'No hay operadores registrados.',
  'users.systemTitle': 'Usuarios del sistema',
  'users.systemSubtitle':
    'Cuentas del SO gestionadas por la aplicación.',
  'users.sessionsRevoked':
    'Sesiones del operador {{name}} revocadas.',
  'users.stepup.delete': 'eliminación del operador {{name}}',
  'users.stepup.revoke':
    'revocación de sesiones del operador {{name}}',
  'users.revokeTitle': 'Revocar sesiones',
  'users.revokeAll': 'Revocar sesiones',
  'users.revokeBody':
    'Todas las sesiones activas del operador {{name}} quedarán ' +
    'invalidadas.',
  'users.deleteTitle': 'Eliminar operador',
  'users.deleteBody':
    'El operador {{name}} quedará marcado como eliminado ' +
    '(borrado lógico, con registro en auditoría).',
  'users.tempPassword': 'Contraseña temporal:',
  'users.createFailed': 'No se pudo crear el operador.',
  'users.creating': 'Creando…',
  'users.statusActive': 'activo',
  'users.statusDisabled': 'deshabilitado',
  'users.permCount': '{{count}} permiso(s)',
  'users.enable': 'Habilitar',
  'users.disable': 'Deshabilitar',
  'users.revokeSessions': 'Revocar sesiones',
  'users.detailError': 'No se pudo cargar el detalle del operador.',
  'users.passkeyCount': '{{count}} passkey(s)',
  'users.protected': 'protegido',
  'users.passkeys': 'Passkeys',
  'users.noPasskeys': 'Sin passkeys registradas.',
  'users.passkeyName': 'Nombre',
  'users.passkeyRegistered': 'Passkey registrada.',
  'users.passkeyRenameAria': 'Renombrar passkey',
  'users.rename': 'Renombrar',
  'users.revoke': 'Revocar',
  'users.registerFailed': 'No se pudo registrar la passkey.',
  'users.passkeyNameAria': 'Nombre de la passkey',
  'users.passkeyNamePlaceholder': 'Portátil del trabajo',
  'users.registering': 'Registrando…',
  'users.registerPasskey': 'Registrar passkey',
  'users.webauthnUnsupported':
    'Este navegador no soporta WebAuthn.',
  'users.stepup.passkey': 'registro de una passkey',
  'users.passkeyRevokeTitle': 'Revocar passkey',
  'users.passkeyRevokeBody':
    'La passkey {{ref}} dejará de poder autenticarse.',

  // --- System users ----------------------------------------------------------------
  'systemUsers.loadError': 'No se pudieron cargar los usuarios del sistema.',
  'systemUsers.opCreate': 'creación de un usuario del sistema',
  'systemUsers.opDelete': 'eliminación del usuario {{name}}',
  'systemUsers.username': 'Usuario',
  'systemUsers.usernameAria': 'Nombre del usuario del sistema',
  'systemUsers.usernamePlaceholder': 'p. ej. vnc-operator',
  'systemUsers.passwordAria': 'Contraseña del usuario del sistema',
  'systemUsers.passwordPlaceholder': 'contraseña segura',
  'systemUsers.create': 'Crear usuario del sistema',
  'systemUsers.home': 'Home',
  'systemUsers.actions': 'Acciones',
  'systemUsers.empty': 'No hay usuarios del sistema gestionados.',
  'systemUsers.deleteTitle': 'Eliminar usuario del sistema',
  'systemUsers.deleteBody':
    'El usuario {{name}} será eliminado del sistema. Esto no ' +
    'afecta a operadores del panel.',

  // --- Deleted operators ---------------------------------------------------------
  'deletedOps.title': 'Operadores eliminados',
  'deletedOps.subtitle':
    'Borrado lógico: restorable mientras persista el registro.',
  'deletedOps.username': 'Usuario',
  'deletedOps.role': 'Rol',
  'deletedOps.deletedAt': 'Eliminado',
  'deletedOps.actions': 'Acciones',
  'deletedOps.restore': 'Restaurar',
  'deletedOps.restoreTitle': 'Restaurar operador',
  'deletedOps.restoreBody':
    'El operador {{name}} volverá a estar activo con sus permisos ' +
    'previos.',
  'deletedOps.stepup.restore': 'restauración del operador {{name}}',
  'deletedOps.restoreFailed': 'No se pudo restaurar el operador.',

  // --- DataTable / bits -----------------------------------------------------------
  'table.errorText': 'Error al cargar los datos.',
  'table.emptyText': 'Sin datos que mostrar.',
  'bits.expired': 'expirado',
  'bits.copyRef': 'Copiar referencia {{id}}',
};

const en: typeof es = {
  'common.cancel': 'Cancel',
  'common.confirm': 'Confirm',
  'common.loading': 'Loading…',
  'common.error': 'Operation failed',
  'common.delete': 'Delete',
  'common.create': 'Create',
  'common.save': 'Save',
  'common.close': 'Close',
  'common.enabled': 'enabled',
  'common.disabled': 'disabled',
  'common.yes': 'yes',
  'common.no': 'no',
  'common.detail': 'Detail',
  'common.errorBox': 'Could not load the information.',
  'lang.label': 'Language',

  'nav.summary': 'Summary',
  'nav.sessions': 'Sessions',
  'nav.users': 'Users',
  'nav.security': 'Security',
  'nav.audit': 'Audit',
  'nav.doctor': 'Operations',
  'nav.backups': 'Backups',
  'nav.config': 'Configuration',
  'nav.jobs': 'Jobs',
  'nav.backToPortal': '← Portal',
  'nav.logout': 'Log out',
  'nav.adminPanel': 'administration panel',
  'nav.notFound': 'Page not found.',
  'nav.sessionError': 'Could not verify the session.',
  'nav.sessionErrorNet': 'Network error — the service may be down.',
  'common.retry': 'Retry',
  'common.open': 'Open',

  'login.title': 'Operator console',
  'login.subtitle':
    'Administrative access. This area is fully audited.',
  'login.username': 'Username',
  'login.password': 'Password',
  'login.totp': 'MFA code',
  'login.totpHint': '6 digits from your authenticator or a recovery code.',
  'login.submit': 'Sign in',
  'login.submitting': 'Signing in…',
  'login.passkey': 'Sign in with passkey',
  'login.failed': 'Sign-in failed',
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

  'confirm.confirming': 'Confirming…',
  'confirm.typeToConfirm': 'Type {{name}} to confirm',

  'jobs.title': 'Jobs',
  'jobs.subtitle':
    'Persistent operation ledger: lifecycle, restores and upgrades ' +
    'executed by the runner — they survive a portal restart.',
  'jobs.loadError': 'Could not load the job ledger.',
  'jobs.loading': 'Loading…',
  'jobs.empty': 'No operations recorded yet.',
  'jobs.col.job': 'Job',
  'jobs.col.op': 'Operation',
  'jobs.col.resource': 'Resource',
  'jobs.col.actor': 'Actor',
  'jobs.col.start': 'Started',
  'jobs.col.state': 'State',
  'jobs.col.detail': 'Detail',
  'jobs.state': 'State',
  'jobs.progress': 'Progress',
  'jobs.detailLabel': 'Detail',
  'jobs.error': 'Error',

  'overview.title': 'Summary',
  'overview.recentJobs': 'Recent jobs',
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
    'Restart with `vnc-remote start`.',
  'overview.lifecycle.restarting':
    'Restarting (job {{job}}) — the UI will return once the portal ' +
    'is back up.',
  'overview.lifecycle.starting':
    'Starting (job {{job}}) the stopped services.',
  'overview.lifecycle.confirm.stop': 'stopping all services',
  'overview.lifecycle.confirm.restart': 'restarting all services',
  'overview.lifecycle.confirm.start': 'starting services',
  'overview.upgrade.check': 'Check for update',
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
  'backups.restoring': 'Queueing…',
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

  'config.title': 'Configuration',
  'config.migrate.dry': 'config migration preview',
  'config.migrate.apply': 'migrating the .env file',

  'security.stepup.rotate': 'rotation of secret {{name}}',
  'security.stepup.signing': 'signing key rotation',
  'security.stepup.recovery': 'MFA recovery-code generation',

  'portal.title': 'VNC Remote Secure',
  'portal.subtitle': 'Secure remote access from your browser.',

  // --- Security ---------------------------------------------------------------
  'security.title': 'Security',
  'security.posture.error': 'Could not load the security posture.',
  'security.score': 'Score: {{score}}/100',
  'security.deployment': 'Deployment',
  'security.deployment.allowed': 'deployment allowed',
  'security.deployment.blocked': 'deployment blocked',
  'security.blockingFindings': 'Blocking findings',
  'security.findings': 'Findings',
  'security.col.check': 'Check',
  'security.col.status': 'Status',
  'security.secrets.title': 'Secrets',
  'security.secrets.forbidden':
    'Secret management is not available with this role (requires admin:*).',
  'security.secrets.col.secret': 'Secret',
  'security.secrets.col.status': 'Status',
  'security.secrets.col.actions': 'Actions',
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
  'audit.chain.broken': 'BROKEN',
  'audit.filter.event': 'Filter by event',
  'audit.filter.user': 'Filter by user',
  'audit.user': 'User',
  'audit.filter.result': 'Filter by result',
  'audit.result.all': 'All',
  'audit.filter.rows': 'Rows to load',
  'audit.rows': '{{n}} rows',
  'audit.refresh': 'Refresh',
  'audit.loadError': 'Could not load the audit log.',
  'audit.caption': 'Audit events (newest first)',
  'audit.empty': 'No events to show.',
  'audit.loadMore': 'Load more',

  // --- Doctor -----------------------------------------------------------------
  'doctor.title': 'Operations',
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
  'doctor.jobs.col.time': 'Time',
  'doctor.jobs.col.op': 'Operation',
  'doctor.jobs.col.actor': 'Actor',
  'doctor.jobs.col.target': 'Resource',
  'doctor.jobs.col.state': 'State',
  'doctor.stepup.maintenance': 'changing maintenance mode',

  // --- Config page --------------------------------------------------------------
  'config.page.title': 'Configuration',
  'config.page.subtitle':
    'Parity with vnc-remote config: effective view with provenance, ' +
    'validation, profile diff and migration.',
  'config.filter': 'Filter variables',
  'config.vars': '{{count}} variables',
  'config.loadError': 'Could not load configuration.',
  'config.col.var': 'Variable',
  'config.col.value': 'Value',
  'config.col.source': 'Source',
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

  // --- Portal ----------------------------------------------------------------
  'portal.metrics.host': 'Host',
  'portal.metrics.os': 'OS',
  'portal.metrics.uptime': 'Uptime',
  'portal.metrics.cpu': 'CPU',
  'portal.metrics.ram': 'RAM',
  'portal.metrics.disk': 'Disk',
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
  'portal.gamepad.resume': 'Resume audio',
  'portal.gamepad.stop': 'Stop',
  'portal.error.restricted': 'Access restricted to operators.',
  'portal.error.load': 'Could not load the portal.',
  'portal.adminLink': 'Administration panel →',
  'portal.shell.system': 'system shell',
  'portal.skipLink': 'Skip to content',
  'portal.tagline': 'Service access portal',
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

  // --- Audio ------------------------------------------------------------------
  'audio.title': 'Remote audio',
  'audio.connect': 'Connect',
  'audio.disconnect': 'Disconnect',
  'audio.volume': 'Volume',
  'audio.info.initial':
    'Press Connect to receive audio from the remote machine.',
  'audio.info.unauthorized': 'Session is not authorized for audio.',
  'audio.info.connectingTo': 'Connecting to {{url}}…',
  'audio.info.receiving': 'Receiving audio…',
  'audio.info.status':
    '{{clients}} listener(s) · device {{device}} · {{bitrate}} kbps',
  'audio.info.closed': 'Connection closed by the server.',
  'audio.info.error': 'Error: {{msg}}',
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
  'gamepad.info.unauthorized': 'Session is not authorized for gamepad.',
  'gamepad.info.closed': 'Connection closed by the server.',
  'gamepad.info.revoked': 'Session revoked.',
  'gamepad.info.error': 'Error: {{msg}}',
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
  'audio.connectingTo': 'Connecting to {{url}}…',
  'audio.receiving': 'Receiving audio…',
  'audio.status':
    '{{clients}} listener(s) · device {{device}} · {{bitrate}} kbps',
  'audio.closed': 'Connection closed by the server.',
  'audio.error': 'Error: {{msg}}',
  'gamepad.unauthorized': 'Session is not authorized for gamepad.',
  'gamepad.closed': 'Connection closed by the server.',
  'gamepad.revoked': 'Session revoked.',
  'gamepad.error': 'Error: {{msg}}',
  'portal.error.adminLink': 'Administration panel →',

  // --- Terminal -------------------------------------------------------------------
  'terminal.unauthorized': 'Session is not authorized for the terminal.',
  'terminal.state.connected': 'connected',
  'terminal.state.connecting': 'connecting',
  'terminal.state.error': 'error',
  'terminal.state.disconnected': 'disconnected',

  // --- Login (extra) ----------------------------------------------------------------
  'login.networkError': 'Network error — the service may be down.',
  'login.passkeyFailed': 'Passkey authentication failed.',
  'login.passkeyWaiting': 'Waiting for your device…',
  'login.auditNote':
    'Sign-in attempts are recorded in the audit log.',

  // --- Sessions ----------------------------------------------------------------
  'sessions.title': 'Sessions',
  'sessions.createTitle': 'New shared session',
  'sessions.role': 'Permission',
  'sessions.ttl': 'Duration (TTL)',
  'sessions.maxUses': 'Max uses',
  'sessions.resource': 'Resource',
  'sessions.allResources': 'All resources',
  'sessions.ipRestriction': 'IP restriction',
  'sessions.ipPlaceholder': 'e.g. 192.168.1.10',
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
  'sessions.tabActive': 'Active',
  'sessions.tabRevoked': 'Revoked/expired',
  'sessions.revokeAll': 'Close all',
  'sessions.loadError': 'Could not load sessions.',
  'sessions.emptyActive': 'No active sessions.',
  'sessions.emptyRevoked': 'No revoked or expired sessions.',
  'sessions.col.ref': 'Ref',
  'sessions.col.state': 'State',
  'sessions.col.role': 'Permission',
  'sessions.col.perms': 'Scope',
  'sessions.col.resource': 'Resource',
  'sessions.col.expires': 'Expires',
  'sessions.col.flags': 'Flags',
  'sessions.col.creator': 'Creator',
  'sessions.stateActive': 'active',
  'sessions.stateRevoked': 'revoked',
  'sessions.permCount': '{{count}} permission(s)',
  'sessions.revoke': 'Revoke',
  'sessions.revokeTitle': 'Revoke session',
  'sessions.revokeBody':
    'Session {{id}} ({{role}} on {{resource}}) will be ' +
    'invalidated immediately.',
  'sessions.revokeBodyResource': 'Affected resource: {{resource}}.',
  'sessions.revokeAllTitle': 'Close all sessions',
  'sessions.revokeAllBody':
    'All {{count}} active sessions will be revoked. Connected ' +
    'guests lose access immediately.',
  'sessions.loadMore': 'Load more',
  'sessions.stepup.revokeAll': 'closing all active sessions',

  // --- Users (operators) --------------------------------------------------------------
  'users.title': 'Operators',
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
  'users.permCount': '{{count}} permission(s)',
  'users.enable': 'Enable',
  'users.disable': 'Disable',
  'users.revokeSessions': 'Revoke sessions',
  'users.detailError': 'Could not load operator details.',
  'users.passkeyCount': '{{count}} passkey(s)',
  'users.protected': 'protected',
  'users.passkeys': 'Passkeys',
  'users.noPasskeys': 'No passkeys registered.',
  'users.passkeyName': 'Name',
  'users.passkeyRegistered': 'Passkey registered.',
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
  'bits.expired': 'expired',
  'bits.copyRef': 'Copy reference {{id}}',
};

export type Lang = 'es' | 'en';
export type I18nKey = keyof typeof es;

const DICTS: Record<Lang, typeof es> = { es, en };
const STORAGE_KEY = 'vnc-lang';

function detect(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'en' || saved === 'es') return saved;
  } catch { /* private mode */ }
  return navigator.language?.toLowerCase().startsWith('en')
    ? 'en' : 'es';
}

interface I18nCtx {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
}

const Ctx = createContext<I18nCtx>({
  lang: 'es',
  setLang: () => undefined,
  t: (k) => k,
});

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, _setLang] = useState<Lang>(detect);
  const setLang = (l: Lang) => {
    _setLang(l);
    try { localStorage.setItem(STORAGE_KEY, l); } catch { /* ignore */ }
  };
  const value = useMemo<I18nCtx>(() => ({
    lang,
    setLang,
    t: (key, vars) => {
      let s: string = (DICTS[lang] as Record<string, string>)[key]
        ?? (DICTS.es as Record<string, string>)[key] ?? key;
      if (vars) {
        for (const [k, v] of Object.entries(vars)) {
          s = s.split(`{{${k}}}`).join(String(v));
        }
      }
      return s;
    },
  }), [lang]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useI18n() {
  return useContext(Ctx);
}

/** Tiny inline language switcher for chrome areas. */
export function LangSwitch() {
  const { lang, setLang, t } = useI18n();
  return (
    <label className="lang-switch" aria-label={t('lang.label')}>
      <select
        value={lang}
        onChange={(e) => setLang(e.target.value as Lang)}
      >
        <option value="es">ES</option>
        <option value="en">EN</option>
      </select>
    </label>
  );
}
