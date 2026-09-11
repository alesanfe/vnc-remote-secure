"""Project-wide constants."""
APP_NAME = "VNC Remote Secure"
APP_VERSION = "0.2.0"
DEFAULT_VNC_PORT = 5900
DEFAULT_NOVNC_PORT = 6080
DEFAULT_TTYD_PORT = 5000
DEFAULT_HEALTH_PORT = 8090
DEFAULT_LANDING_PORT = 8000
DEFAULT_VNC_GEOMETRY = "1280x720"
DEFAULT_VNC_DEPTH = 24
MIN_PASSWORD_LENGTH = 8
WEAK_PASSWORDS = {"changeme", "admin123", "password", "YourStrongPassword123", "12345678"}
RESERVED_USERNAMES = {"root", "admin", "daemon", "bin", "sys", "nobody", "www-data"}
