# Desktop Access (noVNC)

## Accessing the Desktop

1. Open your web browser
2. Navigate to the landing portal — `https://your-server` through
   nginx (port 443), or `http://your-server:8000` directly
   (`LANDING_PORT`)
3. Click on the "VNC Desktop (noVNC)" link
4. The noVNC client will load in your browser

## Features

- Full desktop access via VNC
- Clipboard sync (if enabled)
- Scaling and fullscreen mode
- Works on any modern browser (Chrome, Firefox, Safari, Edge)

## Keyboard Shortcuts

- `Ctrl+Alt+Shift` - Open noVNC control panel
- `Ctrl+Alt+Del` - Send Ctrl+Alt+Del (if enabled)
- `F11` - Toggle fullscreen

## Troubleshooting

If the desktop doesn't load:
- Check that the services are running: `vnc-remote status`
- Through nginx, only port 443 is reachable; direct noVNC access
  uses `NOVNC_PORT` (default 6080)
- Check SSL certificate validity (`vnc-remote doctor` → tls.certificates)
- Ensure the loopback websockify bridge is up (`vnc-remote status` →
  `websockify`, default port 5700)
