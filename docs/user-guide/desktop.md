# Desktop Access (noVNC)

## Accessing the Desktop

1. Open your web browser
2. Navigate to `https://your-server:8000` (landing page)
3. Click on the "Desktop" link
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
- Check that the VNC server is running: `vnc-remote status`
- Verify port 6080 is accessible
- Check SSL certificate validity
- Ensure websockify is running
