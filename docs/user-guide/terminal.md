# Web Terminal

## Accessing the Terminal

1. Open your web browser
2. Navigate to `https://your-server:8000` (landing page)
3. Click on the "Terminal" link
4. Authenticate with your TTYD credentials

## Features

- Full terminal access in the browser
- Multiple sessions supported
- SSL-encrypted connection
- Configurable shell (bash on Linux, cmd.exe on Windows)

## Configuration

Set in `.env`:
```
TTYD_USERNAME=admin
TTYD_PASSWD=YourStrongPassword
WEBTERM_SHELL=bash  # or cmd.exe on Windows
TTYD_PORT=5000
```

## Security

- Terminal is behind the SSL reverse proxy
- Authentication required (username/password)
- Internal port (5000) is not publicly exposed
- Rate limiting via nginx
