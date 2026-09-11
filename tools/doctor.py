#!/usr/bin/env python3
"""
Comprehensive verification of all VNC Remote Secure services.
Tests each service at the protocol level, not just port listening.

Credentials are read from environment variables or .env file.
Set VNC_PASSWORD and TTYD_PASSWD before running, or create a .env file.
"""
import socket
import struct
import ssl
import json
import time
import os
import sys
import base64
import urllib.request
import websocket

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_src_path = os.path.join(_project_root, 'src')
sys.path.insert(0, _src_path)
from vnc_remote_secure.vendor import d3des as d
from vnc_remote_secure.core.config import load_env_file

# Load .env file for credentials
load_env_file()

# Read credentials from environment (never hardcoded)
VNC_PASSWORD = os.environ.get('VNC_PASSWORD', '')
TTYD_USERNAME = os.environ.get('TTYD_USERNAME', 'admin')
TTYD_PASSWORD = os.environ.get('TTYD_PASSWD', '')

if not VNC_PASSWORD:
    print("WARNING: VNC_PASSWORD not set, VNC auth tests will be skipped", file=sys.stderr)
if not TTYD_PASSWORD:
    print("WARNING: TTYD_PASSWD not set, terminal tests will be skipped", file=sys.stderr)

# VNC password is truncated to 8 chars
VNC_PASS_8 = VNC_PASSWORD[:8] if VNC_PASSWORD else ''

# Colors for terminal output
class C:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

passed = 0
failed = 0
warnings = 0
skipped = 0

def ok(msg):
    global passed
    passed += 1
    print(f"  {C.GREEN}[PASS]{C.RESET} {msg}")

def fail(msg):
    global failed
    failed += 1
    print(f"  {C.RED}[FAIL]{C.RESET} {msg}")

def warn(msg):
    global warnings
    warnings += 1
    print(f"  {C.YELLOW}[WARN]{C.RESET} {msg}")

def skip(msg):
    global skipped
    skipped += 1
    print(f"  {C.YELLOW}[SKIP]{C.RESET} {msg}")

def section(title):
    print(f"\n{C.CYAN}{C.BOLD}{'='*60}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD} {title}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'='*60}{C.RESET}")


# ============================================================================
# 1. VNC RFB Authentication Test
# ============================================================================
def test_vnc_rfb():
    section("1. VNC Server (RFB Protocol - port 5900)")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(('localhost', 5900))
        
        # RFB version handshake
        version = s.recv(12)
        ver_str = version.decode('ascii', errors='replace').strip()
        if ver_str.startswith('RFB'):
            ok(f"RFB version handshake: {ver_str}")
        else:
            fail(f"Invalid RFB version: {ver_str}")
            s.close()
            return
        s.send(version)
        
        # Security types
        data = s.recv(1024)
        num_types = data[0]
        sec_types = list(data[1:1+num_types])
        
        if num_types > 0:
            ok(f"Security types offered: {sec_types} ({num_types} types)")
            if 2 in sec_types:
                ok("VNC authentication (type 2) available")
            else:
                warn("VNC auth (type 2) not available")
        else:
            fail("No security types offered - password not configured")
            s.close()
            return
        
        # Select VNC auth
        s.send(bytes([2]))
        
        # Challenge
        challenge = s.recv(16)
        if len(challenge) == 16:
            ok(f"Challenge received: {len(challenge)} bytes")
        else:
            fail(f"Invalid challenge: {len(challenge)} bytes")
            s.close()
            return
        
        # Respond with password (read from environment, truncated to 8 chars)
        if not VNC_PASS_8:
            skip("VNC_PASSWORD not set, skipping auth test")
            s.close()
            return
        password = VNC_PASS_8.encode('latin-1')
        ek = d.deskey(password, False)
        response = d.desfunc(challenge[:8], ek) + d.desfunc(challenge[8:], ek)
        s.send(response)
        
        # Auth result
        result = s.recv(4)
        auth_result = struct.unpack('>I', result)[0]
        
        if auth_result == 0:
            ok(f"Authentication SUCCESSFUL with password '{VNC_PASS_8}'")
            
            # Try to receive FramebufferUpdate to confirm desktop is available
            # Send ClientInit (shared flag = 1)
            s.send(bytes([1]))
            
            # ServerInit
            server_init = s.recv(24)
            if len(server_init) >= 24:
                fb_width = struct.unpack('>H', server_init[0:2])[0]
                fb_height = struct.unpack('>H', server_init[2:4])[0]
                ok(f"Desktop resolution: {fb_width}x{fb_height}")
            else:
                warn(f"ServerInit incomplete: {len(server_init)} bytes")
        else:
            reason_len = struct.unpack('>I', s.recv(4))[0]
            reason = s.recv(reason_len).decode('ascii', errors='replace')
            fail(f"Authentication FAILED: {reason}")
        
        s.close()
    except Exception as e:
        fail(f"Connection error: {e}")


# ============================================================================
# 2. noVNC via websockify (WebSocket proxy test)
# ============================================================================
def test_novnc_websocket():
    section("2. noVNC via websockify (HTTPS WebSocket - port 6080)")
    
    # Test HTTP page
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        req = urllib.request.Request('https://localhost:6080/vnc.html')
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        if resp.status == 200:
            ok("vnc.html page served (HTTP 200)")
            content = resp.read(1000).decode('utf-8', errors='replace')
            if 'noVNC' in content or 'vnc' in content.lower():
                ok("Page content is valid noVNC HTML")
            else:
                warn("Page served but content doesn't look like noVNC")
        else:
            fail(f"HTTP status: {resp.status}")
    except Exception as e:
        fail(f"HTTP request failed: {e}")
    
    # Test WebSocket proxy to VNC
    try:
        ws_url = "wss://localhost:6080/websockify"
        ws = websocket.create_connection(
            ws_url,
            sslopt={"cert_reqs": ssl.CERT_NONE},
            timeout=10
        )
        ok("WebSocket connection to websockify established")
        
        # Should receive RFB version from VNC server through the proxy
        data = ws.recv()
        if isinstance(data, bytes):
            rfb_ver = data.decode('ascii', errors='replace').strip()
        else:
            rfb_ver = data.strip()
        
        if rfb_ver.startswith('RFB'):
            ok(f"RFB version through proxy: {rfb_ver}")
            
            # Send RFB version back
            ws.send_binary(data if isinstance(data, bytes) else data.encode())
            
            # Receive security types
            sec_data = ws.recv()
            if isinstance(sec_data, bytes):
                num_types = sec_data[0]
                sec_types = list(sec_data[1:1+num_types])
                ok(f"Security types through proxy: {sec_types}")
            else:
                warn(f"Unexpected data format: {type(sec_data)}")
        else:
            fail(f"Invalid RFB version through proxy: {rfb_ver}")
        
        ws.close()
    except Exception as e:
        fail(f"WebSocket proxy test failed: {e}")


# ============================================================================
# 3. UltraVNC HTTP server (port 5800)
# ============================================================================
def test_ultravnc_http():
    section("3. UltraVNC HTTP Server (port 5800)")
    
    try:
        req = urllib.request.Request('http://localhost:5800/')
        resp = urllib.request.urlopen(req, timeout=10)
        if resp.status == 200:
            ok("UltraVNC HTTP server responding (HTTP 200)")
            content = resp.read(500).decode('utf-8', errors='replace')
            if 'vnc' in content.lower() or 'ultravnc' in content.lower() or 'java' in content.lower():
                ok("Content appears to be UltraVNC viewer page")
            else:
                warn(f"Page served but content unclear: {content[:100]}")
        else:
            fail(f"HTTP status: {resp.status}")
    except urllib.error.HTTPError as e:
        warn(f"HTTP error {e.code} - UltraVNC HTTP may require different path")
    except Exception as e:
        warn(f"UltraVNC HTTP server test: {e}")


# ============================================================================
# 4. Web Terminal (port 5000)
# ============================================================================
def test_web_terminal():
    section("4. Web Terminal (HTTPS WebSocket - port 5000)")
    
    if not TTYD_PASSWORD:
        skip("TTYD_PASSWD not set, skipping terminal tests")
        return
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    # Test HTTP page
    try:
        credentials = base64.b64encode(f'{TTYD_USERNAME}:{TTYD_PASSWORD}'.encode()).decode('ascii')
        req = urllib.request.Request('https://localhost:5000/')
        req.add_header('Authorization', f'Basic {credentials}')
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        if resp.status == 200:
            ok("Terminal page served with auth (HTTP 200)")
        else:
            fail(f"HTTP status: {resp.status}")
    except Exception as e:
        fail(f"HTTP request failed: {e}")
    
    # Test without auth
    try:
        req = urllib.request.Request('https://localhost:5000/')
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        fail("Terminal page served WITHOUT auth (should be 401)")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            ok("Auth required (401 without credentials)")
        else:
            fail(f"Unexpected status without auth: {e.code}")
    except Exception as e:
        fail(f"Auth test error: {e}")
    
    # Test WebSocket with multiple commands
    try:
        ws_url = "wss://localhost:5000/ws"
        credentials = base64.b64encode(f'{TTYD_USERNAME}:{TTYD_PASSWORD}'.encode()).decode('ascii')
        ws = websocket.create_connection(
            ws_url,
            header=[f"Authorization: Basic {credentials}"],
            sslopt={"cert_reqs": ssl.CERT_NONE},
            timeout=10
        )
        ok("WebSocket connection established")
        
        # Collect welcome message
        time.sleep(1)
        welcome = ""
        for i in range(10):
            try:
                data = ws.recv()
                if isinstance(data, bytes):
                    welcome += data.decode('utf-8', errors='replace')
                else:
                    welcome += data
            except Exception:
                break
        
        if 'Web Terminal' in welcome:
            ok("Welcome message received")
        else:
            warn(f"Welcome message unexpected: {welcome[:100]}")
        
        # Test echo command
        ws.send(json.dumps({"type": "command", "cmd": "echo test123"}))
        time.sleep(2)
        echo_output = ""
        for i in range(10):
            try:
                data = ws.recv()
                if isinstance(data, bytes):
                    echo_output += data.decode('utf-8', errors='replace')
                else:
                    echo_output += data
            except Exception:
                break
        
        if 'test123' in echo_output:
            ok("echo command works: 'test123' received")
        else:
            fail(f"echo command failed: {echo_output[:200]}")
        
        # Test hostname command
        ws.send(json.dumps({"type": "command", "cmd": "hostname"}))
        time.sleep(2)
        host_output = ""
        for i in range(10):
            try:
                data = ws.recv()
                if isinstance(data, bytes):
                    host_output += data.decode('utf-8', errors='replace')
                else:
                    host_output += data
            except Exception:
                break
        
        if host_output.strip() and len(host_output.strip()) > 0:
            ok(f"hostname command works: {host_output.strip().split(chr(13))[0]}")
        else:
            fail("hostname command returned empty")
        
        # Test cd command
        ws.send(json.dumps({"type": "command", "cmd": "cd \\"}))
        time.sleep(1)
        ws.send(json.dumps({"type": "command", "cmd": "cd"}))
        time.sleep(2)
        cd_output = ""
        for i in range(10):
            try:
                data = ws.recv()
                if isinstance(data, bytes):
                    cd_output += data.decode('utf-8', errors='replace')
                else:
                    cd_output += data
            except Exception:
                break
        
        if 'C:\\' in cd_output:
            ok("cd command works (directory change tracked)")
        else:
            warn(f"cd command output: {cd_output[:200]}")
        
        ws.close()
    except Exception as e:
        fail(f"WebSocket test failed: {e}")


# ============================================================================
# 5. Health Dashboard (port 8090)
# ============================================================================
def test_health_dashboard():
    section("5. Health Dashboard (HTTP - port 8090)")
    
    # Test HTML
    try:
        req = urllib.request.Request('http://localhost:8090/health_status')
        resp = urllib.request.urlopen(req, timeout=10)
        if resp.status == 200:
            content = resp.read().decode('utf-8')
            ok("Health dashboard HTML served (HTTP 200)")
            
            # Check for ANSI codes (should not be present)
            if '\033[' in content:
                fail("ANSI escape codes found in HTML output")
            else:
                ok("No ANSI escape codes in HTML")
            
            # Check for service cards
            if 'service-card' in content:
                ok("Service cards present in HTML")
            else:
                fail("Service cards not found in HTML")
            
            # Check for system info
            if 'system-info' in content:
                ok("System info section present")
            else:
                fail("System info section not found")
            
            # Check for no 'N/A' in critical fields
            if 'Disk: N/A' not in content:
                ok("Disk usage is populated")
            else:
                warn("Disk usage shows N/A")
        else:
            fail(f"HTTP status: {resp.status}")
    except Exception as e:
        fail(f"HTML request failed: {e}")
    
    # Test JSON
    try:
        req = urllib.request.Request('http://localhost:8090/health_status.json')
        resp = urllib.request.urlopen(req, timeout=10)
        if resp.status == 200:
            data = json.loads(resp.read().decode('utf-8'))
            ok("Health JSON API responding (HTTP 200)")
            
            # Check structure
            if 'system' in data and 'services' in data and 'summary' in data:
                ok("JSON structure valid (system, services, summary)")
            else:
                fail("JSON structure invalid")
            
            # Check all services
            for svc in data.get('services', []):
                name = svc.get('name', '?')
                status = svc.get('status', '?')
                port = svc.get('port', '?')
                listening = svc.get('port_listening', False)
                if status == 'healthy' and listening:
                    ok(f"  {name}: {status.upper()} on port {port}")
                elif status == 'warning':
                    warn(f"  {name}: {status.upper()} on port {port}")
                else:
                    fail(f"  {name}: {status.upper()} on port {port}")
            
            # Check summary
            summary = data.get('summary', {})
            ok(f"Summary: {summary.get('healthy',0)} healthy, {summary.get('warning',0)} warning, {summary.get('error',0)} error")
            
            # Check system info
            sys_info = data.get('system', {})
            for field in ['hostname', 'os', 'uptime', 'cpu_usage', 'memory_usage', 'disk_usage']:
                val = sys_info.get(field, 'MISSING')
                if val and val != 'MISSING' and val != 'N/A':
                    pass  # ok(f"  System {field}: {val}")
                else:
                    warn(f"  System {field}: {val}")
        else:
            fail(f"JSON HTTP status: {resp.status}")
    except Exception as e:
        fail(f"JSON request failed: {e}")


# ============================================================================
# 6. Port binding check
# ============================================================================
def test_port_bindings():
    section("6. Port Binding Check")
    
    ports = {
        5900: 'UltraVNC RFB',
        5800: 'UltraVNC HTTP',
        6080: 'noVNC/websockify',
        5000: 'Web Terminal',
        8090: 'Health Dashboard',
    }
    
    for port, name in ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(('localhost', port))
            s.close()
            ok(f"{name} (port {port}): accepting connections")
        except Exception:
            fail(f"{name} (port {port}): not accepting connections")


# ============================================================================
# Main
# ============================================================================
if __name__ == '__main__':
    print(f"{C.CYAN}{C.BOLD}")
    print("=" * 60)
    print("  VNC Remote Secure - Full Service Verification")
    print("=" * 60)
    print(f"{C.RESET}")
    
    test_port_bindings()
    test_vnc_rfb()
    test_novnc_websocket()
    test_ultravnc_http()
    test_web_terminal()
    test_health_dashboard()
    
    print(f"\n{C.CYAN}{C.BOLD}{'='*60}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD} Verification Summary{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'='*60}{C.RESET}")
    print(f"  {C.GREEN}Passed:  {passed}{C.RESET}")
    print(f"  {C.RED}Failed:  {failed}{C.RESET}")
    print(f"  {C.YELLOW}Warnings: {warnings}{C.RESET}")
    print(f"  Total: {passed + failed + warnings}")
    
    if failed == 0:
        print(f"\n  {C.GREEN}{C.BOLD}ALL CRITICAL TESTS PASSED{C.RESET}")
    else:
        print(f"\n  {C.RED}{C.BOLD}{failed} TEST(S) FAILED{C.RESET}")
    
    sys.exit(0 if failed == 0 else 1)
