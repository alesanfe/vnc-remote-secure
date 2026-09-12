#!/usr/bin/env python3
"""Configure UltraVNC completely through its GUI dialog."""
import ctypes
from ctypes import wintypes
import time
import sys
import subprocess
import os

user32 = ctypes.windll.user32
WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

WM_CHAR = 0x0102
WM_SETFOCUS = 0x0007
BM_CLICK = 0x00F5
BM_GETCHECK = 0x00F0
BM_SETCHECK = 0x00F1
BST_CHECKED = 1
BST_UNCHECKED = 0


def find_window(title):
    result = []
    def cb(hwnd, lParam):
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        if title.lower() in buf.value.lower():
            result.append((hwnd, buf.value))
        return True
    user32.EnumWindows(WNDENUMPROC(cb), 0)
    return result


def find_child_windows(parent):
    result = []
    def cb(hwnd, lParam):
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        class_buf = ctypes.create_unicode_buffer(256)
        user32.GetClassNameW(hwnd, class_buf, 256)
        visible = user32.IsWindowVisible(hwnd)
        result.append({
            'handle': hwnd,
            'title': buf.value,
            'class': class_buf.value,
            'visible': bool(visible)
        })
        return True
    user32.EnumChildWindows(parent, WNDENUMPROC(cb), 0)
    return result


def find_edit_after_label(children, label_text):
    found = False
    for child in children:
        if child['class'] == 'Static' and label_text.lower() in child['title'].lower():
            found = True
            continue
        if found and child['class'] == 'Edit' and child['visible']:
            return child
    return None


def check_checkbox(children, label_text):
    """Find a checkbox by label and ensure it's checked."""
    for child in children:
        if child['class'] == 'Button' and child['visible']:
            if label_text.lower() in child['title'].lower():
                handle = child['handle']
                state = user32.SendMessageW(handle, BM_GETCHECK, 0, 0)
                print(f'  [{label_text}] current state: {state}')
                if state != BST_CHECKED:
                    print(f'  Checking [{label_text}]...')
                    user32.SendMessageW(handle, BM_SETCHECK, BST_CHECKED, 0)
                    user32.SendMessageW(handle, BM_CLICK, 0, 0)
                    time.sleep(0.3)
                    state2 = user32.SendMessageW(handle, BM_GETCHECK, 0, 0)
                    print(f'  After click: {state2}')
                    return state2 == BST_CHECKED
                else:
                    print(f'  Already checked')
                    return True
    print(f'  [{label_text}] not found')
    return False


def send_text_to_control(hwnd, text):
    """Send text to a control via WM_CHAR messages."""
    user32.SendMessageW(hwnd, WM_SETFOCUS, 0, 0)
    time.sleep(0.2)
    for char in text:
        user32.PostMessageW(hwnd, WM_CHAR, ord(char), 0)
        time.sleep(0.05)
    time.sleep(0.3)


def main():
    password = sys.argv[1] if len(sys.argv) > 1 else 'vnc12345'
    print('Configuring UltraVNC with password: ***')

    # Kill existing UltraVNC
    os.system('taskkill /f /im winvnc.exe 2>nul')
    time.sleep(3)

    # Start UltraVNC
    subprocess.Popen(
        ['bin/ultravnc/x64/winvnc.exe'],
        cwd='bin/ultravnc/x64',
        creationflags=0x08000000  # CREATE_NO_WINDOW
    )
    time.sleep(3)

    # Open settings dialog
    subprocess.Popen(
        ['bin/ultravnc/x64/winvnc.exe', '-properties'],
        cwd='bin/ultravnc/x64',
        creationflags=0x08000000
    )
    time.sleep(3)

    # Find dialog
    windows = find_window('UltraVNC Server Property')
    if not windows:
        print('ERROR: Dialog not found')
        sys.exit(1)

    hwnd, title = windows[0]
    print(f'Dialog: "{title}" (handle: {hwnd})')

    children = find_child_windows(hwnd)

    # 1. Check "Enable connections"
    print('\n1. Checking Enable connections...')
    check_checkbox(children, 'Enable connections')

    # 2. Check "Allow Loopback Connections"
    print('\n2. Checking Allow Loopback Connections...')
    check_checkbox(children, 'Allow Loopback')

    # 3. Uncheck "Loopbackonly" (we want both loopback AND regular)
    print('\n3. Checking Loopbackonly state...')
    for child in children:
        if child['class'] == 'Button' and child['visible']:
            if child['title'].lower() == 'loopbackonly':
                handle = child['handle']
                state = user32.SendMessageW(handle, BM_GETCHECK, 0, 0)
                print(f'  Loopbackonly state: {state}')
                if state == BST_CHECKED:
                    print('  Unchecking Loopbackonly...')
                    user32.SendMessageW(handle, BM_CLICK, 0, 0)
                    time.sleep(0.3)
                break

    # 4. Set VNC Password
    print('\n4. Setting VNC Password...')
    pw_field = find_edit_after_label(children, 'VNC Password')
    if pw_field:
        print(f'  Found password field (handle: {pw_field["handle"]})')
        send_text_to_control(pw_field['handle'], password)
    else:
        print('  ERROR: Password field not found')

    # 5. Set View-Only Password
    print('\n5. Setting View-Only Password...')
    vo_field = find_edit_after_label(children, 'View-Only Password')
    if vo_field:
        print(f'  Found view-only field (handle: {vo_field["handle"]})')
        send_text_to_control(vo_field['handle'], password)
    else:
        print('  View-only field not found')

    # 6. Uncheck MS Logon
    print('\n6. Unchecking MS Logon...')
    for child in children:
        if child['class'] == 'Button' and child['visible']:
            if child['title'].lower() == 'ms logon':
                handle = child['handle']
                state = user32.SendMessageW(handle, BM_GETCHECK, 0, 0)
                print(f'  MS Logon state: {state}')
                if state == BST_CHECKED:
                    print('  Unchecking MS Logon...')
                    user32.SendMessageW(handle, BM_CLICK, 0, 0)
                    time.sleep(0.3)
                break

    # 7. Click OK
    print('\n7. Clicking OK...')
    for child in children:
        if child['class'] == 'Button' and child['visible']:
            clean = child['title'].replace('&', '').lower().strip()
            if clean == 'ok':
                print(f'  Clicking OK (handle: {child["handle"]})')
                user32.SendMessageW(child['handle'], BM_CLICK, 0, 0)
                time.sleep(3)
                print('  OK clicked!')
                break

    # 8. Test connection
    print('\n8. Testing VNC connection...')
    import socket
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(('localhost', 5900))
        v = s.recv(12)
        print(f'  Server version: {v.strip()}')
        s.send(b'RFB 003.008\n')
        n = s.recv(1)
        nt = n[0]
        print(f'  Security types count: {nt}')
        if nt > 0:
            st = s.recv(nt)
            names = {1: 'None', 2: 'VNC Auth', 16: 'Ultra'}
            for t in st:
                print(f'    Type {t}: {names.get(t, "Unknown")}')
            if 2 in st:
                print('  SUCCESS: VNC Auth enabled!')
            elif 1 in st:
                print('  No auth available')
        else:
            el = struct.unpack('>I', s.recv(4))[0]
            print(f'  Error: {s.recv(el).decode()}')
        s.close()
    except Exception as e:
        print(f'  Test failed: {e}')


if __name__ == '__main__':
    main()
