#!/usr/bin/env python3
"""Set UltraVNC password through its GUI dialog using WM_CHAR messages."""
import ctypes
from ctypes import wintypes
import time
import sys

user32 = ctypes.windll.user32
WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

WM_CHAR = 0x0102
WM_SETFOCUS = 0x0007
BM_CLICK = 0x00F5


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
    print('Setting UltraVNC password to: ***')

    windows = find_window('UltraVNC Server Property')
    if not windows:
        print('ERROR: Dialog not found')
        sys.exit(1)

    hwnd, title = windows[0]
    print(f'Dialog: "{title}" (handle: {hwnd})')

    children = find_child_windows(hwnd)
    pw_field = find_edit_after_label(children, 'VNC Password')
    vo_field = find_edit_after_label(children, 'View-Only Password')

    if not pw_field:
        print('ERROR: Password field not found')
        sys.exit(1)

    pw_handle = pw_field['handle']
    print(f'VNC Password field handle: {pw_handle}')

    if vo_field:
        vo_handle = vo_field['handle']
        print(f'View-Only field handle: {vo_handle}')
    else:
        vo_handle = None

    # Send password to VNC Password field
    print(f'\nSending password to VNC Password field...')
    send_text_to_control(pw_handle, password)

    # Send password to View-Only field
    if vo_handle:
        print(f'Sending password to View-Only field...')
        send_text_to_control(vo_handle, password)

    # Find and click OK button
    print('\nLooking for OK button...')
    ok_clicked = False
    for child in children:
        if child['class'] == 'Button' and child['visible']:
            clean = child['title'].replace('&', '').lower().strip()
            if clean == 'ok':
                btn_handle = child['handle']
                print(f'Clicking OK button (handle: {btn_handle})')
                user32.SendMessageW(btn_handle, BM_CLICK, 0, 0)
                time.sleep(2)
                print('OK clicked!')
                ok_clicked = True
                break

    if not ok_clicked:
        print('OK button not found, trying Apply...')
        for child in children:
            if child['class'] == 'Button' and child['visible']:
                clean = child['title'].replace('&', '').lower().strip()
                if clean == 'apply':
                    btn_handle = child['handle']
                    print(f'Clicking Apply button (handle: {btn_handle})')
                    user32.SendMessageW(btn_handle, BM_CLICK, 0, 0)
                    time.sleep(2)
                    ok_clicked = True
                    break

    # Test VNC connection
    print('\nTesting VNC connection...')
    import socket
    import struct
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(('localhost', 5900))
        v = s.recv(12)
        print(f'Server version: {v.strip()}')
        s.send(b'RFB 003.008\n')
        n = s.recv(1)
        nt = n[0]
        print(f'Security types count: {nt}')
        if nt > 0:
            st = s.recv(nt)
            names = {1: 'None', 2: 'VNC Auth', 16: 'Ultra'}
            for t in st:
                print(f'  Type {t}: {names.get(t, "Unknown")}')
            if 2 in st:
                print('SUCCESS: VNC Auth is enabled!')
        else:
            el = struct.unpack('>I', s.recv(4))[0]
            print(f'Error: {s.recv(el).decode()}')
        s.close()
    except Exception as e:
        print(f'Test failed: {e}')


if __name__ == '__main__':
    main()
