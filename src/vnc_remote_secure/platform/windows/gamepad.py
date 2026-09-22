"""Windows gamepad input injection via SendInput (ctypes).

This module is consumed by the Windows platform adapter to provide a
platform-specific injector for the gamepad forwarding service. Keeping the
injector in the platform layer avoids circular imports between
``services.gamepad`` and ``platform.*.adapter``
"""


class WindowsInputInjector:
    """Inject input events on Windows using SendInput (ctypes)."""

    def __init__(self):
        self.available = True
        # Map gamepad buttons to virtual key codes
        self.key_map = {
            "button_0": 0x1D,  # 'A' key (cross button)
            "button_1": 0x1E,  # 'B' key (circle button)
            "button_2": 0x2C,  # 'X' key (square button)
            "button_3": 0x2D,  # 'Y' key (triangle button)
            "button_4": 0x10,  # 'Q' key (L1)
            "button_5": 0x19,  # 'P' key (R1)
            "button_8": 0x3A,  # Escape (Select/Share)
            "button_9": 0x1C,  # Enter (Start)
        }

    def inject_button(self, button_code, value):
        """Inject button."""
        import ctypes
        from ctypes import wintypes

        # SendInput structures
        INPUT_KEYBOARD = 1

        KEYEVENTF_KEYDOWN = 0x0000
        KEYEVENTF_KEYUP = 0x0002

        class KEYBDINPUT(ctypes.Structure):
            _fields_ = [("wVk", wintypes.WORD),
                        ("wScan", wintypes.WORD),
                        ("dwFlags", wintypes.DWORD),
                        ("time", wintypes.DWORD),
                        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

        class INPUT(ctypes.Structure):
            class _INPUT(ctypes.Union):
                _fields_ = [("ki", KEYBDINPUT)]
            _anonymous_ = ("_input",)
            _fields_ = [("type", wintypes.DWORD), ("_input", _INPUT)]

        vk = self.key_map.get(str(button_code))
        if vk is None:
            return

        try:
            value = int(value)
        except (TypeError, ValueError):
            return
        flags = KEYEVENTF_KEYUP if value == 0 else KEYEVENTF_KEYDOWN

        inp = INPUT()
        # ctypes union field assignment
        inp.type = INPUT_KEYBOARD  # pylint: disable=attribute-defined-outside-init
        inp.ki.wVk = vk
        inp.ki.dwFlags = flags

        ctypes.windll.user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(inp))

    def inject_axis(self, axis, value):
        """Inject axis."""
        # On Windows, map left stick to mouse movement
        import ctypes
        from ctypes import wintypes

        INPUT_MOUSE = 2
        MOUSEEVENTF_MOVE = 0x0001

        class MOUSEINPUT(ctypes.Structure):
            _fields_ = [("dx", wintypes.LONG),
                        ("dy", wintypes.LONG),
                        ("mouseData", wintypes.DWORD),
                        ("dwFlags", wintypes.DWORD),
                        ("time", wintypes.DWORD),
                        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

        class INPUT(ctypes.Structure):
            class _INPUT(ctypes.Union):
                _fields_ = [("mi", MOUSEINPUT)]
            _anonymous_ = ("_input",)
            _fields_ = [("type", wintypes.DWORD), ("_input", _INPUT)]

        # Only move on left stick (axis_0 = X, axis_1 = Y)
        try:
            value = float(value)
        except (TypeError, ValueError):
            return
        # Clamp: the JS client sends -1.0..1.0 but a control session
        # could send huge values — MOUSEINPUT dx/dy are LONG, so an
        # overflow would raise inside ctypes and kill the handler.
        value = max(-1.0, min(1.0, value))
        dx = dy = 0
        if axis == "axis_0":
            dx = int(value * 20)
        elif axis == "axis_1":
            dy = int(value * 20)
        else:
            return

        if dx == 0 and dy == 0:
            return

        inp = INPUT()
        # ctypes union field assignment
        inp.type = INPUT_MOUSE  # pylint: disable=attribute-defined-outside-init
        inp.mi.dx = dx
        inp.mi.dy = dy
        inp.mi.dwFlags = MOUSEEVENTF_MOVE

        ctypes.windll.user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(inp))

    def close(self):
        """Close (no-op on Windows — nothing to clean up)."""
