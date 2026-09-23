"""Windows gamepad input injection.

Two backends, chosen at adapter time:

- :class:`ViGEmInjector` — a REAL virtual Xbox 360 controller via
  ViGEmBus (the ``vgamepad`` package). Games see an actual XInput
  device. Requires the third-party ViGEmBus driver installed.
- :class:`WindowsInputInjector` — SendInput (ctypes) keyboard/mouse
  injection. No driver needed, but no game either sees a gamepad.

The adapter prefers ViGEm and falls back to SendInput, keeping the
service functional on machines without the driver.
"""


class ViGEmInjector:
    """Virtual Xbox 360 controller via ViGEmBus (``vgamepad``).

    Raises ``ImportError``/``Exception`` at construction when the
    package or the kernel driver is absent — the adapter treats that
    as "backend unavailable" and falls back to SendInput.
    """

    def __init__(self):
        # Optional Windows-only dependency — ImportError means the
        # backend is unavailable and the adapter falls back.
        import vgamepad as vg  # noqa: F401 # pylint: disable=import-error
        self._vg = vg
        self._pad = vg.VX360Gamepad()
        self.available = True
        b = vg.XUSB_BUTTON
        self._button_map = {
            'button_0': b.XUSB_GAMEPAD_A,
            'button_1': b.XUSB_GAMEPAD_B,
            'button_2': b.XUSB_GAMEPAD_X,
            'button_3': b.XUSB_GAMEPAD_Y,
            'button_4': b.XUSB_GAMEPAD_LEFT_SHOULDER,
            'button_5': b.XUSB_GAMEPAD_RIGHT_SHOULDER,
            'button_6': b.XUSB_GAMEPAD_LEFT_THUMB,
            'button_7': b.XUSB_GAMEPAD_RIGHT_THUMB,
            'button_8': b.XUSB_GAMEPAD_BACK,
            'button_9': b.XUSB_GAMEPAD_START,
            'button_10': b.XUSB_GAMEPAD_GUIDE,
            'button_12': b.XUSB_GAMEPAD_DPAD_UP,
            'button_13': b.XUSB_GAMEPAD_DPAD_DOWN,
            'button_14': b.XUSB_GAMEPAD_DPAD_LEFT,
            'button_15': b.XUSB_GAMEPAD_DPAD_RIGHT,
        }
        # vgamepad sets both stick components atomically — track the
        # last sent values so an axis event updates only its own axis.
        self._left = [0.0, 0.0]
        self._right = [0.0, 0.0]

    def inject_button(self, button_code, value):
        """Inject a gamepad button press/release."""
        btn = self._button_map.get(str(button_code))
        if btn is None:
            return
        try:
            pressed = int(value) != 0
        except (TypeError, ValueError):
            return
        if pressed:
            self._pad.press_button(button=btn)
        else:
            self._pad.release_button(button=btn)
        self._pad.update()

    def inject_axis(self, axis, value):
        """Inject a stick axis movement (-1.0..1.0)."""
        try:
            value = float(value)
        except (TypeError, ValueError):
            return
        value = max(-1.0, min(1.0, value))
        if axis == 'axis_0':
            self._left[0] = value
        elif axis == 'axis_1':
            self._left[1] = value
        elif axis == 'axis_2':
            self._right[0] = value
        elif axis == 'axis_3':
            self._right[1] = value
        else:
            return
        self._pad.left_joystick_float(
            x_value_float=self._left[0],
            y_value_float=self._left[1])
        self._pad.right_joystick_float(
            x_value_float=self._right[0],
            y_value_float=self._right[1])
        self._pad.update()

    def close(self):
        """Release every input and reset the virtual controller."""
        try:
            self._pad.reset()
            self._pad.update()
        except Exception:  # noqa: BLE001 - close is best-effort
            pass


class WindowsInputInjector:
    """Inject input events on Windows using SendInput (ctypes)."""

    def __init__(self):
        self.available = True
        # Keys currently held down — tracked so close() can release
        # them; SendInput has no "release everything" call and a
        # stuck key would keep typing into the user's session.
        self._held = set()
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
        if value == 0:
            self._held.discard(vk)
        else:
            self._held.add(vk)

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
        """Release every held key — disconnect must not leave stuck input.

        Unlike the ViGEm path (``pad.reset()`` clears the virtual pad),
        SendInput has no reset: each key still in ``_held`` gets an
        explicit KEYUP. Best-effort — a SendInput failure mid-release
        still attempts the remaining keys.
        """
        if not self._held:
            return
        for vk in list(self._held):
            try:
                self._send_keyup(vk)
            except Exception:  # noqa: BLE001 - release is best-effort
                pass
        self._held.clear()

    @staticmethod
    def _send_keyup(vk):
        """Send a single KEYUP event for ``vk`` via SendInput."""
        import ctypes
        from ctypes import wintypes

        INPUT_KEYBOARD = 1
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

        inp = INPUT()
        inp.type = INPUT_KEYBOARD  # pylint: disable=attribute-defined-outside-init
        inp.ki.wVk = vk
        inp.ki.dwFlags = KEYEVENTF_KEYUP
        ctypes.windll.user32.SendInput(
            1, ctypes.byref(inp), ctypes.sizeof(inp))
