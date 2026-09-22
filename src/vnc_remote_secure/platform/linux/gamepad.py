"""Linux gamepad input injection via uinput (evdev).

This module is consumed by the Linux platform adapter to provide a
platform-specific injector for the gamepad forwarding service. Keeping the
injector in the platform layer avoids circular imports between
``services.gamepad`` and ``platform.*.adapter``.
"""
import logging

logger = logging.getLogger(__name__)


class LinuxInputInjector:
    """Inject input events on Linux using uinput (via evdev)."""

    def __init__(self):
        self.uinput = None
        self.available = False
        try:
            import evdev
            from evdev import UInput, ecodes
            self.ecodes = ecodes
            self.UInput = UInput
            self.evdev = evdev
            self.available = True
        except ImportError:
            logger.warning("evdev not installed. Gamepad forwarding disabled on Linux.")
            logger.warning("  Install with: pip install evdev")
            logger.warning("  Also ensure uinput module is loaded: sudo modprobe uinput")

    def _button_map(self):
        """Map the client's button names to evdev codes.

        The JS client (gamepad.html) sends standard Gamepad-API names
        (``button_0`` … ``button_15``); the Linux injector must translate
        them — it used to pass the raw string to ``uinput.write`` which
        raised TypeError on every event.
        """
        e = self.ecodes
        return {
            'button_0': e.BTN_A,          # A (cross)
            'button_1': e.BTN_B,          # B (circle)
            'button_2': e.BTN_X,          # X (square)
            'button_3': e.BTN_Y,          # Y (triangle)
            'button_4': e.BTN_TL,         # L1
            'button_5': e.BTN_TR,         # R1
            'button_8': e.BTN_SELECT,     # Select/Share
            'button_9': e.BTN_START,      # Start
            'button_10': e.BTN_THUMBL,    # Left stick press
            'button_11': e.BTN_THUMBR,    # Right stick press
            'button_12': e.BTN_DPAD_UP,   # D-pad up
            'button_13': e.BTN_DPAD_DOWN,
            'button_14': e.BTN_DPAD_LEFT,
            'button_15': e.BTN_DPAD_RIGHT,
        }

    def _axis_map(self):
        """Map the client's axis names to evdev ABS codes."""
        e = self.ecodes
        return {
            'axis_0': e.ABS_X,            # left stick X
            'axis_1': e.ABS_Y,            # left stick Y
            'axis_2': e.ABS_RX,           # right stick X
            'axis_3': e.ABS_RY,           # right stick Y
        }

    def _key_events(self):
        """Return the declared EV_KEY code set (also the allowlist)."""
        return list(self._button_map().values())

    def _abs_events(self):
        """Return the declared EV_ABS code set (also the allowlist)."""
        return list(self._axis_map().values())

    def create_device(self):
        """Create device."""
        if not self.available:
            return False
        try:
            self.uinput = self.UInput(
                events={
                    self.ecodes.EV_KEY: self._key_events(),
                    self.ecodes.EV_ABS: self._abs_events(),
                },
                name="VNC Remote Virtual Gamepad"
            )
            return True
        except Exception:
            logger.exception("Failed to create uinput device:")
            logger.exception("  Ensure uinput is accessible: sudo chmod 0666 /dev/uinput")
            return False

    def inject_button(self, button, value):
        """Inject button."""
        if not self.uinput:
            return
        # Whitelist: the client supplies a button NAME (``button_N``)
        # — anything outside the map is dropped, so a control session
        # cannot emit arbitrary key events. Values are binary
        # press/release.
        code = self._button_map().get(str(button))
        if code is None:
            return
        try:
            value = int(value)
        except (TypeError, ValueError):
            return
        if value not in (0, 1):
            return
        try:
            self.uinput.write(self.ecodes.EV_KEY, code, value)
            self.uinput.syn()
        except OSError:
            pass

    def inject_axis(self, axis, value):
        """Inject axis."""
        if not self.uinput:
            return
        code = self._axis_map().get(str(axis))
        if code is None:
            return
        try:
            value = float(value)
        except (TypeError, ValueError):
            return
        # Clamp to the declared axis range — out-of-range writes are
        # dropped by the driver anyway, so normalise here.
        value = max(-1.0, min(1.0, value))
        uinput_value = int(value * 32767)
        try:
            self.uinput.write(self.ecodes.EV_ABS, code, uinput_value)
            self.uinput.syn()
        except OSError:
            pass

    def close(self):
        """Close."""
        if self.uinput:
            self.uinput.close()
            self.uinput = None
