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

    def create_device(self):
        if not self.available:
            return False
        try:
            self.uinput = self.UInput(
                events={
                    self.ecodes.EV_KEY: [
                        self.ecodes.BTN_GAMEPAD,
                        self.ecodes.BTN_A,
                        self.ecodes.BTN_B,
                        self.ecodes.BTN_X,
                        self.ecodes.BTN_Y,
                        self.ecodes.BTN_TL,
                        self.ecodes.BTN_TR,
                        self.ecodes.BTN_SELECT,
                        self.ecodes.BTN_START,
                        self.ecodes.BTN_THUMBL,
                        self.ecodes.BTN_THUMBR,
                        self.ecodes.KEY_ENTER,
                        self.ecodes.KEY_ESC,
                        self.ecodes.KEY_SPACE,
                        self.ecodes.BTN_LEFT,
                    ],
                    self.ecodes.EV_ABS: [
                        self.ecodes.ABS_X,
                        self.ecodes.ABS_Y,
                        self.ecodes.ABS_RX,
                        self.ecodes.ABS_RY,
                    ],
                },
                name="VNC Remote Virtual Gamepad"
            )
            return True
        except Exception as e:
            logger.error("Failed to create uinput device: %s", e)
            logger.error("  Ensure uinput is accessible: sudo chmod 0666 /dev/uinput")
            return False

    def inject_button(self, button, value):
        if not self.uinput:
            return
        self.uinput.write(self.ecodes.EV_KEY, button, value)
        self.uinput.syn()

    def inject_axis(self, axis, value):
        if not self.uinput:
            return
        # value is -1.0 to 1.0, convert to uinput range (-32768 to 32767)
        uinput_value = int(value * 32767)
        self.uinput.write(self.ecodes.EV_ABS, axis, uinput_value)
        self.uinput.syn()

    def close(self):
        if self.uinput:
            self.uinput.close()
            self.uinput = None
