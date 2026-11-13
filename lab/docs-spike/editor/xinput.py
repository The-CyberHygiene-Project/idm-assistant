# Runs ON the workstation (python3 -I -c, as proto/on-dcli.sh does). Drives the Xvfb display through XTest (no xdotool).
# usage: key CTRL+s | type "text" | click X Y | sleep S ...   e.g. xinput.py key ctrl+s
import ctypes, sys, time, os
X = ctypes.CDLL("libX11.so.6"); T = ctypes.CDLL("libXtst.so.6")
X.XOpenDisplay.restype = ctypes.c_void_p; X.XStringToKeysym.restype = ctypes.c_ulong
X.XKeysymToKeycode.restype = ctypes.c_ubyte; X.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
dpy = X.XOpenDisplay(os.environ.get("DISPLAY", ":77").encode())
ALIAS = {"ctrl": "Control_L", "shift": "Shift_L", "alt": "Alt_L", "enter": "Return", "esc": "Escape"}
def kc(n): n = ALIAS.get(n.lower(), n); return X.XKeysymToKeycode(dpy, X.XStringToKeysym(n.encode()))
def fk(code, down): T.XTestFakeKeyEvent(ctypes.c_void_p(dpy), code, down, 0); X.XFlush(ctypes.c_void_p(dpy)); time.sleep(0.03)
def key(combo):
    parts = combo.split("+"); codes = [kc(p) for p in parts]
    for c in codes: fk(c, 1)
    for c in reversed(codes): fk(c, 0)
def typ(s):
    for ch in s:
        n = {" ": "space", ".": "period", ",": "comma", "-": "minus", "_": "underscore", "/": "slash", ":": "colon", "(": "parenleft", ")": "parenright", "\n": "Return"}.get(ch, ch)
        if ch.isupper() or ch in "_:()": key("shift+" + n if n not in ("underscore", "colon", "parenleft", "parenright") else "shift+" + {"underscore": "minus", "colon": "semicolon", "parenleft": "9", "parenright": "0"}[n])
        else: key(n)
def click(x, y):
    T.XTestFakeMotionEvent(ctypes.c_void_p(dpy), 0, x, y, 0); T.XTestFakeButtonEvent(ctypes.c_void_p(dpy), 1, 1, 0); T.XTestFakeButtonEvent(ctypes.c_void_p(dpy), 1, 0, 0); X.XFlush(ctypes.c_void_p(dpy)); time.sleep(0.2)
a = sys.argv[1:]; i = 0
while i < len(a):
    c = a[i]
    if c == "key": key(a[i+1]); i += 2
    elif c == "type": typ(a[i+1]); i += 2
    elif c == "click": click(int(a[i+1]), int(a[i+2])); i += 3
    elif c == "sleep": time.sleep(float(a[i+1])); i += 2
    else: raise SystemExit("bad " + c)
