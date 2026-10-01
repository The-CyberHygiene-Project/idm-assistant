# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""Authenticate a user through a real PAM stack (row 36: the gdm-password stack, without a screen). A ctypes conversation
answers the module prompts: the TOTP code for a verification-code prompt, the password otherwise. Linux-PAM semantics
(an array of message pointers). Run as root (pam_google_authenticator user=root, pam_kanidm via unixd)."""
import ctypes
import ctypes.util
import re

ECHO_OFF, ECHO_ON, ERROR_MSG, TEXT_INFO = 1, 2, 3, 4
_CODE = re.compile(r"verification code|one-time|token|otp", re.I)


def answer(prompt, style, password, code):
    if style not in (ECHO_OFF, ECHO_ON):
        return None
    if _CODE.search(prompt or ""):
        return code if code is not None else ""
    return password


class _Msg(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class _Resp(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


_CONV = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(_Msg)),
                         ctypes.POINTER(ctypes.POINTER(_Resp)), ctypes.c_void_p)


class _Conv(ctypes.Structure):
    _fields_ = [("conv", _CONV), ("appdata_ptr", ctypes.c_void_p)]


def authenticate(service, user, password, code, lib=None):
    pam = lib or ctypes.CDLL(ctypes.util.find_library("pam") or "libpam.so.0")
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    libc.calloc.restype, libc.calloc.argtypes = ctypes.c_void_p, [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype, libc.strdup.argtypes = ctypes.c_void_p, [ctypes.c_char_p]
    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(_Conv), ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_authenticate.argtypes = pam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_strerror.restype, pam.pam_strerror.argtypes = ctypes.c_char_p, [ctypes.c_void_p, ctypes.c_int]
    prompts = []

    def conv(n, msgs, resp, _data):
        arr = libc.calloc(n, ctypes.sizeof(_Resp))
        if not arr:
            return 5                                   # PAM_BUF_ERR
        r = ctypes.cast(arr, ctypes.POINTER(_Resp))
        for i in range(n):
            m = msgs[i].contents
            p = (m.msg or b"").decode(errors="replace")
            prompts.append(p.strip())
            a = answer(p, m.msg_style, password, code)
            if a is not None:
                r[i].resp = libc.strdup(a.encode())     # PAM frees these with free()
        resp[0] = r
        return 0

    cb = _CONV(conv)
    conv_struct = _Conv(cb, None)
    h = ctypes.c_void_p()
    rc = pam.pam_start(service.encode(), user.encode(), ctypes.byref(conv_struct), ctypes.byref(h))
    if rc != 0:
        return False, f"pam_start failed ({rc})", prompts
    try:
        rc = pam.pam_authenticate(h, 0)
        if rc == 0:
            rc = pam.pam_acct_mgmt(h, 0)
        return rc == 0, ("ok" if rc == 0 else pam.pam_strerror(h, rc).decode(errors="replace")), prompts
    finally:
        pam.pam_end(h, rc)
