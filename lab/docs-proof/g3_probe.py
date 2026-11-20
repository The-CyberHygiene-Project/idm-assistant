import socket, sys
def t(fam, proto, host, port, payload=b"x"):
    try:
        s = socket.socket(fam, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM); s.settimeout(3)
        if proto == "tcp":
            s.connect((host, port)); r = "CONNECTED"
        else:
            s.sendto(payload, (host, port))
            try: s.recvfrom(512); r = "ANSWERED"
            except socket.timeout: r = "sent, no answer"
        s.close(); return r
    except Exception as e:
        return f"refused/failed: {type(e).__name__}: {e}"
q = bytes.fromhex("abcd01000001000000000000076578616d706c6503636f6d0000010001")   # DNS query example.com A
for name, args in [("DNS udp v4 to 1.1.1.1", (socket.AF_INET, "udp", "1.1.1.1", 53, q)),
                   ("DNS tcp v4 to 8.8.8.8", (socket.AF_INET, "tcp", "8.8.8.8", 53)),
                   ("DNS udp v6 to 2606:4700:4700::1111", (socket.AF_INET6, "udp", "2606:4700:4700::1111", 53, q)),
                   ("DoT 853 v4 to 1.1.1.1", (socket.AF_INET, "tcp", "1.1.1.1", 853)),
                   ("DoT 853 to the server", (socket.AF_INET, "tcp", "192.168.100.50", 853)),
                   ("443 v4 to 1.1.1.1", (socket.AF_INET, "tcp", "1.1.1.1", 443)),
                   ("443 v6 to 2606:4700:4700::1111", (socket.AF_INET6, "tcp", "2606:4700:4700::1111", 443)),
                   ("443 to aero 192.168.100.1", (socket.AF_INET, "tcp", "192.168.100.1", 443)),
                   ("DNS udp to the site resolver", (socket.AF_INET, "udp", "192.168.100.50", 53, q)),
                   ("443 to the server (Kanidm)", (socket.AF_INET, "tcp", "192.168.100.50", 443)),
                   ("8443 to the server (NextCloud)", (socket.AF_INET, "tcp", "192.168.100.50", 8443)),
                   ("1514 to the server (Wazuh)", (socket.AF_INET, "tcp", "192.168.100.50", 1514)),
                   ("NTP udp 123 to aero as root (not chrony)", (socket.AF_INET, "udp", "192.168.100.1", 123, b"\x1b" + 47 * b"\0"))]:
    print(f"{name}: {t(*args)}")
