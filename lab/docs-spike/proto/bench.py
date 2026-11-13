"""proto/bench.py (Task 2 SPIKE; RUNS ON THE WORKSTATION as doc_auth.py+bench.py, CHP_DOC_AS=lab01): the cost of route 1's
per-request check at Kanidm's userinfo. 30 PROPFINDs with the Bearer, then 30 with lab01's app password (read from
stdin, never stored or printed). Prints median and p90 in ms."""
import statistics as _st

p, s = load("runtime")
if time.time() > s["expires_at"] - 30:
    s = oidc_refresh(p, s, print) or s
app = sys.stdin.readline().strip()
for label, h in (("Bearer (userinfo check)", "Bearer " + s["access_token"]),
                 ("app password", "Basic " + base64.b64encode(f"lab01:{app}".encode()).decode())):
    t = []
    for _ in range(30):
        t0 = time.perf_counter()
        st, _, _ = req("PROPFIND", f"{FILES}/remote.php/dav/files/lab01/CUI", None, {"Authorization": h, "Depth": "0"})
        t.append((time.perf_counter() - t0) * 1000)
        assert st == 207, st
    t.sort()
    print(f"{label}: 30 x PROPFIND 207; median {_st.median(t):.0f} ms, p90 {t[26]:.0f} ms")
