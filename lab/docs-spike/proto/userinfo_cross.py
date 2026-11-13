"""proto/userinfo_cross.py (Task 2 SPIKE; RUNS ON THE WORKSTATION as doc_auth.py+userinfo_cross.py): is a chp-doc access
token accepted by the NextCloud client's userinfo endpoint too (token confusion)? Also: the same token against
NextCloud with the self-encoded check, as it was before logs/45's fix, is covered there."""
p, s = load("runtime")
for c in ("chp-doc", "nextcloud"):
    st, _, d = req("GET", f"{IDM}/oauth2/openid/{c}/userinfo", headers={"Authorization": "Bearer " + s["access_token"]})
    try:
        j = json.loads(d)
    except ValueError:
        j = {}
    print(f"userinfo of client {c} with a chp-doc token: HTTP {st}; preferred_username={j.get('preferred_username')} "
          f"error={j.get('error')}")
