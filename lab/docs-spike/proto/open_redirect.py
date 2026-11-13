"""proto/open_redirect.py (minor, SPIKE; RUNS ON THE WORKSTATION as doc_auth.py+open_redirect.py; stdin: one credential
line): through the /index.php/login rewrite, does a hostile redirect_url send the browser off-site after sign-in?
One sign-in (the jar keeps the session), then the other cases reuse it."""
cred = json.loads(sys.stdin.readline())
jar = {}
cases = ["https://evil.example/pwn", "//evil.example/pwn", "/index.php/apps/files/"]
for i, target in enumerate(cases):
    url = f"{FILES}/index.php/login?" + urllib.parse.urlencode({"redirect_url": target})
    seen = []
    def until(u, seen=seen):
        seen.append(u)
        h = urllib.parse.urlsplit(u).hostname
        return h not in (f"files.{D}", f"idm.{D}") or (h == f"files.{D}" and "/apps/user_oidc/" not in u and "/login" not in u)
    final = browse(url, cred, jar, until, lambda m: None)
    print(f"redirect_url={target!r}: ended at {urllib.parse.urlsplit(final).scheme}://{urllib.parse.urlsplit(final).netloc}"
          f"{urllib.parse.urlsplit(final).path}  (hops: {len(seen)})")
