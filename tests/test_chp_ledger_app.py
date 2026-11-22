"""Static and contract checks on the chp_ledger 1.0 NextCloud app (ISO 0.7.0 Plan 3 Task 3): route L1's intake.
It stamps a doc-command request with the user NextCloud authenticated, checks it (Compliance areas only, a per-user
rate limit, the publish size cap) and spools it for the root appender (Task 4). The PHP itself runs on the lab server
(Task 11); here, as for chp_foldertag, the source is checked against the contract."""
import json
import re
from pathlib import Path

from chp_site import documents as D
from tests.test_chp_site_documents import Env

TOP = Path(__file__).resolve().parents[1]
PKG = TOP / "appliance/rpm/nextcloud-chp"
APP = PKG / "chp_ledger"
SPEC = (PKG / "nextcloud-chp.spec").read_text()
PHP = sorted(APP.rglob("*.php"))


def php(name):
    return (APP / "lib" / name).read_text()


def code(name):
    """the PHP of lib/<name> without comments (what runs)"""
    return re.sub(r"/\*.*?\*/|(?<![:'\"])//[^\n]*", "", php(name), flags=re.S)


def method(src, name):
    """the body of one PHP method: from its signature to the next method (or the end of the class)"""
    i = src.index(f"function {name}(")
    m = re.search(r"\n\t(?:public|private|protected)(?: static)? function ", src[i + 1:])
    return src[i:i + 1 + m.start()] if m else src[i:]


def section(name):
    m = re.search(rf"^%{name}\b[^\n]*\n(.*?)(?=^%(?:prep|build|install|check|pre|post|preun|postun|posttrans|files|changelog)\b|\Z)",
                  SPEC, re.M | re.S)
    assert m, name
    return m.group(1)


CTL = "Controller/LedgerController.php"


# ---------- the six behaviours the plan names ----------

def test_identity_from_session_not_body():
    c = code(CTL)
    # the user is the one NextCloud authenticated for this request; a "user" in the body is never read
    assert "$user = $this->userSession->getUser();" in c and "$uid = $user->getUID();" in c
    assert "getParam('user')" not in c and "getParams()" not in c and "$_POST" not in c and "php://input" not in c
    spool = method(c, "accept")
    assert "'user' => $uid," in spool
    # the spool record is built from named fields only (no merging of the body into it)
    assert "array_merge" not in c and "+ $this->request" not in c and "...$" not in spool
    for k in ("request_id", "kind", "file_id", "sha256", "reason", "notes", "content", "pdf_content", "path"):
        assert f"'{k}'" in spool, k
    # no signed-in user: 401, nothing spooled
    sub = method(c, "submit")
    assert sub.index("if ($user === null)") < sub.index("$this->accept(")


def test_file_id_restricted_to_compliance():
    a = code("Service/Areas.php")
    # ids come from app config (chp-site renders them from documents.conf), never constants
    assert "getValueString(self::APP_ID, $key, '')" in a
    assert "$this->ids('compliance')" in a and "$this->ids('superseded')" in a
    assert not re.search(r"\b(CUI|Internal|Archive|Compliance|Superseded)\b(?!')", re.sub(r"'[^']*'", "''", a))
    # ancestry from the filecache by parent: the real storage, never a jail-relative path or its path_hash
    walk = method(a, "areaOf")
    assert "path_hash" not in a and "getInternalPath" not in a and "getPath" not in a
    assert "->from('filecache')" in a and "eq('fileid'," in a and "'parent'" in a
    assert "in_array($id, $superseded, true)" in walk and "in_array($id, $allowed, true)" in walk
    assert walk.index("in_array($id, $superseded, true)") < walk.index("return $found;")
    assert "return null;" in walk                                   # inside a Superseded area: not allowed
    assert "isset($seen[$id])" in walk and "self::MAX_DEPTH" in walk  # a cycle or a runaway walk throws
    assert "(int)$row['storage'] !== $storage" in walk              # one storage, top to bottom
    # missing or malformed config throws (the controller's catch-all refuses): fail closed
    ids = method(a, "ids")
    assert "throw new \\RuntimeException(" in ids and "array_is_list($v)" in ids
    # the controller: the user must see the node, and its area must be found, else the generic refusal
    c = code(CTL)
    acc = method(c, "accept")
    assert "->getUserFolder($uid)->getFirstNodeById($fileId)" in acc
    i_node = acc.index("getFirstNodeById($fileId)")
    i_area = acc.index("$this->areas->areaOf($fileId)")
    i_write = acc.index("$this->spool->write(")
    assert i_node < i_area < i_write
    tail = acc[i_node:i_area + 200]
    assert "if ($node === null)" in tail and "if ($area === null)" in tail
    assert tail.count("return $this->refuse(self::REFUSED, Http::STATUS_FORBIDDEN);") >= 2


def test_compliance_ids_rendered_by_documents_enable(tmp_path):
    e = Env(tmp_path)
    e.enable()
    c = dict(ln.split("=", 1) for ln in (e.root / "etc/chp/documents.conf").read_text().splitlines()
             if "=" in ln and not ln.startswith("#"))
    assert json.loads(e.nc.appconf[("chp_ledger", "compliance")]) == [int(c["CUI_COMPLIANCE_ID"]),
                                                                       int(c["INTERNAL_COMPLIANCE_ID"])]
    assert json.loads(e.nc.appconf[("chp_ledger", "superseded")]) == [int(c["CUI_SUPERSEDED_ID"]),
                                                                       int(c["INTERNAL_SUPERSEDED_ID"])]
    assert "chp_ledger" in D.APPS_ON and "chp_ledger" in e.nc.enabled


def test_rate_limit_per_user():
    r = code("Service/RateLimit.php")
    assert "public const LIMIT = 10;" in r and "public const PERIOD = 60;" in r
    ex = method(r, "exceeded")
    assert "hash('sha256', $uid)" in ex                              # per user
    assert "->inc(" in ex and "instanceof IMemcache" in ex           # atomic counter, or throw (fail closed)
    assert "throw new \\RuntimeException(" in ex and "!is_int($n)" in ex
    assert "> self::LIMIT" in ex
    c = code(CTL)
    sub = method(c, "submit")
    i_rl = sub.index("if ($this->rateLimit->exceeded($uid))")
    assert "return $this->refuse(self::TOO_MANY, Http::STATUS_TOO_MANY_REQUESTS);" in sub[i_rl:i_rl + 200]
    assert i_rl < sub.index("$this->accept(")                       # before any check, read or spool write
    assert "$this->spool->write(" not in sub


def test_publish_size_cap():
    c = code(CTL)
    assert "public const MAX_CONTENT = 67108864;" in c               # 64 MiB, decoded
    acc = method(c, "accept")
    # content and pdf_content share the cap (combined decoded size), checked before anything is spooled
    assert "$size = self::decodedSize($content) + self::decodedSize($pdf);" in acc or \
        re.search(r"\$csize \+ \$psize > self::MAX_CONTENT", acc)
    i_cap = acc.index("> self::MAX_CONTENT")
    assert "Http::STATUS_REQUEST_ENTITY_TOO_LARGE" in acc[i_cap:i_cap + 200]
    assert i_cap < acc.index("$this->spool->write(")
    # both are required for publish and refused on any other kind
    assert "if ($kind === 'publish')" in acc
    # the size is computed, never by decoding (PHP memory: 64 MiB more per request)
    ds = method(c, "decodedSize")
    assert "base64_decode" not in c and "strspn(" in ds and "% 4" in ds
    assert "intdiv(strlen($b64), 4) * 3" in ds
    # a string too long to fit is refused before it is scanned
    assert "self::MAX_B64" in ds and "public const MAX_B64 = 89478488;" in c   # 4 * ceil(64 MiB / 3)


def test_generic_refusal_text():
    c = code(CTL)
    m = re.search(r"public const REFUSED = '([^']+)';", c)
    assert m and "Compliance" not in m.group(1) and "superseded" not in m.group(1).lower()
    # every refusal goes through refuse(); the only other texts are "not signed in" and the rate limit
    texts = re.findall(r"\$this->refuse\(([^,]+),", c)
    assert texts and set(texts) <= {"self::REFUSED", "self::TOO_MANY", "self::SIGN_IN", "self::NO_GROUPS"}, set(texts)
    assert "'message' => $message" in method(c, "refuse") and "'state' => 'refused'" in method(c, "refuse")
    # not found, not visible, outside the areas and inside a Superseded area all read the same
    acc = method(c, "accept")
    assert "STATUS_NOT_FOUND" not in acc                                # no 404-vs-403 tell for a file id
    # the result of someone else's request reads the same as an unknown one
    res = method(c, "result")
    assert res.count("return $this->refuse(self::REFUSED, Http::STATUS_NOT_FOUND);") >= 2


def test_fail_closed_on_throwable():
    c = code(CTL)
    for name in ("submit", "result"):
        m = method(c, name)
        i_try, i_any = m.index("try {"), m.index("catch (\\Throwable $e) {")
        assert i_try < m.index("$this->userSession->getUser()") < i_any, name
        tail = m[i_any:]
        assert "return $this->refuse(self::REFUSED, Http::STATUS_INTERNAL_SERVER_ERROR);" in tail, name
        # the log line names the error class and place only: never the request, never the token
        assert "get_class($e)" in tail and "$e->getMessage()" not in tail and "$doc" not in tail, name
        i_log = tail.index("try {")
        assert i_log < tail.index("} catch (\\Throwable $ignored) {") < tail.index("return $this->refuse("), name
    # the methods take no typed body parameters (a TypeError would happen before the catch-all)
    assert "public function submit(): DataResponse {" in c
    assert "public function result(string $request_id): DataResponse {" in c


# ---------- auth kind, token, spool, result ----------

def test_auth_kind_recorded_honestly():
    c = code(CTL)
    ak = method(c, "authKind")
    # NextCloud marks a sign-in by app password or device token (Basic, a token sent as Bearer, Login Flow v2)
    assert "$this->session->exists('app_password')" in ak
    assert "'app-password'" in ak and "'bearer'" in ak and "'session'" in ak
    assert ak.index("'app-password'") < ak.index("return ['bearer'")   # an app token is never labelled bearer
    assert "return ['app-password', $scheme, $appToken, null];" in ak    # ... and never spooled
    assert "return ['session', $scheme, $appToken, null];" in ak
    assert "$this->session->exists('one_time_token')" in ak
    acc = method(c, "accept")
    for k in ("'auth' => $auth,", "'auth_header' => $scheme,", "'nc_app_token' => $appToken,",
              "'bearer_token' => $token,"):
        assert k in acc, k
    # the token's claims are never read here: the appender verifies it at Kanidm's chp-doc userinfo
    assert "base64" not in ak.lower() and "json_decode" not in ak


def test_bearer_token_never_logged():
    for p in PHP:
        src = re.sub(r"/\*.*?\*/|(?<![:'\"])//[^\n]*", "", p.read_text(), flags=re.S)
        for call in re.findall(r"(?:->(?:error|warning|info|debug|notice|critical|alert|emergency|log)\(|error_log\()"
                               r"[^;]*;", src):
            assert "token" not in call.lower() and "$doc" not in call and "Authorization" not in call, (p, call)
    assert "getParam('bearer_token')" not in code(CTL)              # never taken from the body


def test_spool_file_written_exclusive_0640_and_linked():
    s = code("Service/Spool.php")
    assert "public const SPOOL = '/var/lib/chp-docs/spool';" in s
    assert "public const OUT = '/var/lib/chp-docs/out';" in s
    w = method(s, "write")
    # O_CREAT|O_EXCL: fopen 'x' never follows a symlink at the name and never reuses a file; 0640 through the umask
    assert "umask(0137)" in w and "fopen($tmp, 'xb')" in w and "umask($old)" in w
    assert w.index("umask(0137)") < w.index("fopen($tmp, 'xb')") < w.index("umask($old)")
    assert "fsync($fh)" in w
    # the request appears complete under its final name, and never replaces another: link() fails on an existing name
    assert "link($tmp, $final)" in w and "rename(" not in w and "file_put_contents" not in s
    assert "unlink($tmp)" in w
    assert "'/.' . $id . '.tmp'" in w                               # the appender reads <id>.json only
    assert "JSON_UNESCAPED_SLASHES" in w and "JSON_THROW_ON_ERROR" in w


def test_request_id_and_fields_validated():
    c = code(CTL)
    acc = method(c, "accept")
    assert "preg_match('/^[0-9a-f]{32}\\z/', $id) !== 1" in acc
    assert "public const KINDS = ['checkout', 'new', 'approve', 'override', 'publish'];" in c
    assert "preg_match('/^[0-9a-f]{64}\\z/', $sha) !== 1" in acc
    assert "preg_match('/^[1-9][0-9]{0,17}\\z/', $fid) === 1" in acc
    assert "in_array($kind, ['approve', 'override', 'publish'], true)" in acc       # sha256 required
    assert "if ($kind === 'override' && $reason === '')" in acc                       # override needs a reason
    # checkout is of a file; new is a name in an area folder; the others either
    assert "if ($kind === 'checkout' && !$isFile)" in acc and "if ($kind === 'new' && $isFile)" in acc
    nm = method(c, "name")
    assert "strlen($v) > 255" in nm and "preg_match('//u', $v) !== 1" in nm and "'/'" in nm


def test_result_read_only_from_out_and_only_for_its_user():
    c = code(CTL)
    res = method(c, "result")
    assert "preg_match('/^[0-9a-f]{32}\\z/', $request_id) !== 1" in res
    assert "($r['user'] ?? null) !== $uid" in res
    assert "['done', 'refused', 'retry']" in res
    assert "'state' => 'queued'" in res
    s = code("Service/Spool.php")
    rd = method(s, "result")
    assert "self::OUT . '/' . $id . '.json'" in rd and "is_link($f)" in rd and "self::MAX_RESULT" in rd
    # the app never writes into out/ (root's appender does) and never deletes from either directory except its tmp
    assert "self::OUT" not in method(s, "write")


def test_duplicate_request_id_never_overwrites():
    c = code(CTL)
    acc = method(c, "accept")
    i = acc.index("$this->spool->write(")
    assert "STATUS_CONFLICT" in acc[i:i + 300]
    prior = acc.index("$this->spool->result($id)")
    assert prior < i and "($prior['user'] ?? null) === $uid" in acc


# ---------- package ----------

def test_info_xml_and_licence_headers():
    info = (APP / "appinfo/info.xml").read_text()
    assert "<id>chp_ledger</id>" in info and "<version>1.0.2</version>" in info
    assert "<licence>Apache-2.0</licence>" in info and "<namespace>ChpLedger</namespace>" in info
    assert '<nextcloud min-version="35" max-version="35"/>' in info
    assert len(PHP) >= 5
    for p in PHP:
        head = p.read_text().splitlines()[:8]
        assert head[0] == "<?php" and "declare(strict_types=1);" in p.read_text(), p
        assert " * SPDX-License-Identifier: Apache-2.0" in head, p
    for p in APP.rglob("*"):
        if p.is_file():
            assert not re.search(r"spike|throwaway", p.read_text(), re.I), p


def test_routes_are_ocs_api_routes():
    c = code(CTL)
    assert "#[ApiRoute(verb: 'POST', url: '/api/v1/request')]" in c
    assert "#[ApiRoute(verb: 'GET', url: '/api/v1/result/{request_id}')]" in c
    assert c.count("#[NoAdminRequired]") == 2 and "NoCSRFRequired" not in c and "PublicPage" not in c
    assert "extends OCSController" in c


def test_spec_bundles_the_app_and_its_directories():
    g = dict(re.findall(r"^%global\s+(\S+)\s+(\S+)", SPEC, re.M))
    assert g["ledger_ver"] == "1.0.2"
    assert re.search(r"^Source7:\s+chp_ledger\.tar\.gz$", SPEC, re.M)
    prep = section("prep")
    assert "%{SOURCE7}" in prep and "chp_ledger:%{ledger_ver}" in prep
    b = (PKG / "build-rpm.sh").read_text()
    assert "chp_ledger.tar.gz" in b and re.search(r"-C \"\$here\" --exclude \.DS_Store chp_ledger", b)
    files = section("files")
    assert "%dir %attr(0750,root,apache) %{_localstatedir}/lib/chp-docs\n" in files
    assert "%dir %attr(1730,root,apache) %{_localstatedir}/lib/chp-docs/spool\n" in files
    assert "%dir %attr(0750,root,apache) %{_localstatedir}/lib/chp-docs/out\n" in files
    post = section("post")
    assert "semanage fcontext -a -t httpd_sys_rw_content_t '%{_localstatedir}/lib/chp-docs/spool(/.*)?'" in post
    assert "semanage fcontext -a -t httpd_sys_content_t '%{_localstatedir}/lib/chp-docs/out(/.*)?'" in post
    assert re.search(r"restorecon -R (?:[^\n]|\\\n)*%\{_localstatedir\}/lib/chp-docs", post)   # continued line
    # fapolicyd trusts the app through the rpm database, like chp_foldertag: nothing added by hand
    assert "--trust-file" not in SPEC and "fapolicyd-cli --file add" not in SPEC
    assert "chp_ledger %{ledger_ver}" in section("description")
    assert re.search(r"^Release:\s+7\.chp%\{\?dist\}$", SPEC, re.M)
    assert re.search(r"^\* .* - 35\.0\.3-7\.chp\n- chp_ledger 1\.0\.2", section("changelog"))     # Task 13a on top
    assert re.search(r"^\* .* - 35\.0\.3-6\.chp\n- chp_ledger 1\.0\.0", section("changelog"), re.M)


def test_no_validation_pattern_ends_in_a_bare_dollar():
    # Fix round 1: PCRE's $ (without the D flag) also matches before a final newline, so "<32 hex>\n" passed as a
    # request id and made spool/<hex>\n.json, which the appender never picks up. Anchor the end with \z.
    pats = []
    for p in PHP:
        for pat in re.findall(r"preg_match\('([^']*)'", p.read_text()):
            pats.append((p.name, pat))
            body, _, flags = pat[1:].rpartition(pat[0])
            assert not (body.endswith("$") and "D" not in flags), (p.name, pat)
    assert len([x for x in pats if x[1].endswith("\\z/")]) == 4, pats


# ---------- Task 13a (P3-D3, ruling) ----------

def test_13a_d3_an_account_without_groups_is_refused_plainly_and_audited():
    """P3-D3: user_oidc makes a group-less account from a chp-doc Bearer for a person who never signed in on the web.
    Its requests are refused with a plain "sign in once on the web" text (403) and one audit line (Wazuh) each;
    nothing is spooled. Checked after the rate limit (no audit flood), before any other check or the spool."""
    c = code(CTL)
    m = re.search(r"public const NO_GROUPS = '([^']+)';", c)
    assert m and "sign in once" in m.group(1) and "browser" in m.group(1) and "doc login" in m.group(1)
    assert "IGroupManager $groupManager" in c and "use OCP\\IGroupManager;" in c
    sub = method(c, "submit")
    i_rl = sub.index("if ($this->rateLimit->exceeded($uid))")
    i_g = sub.index("$this->groupManager->getUserGroupIds($user) === []")
    i_acc = sub.index("$this->accept(")
    assert i_rl < i_g < i_acc
    blk = sub[i_g:i_acc]
    assert "$this->audit->event(Audit::NO_GROUPS, " in blk and "'user' => $uid" in blk
    assert "return $this->refuse(self::NO_GROUPS, Http::STATUS_FORBIDDEN);" in blk
    a = code("Service/Audit.php")
    assert "public const NO_GROUPS = 'chp.ledger.nogroups';" in a
    assert "getCustomPsrLogger(" in a and "'logfile_audit'" in a and "->warning(" in a
    assert "'app' => 'chp_ledger'" in a


def test_13a_d3_wazuh_pages_the_audit_line():
    from chp_site import wazuh as W
    r = W.NEXTCLOUD_RULES
    base = re.search(rf'<rule id="{W.LEDGER_AUDIT_RULE}" level="0">(.*?)</rule>', r, re.S).group(1)
    assert "<decoded_as>json</decoded_as>" in base and "<field name=\"app\">^chp_ledger$</field>" in base
    kid = re.search(rf'<rule id="{W.LEDGER_NOGROUPS_RULE}" level="12">(.*?)</rule>', r, re.S).group(1)
    assert f"<if_sid>{W.LEDGER_AUDIT_RULE}</if_sid>" in kid and "chp.ledger.nogroups" in kid
    assert "chp_access_granted" not in kid and "<group>chp_doc_refused,chp_account,</group>" in kid   # fix round 1


def test_fixwave_a_i1_text_refuses_c0_c1_and_del():                           # final review A I-1
    c = code(CTL)
    t = method(c, "text")
    assert "preg_match('/[\\x00-\\x1f\\x7f]|\\xc2[\\x80-\\x9f]/', $v) === 1" in t
    assert "preg_match('//u', $v) !== 1" in t and "strlen($v) > self::MAX_TEXT" in t
    import re as _r
    pat = _r.compile(rb"[\x00-\x1f\x7f]|\xc2[\x80-\x9f]")               # the same pattern on UTF-8 bytes
    for bad in ("a\nb", "\x01", "x\x7f", "c1 \x85"):
        assert pat.search(bad.encode()), bad
    for good in ("Geprüft – OK ✅", "é" * 900, "plain"):
        assert not pat.search(good.encode()), good
