"""Static checks on the nextcloud-chp package and its chp_foldertag 1.0 app (ISO 0.7.0 Plan 2 Task 3).
The PHP itself is exercised on the lab server (lab/docs-spike/logs/90-foldertag-1.0.log)."""
import re
from pathlib import Path

TOP = Path(__file__).resolve().parents[1]
PKG = TOP / "appliance/rpm/nextcloud-chp"
APP = PKG / "chp_foldertag"
SPEC = (PKG / "nextcloud-chp.spec").read_text()
MANIFEST = [l.split("|") for l in (PKG / "MANIFEST.txt").read_text().splitlines() if l and not l.startswith("#")]
PHP = sorted(APP.rglob("*.php"))


def section(name):
    """the body of a spec section (%files, %post, ...) up to the next section"""
    m = re.search(rf"^%{name}\b[^\n]*\n(.*?)(?=^%(?:prep|build|install|check|pre|post|preun|postun|posttrans|files|changelog)\b|\Z)",
                  SPEC, re.M | re.S)
    assert m, name
    return m.group(1)


def globals_():
    return dict(re.findall(r"^%global\s+(\S+)\s+(\S+)", SPEC, re.M))


def php(name):
    return (APP / "lib" / name).read_text()


def test_code_installed_under_usr_lib_nextcloud():
    files = section("files")
    assert "%{_prefix}/lib/nextcloud\n" in files
    assert "/usr/share/nextcloud" not in SPEC and "%{_datadir}" not in SPEC
    assert "cp -a . %{buildroot}%{_prefix}/lib/nextcloud/" in section("install")
    assert "ln -s %{_sysconfdir}/nextcloud %{buildroot}%{_prefix}/lib/nextcloud/config" in section("install")


def test_data_dir_not_in_the_rpm():
    assert "/data" not in section("files") and "/data" not in section("install")
    # the only /data mention outside comments is the SELinux label for the directory chp-site creates
    used = [l for l in SPEC.splitlines() if "/data" in l and not l.lstrip().startswith("#")]
    assert used == ["semanage fcontext -a -t httpd_sys_rw_content_t '/data/nextcloud(/.*)?' 2>/dev/null || :"]


def test_web_installer_marker_not_shipped():
    assert "rm -f %{buildroot}%{_prefix}/lib/nextcloud/config/CAN_INSTALL" in section("install")
    assert "CAN_INSTALL" not in section("files")


def test_occ_upgrade_runs_only_when_nextcloud_is_installed():
    # %posttrans, not %post: on an update the old package's files are removed after %post (see the spec comment)
    for s in ("pre", "post", "preun", "postun"):
        if re.search(rf"^%{s}\b", SPEC, re.M):
            assert "occ upgrade" not in section(s), s
    body = section("posttrans")
    lines = [l.strip() for l in body.splitlines() if l.strip() and not l.strip().startswith("#")]
    cond = next(i for i, l in enumerate(lines) if l.startswith("if "))
    up = next(i for i, l in enumerate(lines) if "occ upgrade" in l)
    assert "occ status --output=json" in " ".join(lines[cond:cond + 2])
    assert """grep -q '"installed":true'""" in " ".join(lines[cond:cond + 2])
    assert cond < up < lines.index("fi", up)
    assert lines[-1] == ":"   # a failed upgrade never fails the transaction (the message says what to do)


def test_bundled_app_versions_equal_manifest():
    g = globals_()
    man = {r[0]: r[1] for r in MANIFEST}
    assert man["nextcloud-%s.tar.bz2" % g["ncver"]] == g["ncver"]
    for app in ("groupfolders", "files_accesscontrol", "user_oidc"):
        ver = g[f"{app}_ver"]
        assert man[f"{app}-{ver}.tar.gz"] == ver, app
        assert re.search(rf"^Source\d+:\s+{app}-%{{{app}_ver}}\.tar\.gz$", SPEC, re.M), app
        assert f"{app}:%{{{app}_ver}}" in section("prep"), app   # %prep compares info.xml with the pin
    assert len(MANIFEST) == 4
    pins = dict(p.split(":") for p in re.search(r'^APPS="([^"]+)"', (PKG / "fetch-inputs.sh").read_text(), re.M).group(1).split())
    assert pins == {a: g[f"{a}_ver"] for a in ("groupfolders", "files_accesscontrol", "user_oidc")}
    assert re.search(rf"^NC={re.escape(g['ncver'])}$", (PKG / "fetch-inputs.sh").read_text(), re.M)


def test_manifest_records_sha256_and_signature_result():
    for f, ver, size, sha, src, how in MANIFEST:
        assert re.fullmatch(r"[0-9a-f]{64}", sha) and int(size) > 0 and src.startswith("https://"), f
        assert ("GPG VALIDSIG 28806A878AE423A28372792ED75899B9A724937A" in how) if f.startswith("nextcloud-") \
            else ("signature OK" in how and "chains to nextcloud root.crt" in how), f


def test_foldertag_info_xml_is_1_0_0_and_matches_the_spec():
    info = (APP / "appinfo/info.xml").read_text()
    assert "<version>1.0.0</version>" in info and globals_()["foldertag_ver"] == "1.0.0"
    assert "<id>chp_foldertag</id>" in info and "<licence>Apache-2.0</licence>" in info
    assert "chp_foldertag:%{foldertag_ver}" in section("prep")


def test_no_spike_label_in_product_code():
    for p in [*APP.rglob("*"), *PKG.iterdir()]:
        if p.is_file():
            assert not re.search(r"spike|throwaway", p.read_text(), re.I), p


def test_every_php_file_has_the_licence_header():
    assert len(PHP) >= 8
    for p in PHP:
        head = p.read_text().splitlines()[:8]
        assert head[0] == "<?php", p
        assert " * SPDX-License-Identifier: Apache-2.0" in head, p
        assert any(l.startswith(" * SPDX-FileCopyrightText: ") and "The CyberHygiene Project" in l for l in head), p


def test_licence_shipped_and_declared():
    assert re.search(r"^License:\s+AGPL-3.0-or-later AND Apache-2.0$", SPEC, re.M)
    assert "%license LICENSE.chp_foldertag" in section("files")
    assert "LICENSE" in (PKG / "build-rpm.sh").read_text()


def test_release_style_and_unsigned_build_on_chp_build():
    assert re.search(r"^Release:\s+\d+\.chp%\{\?dist\}$", SPEC, re.M)
    b = (PKG / "build-rpm.sh").read_text()
    assert "lab/build-vm/ssh_config" in b and "chp-build" in b and "/data/chp-release/built" in b
    runs = [l for l in b.splitlines() if "rpmbuild" in l and not l.lstrip().startswith("#")]
    assert runs and all(l.lstrip().startswith('B "rpmbuild') for l in runs)   # only ever over ssh to chp-build
    assert "rpmsign" not in b and "--addsign" not in b and "gpg" not in b


def test_listeners_for_create_write_copy_rename_and_guards():
    a = php("AppInfo/Application.php")
    for ev in ("NodeCreatedEvent", "NodeWrittenEvent", "NodeCopiedEvent", "NodeRenamedEvent"):
        assert f"{ev}::class" in a and "TagListener::class" in a, ev
    assert "registerEventListener(BeforeNodeCopiedEvent::class, ContainListener::class)" in a
    assert "registerEventListener(BeforeNodeRenamedEvent::class, ContainListener::class)" in a
    assert "registerEventListener(AppDisableEvent::class, AppDisableListener::class)" in a
    assert "registerEventListener(SabrePluginAddEvent::class, DavGuardListener::class)" in a
    assert "registerEventListener(BeforeNodeDeletedEvent::class, FolderGuardListener::class)" in a


def test_policy_comes_from_app_config_not_constants():
    pol = php("Service/Policy.php")
    for key in ("rules", "contain", "contain_allow"):
        assert f"getValueString(self::APP_ID, '{key}', '')" in pol, key
    for f in ("Listener/ContainListener.php", "Listener/TagListener.php"):
        code = re.sub(r"/\*.*?\*/|//[^\n]*", "", php(f), flags=re.S)
        assert not re.search(r"\b(CUI|FCI|Archive)\b", code), f   # no folder names or ids in the logic
        assert not re.search(r"\[\s*\d+\s*,\s*\d+\s*\]", code), f


def test_containment_allows_only_the_configured_pairs():
    pol = php("Service/Policy.php")
    body = pol[pol.index("public function refuses"):pol.index("public static function folderOfMount")]
    assert "in_array($src, $this->contained(), true)" in body
    assert "if ($dst === $src)" in body and "if ($dst === null)" in body
    assert "!in_array([$src, $dst], $this->allowedPairs(), true)" in body
    c = php("Listener/ContainListener.php")
    assert "catch (PolicyError $e)" in c and "$refused = $src !== null && $dst !== $src;" in c   # fail closed
    assert "throw new AbortedEventException" in c


def test_audit_event_names_and_documented_fields():
    audit = php("Service/Audit.php")
    names = {"REFUSED": "chp.contain.refused", "TAG_APPLIED": "chp.tag.applied", "TAG_FAILED": "chp.tag.failed",
             "APP_DISABLED": "chp.app.disabled", "FOLDEROP_REFUSED": "chp.folderop.refused"}
    for const, name in names.items():
        assert f"public const {const} = '{name}';" in audit
    assert "getCustomPsrLogger($file, $type, $tag)" in audit and "'logfile_audit'" in audit
    assert "->warning($message, $context)" in audit   # level 2: kept at any loglevel 0-2
    readme = (APP / "README.md").read_text()
    for name in names.values():
        assert f"`{name}`" in readme, name
    for key in ("source_folder", "target_folder", "file_id", "app_id", "control", "actor", "reason", "error"):
        assert f"`{key}`" in readme, key
    for f, const in (("Listener/ContainListener.php", "REFUSED"), ("Listener/DavGuardListener.php", "REFUSED"),
                     ("Listener/TagListener.php", "TAG_APPLIED"), ("Listener/TagListener.php", "TAG_FAILED"),
                     ("Listener/AppDisableListener.php", "APP_DISABLED"), ("Listener/FolderGuardListener.php", "FOLDEROP_REFUSED")):
        assert f"Audit::{const}" in php(f), (f, const)


def test_trash_and_version_items_cannot_be_copied_into_files():
    g = php("Listener/DavGuardListener.php")
    assert "['beforeMove' => 'move', 'beforeCopy' => 'copy']" in g
    assert "in_array($from, ['trashbin', 'versions'], true) || $to !== 'files'" in g
    assert "throw new Forbidden(" in g


def test_tags_are_only_added_never_removed():
    for p in PHP:
        assert "unassignTags" not in p.read_text() and "setObjectIdsForTag" not in p.read_text(), p


def _handle(src):
    return src[src.index("public function handle(Event $event): void {"):]


def test_before_listeners_fail_closed_on_any_error():
    # NextCloud's OC_Hook::emit swallows every exception except AbortedEventException and lets the operation
    # proceed, so each Before-listener must turn any other error into an AbortedEventException.
    for f, const in (("Listener/ContainListener.php", "REFUSED"), ("Listener/FolderGuardListener.php", "FOLDEROP_REFUSED")):
        h = _handle(php(f))
        i_try = h.index("try {")
        i_dec = h.index("$this->decide(")
        i_rethrow = h.index("catch (AbortedEventException $e) {\n\t\t\tthrow $e;")
        i_any = h.index("catch (\\Throwable $e) {")
        assert i_try < i_dec < i_rethrow < i_any, f
        tail = h[i_any:h.index("\n\t}\n")]
        assert f"Audit::{const}" in tail and "'internal error: ' . get_class($e)" in tail, f
        assert "throw new AbortedEventException(" in tail, f
    fg = _handle(php("Listener/FolderGuardListener.php"))
    assert "$node instanceof Folder || ($node instanceof File && $target !== null && $this->leavesOrUnknown($node, $target))" in fg


def test_tag_listener_reports_every_failure():
    t = php("Listener/TagListener.php")
    h = _handle(t)
    rules = h[h.index("$rules = $this->policy->rules();"):]
    assert rules.index("catch (\\Throwable $e)") < rules.index("return;")   # not only PolicyError
    assert h.count("catch (\\Throwable $e)") >= 3    # rules, per file, the subtree walk
    assert h.count("$this->failed(") + h.count("$this->failedAt(") >= 3
    assert "Audit::TAG_FAILED" in t[t.index("private function failed("):]


def test_before_listener_refusal_survives_a_failing_audit_write():
    # an exception from the audit/logger call in the catch-all must not replace the AbortedEventException
    for f in ("Listener/ContainListener.php", "Listener/FolderGuardListener.php"):
        h = _handle(php(f))
        tail = h[h.index("catch (\\Throwable $e) {"):h.index("\n\t}\n")]
        i_try = tail.index("try {   // the refusal below must happen even when the audit write fails")
        i_audit = tail.index("$this->audit->event(")
        i_ign = tail.index("} catch (\\Throwable $auditError) {")
        assert "error_log('chp_foldertag: could not audit a refused '" in tail, f
        i_throw = tail.index("throw new AbortedEventException(")
        assert i_try < i_audit < i_ign < i_throw, f


def test_children_come_from_the_filecache_not_the_acting_users_listing():
    # groupfolders ACLs hide children from the acting user's listing ([]): count and walk by filecache parent.
    # The ACL-hidden case itself is proven on the lab server (Task 9).
    for p in PHP:
        assert "getDirectoryListing" not in p.read_text(), p
    fg = php("Listener/FolderGuardListener.php")
    assert "$node instanceof Folder && $this->hasChildren($node)" in fg
    hc = fg[fg.index("private function hasChildren("):fg.index("private function hasOldVersions(")]
    assert "->from('filecache')" in hc and "$q->expr()->eq('parent'," in hc
    assert "return true;   // cannot tell: treat as non-empty (fail closed)" in hc
    assert "return true;   // not in the filecache yet" in hc
    t = php("Listener/TagListener.php")
    walk = t[t.index("private function files(Node $node, string $op)"):t.index("private function storageOf(")]
    assert "->from('filecache')" in walk and "$q->expr()->eq('parent'," in walk
    assert "$this->mimeTypeLoader->getId('httpd/unix-directory')" in walk and "$queue[] =" in walk
    assert "throw new \\RuntimeException('folder has no id yet')" in walk   # becomes chp.tag.failed, never silent
    assert "->get($rel)" not in t


def test_copy_source_found_by_parent_and_name_never_silently():
    # jail-independent: from the source's own id down the $rel segments; never a path_hash of a jail-relative path
    t = php("Listener/TagListener.php")
    src = t[t.index("private function sourceId("):t.index("private function managedTagsOf(")]
    assert "path_hash" not in src and "getInternalPath" not in src
    assert "(int)$source->getId()" in src and "explode('/', $rel)" in src
    assert "eq('parent', $q->createNamedParameter($id, IQueryBuilder::PARAM_INT))" in src and "eq('name'," in src
    assert "throw new \\RuntimeException('source file ' . $rel . ' not found in the filecache')" in src
    m = t[t.index("private function managedTagsOf("):t.index("private function tag(")]
    assert m.index("$this->sourceId(") < m.index("catch (\\Throwable $e)") < m.index("Audit::TAG_FAILED")


def test_subtree_walk_is_bounded_and_reports_what_it_skips():
    t = php("Listener/TagListener.php")
    walk = t[t.index("private function files(Node $node, string $op)"):t.index("private function children(")]
    assert "$seen = [$root => true];" in walk and "throw new \\RuntimeException('filecache cycle at file id '" in walk
    assert "++$n > self::MAX_WALK" in walk and "private const MAX_WALK = 200000;" in t
    assert "(int)$row['storage'] !== $storage" in walk and "entry of another storage below the target, not walked" in walk
    assert "$this->mounts->findIn($base)" in walk and "mounts below the target are not walked" in walk
    i = walk.index("(int)$row['storage'] !== $storage")
    assert "$this->failedAt(" in walk[i:i + 300]
    h = _handle(t)
    assert "foreach ($this->files($target, $reason) as" in h   # a throw lands in the walk's catch -> chp.tag.failed
