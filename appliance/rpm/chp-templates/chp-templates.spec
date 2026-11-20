# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
Name:           chp-templates
Version:        1.4.0
Release:        2.chp%{?dist}
Summary:        CyberHygiene SSP and POA&M templates (NIST SP 800-171 Rev 2), their renderer and document templates
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/chp-templates
BuildArch:      noarch
Source0:        chp-templates-%{version}-rpm.tar.gz
Requires:       python3

%description
The signed chp-templates release, the same library Automated_Compliance pins: placeholder-only SSP and POA&M
templates, the vocabulary, the site.conf mapping and the renderer. `chp-site docs` renders a site's documents from it.
It also carries the marked controlled-document templates that `chp-site doc new` starts from, as
doc/{cui,fci,noncui}/Template.{docx,xlsx,md}.

%prep
%setup -q -n chp-templates-%{version}

%install
install -d -m 0755 %{buildroot}%{_datadir}/chp-templates
cp -a rev2 %{buildroot}%{_datadir}/chp-templates/
install -m 0644 chpfill.pyz vocabulary.md site-conf-mapping.csv README.md %{buildroot}%{_datadir}/chp-templates/
# the document templates under their plain names (the repo names follow the document name rule)
install -Dm0644 doc/cui/CUI_Template_v0.1-DRAFT.docx %{buildroot}%{_datadir}/chp-templates/doc/cui/Template.docx
install -Dm0644 doc/cui/CUI_Template_v0.1-DRAFT.xlsx %{buildroot}%{_datadir}/chp-templates/doc/cui/Template.xlsx
install -Dm0644 doc/cui/CUI_Template_v0.1-DRAFT.md %{buildroot}%{_datadir}/chp-templates/doc/cui/Template.md
install -Dm0644 doc/fci/FCI_Template_v0.1-DRAFT.docx %{buildroot}%{_datadir}/chp-templates/doc/fci/Template.docx
install -Dm0644 doc/fci/FCI_Template_v0.1-DRAFT.xlsx %{buildroot}%{_datadir}/chp-templates/doc/fci/Template.xlsx
install -Dm0644 doc/fci/FCI_Template_v0.1-DRAFT.md %{buildroot}%{_datadir}/chp-templates/doc/fci/Template.md
install -Dm0644 doc/noncui/Template_v0.1-DRAFT.docx %{buildroot}%{_datadir}/chp-templates/doc/noncui/Template.docx
install -Dm0644 doc/noncui/Template_v0.1-DRAFT.xlsx %{buildroot}%{_datadir}/chp-templates/doc/noncui/Template.xlsx
install -Dm0644 doc/noncui/Template_v0.1-DRAFT.md %{buildroot}%{_datadir}/chp-templates/doc/noncui/Template.md
install -Dm0644 LICENSE %{buildroot}%{_datadir}/licenses/%{name}/LICENSE
find %{buildroot}%{_datadir}/chp-templates -type d -exec chmod 0755 {} +
find %{buildroot}%{_datadir}/chp-templates -type f -exec chmod 0644 {} +

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%dir %{_datadir}/chp-templates
%{_datadir}/chp-templates/rev2
%{_datadir}/chp-templates/doc
%{_datadir}/chp-templates/chpfill.pyz
%{_datadir}/chp-templates/vocabulary.md
%{_datadir}/chp-templates/site-conf-mapping.csv
%{_datadir}/chp-templates/README.md

%changelog
* Fri Nov 20 2026 The CyberHygiene Project - 1.4.0-2.chp
- The FCI templates (Task 12, owner decision 2026-11-20, "FCI should be marked as FCI"): doc/fci/ installed as
  doc/fci/Template.{docx,xlsx,md} (the banner FCI, no designation block), for `chp-site doc new --fci`; Rev 2 content
  1.2.6 (3.8.4 FCI marking; 3.3.7, 3.4.7, 3.13.1, 3.13.6 time from the server, 123/udp to the site subnet only).
- NEEDS the re-tagged templates-1.4.0 (chp-templates commit with doc/fci/) and the build-rpm.sh sha256 pin redone
  to its git archive: the current pin (0a18aca) has no doc/fci/ and this spec's %install would fail on it.

* Thu Nov 19 2026 The CyberHygiene Project - 1.4.0-1.chp
- chp-templates 1.4.0 (sha256 pinned in build-rpm.sh): the marked controlled-document templates (doc/cui and
  doc/noncui, installed as Template.{docx,xlsx,md}), five new site.conf mappings (DOC_ISSO_ACCOUNT,
  DOC_APPROVER_ACCOUNTS, CUI_CONTROLLED_BY, CUI_CATEGORY, CUI_POC), and Rev 2 content 1.2.5: narratives for the
  document workflow (3.1.3, 3.1.22, 3.3.1, 3.4.3, 3.8.4, 3.8.9, 3.13.8).
- PRE-RELEASE LAB CANDIDATE: built from the UNSIGNED local tag templates-1.4.0 (build-rpm.sh CHP_TEMPLATES_TAG,
  sha256 pin only, no signature provenance); the signed release follows as a new Release.

* Fri Nov 06 2026 The CyberHygiene Project - 1.3.1-1.chp
- chp-templates 1.3.1 from the signed tarball (sha256 73682cfc17b1707e…): Rev 2 content 1.2.3, narratives for the
  security add-on (YARA 3.14.2/4/5, Suricata 3.14.6/7 and 3.13.1). Placeholders unchanged. Rev 2 library only.

* Sun Oct 25 2026 The CyberHygiene Project - 1.2.0-1.chp
- First release: chp-templates 1.2.0 from the signed tarball (sha256 ca40b7ff4cfa9504…). The renderer ships as the
  zipapp chpfill.pyz, built from the verified render/chpfill.py (fapolicyd blocks reading raw .py on the build host).
