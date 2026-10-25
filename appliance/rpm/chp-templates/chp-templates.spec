# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
Name:           chp-templates
Version:        1.2.0
Release:        1.chp%{?dist}
Summary:        CyberHygiene SSP and POA&M templates (NIST SP 800-171 Rev 2) and their renderer
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/chp-templates
BuildArch:      noarch
Source0:        chp-templates-%{version}-rpm.tar.gz
Requires:       python3

%description
The signed chp-templates release, the same library Automated_Compliance pins: placeholder-only SSP and POA&M
templates, the vocabulary, the site.conf mapping and the renderer. `chp-site docs` renders a site's documents from it.

%prep
%setup -q -n chp-templates-%{version}

%install
install -d -m 0755 %{buildroot}%{_datadir}/chp-templates
cp -a rev2 %{buildroot}%{_datadir}/chp-templates/
install -m 0644 chpfill.pyz vocabulary.md site-conf-mapping.csv README.md %{buildroot}%{_datadir}/chp-templates/
install -Dm0644 LICENSE %{buildroot}%{_datadir}/licenses/%{name}/LICENSE
find %{buildroot}%{_datadir}/chp-templates -type d -exec chmod 0755 {} +
find %{buildroot}%{_datadir}/chp-templates -type f -exec chmod 0644 {} +

%files
%license %{_datadir}/licenses/%{name}/LICENSE
%dir %{_datadir}/chp-templates
%{_datadir}/chp-templates/rev2
%{_datadir}/chp-templates/chpfill.pyz
%{_datadir}/chp-templates/vocabulary.md
%{_datadir}/chp-templates/site-conf-mapping.csv
%{_datadir}/chp-templates/README.md

%changelog
* Sun Oct 25 2026 The CyberHygiene Project - 1.2.0-1.chp
- First release: chp-templates 1.2.0 from the signed tarball (sha256 ca40b7ff4cfa9504…). The renderer ships as the
  zipapp chpfill.pyz, built from the verified render/chpfill.py (fapolicyd blocks reading raw .py on the build host).
