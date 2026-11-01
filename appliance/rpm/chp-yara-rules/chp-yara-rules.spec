Name:           chp-yara-rules
Version:        %{rules_version}
Release:        1.chp%{?dist}
Summary:        CyberHygiene Project YARA rules (Neo23x0 signature-base, compiled)
License:        DRL-1.1
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        rules.yarc
Source1:        SKIPPED.txt
Source2:        COMMIT
Source3:        LICENSE
Source4:        NOTICE
Requires:       yara = %{yara_evr}

%description
signature-base YARA rules compiled once at build time for the CHP security add-on (YARA spec §2). Alert only.

%install
install -d %{buildroot}%{_datadir}/chp-yara-rules
for f in %{SOURCE0} %{SOURCE1} %{SOURCE2} %{SOURCE3} %{SOURCE4}; do install -m0644 "$f" %{buildroot}%{_datadir}/chp-yara-rules/; done

%files
%dir %{_datadir}/chp-yara-rules
%{_datadir}/chp-yara-rules/rules.yarc
%{_datadir}/chp-yara-rules/SKIPPED.txt
%{_datadir}/chp-yara-rules/COMMIT
%{_datadir}/chp-yara-rules/LICENSE
%{_datadir}/chp-yara-rules/NOTICE

%changelog
* Sun Nov 01 2026 The CyberHygiene Project - %{rules_version}-1.chp
- First release: signature-base at the commit in COMMIT.
