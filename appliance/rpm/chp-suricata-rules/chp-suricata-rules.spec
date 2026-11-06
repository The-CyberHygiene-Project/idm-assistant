Name:           chp-suricata-rules
Version:        %{rules_version}
Release:        1.chp%{?dist}
Summary:        CyberHygiene Project Suricata rules (Emerging Threats Open, merged)
License:        GPL-2.0-only AND BSD-3-Clause
Vendor:         The CyberHygiene Project
URL:            https://github.com/The-CyberHygiene-Project/idm-assistant
BuildArch:      noarch
Source0:        chp-suricata.rules
Source1:        DISABLED.txt
Source2:        ET_DATE
Source3:        LICENSE
Source4:        NOTICE
Source5:        classification.config
Source6:        reference.config
Requires:       suricata >= 7.0, suricata < 8

%description
ET Open merged into one rules file for the CHP security add-on (Suricata spec §2). IDS only: alert, never block.
Rules that fire on a clean appliance are commented out with the reason, and listed in DISABLED.txt.

%install
install -d %{buildroot}%{_datadir}/chp-suricata-rules
for f in %{SOURCE0} %{SOURCE1} %{SOURCE2} %{SOURCE3} %{SOURCE4} %{SOURCE5} %{SOURCE6}; do
  install -m0644 "$f" %{buildroot}%{_datadir}/chp-suricata-rules/
done

%files
%dir %{_datadir}/chp-suricata-rules
%{_datadir}/chp-suricata-rules/chp-suricata.rules
%{_datadir}/chp-suricata-rules/DISABLED.txt
%{_datadir}/chp-suricata-rules/ET_DATE
%{_datadir}/chp-suricata-rules/LICENSE
%{_datadir}/chp-suricata-rules/NOTICE
%{_datadir}/chp-suricata-rules/classification.config
%{_datadir}/chp-suricata-rules/reference.config

%changelog
* Thu Nov 05 2026 The CyberHygiene Project - %{rules_version}-1.chp
- First release: ET Open for Suricata 7 as downloaded on the date in ET_DATE.
