%global debug_package %{nil}
Name:           step-cli
Version:        0.31.0
Release:        2.chp%{?dist}
Summary:        step command-line tool (built from source)
License:        Apache-2.0
Vendor:         The CyberHygiene Project
URL:            https://github.com/smallstep/cli
Source0:        step-cli-%{version}-staged.tar.gz

%description
The step CLI %{version}, built offline from source with CGO disabled and Go's FIPS 140-3 module selected at build time.

%prep
%setup -q -n staged

%install
install -Dm0755 step-cli %{buildroot}%{_bindir}/step-cli
ln -s step-cli %{buildroot}%{_bindir}/step
install -Dm0644 LICENSE-step-cli %{buildroot}%{_datadir}/licenses/step-cli/LICENSE

%files
%license %{_datadir}/licenses/step-cli/LICENSE
%{_bindir}/step-cli
%{_bindir}/step

%changelog
* Tue Sep 29 2026 The CyberHygiene Project - 0.31.0-2.chp
- Built from source (vendored modules, pinned Go), GOFIPS140 module.
