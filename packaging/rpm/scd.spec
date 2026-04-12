Name:           scd
Version:        1.0.0
Release:        1%{?dist}
Summary:        Suspicious Command Detector — CLI security utility
License:        MIT
URL:            https://github.com/Aryansin1234/Suspicious-Command-Detector
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc >= 4.9
BuildRequires:  make

%description
SCD is a lightweight, zero-dependency CLI security tool written in C
that scans shell command history for dangerous or suspicious patterns
and produces structured alerts. Supports regex rules, webhook alerts,
web dashboard, daemon mode, and user behavior baselining.

%prep
%setup -q

%build
make all CFLAGS="-D_GNU_SOURCE -Wall -Wextra -pedantic -std=c11 -O2"

%install
install -Dm755 scd %{buildroot}%{_bindir}/scd
install -Dm644 config/rules.conf %{buildroot}%{_sysconfdir}/scd/rules.conf
install -Dm644 config/whitelist.conf %{buildroot}%{_sysconfdir}/scd/whitelist.conf
install -Dm644 web/dashboard.html %{buildroot}%{_datadir}/scd/web/dashboard.html
install -Dm644 packaging/systemd/scd.service %{buildroot}%{_unitdir}/scd.service

%files
%license LICENSE
%doc README.md
%{_bindir}/scd
%config(noreplace) %{_sysconfdir}/scd/rules.conf
%config(noreplace) %{_sysconfdir}/scd/whitelist.conf
%{_datadir}/scd/web/dashboard.html
%{_unitdir}/scd.service

%changelog
* Sat Apr 12 2026 SCD Team <scd@example.com> - 1.0.0-1
- Initial release
- 10 rule categories, 32+ detection patterns
- POSIX regex rule support
- Webhook alerts (generic + Slack)
- Web dashboard
- User behavior baseline
- Daemon mode with inotify/polling
