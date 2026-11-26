# Security

Use release **2.0.1 or later**. Version 2.0.0 and historical component releases
lack the corrections in the [15 October 2026 review](docs/security-review-2026-10-15.md).

Report suspected vulnerabilities privately to the repository owner. Include
affected version and reproduction with synthetic records. Do not attach real
passwords, account databases, credentials, keys or unredacted production logs.

```bash
RDMON_CONFIG=config/examples/console.ini.example python3 -m unittest discover -s console/tests -v
python3 -m pip install -r requirements-security.txt
python3 -m bandit -r console/app console/install.py console/bin/rdmon-passwd -ll
python3 -m pip_audit
```

Scanner requirements are development tools, not runtime packages. Review the
[security boundaries](docs/security.md), keep operating-system/RustDesk packages
updated, and restrict administrative services to trusted networks.
