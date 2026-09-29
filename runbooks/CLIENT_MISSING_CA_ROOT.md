default_repair: client-ca-trust
---
The step-ca root is not in this host's trust store. unixd uses that anchor file directly (ca_path), so without it unixd cannot reach Kanidm. The repair installs the root after checking its pinned fingerprint.
