default_repair: ssh-user-cert-reissue
---
The newest SSH certificate the CA issued to this user has expired, so certificate logins are refused. The repair signs the user's registered public key again with a short validity; the user receives the new certificate. No private key ever moves.
