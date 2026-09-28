# Redaction for idm-collect. POSIX ERE only (portable between GNU sed on the hosts and BSD sed in the Mac tests).
# Whole private-key blocks:
/-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/s/.*/[REDACTED]/
# Kanidm credential-reset tokens (xxxxx-xxxxx-xxxxx-xxxxx):
s/[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}/[REDACTED]/g
# JWS / API tokens:
s/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(\.[A-Za-z0-9_-]*)?/[REDACTED]/g
# otpauth URIs and TOTP secrets (base32):
s/otpauth:\/\/[^ "]*/[REDACTED]/g
s/([Ss]ecret[=:] *)[A-Z2-7]{16,}=*/\1[REDACTED]/g
s/(TOTP_SECRET=)[^ ]*/\1[REDACTED]/g
# Passwords in key=value, JSON and recover-account output:
s/([Pp]assword=)[^ &"]*/\1[REDACTED]/g
s/("[a-z_]*password"[[:space:]]*:[[:space:]]*")[^"]*"/\1[REDACTED]"/g
s/(new_password:[[:space:]]*")[^"]*"/\1[REDACTED]"/g
# HTTP auth headers:
s/(Authorization:[[:space:]]*[A-Za-z]+[[:space:]]+)[^ ]*/\1[REDACTED]/g
