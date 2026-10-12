# CyberHygiene Project Lab Installer — based on Rocky Linux 9.
# Not an official Rocky Linux product.
# Rocky Linux is a trademark of the Rocky Enterprise Software Foundation.
"""ssg-fix.py DS RULE: print the SSG's own shell remediation (urn:xccdf:fix:script:sh) for one rule from the data
stream. `oscap xccdf generate fix` with our tailoring omitted the AIDE rules (Plan A Task 9 ruling), so the fix text is
taken from the rule itself. Refuses a fix that needs an XCCDF variable (<sub>): it would run with an empty value."""
import re
import sys
import html

t = open(sys.argv[1]).read()
m = re.search(r'<xccdf-1.2:Rule[^>]*rule_' + re.escape(sys.argv[2]) + r'".*?</xccdf-1.2:Rule>', t, re.S)
if not m:
    sys.exit(f"rule {sys.argv[2]} not found")
fx = re.search(r'<xccdf-1.2:fix [^>]*system="urn:xccdf:fix:script:sh"[^>]*>(.*?)</xccdf-1.2:fix>', m.group(0), re.S)
if not fx:
    sys.exit(f"rule {sys.argv[2]} has no sh fix")
if "<xccdf-1.2:sub" in fx.group(1):
    sys.exit(f"rule {sys.argv[2]}: its fix needs an XCCDF variable; not run")
sys.stdout.write(html.unescape(re.sub(r"<[^>]+>", "", fx.group(1))))
