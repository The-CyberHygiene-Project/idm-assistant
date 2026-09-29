default_repair: time-resync
---
This host's clock differs from the lab time source by more than the 30-second TOTP window. One-time codes fail and certificate validity checks are unreliable. chrony will only slew a large offset slowly (hours), so the repair steps the clock once.
