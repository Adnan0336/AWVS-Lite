# Safe Extension Notes (Important)

This project is designed for **defensive security auditing** of systems you own or have explicit permission to test.

It intentionally **does not include exploit payload injection** modules (e.g., active XSS/SQLi exploitation),
because that can be misused.

If you want to extend functionality safely, focus on:
- configuration checks (headers, TLS, cookies, CSP evaluation)
- dependency / version reporting from *your own* app logs or SBOMs
- authenticated, consented checks in a controlled environment

If you need a private, enterprise version for your own assets, implement extensions with strict allowlists,
rate limits, and explicit proof-of-authorization banners.
