CWE-352: Cross-Site Request Forgery (CSRF) in Reviewdemo
========================================================

Reviewdemo performs state-changing actions using cookie-based authentication, but does not implement anti-CSRF protections (e.g., synchronizer tokens or same-origin checks).

This allows an attacker to cause a logged-in victim’s browser to send an authenticated request that changes victim data.

Vulnerable endpoint
-------------------
`/csrf-update-profile` updates the currently logged-in user's profile fields purely based on request parameters and **does not validate any CSRF token**.

Exploit
-------
1. Log in to Reviewdemo in your browser.
2. While still logged in, open a new tab and navigate to the following URL (simulating a malicious site tricking the victim into clicking a link):
   `/reviewdemo/csrf-update-profile?realName=CSRFd&blabName=Owned`
3. Return to `/reviewdemo/profile` and observe that your `Real Name` and `Blab Name` have been changed.

Notes:
- Modern browsers may apply `SameSite` cookie protections; this exploit is intentionally shown as a **top-level navigation GET**, which commonly still includes cookies for `SameSite=Lax` cookies.

Mitigate
--------
- Ensure all state-changing actions require POST (or other non-GET methods) and enforce CSRF protections.
- Use `SameSite` cookie protections (and prefer `HttpOnly` where possible), but do not rely on cookies alone as your primary CSRF control.

Remediate
---------
- Implement CSRF tokens (synchronizer token pattern) and validate them server-side on every state-changing request.
- Consider using Spring Security’s CSRF protection and require per-request tokens for forms and AJAX calls.

Resources
---------
* [CWE-352](https://cwe.mitre.org/data/definitions/352.html)
* [OWASP: CSRF](https://owasp.org/www-community/attacks/csrf)
