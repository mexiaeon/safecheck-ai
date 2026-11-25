# SafeCheck AI

Responsive dark-theme homepage for an early-stage scam-awareness product.

## Current status
This is a **front-end preview**, not a production security product.
- Text and email modes run limited pattern checks locally in the browser.
- URL mode parses the address and checks a few visible URL characteristics only.
- No live threat-intelligence service, AI API, OCR, screenshot analysis, accounts, or payment flow is connected.
- A clean result is never proof that a message or website is safe.

## Files
- index.html — homepage and checker interface
- styles.css — responsive dark theme
- script.js — local-only preview checks
- .nojekyll — disables Jekyll processing
- .gitignore — local development exclusions

## GitHub Pages
Open Settings → Pages. Choose Deploy from a branch, select main and /(root), then save.
Expected URL: https://YOUR-GITHUB-USERNAME.github.io/safecheck-ai/

## Before production scanning
- Add a backend; never expose private API keys in browser JavaScript.
- Choose a commercial URL reputation provider and review its terms and pricing.
- Add server-side rate limits, input limits, abuse controls, and monitoring.
- Minimize retention of submitted text and images; publish a clear privacy policy.
- Treat detections as probabilistic signals, not guarantees.
- Complete security testing before accepting sensitive user content.

This static preview has no paid dependencies. Domain, backend, AI usage, and commercial threat-intelligence lookups are separate future costs.

## Live URL reputation backend
See [LIVE-URL-SETUP.md](LIVE-URL-SETUP.md). Live lookups remain disabled until the Cloudflare Worker is deployed, its `WEBRISK_API_KEY` secret is configured, and its URL is added to `LIVE_CHECK_ENDPOINT` in `script.js`. Never put API keys in frontend files.
