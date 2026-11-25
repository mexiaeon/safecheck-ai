# SafeCheck AI — live URL reputation backend

The Worker keeps the Google API key server-side. It does not visit submitted websites; it sends the URL to Google Web Risk for a reputation lookup.

## 1. Create the Google Web Risk API key
1. Create/select a project in Google Cloud Console.
2. Enable **Web Risk API**.
3. Create an API key and restrict it to the Web Risk API.
4. Review billing, quotas, and current terms. Google currently lists up to 100,000 Lookup API `uris.search` calls/month at no charge. See https://cloud.google.com/web-risk/pricing.

## 2. Deploy the Cloudflare Worker
1. Create/sign in to Cloudflare.
2. Open Workers & Pages → Create → Worker. Name it `safecheck-url-check`.
3. Replace the starter code with `worker.js` from this repository and Deploy.
4. In Worker settings, add a secret named `WEBRISK_API_KEY` and paste the Google API key.
5. Your Worker URL will look like `https://safecheck-url-check.YOUR-SUBDOMAIN.workers.dev`.

## 3. Connect the website
1. Open `script.js` in GitHub.
2. Find `const LIVE_CHECK_ENDPOINT = "";`.
3. Put your Worker base URL between the quotes (no trailing slash).
4. Commit. GitHub Pages will publish the update.

## Security before public launch
- The key is stored only as a Cloudflare Worker secret, never in browser code.
- The Worker allows the published GitHub Pages origin and localhost development origins.
- CORS is not authentication. Configure Cloudflare rate limiting, abuse controls, and usage alerts before public promotion.
- Add a privacy notice explaining that URLs entered for live checks are sent to Google for reputation lookup.
- A no-match response is not proof of safety. New and targeted threats may not be listed.
- Review Google Web Risk terms, branding/attribution, retention, and commercial-use requirements before monetizing.

## Current status
The front-end integration and Worker source are prepared, but live lookup stays disabled until you deploy the Worker, set its secret, and configure `LIVE_CHECK_ENDPOINT`.
