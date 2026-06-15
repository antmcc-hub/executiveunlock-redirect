# Executive Unlock Redirect Agent Instructions

This repo is a static redirect from `executiveunlock.ai` to `https://aiexecutiveunlock.com`.

## Map

- `index.html` redirects normal requests.
- `404.html` redirects deep links and unknown paths.
- `CNAME` points the custom domain to `executiveunlock.ai`.

## Build, Test, Ship

- There is no build step.
- Verify redirects by opening `index.html` and `404.html`, or by checking the deployed domain after GitHub deployment.
- Shipping path is GitHub-only. Do not manually deploy outside GitHub.

## Guardrails

- Preserve path-forwarding behavior in the JavaScript redirect.
- Keep canonical target as `https://aiexecutiveunlock.com` unless Ant explicitly changes the destination.
- Do not add analytics or scripts unless requested; this should remain a minimal redirect.
