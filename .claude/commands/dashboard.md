---
description: Build and serve the ClaudeSec security dashboard
---
Build and serve the ClaudeSec dashboard:
1. Run `npm run dashboard` (default safe runner with port fallback)
2. If Docker is preferred, run `./scripts/quick-start.sh` (auto-fallback to local scanner when Docker is unavailable)
3. For deterministic local generation only, run `./scripts/run-dashboard-safe.sh --no-serve`
4. Open http://localhost:11777/ in the browser
5. Show the dashboard URL to the user
