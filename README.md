# Amiti’s: tasks, calendar and food (Cloudflare)

One Cloudflare Worker serves the app and its API. Data lives in a D1 database (SQLite).
Sign-in is a single password (free, no card needed). AI features run on Cloudflare Workers AI (free daily allowance).
Google Calendar uses the Google Calendar API (free).

```
public/        the app (index.html, logo, icons)
src/worker.js  API: /api/state, /api/sync, /api/ai, /api/gcal/*, /api/google/*
schema.sql     D1 tables
wrangler.toml  Cloudflare config
```

## Cost: stays free

| Piece | Free plan |
|---|---|
| Worker + static files | 100,000 requests/day |
| D1 database | 5 GB, 5M reads/day |
| Password login | built in, nothing to buy |
| Workers AI | ~10,000 neurons/day free |
| Google Calendar API | free |

When a free daily limit is reached, the Worker stops answering (or the AI button says "limit reached") until it resets.
The Workers Free plan has no overage billing. Optional free AI: add a `GEMINI_API_KEY` secret (free key from Google AI Studio, no card). It is used before Workers AI and falls back to it. Do NOT add `ANTHROPIC_API_KEY` (paid) and do NOT upgrade to Workers Paid.
The free AI is a small open model, so food estimates and plate-photo answers are rougher than Claude's. Always check the numbers.

## 1. Deploy the app and database

You need Node 18+ and a free Cloudflare account.

```bash
npm install
npx wrangler login
npx wrangler d1 create amitis
```

Copy the `database_id` it prints into `wrangler.toml` (replace `REPLACE_WITH_YOUR_D1_DATABASE_ID`). Then:

```bash
npm run db:remote                       # creates the tables
npx wrangler secret put APP_PASSWORD    # choose 10+ characters, you type it in the terminal
npm run deploy                          # prints https://amitis.<your-subdomain>.workers.dev
```

Open the URL, sign in with that password (the session lasts 30 days). After 10 wrong attempts sign-in locks for 15 minutes.
Until `APP_PASSWORD` is set, the deployed app refuses every request (503), so nothing is exposed.

## 2. AI features (describe food, plate photo, suggest a time)

Already on: `wrangler.toml` has `[ai] binding = "AI"`. Nothing to configure.
If a model has been retired, pick another from the Workers AI list in the dashboard and change `AI_TEXT_MODEL` / `AI_VISION_MODEL`.

## Google Calendar sync for tasks

Every task that has a time is added to Google Calendar automatically (no manual button, no opt-out). A task without a time
stays only in the app. Changing the title, time, duration or tag updates the event, clearing the time removes the event,
and deleting the task deletes the event. A task you mark done keeps its past event.
If Google is not connected yet, upcoming timed tasks are added as soon as it is. The event id lives in the `gcal_id`
column. On an existing database run `migrations/001_gcal_id.sql` once (before deploying this version).

## Automatic deploys from Git

Push this folder to a GitHub repo, then in Cloudflare: Workers & Pages → Create → Import a repository → pick the repo.
Build command: leave empty. Deploy command: `npx wrangler deploy`. Every push to `main` then deploys by itself.
The database id in `wrangler.toml` is not a secret. Set `APP_PASSWORD` (and the Google secrets) under the Worker's
Settings → Variables and Secrets, never in the repo.

## Optional: Cloudflare Access instead of a password

Cloudflare Zero Trust has a free plan (up to 50 users), but the dashboard may ask for a payment method when you first
enable it. If it does, skip this and keep the password. To use it: create a self-hosted Access application for the
Worker's hostname, then set `TEAM_DOMAIN` and `ACCESS_AUD` in `wrangler.toml` and redeploy. When both are set, Access
replaces the password login.

## 4. Google Calendar

1. console.cloud.google.com → create a project → **APIs & Services → Library** → enable **Google Calendar API**.
2. **OAuth consent screen**: User type External, add your Google account as a test user.
   Add the scope `.../auth/calendar.events`.
3. **Credentials → Create credentials → OAuth client ID → Web application**.
   Authorized redirect URI: `https://YOUR-APP-URL/api/google/callback` (exactly, with your real hostname).
4. Store the client in Cloudflare:

```bash
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
```

5. Open the app → Calendar → **Connect Google Calendar** and approve.

Important: while the consent screen is in **Testing**, Google expires the login after 7 days. For personal use,
set the publishing status to **In production** (you will see an “unverified app” warning once; continue past it).
Do not share the app with other people while it is unverified.

## Local development

```bash
cp .dev.vars.example .dev.vars    # optional: add keys for local testing
npm run db:local
npm run dev                       # http://localhost:8787 (no login needed on localhost)
```

For Google login locally, add `http://localhost:8787/api/google/callback` as a second redirect URI.

## Notes

- Alerts for tasks fire only while the app is open in a browser tab (no background push).
- Several devices can use the same app; changes sync when you save, and the app refreshes when you return to it.
  If two devices edit the same item at once, the last save wins.
- Your tasks and food from the old claude.ai artifact live in that artifact’s browser storage and were not
  moved automatically.

## Alerts when the app is closed, Classroom and order checks (free)

Cloudflare Pages cannot run on a schedule, so a tiny second Worker does it. It is free (cron triggers are included).

1. Cloudflare dashboard > **Workers & Pages** > **Create** > **Import a repository** > choose `amiti-website`.
2. Project name: `amiti-cron`. Deploy command: `npx wrangler deploy -c wrangler.cron.toml`. Leave the build command empty.
3. After it deploys: **amiti-cron** > **Settings** > **Variables and Secrets** > add `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` (the same two values as the website, as **Secret**).
4. On your phone, open the site from the Home Screen icon and tap **Enable alerts** (on iPhone this only appears in the Home Screen app).

Every 15 minutes the worker sends reminders for tasks that came due, and checks Classroom and Gmail. Without it, reminders still work while the app is open.

## Backup

The 💾 button in the header downloads all your tasks, food, meals and orders as a JSON file.

## Database changes

Run the files in `migrations/` once, in order, against the remote database (`001_gcal_id.sql`, `002_classroom_orders.sql`, `003_recurring_push.sql`).


## Notion (optional, free)
Create an internal integration at notion.so/profile/integrations, share one Notion page with it ("Connect to"), and add its token as the `NOTION_TOKEN` secret. Recipes and the shopping list then sync both ways with two databases under that page. Run `migrations/014_notion.sql` once.
