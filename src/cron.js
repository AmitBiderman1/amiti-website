// Amiti's: scheduled worker. Runs every 15 minutes (free Cloudflare plan) and
//  - sends reminders for tasks that came due, even when the app is closed,
//  - checks Google Classroom for new assignments,
//  - checks Gmail for order updates.
// It uses the same database as the website. Deploy it once (see README, "Alerts when the app is closed").
import { scheduledRun } from './worker.js';

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(scheduledRun(env));
  },
  // Visiting the worker address shows nothing useful on purpose.
  async fetch() {
    return new Response('Amiti’s scheduler', { status: 200 });
  },
};
