-- When a task was marked done (for the evening summary).
ALTER TABLE tasks ADD COLUMN done_at TEXT NOT NULL DEFAULT '';
