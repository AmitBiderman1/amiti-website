-- Run once on an existing database (new databases get this column from schema.sql).
ALTER TABLE tasks ADD COLUMN gcal_id TEXT NOT NULL DEFAULT '';
