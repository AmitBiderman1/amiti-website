-- Amiti's database (Cloudflare D1 / SQLite)
CREATE TABLE IF NOT EXISTS tasks (
  owner     TEXT NOT NULL,
  id        TEXT NOT NULL,
  text      TEXT NOT NULL,
  due       TEXT NOT NULL DEFAULT '',
  dur       INTEGER NOT NULL DEFAULT 30,
  snooze    TEXT NOT NULL DEFAULT '',
  fired     TEXT NOT NULL DEFAULT '',
  tag       TEXT NOT NULL DEFAULT 'priv',
  urgent    INTEGER NOT NULL DEFAULT 0,
  important INTEGER NOT NULL DEFAULT 0,
  done      INTEGER NOT NULL DEFAULT 0,
  gcal      INTEGER NOT NULL DEFAULT 0,
  gcal_id   TEXT NOT NULL DEFAULT '',
  src       TEXT NOT NULL DEFAULT '',
  updated   TEXT NOT NULL,
  PRIMARY KEY (owner, id)
);
CREATE INDEX IF NOT EXISTS tasks_due ON tasks (owner, due);

CREATE TABLE IF NOT EXISTS food (
  owner TEXT NOT NULL,
  id    TEXT NOT NULL,
  day   TEXT NOT NULL,
  slot  TEXT NOT NULL,
  name  TEXT NOT NULL,
  kcal  INTEGER NOT NULL DEFAULT 0,
  p     REAL NOT NULL DEFAULT 0,
  c     REAL NOT NULL DEFAULT 0,
  f     REAL NOT NULL DEFAULT 0,
  PRIMARY KEY (owner, id)
);
CREATE INDEX IF NOT EXISTS food_day ON food (owner, day);

CREATE TABLE IF NOT EXISTS meals (
  owner    TEXT NOT NULL,
  id       TEXT NOT NULL,
  name     TEXT NOT NULL,
  servings REAL NOT NULL DEFAULT 1,
  ing      TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (owner, id)
);

CREATE TABLE IF NOT EXISTS settings (
  owner TEXT NOT NULL,
  key   TEXT NOT NULL,
  value TEXT NOT NULL,
  PRIMARY KEY (owner, key)
);

CREATE TABLE IF NOT EXISTS seen (
  owner TEXT NOT NULL,
  kind  TEXT NOT NULL,
  key   TEXT NOT NULL,
  PRIMARY KEY (owner, kind, key)
);

CREATE TABLE IF NOT EXISTS orders (
  owner    TEXT NOT NULL,
  id       TEXT NOT NULL,
  shop     TEXT NOT NULL,
  item     TEXT NOT NULL DEFAULT '',
  order_no TEXT NOT NULL DEFAULT '',
  status   TEXT NOT NULL DEFAULT 'ordered',
  placed   TEXT NOT NULL,
  updated  TEXT NOT NULL,
  msg_id   TEXT NOT NULL DEFAULT '',
  hidden   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (owner, id)
);
