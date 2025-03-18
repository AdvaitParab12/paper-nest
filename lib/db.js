import Database from "better-sqlite3";
export const db = new Database("database.db");

db.pragma("journal_mode = WAL");

// Database Setup
const createTables = db.transaction(() => {
  // Create users table
  // 1. write a sql statement db.prepare
  // 2. to run it .run()
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username STRING NOT NULL UNIQUE,
      password STRING NOT NULL
    )
    `
  ).run();

  db.prepare(
    `
      CREATE TABLE IF NOT EXISTS papers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body STRING NOT NULL,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users (id)
      )
    `
  ).run();
});
createTables();

db;