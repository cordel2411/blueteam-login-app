import sqlite3, sys, getpass, os
from argon2 import PasswordHasher
DB = os.environ.get("DB_PATH", "users.db")
con = sqlite3.connect(DB)
con.execute("""CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  failed INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0)""")
if len(sys.argv) > 1:
    pw = getpass.getpass(f"Password for {sys.argv[1]}: ")
    if len(pw) < 12:
        sys.exit("Use at least 12 characters.")
    con.execute("INSERT INTO users(username, pw_hash) VALUES(?,?)",
                (sys.argv[1], PasswordHasher().hash(pw)))
con.commit()
os.chmod(DB, 0o600)
print("done")
