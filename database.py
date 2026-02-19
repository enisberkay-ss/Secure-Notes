import sqlite3


class DatabaseManager:

    def __init__(self, db_name="secure_notes.db"):
        self.db_name = db_name
        self.conn = None
        self.cursor = None

    def connect(self):
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()

    def create_tables(self):
        # Master user table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS master_user (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        """)

        # Notes table with nonce
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content BLOB NOT NULL,
                nonce BLOB NOT NULL
            )
        """)

        # Failed attempts table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS failed_attempts (
                id INTEGER PRIMARY KEY,
                attempts INTEGER,
                last_failed INTEGER
            )
        """)

        self.conn.commit()

    # -------------------------
    # MASTER USER
    # -------------------------
    def get_master_user(self):
        self.cursor.execute("SELECT password_hash, salt FROM master_user LIMIT 1")
        return self.cursor.fetchone()

    # -------------------------
    # FAILED ATTEMPTS
    # -------------------------
    def get_failed_attempt_info(self):
        self.cursor.execute("SELECT attempts, last_failed FROM failed_attempts WHERE id=1")
        return self.cursor.fetchone()

    def record_failed_attempt(self):
        self.cursor.execute("SELECT attempts FROM failed_attempts WHERE id=1")
        row = self.cursor.fetchone()

        if row:
            attempts = row[0] + 1
            self.cursor.execute("""
                UPDATE failed_attempts
                SET attempts=?, last_failed=strftime('%s','now')
                WHERE id=1
            """, (attempts,))
        else:
            self.cursor.execute("""
                INSERT INTO failed_attempts (id, attempts, last_failed)
                VALUES (1, 1, strftime('%s','now'))
            """)

        self.conn.commit()

    def reset_failed_attempts(self):
        self.cursor.execute("DELETE FROM failed_attempts WHERE id=1")
        self.conn.commit()

    # -------------------------
    # NOTES
    # -------------------------
    def add_note(self, title, content, nonce):
        self.cursor.execute("""
            INSERT INTO notes (title, content, nonce)
            VALUES (?, ?, ?)
        """, (title, content, nonce))
        self.conn.commit()

    def update_note(self, note_id, new_title, new_content, nonce):
        self.cursor.execute("""
            UPDATE notes
            SET title=?, content=?, nonce=?
            WHERE id=?
        """, (new_title, new_content, nonce, note_id))
        self.conn.commit()

    def delete_note(self, note_id):
        self.cursor.execute("DELETE FROM notes WHERE id=?", (note_id,))
        self.conn.commit()

    def get_all_notes(self):
        self.cursor.execute("SELECT id, title FROM notes ORDER BY id DESC")
        return self.cursor.fetchall()

    def get_note_by_id(self, note_id):
        self.cursor.execute("SELECT id, title, content, nonce FROM notes WHERE id=?", (note_id,))
        return self.cursor.fetchone()

    def search_notes_by_title(self, keyword):
        self.cursor.execute("""
            SELECT id, title FROM notes
            WHERE title LIKE ?
        """, (f"%{keyword}%",))
        return self.cursor.fetchall()