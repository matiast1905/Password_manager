import os
import sqlite3


class Database:
    def __init__(self, database_path) -> None:
        self.database = database_path
        if os.path.exists(os.path.join(os.getcwd(), self.database)):
            return
        try:
            with sqlite3.connect(self.database) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """CREATE TABLE passwords(
                    site text,
                    user text,
                    pass text
                    )"""
                )
                conn.commit()
        except sqlite3.OperationalError:
            print("Error creating database.")

    def save_to_database(self, site, user, password):
        with sqlite3.connect(self.database) as conn:
            cursor = conn.cursor()
            if cursor.execute(
                f"SELECT * FROM passwords WHERE site=:site and user=:user",
                {"site": site, "user": user},
            ).fetchone():
                print("Error,user for that site exist already.")
                return None
            cursor.execute(
                f"INSERT INTO passwords VALUES(:site,:user,:pass)",
                {"site": site, "user": user, "pass": str(password)},
            )
            conn.commit()
            return True

    def load_from_database(self, site):
        with sqlite3.connect(self.database) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM passwords WHERE site=:site", {"site": site})
            ans = cursor.fetchall()
            conn.commit()
            return ans

    def get_every_item_from_database(self):
        with sqlite3.connect(self.database) as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM passwords")
            ans = cursor.fetchall()
            conn.commit()
            return ans

    def remove_from_database(self, site, user):
        with sqlite3.connect(self.database) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"DELETE FROM passwords WHERE site=:site and user=:user",
                {"site": site, "user": user},
            )
            conn.commit()

    def update_in_database(self, site, user, password):
        with sqlite3.connect(self.database) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE passwords SET pass=:pass WHERE site=:site and user=:user",
                {"site": site, "user": user, "pass": password},
            )
            conn.commit()
