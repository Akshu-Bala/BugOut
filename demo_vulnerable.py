def find_user(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
