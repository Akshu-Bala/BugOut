def find_user(cursor, username):
    query = "SELECT * FROM users WHERE username = " + username
    cursor.execute(query)
