import mysql.connector
from config import Config


def get_db_connection():
    connection = mysql.connector.connect(
        host=Config.DB_HOST,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME
    )

    return connection


if __name__ == "__main__":
    connection = get_db_connection()

    if connection.is_connected():
        print("Successfully connected to MySQL!")
        print("Database:", Config.DB_NAME)

    connection.close()