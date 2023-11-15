import mariadb


def create_database(database_name:str):
    try:
        connection = mariadb.connector.connect(
            host="127.0.0.1",
            port="3306",
            user="root",
            password="azerty"
        )

        cursor = connection.cursor()

        cursor.execute(f"CREATE DATABASE {database_name}")

        print(f"Database '{database_name}' created successfully!")

    except mariadb.connector.Error as err:
        print(f"Error: {err}")
        

def drop_database(database_name:str):
    try:
        connection = mariadb.connector.connect(
            host="127.0.0.1",
            port="3306",
            user="root",
            password="azerty"
        )

        cursor = connection.cursor()

        cursor.execute(f"DROP DATABASE {database_name}")

        print(f"Database '{database_name}' dropped successfully!")

    except mariadb.connector.Error as err:
        print(f"Error: {err}")
        
        

def init_database():
    configdatabase = {
        'host': '127.0.0.1',
        'port': 3306,
        'user': 'root',
        'password': 'azerty',
        'database': 'vdi'
    }
        
    conn = mariadb.connect(configdatabase)
    
    # Create the table users
    try:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS users (uuid VARCHAR(255), first_name VARCHAR(255), last_name VARCHAR(255), email VARCHAR(255), password VARCHAR(255), role VARCHAR(255), creationDate DATETIME DEFAULT CURRENT_TIMESTAMP)")
        conn.commit()
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")


    
    # Create the table tokens_user
    try:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS tokens_user (uuid_user VARCHAR(255), token VARCHAR(255), creationDate DATETIME DEFAULT CURRENT_TIMESTAMP)")
        conn.commit()
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")


    # Create the table vms
    try:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS vms (uuid VARCHAR(255), user_uuid VARCHAR(255), template_uuid VARCHAR(255), creationDate DATETIME DEFAULT CURRENT_TIMESTAMP)")
        conn.commit()
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")

   
   
    # Create the table templates
    try:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS templates (uuid VARCHAR(255), name VARCHAR(255), creationDate DATETIME DEFAULT CURRENT_TIMESTAMP, user_uuid VARCHAR(255))")
        conn.commit()
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB Platform: {e}")

         
    conn.close()
    print("Database initialized successfully!")
 