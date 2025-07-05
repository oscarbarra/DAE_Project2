
import os
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

def make_db(nombre_bd="instance/ClaveForte.db"):
    os.makedirs(os.path.dirname(nombre_bd), exist_ok=True)
    
    conexion = sqlite3.connect(nombre_bd)
    cursor = conexion.cursor()

    # Tabla Roles
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Roles (
        id_rol     INTEGER PRIMARY KEY AUTOINCREMENT,
        rol_type   TEXT NOT NULL
    );
    """)

    # Tabla Users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Users (
        id_usr       INTEGER PRIMARY KEY AUTOINCREMENT,
        usr_name     TEXT NOT NULL,
        usr_mail     TEXT NOT NULL UNIQUE,
        usr_pass     TEXT NOT NULL,       -- Contraseña principal (hash)
        secret_pass  TEXT,                -- Contraseña para compartir (hash)
        last_login   TEXT,                -- Fecha en formato ISO
        id_rol       INTEGER NOT NULL,
        FOREIGN KEY (id_rol) REFERENCES Roles(id_rol)
    );
    """)

    # Tabla Credentials
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Credentials (
        id_credential   INTEGER PRIMARY KEY AUTOINCREMENT,
        service_name    TEXT NOT NULL,
        service_pass    TEXT NOT NULL,
        users_allows    TEXT,
        name_owner      TEXT,
        id_usr          INTEGER NOT NULL,
        FOREIGN KEY (id_usr) REFERENCES Users(id_usr)
    );
    """)

    # Tabla Access
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Access (
        id_access       INTEGER PRIMARY KEY AUTOINCREMENT,
        timestam        TEXT NOT NULL,  -- Fecha en formato ISO
        motivo          TEXT,
        usr_name        TEXT,
        id_usr          INTEGER NOT NULL,
        id_credential   INTEGER NOT NULL,
        FOREIGN KEY (id_usr) REFERENCES Users(id_usr),
        FOREIGN KEY (id_credential) REFERENCES Credentials(id_credential)
    );
    """)
    return

def init_table_roles(nombre_bd="instance/ClaveForte.db"):
    conexion = sqlite3.connect(nombre_bd)
    cursor = conexion.cursor()
    # Insertar roles si no existen
    cursor.execute("SELECT COUNT(*) FROM Roles")
    total_roles = cursor.fetchone()[0]

    if total_roles == 0:
        cursor.executemany("INSERT INTO Roles (rol_type) VALUES (?)", [
            ("administrador",),
            ("usuario",)
        ])

    conexion.commit()
    conexion.close()
    return

def init_table_users(nombre_bd="instance/ClaveForte.db"):
    conexion = sqlite3.connect(nombre_bd)
    cursor = conexion.cursor()
    # Insertar usuarios basicos si no existen
    cursor.execute("SELECT COUNT(*) FROM Users")
    total_users = cursor.fetchone()[0]
    encyrpt_pass = generate_password_hash('1234')
    if total_users == 0:
        date = str(datetime.now())
        cursor.executemany("INSERT INTO Users (usr_name, usr_mail, usr_pass, secret_pass, last_login, id_rol)\
                        VALUES (?,?,?,?,?,?)", [
                        ("admin","admin@gmail.com", encyrpt_pass, encyrpt_pass, date, 1),
                        ("invitado","invitado@gmail.com", encyrpt_pass, encyrpt_pass, date, 2)
                        ])
    conexion.commit()
    conexion.close()
    return

def init_db(nombre_bd="instance/ClaveForte.db"):
    make_db(nombre_bd="instance/ClaveForte.db")
    init_table_roles(nombre_bd="instance/ClaveForte.db")
    init_table_users(nombre_bd="instance/ClaveForte.db")
    return

# Ejecuta esta función una sola vez para crear la base
if __name__ == '__main__':
    init_db(nombre_bd="instance/ClaveForte.db")
