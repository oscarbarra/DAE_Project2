
import os
import sqlite3

def crear_base_datos():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Tabla de usuarios
    c.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            rut TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            rol TEXT NOT NULL
        )
    ''')

    # Tabla de credenciales
    c.execute('''
        CREATE TABLE IF NOT EXISTS credenciales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            servicio TEXT NOT NULL,
            usuario_servicio TEXT NOT NULL,
            contraseña TEXT NOT NULL,
            FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
        )
    ''')

    conn.commit()
    conn.close()

def init_db(nombre_bd="instance/ClaveForte.db"):
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
        secret_pass  TEXT NOT NULL,       -- Contraseña para compartir (hash)
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
        id_usr          INTEGER NOT NULL,
        id_credential   INTEGER NOT NULL,
        FOREIGN KEY (id_usr) REFERENCES Users(id_usr),
        FOREIGN KEY (id_credential) REFERENCES Credentials(id_credential)
    );
    """)

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

# Ejecuta esta función una sola vez para crear la base
if __name__ == '__main__':
    init_db()
