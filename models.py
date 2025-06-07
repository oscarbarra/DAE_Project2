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

# Ejecuta esta función una sola vez para crear la base
if __name__ == '__main__':
    crear_base_datos()
