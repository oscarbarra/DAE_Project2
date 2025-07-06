# ClaveForte
ClaveForte es una aplicación web construida con Flask, que permite a los usuarios registrar, almacenar y compartir de forma segura sus credenciales de servicios. Incluye roles diferenciados para administradores y usuarios normales.

--------------------------------------

¿Cómo ingresar?

1. Ejecuta el archivo app.py.
2. Accede en el navegador a:  
   👉 [http://127.0.0.1:5000](https://claveforte-uct-2025.onrender.com/)

---------------------------

👤 Usuarios habilitados

| Rol           | Correo               | Contraseña pricipal | Contraseña secundaria |
|---------------|----------------------|---------------------|-----------------------|
| Administrador | admin@gmail.com      | 1234                | 1234                  |
| Invitado      | invitado@gmail.com   | 1234                | 1234                  |

También puedes registrarte con tu propio usuario en la opción “Regístrate”, pero este deberá tener una contraseña principal distinta a la secundaria .

-------------------------

 Funcionalidades

- Registro e inicio de sesión con hash seguro de contraseñas
- Edición de perfil personal (nombre, correo, contraseña)
- Gestión de credenciales privadas y compartidas
- Compartición segura de credenciales entre usuarios
- Eliminación de cuenta personal
- Sistema de roles: Administrador / Usuario
- Administración de usuarios (solo para administradores)
- Interfaz moderna con Tailwind CSS
- Mensajes flash para retroalimentación al usuario


--------------

Tecnologías utilizadas

- Python 3.11+
- Flask
- SQLite3
- Jinja2 (para plantillas HTML)
- Tailwind CSS (interfaz)
- dotenv (manejo seguro de claves)
- werkzeug.security (hash unidireccional para la contraseña principal y secundaria)
- cryptography.fernet (cifrado simétrico para las contraseñas de las servicios)