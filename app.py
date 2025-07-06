
import os
import json
import sqlite3
from datetime import datetime
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify

from models import init_db

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
fernet = Fernet(os.getenv('FERNET_KEY').encode())

# ========== AUTENTICACIÓN ==========
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        correo = request.form['email']
        contraseña = request.form['password']

        try:
            conexion = sqlite3.connect('instance/ClaveForte.db')
            cursor = conexion.cursor()
            cursor.execute("SELECT id_usr, usr_name, usr_mail, usr_pass, id_rol FROM Users WHERE usr_mail = ?", (correo,))
        finally:
            usuario = cursor.fetchone()
            conexion.close()

        if not usuario:
            flash("Correo y/o Contraseña incorrectas", "danger")
            return redirect(url_for('login'))
        
        id_usr, usr_name, usr_mail, usr_pass, id_rol = usuario
        if check_password_hash(usr_pass, contraseña):
            session['usuario_id'] = id_usr
            session['usuario_nombre'] = usr_name
            session['usuario_correo'] = usr_mail
            session['usuario_rol'] = id_rol
            flash("Inicio de sesión exitoso", "success") 
            return render_template("/auth/login.html", redirigir=True)
        
    return render_template('/auth/login.html')


@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password_plano = request.form['password']
        password = generate_password_hash(password_plano)
        secret   = None
        created  = str(datetime.now())
        rol = request.form['rol']

        try:
            conexion = sqlite3.connect('instance/ClaveForte.db')
            cursor = conexion.cursor()
            cursor.execute("""
                INSERT INTO Users (usr_name, usr_mail, usr_pass, secret_pass, last_login, id_rol)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, email, password, secret, created , rol))
            conexion.commit()
        except sqlite3.IntegrityError:
            flash("Correo ya registrado", "danger")
            return redirect(url_for('signup'))
        finally:
            conexion.close()

        flash("Cuenta creada correctamente", "success")
        return redirect(url_for('login'))

    return render_template('/auth/signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Sesión cerrada correctamente", "info")
    return redirect('/login')


# ========== HOME Y PERFIL ==========
@app.route('/home')
def home():
    if not session:
        return redirect("login")
    rol = session.get('usuario_rol')
    return render_template('/home/home.html',
                           usr_rol=rol)

@app.route('/profile', methods=['GET', 'POST'])
def perfil():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    rol = session.get('usuario_rol')
    usuario_id = session['usuario_id']
    conn = sqlite3.connect('instance/ClaveForte.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    if request.method == 'POST':
        nuevo_nombre = request.form['nombre']
        nuevo_correo = request.form['correo']
        nueva_pass = request.form['password']

        if nueva_pass.strip():
            nueva_pass_hash = generate_password_hash(nueva_pass)
            cur.execute("""
                UPDATE Users
                SET usr_name = ?, usr_mail = ?, usr_pass = ?
                WHERE id_usr = ?
            """, (nuevo_nombre, nuevo_correo, nueva_pass_hash, usuario_id))
        else:
            cur.execute("""
                UPDATE Users
                SET usr_name = ?, usr_mail = ?
                WHERE id_usr = ?
            """, (nuevo_nombre, nuevo_correo, usuario_id))

        conn.commit()
        conn.close()

        session['usuario_nombre'] = nuevo_nombre
        session['usuario_correo'] = nuevo_correo
        flash("Perfil actualizado correctamente.")
        return redirect(url_for('perfil'))

    cur.execute("SELECT usr_name, usr_mail, id_rol FROM Users WHERE id_usr = ?", (usuario_id,))
    datos = cur.fetchone()
    conn.close()
    return render_template('/profile/profile.html', 
                           usr_rol=rol,
                           usuario=datos)

@app.route('/eliminar_cuenta', methods=['POST'])
def eliminar_cuenta():
    if 'usuario_id' not in session:
        flash("Sesión expirada.")
        return redirect(url_for('login'))

    if request.method == "POST":
        usuario_id = session.get('usuario_id')
        try:
            conn = sqlite3.connect('instance/ClaveForte.db')
            cur = conn.cursor()
            cur.execute("DELETE FROM Credentials WHERE id_usr = ?", (usuario_id,))
            cur.execute("DELETE FROM Users WHERE id_usr = ?", (usuario_id,))
            conn.commit()
            conn.close()

            session.clear()
            flash("Cuenta eliminada correctamente.")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error al eliminar cuenta: {str(e)}")
            return redirect(url_for('perfil'))

# ======== Usuarios Con Rol Estandar ========
def registrar_acceso(motivo, owner_name, id_usr, id_credencial):
    try:
        conn = sqlite3.connect('instance/ClaveForte.db')
        cursor = conn.cursor()

        timestamp_actual = datetime.now()

        cursor.execute('''
            INSERT INTO Access (timestam, motivo, usr_name, id_usr, id_credential)
            VALUES (?, ?, ?, ?, ?);
        ''', (timestamp_actual, motivo, owner_name, id_usr, id_credencial))

        conn.commit()

    except Exception as e:
        print(f"Error al registrar acceso: {str(e)}")
    finally:
        conn.close()

# -------- Credenciales -------
@app.route('/crear_pass_secundaria', methods=['POST'])
def crear_pass_secundaria():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    secret = request.form.get('secret_pass')
    confirm = request.form.get('confirm_pass')
    origen = request.form.get('origen')
    print(origen)

    if not secret or secret != confirm:
        flash("Las contraseñas no coinciden.", "danger")
        return redirect(url_for(origen))

    try:
        conn = sqlite3.connect('instance/ClaveForte.db')
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("SELECT usr_pass FROM Users WHERE id_usr = ?", (usuario_id,))
        fila = cur.fetchone()

        if fila is None:
            flash("Usuario no encontrado.", "danger")
            return redirect(url_for(origen))

        if check_password_hash(fila['usr_pass'], secret):
            flash("La contraseña secundaria no puede ser igual a tu contraseña principal.", "warning")
            return redirect(url_for(origen))

        hashed_secret = generate_password_hash(secret)
        cur.execute("UPDATE Users SET secret_pass = ? WHERE id_usr = ?", (hashed_secret, usuario_id))
        conn.commit()

        flash("Contraseña secundaria creada con éxito.", "success")
        return redirect(url_for(origen))

    except sqlite3.Error as e:
        flash("Error en la base de datos.", "danger")
        return redirect(url_for(origen))

    finally:
        conn.close()

@app.route('/ver_password/<int:cred_id>', methods=['POST'])
def ver_password(cred_id):
    if 'usuario_id' not in session:
        return jsonify({'error': 'No autorizado'}), 403

    # (opcional) validar clave secundaria aquí

    conn = sqlite3.connect('instance/ClaveForte.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT service_pass FROM Credentials WHERE id_credential = ?", (cred_id,))
    fila = cur.fetchone()
    conn.close()

    if not fila:
        return jsonify({'error': 'Credencial no encontrada'}), 404

    try:
        fernet = Fernet(os.getenv("FERNET_KEY").encode())
        pass_desencriptada = fernet.decrypt(fila['service_pass'].encode()).decode()
        return jsonify({'password': pass_desencriptada})
    except Exception as e:
        return jsonify({'error': 'Error al desencriptar'}), 500

@app.route('/credentials')
def mostrar_credenciales():
    # Verificar sesión activa
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    usuario_rol = session.get('usuario_rol')

    # Conectar a la base de datos
    conn = sqlite3.connect('instance/ClaveForte.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 1. Obtener credenciales que sean del usuario o compartidas
    cur.execute("""
        SELECT * FROM Credentials 
        WHERE id_usr = ? OR users_allows IS NOT NULL
    """, (usuario_id,))
    resultados = cur.fetchall()

    # 2. Filtrar credenciales accesibles para el usuario
    credenciales_visibles = []
    for credencial in resultados:
        if credencial['id_usr'] == usuario_id:
            credenciales_visibles.append(credencial)
        else:
            try:
                usuarios_autorizados = json.loads(credencial['users_allows'])
                if isinstance(usuarios_autorizados, list) and usuario_id in usuarios_autorizados:
                    credenciales_visibles.append(credencial)
            except (json.JSONDecodeError, TypeError):
                continue

    # 3. Verificar si el usuario tiene contraseña secundaria
    cur.execute("SELECT secret_pass FROM Users WHERE id_usr = ?", (usuario_id,))
    fila_usuario = cur.fetchone()
    tiene_pass_secundaria = bool(fila_usuario and fila_usuario['secret_pass'])

    conn.close()

    # 4. Renderizar la plantilla
    return render_template(
        'credentials/credentials.html',
        credenciales=credenciales_visibles,
        usuario_actual=usuario_id,
        usr_rol=usuario_rol,
        tiene_pass_secundaria=tiene_pass_secundaria,
        origen='mostrar_credenciales'
    )

@app.route('/add_credential', methods=['POST'])
def agregar_credencial():
    if not session:
        return redirect("login")
    
    id_usr = session.get('usuario_id')
    name_owner    = session.get('usuario_nombre')
    service_name  = request.form['servicio']
    service_pass  = request.form['contrasena']
    users_allows  = json.dumps([])

    encrypted_pass = fernet.encrypt(service_pass.encode())
    encrypted_pass_str = encrypted_pass.decode()

    try:
        conn = sqlite3.connect('instance/ClaveForte.db')
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO Credentials (service_name, service_pass, users_allows, name_owner, id_usr)
            VALUES (?, ?, ?, ?, ?)
        """, (service_name, encrypted_pass_str, users_allows,name_owner, id_usr))
    finally:
        id_credencial_nueva = cur.lastrowid
        conn.commit()
        conn.close()    
        # Mantiene un registro de las acciones del usuario 
        registrar_acceso("creación", name_owner, id_usr, id_credencial_nueva)
        flash('Credencial registrada correctamete', 'success')
    return redirect('/credentials')

@app.route('/share_credential', methods=['GET', 'POST'])
def compartir_credencial():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session.get('usuario_id')
    usuario_nombre = session.get('usuario_nombre')
    rol = session.get('usuario_rol')

    # GET → Mostrar vista inicial con credenciales propias
    if request.method == 'GET':
        with sqlite3.connect('instance/ClaveForte.db') as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            cur.execute("SELECT * FROM Credentials WHERE id_usr = ?", (usuario_id,))
            credenciales = cur.fetchall()

            cur.execute("SELECT secret_pass FROM Users WHERE id_usr = ?", (usuario_id,))
            fila_usuario = cur.fetchone()
            tiene_pass_secundaria = bool(fila_usuario and fila_usuario['secret_pass'])

        return render_template(
            './credentials/compartir/compartir.html',
            credenciales=credenciales,
            usuario_actual=usuario_id,
            usr_rol=rol,
            tiene_pass_secundaria=tiene_pass_secundaria,
            origen='compartir_credencial'
        )

    # POST → Procesar formulario para compartir
    id_credencial = request.form.get('id_credential')
    correo_receptor = request.form.get('correo_receptor')
    clave_validacion = request.form.get('pass_validacion')

    # Validación de campos
    if not id_credencial or not correo_receptor or not clave_validacion:
        flash("Faltan campos obligatorios.", "danger")
        return redirect(url_for('compartir_credencial'))

    try:
        with sqlite3.connect('instance/ClaveForte.db') as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # Buscar receptor por correo
            cur.execute("SELECT id_usr FROM Users WHERE usr_mail = ?", (correo_receptor,))
            receptor = cur.fetchone()
            if not receptor:
                flash("El correo del receptor no está registrado.", "danger")
                return redirect(url_for('compartir_credencial'))
            id_receptor = receptor['id_usr']

            # Verificar clave secundaria del propietario
            cur.execute("SELECT secret_pass FROM Users WHERE id_usr = ?", (usuario_id,))
            propietario = cur.fetchone()
            if not propietario or not check_password_hash(propietario['secret_pass'], clave_validacion):
                flash("Clave secundaria incorrecta.", "danger")
                return redirect(url_for('compartir_credencial'))

            # Verificar propiedad de la credencial
            cur.execute(
                "SELECT users_allows FROM Credentials WHERE id_credential = ? AND id_usr = ?",
                (id_credencial, usuario_id)
            )
            credencial = cur.fetchone()
            if not credencial:
                flash("No se encontró la credencial o no eres su propietario.", "danger")
                return redirect(url_for('compartir_credencial'))

            # Agregar receptor si no está ya permitido
            try:
                usuarios_permitidos = json.loads(credencial['users_allows']) if credencial['users_allows'] else []
            except json.JSONDecodeError:
                usuarios_permitidos = []

            if id_receptor not in usuarios_permitidos:
                usuarios_permitidos.append(id_receptor)
                cur.execute(
                    "UPDATE Credentials SET users_allows = ? WHERE id_credential = ?",
                    (json.dumps(usuarios_permitidos), id_credencial)
                )
                conn.commit()

        # Registrar acción
        flash("Credencial compartida exitosamente.", "success")
        registrar_acceso("compartir", usuario_nombre, usuario_id, id_credencial)
        return redirect(url_for('compartir_credencial'))

    except sqlite3.Error as e:
        flash(f"Error en la base de datos: {str(e)}", "danger")
        return redirect(url_for('compartir_credencial'))


# ========== ADMINISTRADOR ==========
@app.route('/user_management', methods=['GET', 'POST'])
def gestionar_usuarios():
    if not session:
        return redirect("login")

    if request.method == "POST":
        method = request.form.get('_method')
        if method == 'UPDATE':
            id_usuario   = request.form.get('id_usuario')
            old_usr_mail = request.form.get('old_mail')
            new_usr_name = request.form.get('new_nombre_usuario')
            new_usr_mail = request.form.get('new_correo_usuario')
            new_usr_role = request.form.get('new_rol_usuario')
            print(new_usr_role)
            new_id_role  = 1 if (new_usr_role == "administrador") else 2

            conn = sqlite3.connect('instance/ClaveForte.db')
            cursor = conn.cursor()
            cursor.execute('''
                    UPDATE Users
                    SET usr_name = ?, usr_mail = ?, id_rol = ?
                    WHERE id_usr = ? AND usr_mail = ?;
                ''', (new_usr_name, new_usr_mail, new_id_role, id_usuario, old_usr_mail))
            conn.commit()
            conn.close()
        elif method == 'DELETE':
            # obtener el id enviado desde el formulario
            id_usuario = request.form.get('id_usuario')
            conn = sqlite3.connect('instance/ClaveForte.db')
            cur = conn.cursor()
            cur.execute("DELETE FROM Users WHERE id_usr = ?", (id_usuario,))
            conn.commit()
            conn.close()

    rol = session.get('usuario_rol')
    usuario_logeado_email = session.get('usuario_correo')
    correos_a_ignorar = ["admin@gmail.com", "invitado@gmail.com", usuario_logeado_email]

    conn = sqlite3.connect('instance/ClaveForte.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    placeholders = ', '.join(['?'] * len(correos_a_ignorar))
    cur.execute(f"""SELECT * FROM Users WHERE usr_mail NOT IN ({placeholders})""",
                correos_a_ignorar)
    usuarios = cur.fetchall()
    conn.close()

    return render_template('./admin/management/management.html',
                           usr_rol=rol,
                           users=usuarios)

@app.route('/recent_actions')
def acciones_recientes():
    active_rol = session.get('usuario_rol')
    rcnt_act = []

    try:
        conn = sqlite3.connect('instance/ClaveForte.db')
        conn.row_factory = sqlite3.Row  # Permite acceder a columnas por nombre
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM Access
        ''')
        rcnt_act = cursor.fetchall()

    except Exception as e:
        print(f"Error al recuperar acciones recientes: {e}")

    finally:
        conn.close()

    return render_template('./admin/recent/recent.html',
                           usr_rol=active_rol,
                           recent_acctions=rcnt_act)


# ------- Aplicación General -------
if __name__ == '__main__':
    db_path = 'instance/ClaveForte.db'
    if not os.path.exists(db_path):
        init_db(db_path)

    # --- Aplicación ------------------
    app.run(debug=True)