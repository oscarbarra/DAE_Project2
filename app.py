
import os
import json
import sqlite3
from datetime import datetime
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, redirect, url_for, request, session, flash

from models import init_db

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')


# ========== AUTENTICACIÓN ==========

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        correo = request.form['email']
        contraseña = request.form['password']

        conexion = sqlite3.connect('instance/ClaveForte.db')
        cursor = conexion.cursor()
        cursor.execute("SELECT id_usr, usr_name, usr_mail, usr_pass, id_rol FROM Users WHERE usr_mail = ?", (correo,))
        usuario = cursor.fetchone()
        conexion.close()

        if usuario:
            id_usr, usr_name, usr_mail, usr_pass, id_rol = usuario
            if check_password_hash(usr_pass, contraseña):
                session['usuario_id'] = id_usr
                session['usuario_nombre'] = usr_name
                session['usuario_correo'] = usr_mail
                session['usuario_rol'] = id_rol
                return redirect(url_for('home'))
            else:
                flash("Contraseña incorrecta")
        else:
            flash("Correo no registrado")
    return render_template('/auth/login.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password_plano = request.form['password']
        password = generate_password_hash(password_plano)
        secret = generate_password_hash(password_plano)
        created = str(datetime.now())
        rol = request.form['rol']

        conexion = sqlite3.connect('instance/ClaveForte.db')
        cursor = conexion.cursor()
        cursor.execute("""
            INSERT INTO Users (usr_name, usr_mail, usr_pass, secret_pass, last_login, id_rol)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, email, password, secret, created , rol))
        conexion.commit()
        conexion.close()

        return redirect(url_for('login'))
    return render_template('/auth/signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# ========== HOME Y PERFIL ==========

@app.route('/home')
def home():
    if not session:
        return redirect("login")
    rol = session.get('usuario_rol')
    return render_template('/home/home.html', usr_rol=rol)

@app.route('/perfil', methods=['GET', 'POST'])
def perfil():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

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

    cur.execute("SELECT usr_name, usr_mail FROM Users WHERE id_usr = ?", (usuario_id,))
    datos = cur.fetchone()
    conn.close()
    return render_template('./perfil/perfil.html', usuario=datos)

@app.route('/eliminar_cuenta', methods=['POST'])
def eliminar_cuenta():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    conn = sqlite3.connect('instance/ClaveForte.db')
    cur = conn.cursor()
    cur.execute("DELETE FROM Credentials WHERE id_usr = ?", (usuario_id,))
    cur.execute("DELETE FROM Users WHERE id_usr = ?", (usuario_id,))
    conn.commit()
    conn.close()

    session.clear()
    flash("Cuenta eliminada correctamente.")
    return redirect(url_for('signup'))


# ========== CREDENCIALES (USUARIOS) ==========

@app.route('/credentials')
def credenciales():
    if not session:
        return redirect("login")

    usuario_id = session.get('usuario_id')
    rol = session.get('usuario_rol')

    conn = sqlite3.connect('instance/ClaveForte.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM Credentials WHERE id_usr = ? OR users_allows IS NOT NULL", (usuario_id,))
    todas = cur.fetchall()
    conn.close()

    credenciales = []
    for c in todas:
        if c['id_usr'] == usuario_id:
            credenciales.append(c)
        else:
            try:
                compartidos = json.loads(c['users_allows'])
                if isinstance(compartidos, list) and usuario_id in compartidos:
                    credenciales.append(c)
            except (json.JSONDecodeError, TypeError):
                continue
    return render_template('/credentials/credentials.html',
                           credenciales=credenciales,
                           usuario_actual=usuario_id,
                           usr_rol=rol)

@app.route('/add_credential', methods=['GET','POST'])
def agregar_credencial():
    if not session:
        return redirect("login")
    if request.method == 'POST':
        id_usr = session.get('usuario_id')
        service_name = request.form['servicio']
        service_pass = request.form['contrasena']
        users_allows = json.dumps([])
        name_owner = session.get('usuario_nombre')

        conn = sqlite3.connect('instance/ClaveForte.db')
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO Credentials (service_name, service_pass, users_allows, name_owner, id_usr)
            VALUES (?, ?, ?, ?, ?)
        """, (service_name, service_pass, users_allows, name_owner, id_usr))
        conn.commit()
        conn.close()
    return redirect('/credentials')

@app.route('/share_credential', methods=['GET', 'POST'])
def compartir_credencial():
    if not session:
        return redirect("login")
    if request.method == 'POST':
        id_owner = session.get('usuario_id')
        id_credencial = request.form.get('id_credential')
        correo_receptor = request.form.get('correo_receptor')
        clave_validacion = request.form.get('pass_validacion')

        if not id_owner or not id_credencial or not correo_receptor or not clave_validacion:
            flash("Faltan campos obligatorios.", "danger")
            return redirect(url_for('compartir_credencial'))

        try:
            with sqlite3.connect('instance/ClaveForte.db') as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()

                cur.execute("SELECT id_usr FROM Users WHERE usr_mail = ?", (correo_receptor,))
                receptor = cur.fetchone()
                if not receptor:
                    flash("El correo del receptor no está registrado.", "danger")
                    return redirect(url_for('compartir_credencial'))

                id_receptor = receptor['id_usr']

                cur.execute("SELECT secret_pass FROM Users WHERE id_usr = ?", (id_owner,))
                propietario = cur.fetchone()
                if not propietario or not check_password_hash(propietario['secret_pass'], clave_validacion):
                    flash("Clave secundaria incorrecta.", "danger")
                    return redirect(url_for('compartir_credencial'))

                cur.execute(
                    "SELECT users_allows FROM Credentials WHERE id_credential = ? AND id_usr = ?",
                    (id_credencial, id_owner)
                )
                credencial = cur.fetchone()
                if not credencial:
                    flash("No se encontró la credencial o no eres su propietario.", "danger")
                    return redirect(url_for('compartir_credencial'))

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

            flash("Credencial compartida exitosamente.", "success")
            return redirect(url_for('compartir_credencial'))

        except sqlite3.Error as e:
            flash(f"Error en la base de datos: {str(e)}", "danger")
            return redirect(url_for('compartir_credencial'))

    usuario_id = session.get('usuario_id')
    rol = session.get('usuario_rol')
    conn = sqlite3.connect('instance/ClaveForte.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM Credentials WHERE id_usr = ?", (usuario_id,))
    credenciales = cur.fetchall()
    conn.close()

    return render_template('./credentials/compartir/compartir.html',
                           credenciales=credenciales,
                           usuario_actual=usuario_id,
                           usr_rol=rol)


# ========== ADMINISTRADOR ==========

@app.route('/user_management', methods=['GET', 'POST'])
def gestionar_usuarios():
    if not session:
        return redirect("login")

    if request.method == "POST":
        method = request.form.get('_method')
        if method == 'DELETE':
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


# ========== EJECUCIÓN ==========
if __name__ == '__main__':
    db_path = 'instance/ClaveForte.db'
    if not os.path.exists(db_path):
        init_db(db_path)

    app.run(debug=True)
