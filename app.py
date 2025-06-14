
import os
import json
import sqlite3
from datetime import datetime
from flask import Flask,render_template,redirect,url_for,request,session,flash

from models import init_db

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# ------- Autentificación -------
@app.route('/')
def index():
    return redirect(url_for('/auth/login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        correo     = request.form['email']
        contraseña = request.form['password']

        conexion = sqlite3.connect('instance/ClaveForte.db')
        cursor = conexion.cursor()
        cursor.execute("SELECT id_usr, usr_name, usr_pass FROM Users WHERE usr_mail = ?", (correo,))
        usuario = cursor.fetchone()
        conexion.close()

        if usuario:
            id_usr, usr_name, usr_pass = usuario
            if usr_pass == contraseña:
                # session: utiliza coockies para guardar la info del usuario
                session['usuario_id'] = id_usr
                session['usuario_nombre'] = usr_name
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
        email    = request.form['email']
        password = request.form['password']
        secret   = request.form['password']
        created  = str(datetime.now())
        rol      = request.form['rol']

        # Guardar en la base de datos
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

# ------- Pagina de Inicio -------
@app.route('/home')
def home():
    return render_template('/home/home.html')

# ------- Credenciales -------
@app.route('/credentials')
def credenciales():
    usuario_id = session.get('usuario_id')

    conn = sqlite3.connect('instance/ClaveForte.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Obtener todas las credenciales que tengan algún valor en users_allows
    cur.execute("SELECT * FROM Credentials WHERE id_usr = ? OR users_allows IS NOT NULL", (usuario_id,))
    todas = cur.fetchall()
    conn.close()

    # Filtrar en Python las que pertenecen al usuario o le fueron compartidas
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
                continue  # evitar errores si el JSON está mal formado o vacío

    return render_template('/credentials/credentials.html', credenciales=credenciales, usuario_actual=usuario_id)

@app.route('/add_credential', methods=['GET','POST'])
def agregar_credencial():
    id_usr = session.get('usuario_id')
    service_name  = request.form['servicio']
    service_pass  = request.form['contrasena']
    users_allows  = json.dumps([])
    name_owner    = session.get('usuario_nombre')

    conn = sqlite3.connect('instance/ClaveForte.db')
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO Credentials (service_name, service_pass, users_allows, name_owner, id_usr)
        VALUES (?, ?, ?, ?, ?)
    """, (service_name, service_pass, users_allows,name_owner, id_usr))
    conn.commit()
    conn.close()

    return redirect('/credentials')

@app.route('/share_credential', methods=['GET','POST'])
def compartir_credencial():
    id_owner = session['usuario_id']
    id_credencial = request.form.get('id_credential')
    correo_nuevo_usuario = request.form.get('emal2')
    clave_secundaria = request.form.get('pass_sct')

    # Verificar que el nuevo usuario existe por correo
    conn = sqlite3.connect('instance/ClaveForte.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id_usr FROM Users WHERE usr_mail = ?", (correo_nuevo_usuario,))
    nuevo_usuario = cur.fetchone()

    if not nuevo_usuario:
        flash("El correo del usuario al que deseas compartir no existe.")
        conn.close()
        return redirect('/credentials')

    nuevo_usuario_id = nuevo_usuario['id_usr']

    # Verificar que el usuario actual sea el dueño y que su contraseña secundaria coincida
    cur.execute("SELECT * FROM Users WHERE id_usr = ?", (id_owner,))
    propietario = cur.fetchone()

    if not propietario or propietario['secret_pass'] != clave_secundaria:
        flash("Clave secundaria incorrecta.")
        conn.close()
        return redirect('/credentials')

    # Obtener la credencial y su lista de usuarios permitidos
    cur.execute("SELECT users_allows FROM Credentials WHERE id_credential = ? AND id_usr = ?", (id_credencial, id_owner))
    cred = cur.fetchone()

    if not cred:
        flash("No se encontró la credencial o no eres su propietario.")
        conn.close()
        return redirect('/credentials')

    # Convertir campo users_allows desde JSON a lista
    try:
        users_allows = json.loads(cred['users_allows']) if cred['users_allows'] else []
    except json.JSONDecodeError:
        users_allows = []

    # Evitar duplicados
    if nuevo_usuario_id not in users_allows:
        users_allows.append(nuevo_usuario_id)

    # Actualizar campo en la base de datos
    cur.execute(
        "UPDATE Credentials SET users_allows = ? WHERE id_credential = ?",
        (json.dumps(users_allows), id_credencial)
    )

    conn.commit()
    conn.close()
    flash("Credencial compartida exitosamente.")
    return redirect('/credentials')

# ------- Aplicación General -------
if __name__ == '__main__':
    # --- Crea la bd si no existe -----
    db_path = 'instance/ClaveForte.db'
    if not os.path.exists(db_path):
        init_db(db_path)

    # --- Aplicación ------------------
    app.run(debug=True)