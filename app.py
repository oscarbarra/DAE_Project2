from flask import Flask,render_template,redirect,url_for,request,session,flash
import sqlite3
import os
from datetime import datetime
from models import init_db
from dotenv import load_dotenv

load_dotenv()  # Carga las variables del archivo .env

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

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

@app.route('/home')
def home():
    return render_template('/home/home.html')

@app.route('/credentials')
def credentials():
    usuario_id = session.get('usuario_id')

    conn = sqlite3.connect('instance/ClaveForte.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM Credentials WHERE id_usr = ?", (usuario_id,))
    credenciales = cur.fetchall()
    conn.close()

    return render_template('/credentials/credentials.html', credenciales=credenciales)

@app.route('/share_credential')
def share():
    return render_template('/share_credential/share.html')

if __name__ == '__main__':
    # --- Crea la bd si no existe -----
    db_path = 'instance/ClaveForte.db'
    if not os.path.exists(db_path):
        init_db(db_path)

    # --- Aplicación ------------------
    app.run(debug=True)

@app.route('/agregar-credencial', methods=['POST'])
def agregar_credencial():
    usuario_id = session.get('usuario_id')
    if not usuario_id:
        return redirect('/login')

    servicio = request.form['servicio']
    usuario = request.form['usuario']
    contrasena = request.form['contrasena']

    conn = sqlite3.connect('instance/database.db')
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO credenciales (usuario_id, servicio, usuario, contrasena)
        VALUES (?, ?, ?, ?)
    """, (usuario_id, servicio, usuario, contrasena))
    conn.commit()
    conn.close()

    return redirect('/mis-credenciales')

