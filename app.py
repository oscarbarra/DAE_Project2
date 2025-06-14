from flask import Flask, render_template, redirect, url_for, request, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'clave_super_secreta_123'

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/mis-credenciales')
def mis_credenciales():
    usuario_id = session.get('usuario_id')
    if not usuario_id:
        return redirect(url_for('login'))

    conn = sqlite3.connect('instance/database.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM credenciales WHERE usuario_id = ?", (usuario_id,))
    credenciales = cur.fetchall()
    conn.close()

    return render_template('mis_credenciales.html', credenciales=credenciales)

if __name__ == '__main__':
    app.run(debug=True)
