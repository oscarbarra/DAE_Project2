
import os
from models import init_db
from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return redirect(url_for('/auth/login'))

@app.route('/login')
def login():
    return render_template('/auth/login.html')

@app.route('/signup')
def signup():
    return render_template('/auth/signup.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    # --- Crea la bd si no existe -----
    db_path = 'instance/ClaveForte.db'
    if not os.path.exists(db_path):
        init_db(db_path)

    # --- Aplicación ------------------
    app.run(debug=True)
