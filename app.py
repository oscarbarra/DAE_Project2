from flask import Flask, render_template, redirect, url_for, request, session
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form["usuario"]
        contraseña = request.form["contraseña"]

        # Aquí validas con tus datos reales
        if usuario == "admin" and contraseña == "123":
            session["usuario"] = usuario
            return redirect(url_for("index"))
        else:
            return render_template("login.html", error="Credenciales incorrectas")

    return render_template("login.html")

@app.route("/home")
def Home():
    return render_template("./home/page.html")

if __name__ == "__main__":
    # en paralelo ejecutar:
    # npx tailwindcss -i ./input.css -o ./static/css/style.css --watch
    app.run(debug=True, host="0.0.0.0")

    print(app.secret_key)