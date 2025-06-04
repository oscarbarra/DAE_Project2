
from flask import Flask, render_template

app = Flask(__name__)

@app.route("/home")
def Home():
    return render_template("./home/page.html")

if __name__ == "__main__":
    # en paralelo ejecutar:
    # npx tailwindcss -i ./input.css -o ./static/css/style.css --watch
    app.run(debug=True, host="0.0.0.0")