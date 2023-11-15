import sys
import subprocess

subprocess.check_call([sys.executable, "-m", "pip", "install", "flask"])

import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Inicializar la base de datos
conn = sqlite3.connect("database.db")
c = conn.cursor()
c.execute("""CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)""")
c.execute("""INSERT INTO users VALUES ('admin', 'secret_flag_here')""")
conn.commit()
conn.close()


@app.route("/")
def home():
    return "Bienvenido al desafío de Privacidad de Datos CTF!"


@app.route("/login", methods=["GET"])
def login():
    username = request.args.get("username")
    password = request.args.get("password")

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    query = (
        f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    )

    c.execute(query)
    result = c.fetchone()

    if result:
        return f"¡Ingresaste! La bandera es {result[1]}"
    else:
        return "Falló el inicio de sesión"


if __name__ == "__main__":
    app.run(debug=True)
