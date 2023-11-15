import sys
import subprocess

subprocess.check_call([sys.executable, "-m", "pip", "install", "flask"])

from flask import Flask, request, render_template_string, redirect, url_for, session
import sqlite3
import random

app = Flask(__name__)
app.secret_key = "una_clave_secreta_muy_segura"  # Necesario para usar sesiones

# Inicializar la base de datos
conn = sqlite3.connect("database.db")
c = conn.cursor()
c.execute(
    """CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, access_code TEXT)"""
)
c.execute(
    """INSERT INTO users VALUES ('admin', 'complex_password', '123456')"""
)  # Código de acceso inicial
conn.commit()
conn.close()


# Generar un código de acceso aleatorio
def generate_access_code():
    return str(random.randint(100000, 999999))


@app.route("/")
def home():
    home_page = """
    <html>
        <head><title>Inicio CTF de Privacidad de Datos</title></head>
        <body>
            <h1>Bienvenido al desafío de Privacidad de Datos CTF!</h1>
            <a href="/login_page">Ir a la página de Login</a>
        </body>
    </html>
    """
    return render_template_string(home_page)


@app.route("/login_page")
def login_page():
    login_page = """
    <html>
        <head><title>Login</title></head>
        <body>
            <h2>Login</h2>
            <form action="/login" method="get">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Submit">
            </form>
        </body>
    </html>
    """
    return render_template_string(login_page)


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
        new_code = generate_access_code()
        c.execute(
            f"UPDATE users SET access_code = '{new_code}' WHERE username = '{username}'"
        )
        conn.commit()

        # Guardar el nombre de usuario en la sesión para usarlo en la validación del código 2FA
        session["username"] = username
        return redirect(url_for("validate_2fa_page"))
    else:
        return "Falló el inicio de sesión"


@app.route("/validate_2fa_page")
def validate_2fa_page():
    validate_2fa_page = """
    <html>
        <head><title>Validación 2FA</title></head>
        <body>
            <h2>Validación 2FA</h2>
            <form action="/validate_code" method="get">
                Código de Acceso: <input type="text" name="access_code"><br>
                <input type="submit" value="Submit">
            </form>
        </body>
    </html>
    """
    return render_template_string(validate_2fa_page)


@app.route("/validate_code", methods=["GET"])
def validate_code():
    access_code = request.args.get("access_code")
    username = session.get("username")

    if not username:
        return "Sesión no iniciada o expirada."

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    # Vulnerabilidad de inyección SQL en la siguiente línea
    query = f"SELECT * FROM users WHERE username = '{username}' AND access_code = '{access_code}'"

    c.execute(query)
    result = c.fetchone()

    if result:
        return f"Validación exitosa. La bandera es {result[1]}"
    else:
        return "Validación fallida."


if __name__ == "__main__":
    app.run(debug=True)
