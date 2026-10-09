from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ShieldAI Demo Target</title>
    </head>
    <body>
        <h1>ShieldAI Local Demo Target</h1>

        <p>
            This application is intentionally provided
            for authorized local security testing.
        </p>

        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>

        <br>

        <a href="/about">About</a>
    </body>
    </html>
    """


@app.route("/about")
def about():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>About</title>
    </head>
    <body>
        <h1>About ShieldAI Demo Target</h1>
        <p>This is a local testing application.</p>
    </body>
    </html>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    return """
    <!DOCTYPE html>
    <html>
    <body>
        <h1>Demo Login</h1>
        <p>This is a local demonstration endpoint.</p>
    </body>
    </html>
    """


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True
    )