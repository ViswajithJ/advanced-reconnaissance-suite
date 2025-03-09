from flask import Flask, render_template, session
from app.routes import osint_scrapper
app = Flask(
    __name__, template_folder="app/templates", static_folder="app/static"
)  # templates inside /app/ . so mention explicitly

app.secret_key = "demo_key_hehe"

app.register_blueprint(osint_scrapper.osint_scrapper, url_prefix="/osint_scrapper")
## note to future self: set secret key before registering blueprints (for sessions)
@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
