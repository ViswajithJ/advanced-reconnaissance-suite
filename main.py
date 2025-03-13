from flask import Flask, render_template, session
from app.routes import osint_scrapper, subdir_enumerator, subdom_enumerator, vuln_checker
app = Flask(
    __name__, template_folder="app/templates", static_folder="app/static"
)  # templates inside /app/ . so mention explicitly

app.secret_key = "demo_key_hehe"

app.register_blueprint(osint_scrapper.osint_scrapper, url_prefix="/osint_scrapper")
app.register_blueprint(subdir_enumerator.subdir_enumerator, url_prefix="/subdir_enumerator")
app.register_blueprint(subdom_enumerator.subdom_enumerator, url_prefix="/subdom_enumerator")
app.register_blueprint(vuln_checker.vuln_checker, url_prefix="/vuln_checker")

## note to future self: set secret key before registering blueprints (for sessions)
@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)
