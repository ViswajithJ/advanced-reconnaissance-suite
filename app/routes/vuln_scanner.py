from flask import (
    Blueprint,
    render_template,
    session,
    request,
    redirect,
    url_for,
)
from app.logic.vuln_scanner.vuln_scanner import vuln_scan

vuln_scanner = Blueprint(
    "vuln_scanner",
    __name__,
    template_folder="app/templates",
    static_folder="app/static",
)  # vuln_scanner: name of blueprint; __name__: import name of blueprint's module


@vuln_scanner.route("/input", methods=["GET", "POST"])
def input():
    if request.method == "POST":
        if request.form.get("Submit") == "Submit":
            domain_name = request.form.get("domain_name")
            option_list = request.form.getlist("option")

            vuln_result = vuln_scan(domain_name, option_list)
            session["vuln_option_list"] = option_list
            session["vuln_result"] = vuln_result

            return redirect(url_for("vuln_scanner.output"))
    return render_template("vuln_input.html")


@vuln_scanner.route("/output", methods=["GET"])
def output():
    vuln_result = session["vuln_result"]
    return render_template("vuln_output.html", vuln_result=vuln_result)
