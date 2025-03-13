from flask import (
    Blueprint,
    render_template,
    session,
    request,
    redirect,
    url_for,
)
from app.logic.vuln_checker.vuln_checker import vuln_check

vuln_checker = Blueprint(
    "vuln_checker",
    __name__,
    template_folder="app/templates",
    static_folder="app/static",
)  # vuln_checker: name of blueprint; __name__: import name of blueprint's module


@vuln_checker.route("/input", methods=["GET", "POST"])
def input():
    if request.method == "POST":
        if request.form.get("Submit") == "Submit":
            domain_name = request.form.get("domain_name")
            option_list = request.form.getlist("option")

            vuln_result = vuln_check(domain_name, option_list)
            session["vuln_option_list"] = option_list
            session["vuln_result"] = vuln_result

            return redirect(url_for("vuln_checker.output"))
    return render_template("vuln_input.html")


@vuln_checker.route("/output", methods=["GET"])
def output():
    vuln_result = session["vuln_result"]
    return render_template("vuln_output.html", vuln_result=vuln_result)
