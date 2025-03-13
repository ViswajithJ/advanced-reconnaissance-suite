from flask import (
    Blueprint,
    render_template,
    session,
    request,
    redirect,
    url_for,
)
from app.logic.osint_scrapper.osint_scrapper import osint_scrape

osint_scrapper = Blueprint(
    "osint_scrapper",
    __name__,
    template_folder="app/templates",
    static_folder="app/static",
)  # osint_scrapper: name of blueprint; __name__: import name of blueprint's module


@osint_scrapper.route("/input", methods=["GET", "POST"])
def input():
    if request.method == "POST":
        if request.form.get("Submit") == "Submit":
            domain_name = request.form.get("domain_name")
            option_list = request.form.getlist("option")

            osint_result = osint_scrape(domain_name, option_list)
            session["osint_option_list"] = option_list
            session["osint_result"] = osint_result

            return redirect(url_for("osint_scrapper.output"))
    return render_template("osint_input.html")


@osint_scrapper.route("/output", methods=["GET"])
def output():
    osint_result = session["osint_result"]
    return render_template("osint_output.html", osint_result=osint_result)
