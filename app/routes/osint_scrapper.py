from flask import (
	Blueprint,
	render_template,
	jsonify,
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
			session["osint"] = [domain_name, option_list]
			
			osint_result = osint_scrape(domain_name)
			return redirect(url_for("osint_scrapper.output"))
	return render_template("osint_input.html")


@osint_scrapper.route("/output", methods=["GET"])
def output():
	domain_name = session["domain_name"]
	return render_template("osint_output.html", domain_name=domain_name)
