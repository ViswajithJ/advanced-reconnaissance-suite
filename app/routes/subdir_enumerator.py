from flask import (
	Blueprint,
	render_template,
	session,
	request,
	redirect,
	url_for,
)

from app.logic.subdir_enumerator.subdir_enumerator import subdir_enum


subdir_enumerator = Blueprint(
	"subdir_enumerator",
	__name__,
	template_folder="app/templates",
	static_folder="app/static",
)

@subdir_enumerator.route("/input", methods=["GET", "POST"])
def input():
	if request.method == "POST":
		if request.form.get("Submit") == "START ENUMERATION":
			domain_name = request.form.get("domain_name").strip().lower()
			wordlist_size = request.form.get("wordlist_size").strip().lower()
			# change to subdir function, and its parameters
			####
			# domain_name = "google.com"
			# wordlist_size = "small".strip().lower()
			subdir_result = subdir_enum(domain_name, wordlist_size)
			session["subdir_result"] = subdir_result
			print(subdir_result)
			return redirect(url_for("subdir_enumerator.output"))
	return render_template("subdir_input.html")


@subdir_enumerator.route("/output", methods=["GET"])
def output():
	subdir_result = session["subdir_result"]
	return render_template("subdir_output.html", subdir_result=subdir_result)
