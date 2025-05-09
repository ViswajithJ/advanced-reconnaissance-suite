from flask import (
    Blueprint,
    render_template,
    session,
    request,
    redirect,
    url_for,
)
import time

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
            start_time = time.time()
            subdir_result = subdir_enum(domain_name, wordlist_size)
            end_time = time.time()
            scan_time = end_time - start_time
            print(round(scan_time))
            session["subdir_result"] = subdir_result
            session["domain_name"] = domain_name
            session["subdir_scan_time"] = round(scan_time)
            print(subdir_result)
            return redirect(url_for("subdir_enumerator.output"))
    return render_template("subdir_input.html")


@subdir_enumerator.route("/output", methods=["GET"])
def output():
    subdir_result = session["subdir_result"]
    domain_name = session["domain_name"]
    scan_time = session["subdir_scan_time"]
    return render_template(
        "subdir_output.html",
        subdir_result=subdir_result,
        domain_name=domain_name,
        scan_time=scan_time,
    )
