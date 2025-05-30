from flask import (
    Blueprint,
    render_template,
    session,
    request,
    redirect,
    url_for,
)
import time

from app.logic.subdom_enumerator.subdom_enumerator import subdom_enum


subdom_enumerator = Blueprint(
    "subdom_enumerator",
    __name__,
    template_folder="app/templates",
    static_folder="app/static",
)


@subdom_enumerator.route("/input", methods=["GET", "POST"])
def input():
    if request.method == "POST":
        if request.form.get("Submit") == "START ENUMERATION":
            domain_name = request.form.get("domain_name").strip().lower()
            wordlist_size = request.form.get("wordlist_size").strip().lower()

            # change to subdom function, and its parameters
            start_time = time.time()
            subdom_result = subdom_enum(domain_name, wordlist_size)
            end_time = time.time()
            scan_time = end_time - start_time
            print(round(scan_time))
            session["subdom_result"] = subdom_result
            session["domain_name"] = domain_name
            session["subdom_scan_time"] = round(scan_time)
            print(subdom_result)
            return redirect(url_for("subdom_enumerator.output"))
    return render_template("subdom_input.html")


@subdom_enumerator.route("/output", methods=["GET"])
def output():
    subdom_result = session["subdom_result"]
    domain_name = session["domain_name"]
    scan_time = session["subdom_scan_time"]
    return render_template(
        "subdom_output.html",
        subdom_result=subdom_result,
        domain_name=domain_name,
        scan_time=scan_time,
    )
