from flask import Flask, render_template

app = Flask(__name__, template_folder="app/templates") # templates inside /app/ . so mention explicitly


@app.route("/")
def index():
	return render_template("index.html")

if __name__=="__main__":
	app.run(debug=True)