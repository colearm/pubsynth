from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def search():
    return render_template('search.html')


@app.route("/recents")
def recents():
    return render_template('recents.html')


@app.route("/favorites")
def favorites():
    return render_template('favorites.html')


@app.route("/results")
def results():
    return render_template('results.html')
