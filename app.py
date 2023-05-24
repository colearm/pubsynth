from flask import Flask, render_template, request
import requests

app = Flask(__name__)


@app.route("/")
def search():
    return render_template("search.html")


@app.route("/recents")
def recents():
    return render_template("recents.html")


@app.route("/favorites")
def favorites():
    return render_template("favorites.html")


@app.route("/results", methods=["GET"])
def results():
    return render_template("results.html")


response = requests.get(
    "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?term=does+deodorant+cause+breast+cancer&retmax=5&retmode=json&sort=relevance")
pmids = response.json()['esearchresult']['idlist']
print(pmids)
