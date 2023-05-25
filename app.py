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


def get_abstracts(medline):
    ab, abstract, abstract_list = False, "", []
    for line in medline.splitlines():
        if line.startswith("AB"):
            ab = True
            abstract += line[6:]
        elif ab and line.startswith("      "):
            abstract += line[6:]
        elif ab:
            abstract_list.append(abstract)
            ab, abstract = False, ""
        else:
            continue
    return abstract_list


query = input("Search query: ")
esearch_params = {"db": "pubmed", "term": query, "retmax": "5", "retmode": "json", "sort": "relevance"}
esearch = requests.get("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi", params=esearch_params)
pmids = ','.join(esearch.json()['esearchresult']['idlist'])
print("===========================")
print(pmids)

efetch_params = {"db": "pubmed", "id": pmids, "rettype": "medline", "retmode": "text"}
efetch = requests.get("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi", params=efetch_params)
abstracts = get_abstracts(efetch.text)
print(abstracts)
print("===========================")
