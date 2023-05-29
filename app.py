from flask import Flask, render_template, request, redirect, session
from flask_session import Session
import requests
import os
import openai

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

openai.apikey = os.getenv("OPENAI_API_KEY")


@app.route("/", methods=["POST", "GET"])
def search():
    if request.method == "POST":
        query = request.form["query"]  # get search query from search bar
        session["query"] = query
        pmids = get_pmids(query)  # get pmids from search query
        session["pmids"] = pmids
        titles = get_titles(pmids)
        session["titles"] = titles
        abstracts = get_abstracts(pmids)  # get abstracts from pmids
        session["abstracts"] = abstracts
        summary = get_summary(abstracts)  # get summary from abstracts
        session["result"] = summary
        return redirect("/results")
    return render_template("search.html")


@app.route("/recents")
def recents():
    return render_template("recents.html")


@app.route("/favorites")
def favorites():
    return render_template("favorites.html")


@app.route("/results", methods=["POST", "GET"])
def results():
    query = session["query"]  # query is the same regardless of level of detail
    pmids = session["pmids"] # pmids are the same regardless of level of detail
    titles = session["titles"] # titles are the same regardless of level of detail
    print(pmids)
    pmid_list = pmids.split(",")
    if request.method == "POST":
        detail = 1 if "increase" in request.form else -1
        summary = get_summary(session["abstracts"], detail)
        session["result"] = summary  # update session variable
        return render_template("results.html", query=query, result=summary, pmids=pmid_list, titles=titles)
    result = session["result"]
    return render_template("results.html", query=query, result=result, pmids=pmid_list, titles=titles)


def parse_abstracts(medline):
    ab, tmp, abstracts = False, "", ""
    for line in medline.splitlines():
        if line.startswith("AB"):  # reached the start of the abstract
            ab = True
            tmp += line[6:]
        elif ab and line.startswith("      "):  # in the middle of the abstract
            tmp += line[6:]
        elif ab:  # reached the end of the abstract
            abstracts += ("#####" + tmp)
            ab, tmp = False, ""
        else:  # haven't found start of next abstract yet
            continue
    return abstracts


def get_pmids(query):
    esearch_params = {"db": "pubmed", "term": query, "retmax": "3", "retmode": "json", "sort": "relevance"}
    esearch = requests.get(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi", params=esearch_params)
    return ','.join(esearch.json()["esearchresult"]["idlist"])


def get_titles(pmids):
    esummary_params = {"db" : "pubmed", "id": pmids, "retmode" : "json"}
    esummary = requests.get("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi", params=esummary_params).json()
    titles = {}
    for pmid in pmids.split(","):
        titles[pmid] = esummary["result"][pmid]["title"].rstrip(".")
    return titles


def get_abstracts(pmids):
    efetch_params = {"db" : "pubmed", "id" : pmids, "rettype" : "medline", "retmode" : "text"}
    efetch = requests.get(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi", params=efetch_params)
    return parse_abstracts(efetch.text)


def get_summary(abstracts, detail=0):
    if detail == 0:
        prompt = """Your job is to synthesize the key pieces of information from the following research paper abstracts into one coherent summary that is comprehensible to the 
        average person. Each abstract you are being given starts with #####. Use this to help you isolate the topics of each abstract to create a more intelligible summary. Your 
        summary should be around 10 sentences long: """
    elif detail == 1:
        summary = session["result"]
        prompt = f"""Your job is to synthesize the key pieces of information from the following research paper abstracts into one coherent summary that is comprehensible to the 
        average person. The summary you gave last time was: "{summary}" Use details from the following abstracts to create a new summary with an increased level of detail and 
        technicality. Your #1 priority is to make your response at least 20% longer than your last summary in terms of characters used. Each abstract begins with #####: """
    else:
        summary = session["result"]
        prompt = f"""Your job is to synthesize the key pieces of information from the following research paper abstracts into one coherent summary that is comprehensible to the 
        average person. The summary you gave last time was: "{summary}" Use the following abstracts to create a new, more generalized summary with a decreased level of detail and 
        shorter response length compared to last time. Each abstract begins with #####: """

    gpt_response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {
                "role" : "assistant",
                "content" : prompt + abstracts
            }
        ]
    )
    return gpt_response["choices"][0]["message"]["content"]


if __name__ == "__main__":
    app.run(debug=True)
