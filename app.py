from flask import Flask, render_template, request
import requests
import os
import openai

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


query = input("Search query: ")  # simulating search bar entry for now

if query == "":
    exit()


esearch_params = {"db": "pubmed", "term": query, "retmax": "3", "retmode": "json", "sort": "relevance"}
esearch = requests.get("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi", params=esearch_params)
pmids = ','.join(esearch.json()['esearchresult']['idlist'])
print("===========================")
# print(pmids)
# print("===========================")


efetch_params = {"db": "pubmed", "id": pmids, "rettype": "medline", "retmode": "text"}
efetch = requests.get("https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi", params=efetch_params)
abstracts = get_abstracts(efetch.text)
# print(abstracts)
# print("===========================")


openai.apikey = os.getenv("OPENAI_API_KEY")

prompt = """Synthesize the key pieces of information from the following research paper abstracts into one coherent summary that is comprehensible to the average person. 
Each abstract you are being given starts with #####. Use this to help you isolate the topics of each abstract to create a more intelligible summary.
Your summary shold be around 10 sentences long: """
"""
gpt_response = openai.ChatCompletion.create(
    model="gpt-3.5-turbo",
    messages=[
        {
            "role": "assistant",
            "content": prompt + abstracts
        }
    ]
)
result = gpt_response["choices"][0]["message"]["content"]
print(result)
print("===========================")
"""
