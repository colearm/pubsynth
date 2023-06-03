from flask import Flask, render_template, request, redirect, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import requests
import os
import openai
import pdfkit


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.getenv('PS_SECRET_KEY')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
openai.apikey = os.getenv("OPENAI_API_KEY")


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader # loads users object from the user id stored in the session
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"}) # different than pass length in db b/c pass will be hashed
    submit = SubmitField("Register")
    def validate_username(self, username): # check for duplicate username in db
        existing_user = Users.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("That username is already taken.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"}) # different than pass length in db b/c pass will be hashed
    submit = SubmitField("Login")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pass = bcrypt.generate_password_hash(form.password.data)
        new_user = Users(username=form.username.data, password=hashed_pass)
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect("/")
    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect("/login")


@app.route("/", methods=["GET", "POST"])
@login_required
def search():
    if request.method == "POST":
        search_query = request.form["query"]  # get search query from search bar
        session["search_query"] = search_query
        pmids = get_pmids(search_query)  # get pmids from search query
        session["pmids"] = pmids
        titles = get_titles(pmids) # get titles from pmids
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


@app.route("/results", methods=["GET", "POST"])
def results():
    search_query = session["search_query"]  # query is the same regardless of level of detail
    pmids = session["pmids"] # pmids are the same regardless of level of detail
    titles = session["titles"] # titles are the same regardless of level of detail
    pmid_list = pmids.split(",")
    if request.method == "POST":
        detail = 1 if "increase" in request.form else -1
        summary = get_summary(session["abstracts"], detail)
        session["result"] = summary  # update session variable
        return render_template("results.html", query=search_query, result=summary, pmids=pmid_list, titles=titles)
    result = session["result"]
    return render_template("results.html", query=search_query, result=result, pmids=pmid_list, titles=titles)


@app.route("/download")
def download_pdf():
    pdf = generate_pdf()
    response = Response(pdf)
    search_query = session["search_query"]
    response.headers["Content-Disposition"] = f"attachment; filename={search_query}.pdf"
    response.mimetype = "application/pdf"
    return response


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


def get_pmids(search_query):
    esearch_params = {"db": "pubmed", "term": search_query, "retmax": "3", "retmode": "json", "sort": "relevance"}
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


def generate_pdf():
    render = render_template("download.html", pmids=session["pmids"].split(","), query=session["search_query"], result=session["result"])
    options = {
        'page-size': 'Letter',
        'margin-top': '0.75in',
        'margin-right': '0.75in',
        'margin-bottom': '0.75in',
        'margin-left': '0.75in',
        'encoding': "UTF-8",
    }
    pdf = pdfkit.from_string(render, False, options=options)
    return pdf


if __name__ == "__main__":
    app.run(debug=True)
