from flask import Flask, render_template, request, redirect, session, Response, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from wtforms import EmailField, StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Email, EqualTo
from datetime import timedelta
from time import time
from retrying import retry
import jwt
import requests
import os
import openai
import pdfkit


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_CONNECTION_STRING')
app.config['SECRET_KEY'] = os.getenv('PS_SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
app.json_provider_class.compact = False
db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
openai.apikey = os.getenv("OPENAI_API_KEY")


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to view this page."
login_manager.login_message_category = "danger"


@login_manager.user_loader  # loads users object from the user id stored in the session
def load_user(user_id):
    return db.session.get(Users, user_id)


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    results = db.relationship('Results', backref='users')

    def generate_token(self, expiration=600):  # reset link is valid for 10 minutes
        return jwt.encode(
            {"user_id": self.id, "exp": time() + expiration},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )

    @staticmethod
    def verify_token(token):
        try:
            user_id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[
                                 'HS256'])['user_id']
        except:
            return
        return db.session.get(Users, user_id)


class Results(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'users.id'), nullable=False, index=True)
    search_query = db.Column(db.String(500), nullable=False)
    pmids = db.Column(db.String(50), nullable=False)
    titles = db.Column(db.String(1000), nullable=False)
    abstracts = db.Column(db.String(30000), nullable=False)
    result = db.Column(db.String(10000), nullable=False)
    favorite = db.Column(db.Boolean, default=False)


class RegisterForm(FlaskForm):
    email = EmailField(validators=[InputRequired(), Length(max=100), Email(
        message="Enter a valid email address.", check_deliverability=True)], render_kw={"placeholder": "Email address"})
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={
                             "placeholder": "Password"})  # different than pass length in db b/c pass will be hashed
    submit = SubmitField("Register")

    def validate_email(self, email):  # check for duplicate email in db
        existing_email = Users.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError("That email address is already in use.")

    def validate_username(self, username):  # check for duplicate username in db
        existing_user = Users.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("That username is already in use.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={
                             "placeholder": "Password"})  # different than pass length in db b/c pass will be hashed
    remember_me = BooleanField()
    submit = SubmitField("Log in")


class ResetRequestForm(FlaskForm):
    email = EmailField(validators=[InputRequired(), Length(max=100), Email(
        message="Enter a valid email address.", check_deliverability=True)], render_kw={"placeholder": "Email address"})
    submit = SubmitField("Reset password")


class ResetPasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "New password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=4, max=20), EqualTo(
        "password", message="The passwords you entered do not match.")], render_kw={"placeholder": "Confirm new password"})
    submit = SubmitField("Reset password")


class ChangeEmailForm(FlaskForm):
    email = EmailField(validators=[InputRequired(), Length(max=100), Email(
        message="Enter a valid email address.", check_deliverability=True)], render_kw={"placeholder": "Email address"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Current password"})
    submit = SubmitField("Save changes")

    def validate_email(self, email):  # check for duplicate email in db
        existing_email = Users.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError("That email address is already in use.")


class ChangeUsernameForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Current password"})
    submit = SubmitField("Save changes")

    def validate_username(self, username):  # check for duplicate username in db
        existing_user = Users.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("That username is already in use.")


class ChangePasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Current password"})
    new_password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "New password"})
    confirm_password = PasswordField(validators=[InputRequired(), Length(min=4, max=20), EqualTo(
        "new_password", message="The passwords you entered do not match.")], render_kw={"placeholder": "Confirm new password"})
    submit = SubmitField("Save changes")


class DeleteAccountForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Current password"})
    submit = SubmitField("Delete account")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect("/")
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pass = bcrypt.generate_password_hash(form.password.data)
        new_user = Users(email=form.email.data,
                         username=form.username.data, password=hashed_pass)
        db.session.add(new_user)
        db.session.commit()
        return redirect("/login")
    if form.email.errors:
        flash(form.email.errors[0], "danger")
    elif form.username.errors:
        flash(form.username.errors[0], "danger")
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect("/")
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if form.remember_me.data:
                login_user(user, remember=True, duration=timedelta(days=14))
            else:
                login_user(user)
            return redirect("/")
        flash("Username or password is incorrect.", "danger")
        return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect("/login")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        return redirect("/")
    form = ResetRequestForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash("If the email address you entered is connected to an account, you'll receive a link to reset your password shortly.", "success")
        return render_template("request.html", form=form, success=True)
    if form.email.errors:
        flash(form.email.errors[0], "danger")
    return render_template("request.html", form=form)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect("/")
    user = Users.verify_token(token)
    if not user:
        return redirect("/reset-password")
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_pass = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_pass
        db.session.commit()
        return redirect("/login")
    if form.confirm_password.errors:
        flash(form.confirm_password.errors[0], "danger")
    return render_template("reset.html", form=form)


@app.route("/", methods=["GET", "POST"])
@retry(stop_max_attempt_number=6, wait_fixed=4000)
def search():
    if request.method == "POST":
        # get search query from search bar
        search_query = request.form["query"]
        pmids = get_pmids(search_query)  # get pmids from search query
        if not pmids:
            return render_template("error-no-matches.html"), 500
        titles = get_titles(pmids)  # get titles from pmids
        abstracts = get_abstracts(pmids)  # get abstracts from pmids
        summary = get_summary(abstracts)  # get summary from abstracts
        if not current_user.is_authenticated:
            session["search_query"] = search_query
            session["pmids"] = pmids
            session["titles"] = titles
            session["abstracts"] = abstracts
            session["result"] = summary
            return redirect("/results/guest")
        new_result = Results(user_id=current_user.id, search_query=search_query,
                             pmids=pmids, titles=titles, abstracts=abstracts, result=summary)
        db.session.add(new_result)
        db.session.commit()
        # pass variable here to indicate that add to favorites should display
        return redirect(url_for("results", result_id=new_result.id))
    return render_template("search.html")


@app.route("/recents")
@login_required
def recents():
    id_list = []
    query_list = []
    result_list = []
    rows = Results.query.filter_by(user_id=current_user.id).order_by(
        Results.id.desc()).limit(10)
    for row in rows:
        id_list.append(row.id)
        query_list.append(row.search_query)
        result_list.append(row.result)
    return render_template("recents.html", id_list=id_list, query_list=query_list, result_list=result_list)


@app.route("/favorites")
@login_required
def favorites():
    id_list = []
    query_list = []
    result_list = []
    rows = Results.query.filter_by(
        user_id=current_user.id, favorite=1).order_by(Results.id.desc()).all()
    for row in rows:
        id_list.append(row.id)
        query_list.append(row.search_query)
        result_list.append(row.result)
    return render_template("favorites.html", id_list=id_list, query_list=query_list, result_list=result_list)


@app.route("/results/guest", methods=["GET", "POST"])
def results_guest():  # use session data b/c these results won't be added to db
    if current_user.is_authenticated:
        return redirect("/")
    if not "search_query" in session:
        return render_template("error-404.html"), 404

    # search query, pmids, and titles will all be the same regardless of http method, so don't have to check session data each time
    search_query = session["search_query"]
    pmids = session["pmids"].split(",")
    titles = session["titles"].split(",")

    if request.method == "POST":
        detail = 1 if "increase" in request.form else -1  # 1 ~ increase; 2 ~ decrease
        new_summary = get_summary(
            session["abstracts"], detail, session["result"])
        session["result"] = new_summary  # update session variable
        return render_template("results.html", query=search_query, pmids=pmids, titles=titles, result=new_summary, result_id="guest")
    return render_template("results.html", query=search_query, pmids=pmids, titles=titles, result=session["result"], result_id="guest")


@app.route("/results/<result_id>", methods=["GET", "POST"])
@login_required
def results(result_id):  # use data from db b/c user is logged in
    result_row = db.session.get(Results, result_id)
    if not result_row:  # if result id doesn't exist
        return render_template("error-404.html"), 404
    # if user is trying to access a result that doesn't belong to them
    elif current_user.id != result_row.user_id:
        return render_template("error-403.html"), 403

    # search query, pmids, and titles will all be the same regardless of http method, so don't have to query db each time
    search_query = result_row.search_query
    pmids = result_row.pmids.split(",")
    titles = result_row.titles.split(",")

    if request.method == "POST":
        # toggle favorite
        if "add-favorite" in request.form:
            result_row.favorite = 1
            db.session.commit()
            return render_template("results.html", query=search_query, pmids=pmids, titles=titles, result=result_row.result, result_id=result_id, favorite=1)
        if "remove-favorite" in request.form:
            result_row.favorite = 0
            db.session.commit()
            return render_template("results.html", query=search_query, pmids=pmids, titles=titles, result=result_row.result, result_id=result_id, favorite=0)

        # adjust detail
        detail = 1 if "increase" in request.form else -1  # 1 ~ increase; 2 ~ decrease
        new_summary = get_summary(
            result_row.abstracts, detail, result_row.result)
        result_row.result = new_summary  # update result column for this row
        db.session.commit()
        return render_template("results.html", query=search_query, pmids=pmids, titles=titles, result=new_summary, result_id=result_id, favorite=result_row.favorite)
    return render_template("results.html", query=search_query, pmids=pmids, titles=titles, result=result_row.result, result_id=result_id, favorite=result_row.favorite)


@app.route("/profile/email", methods=["GET", "POST"])
@login_required
def change_email():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.password.data):
            current_user.email = form.email.data
            db.session.commit()
            flash("Your changes have been saved successfully.", "success")
            return render_template("email.html", form=form)
        flash("The password you entered is incorrect.", "danger")
    if form.email.errors:
        flash(form.email.errors[0], "danger")
    return render_template("email.html", form=form)


@app.route("/profile/username", methods=["GET", "POST"])
@login_required
def change_username():
    form = ChangeUsernameForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.password.data):
            current_user.username = form.username.data
            db.session.commit()
            flash("Your changes have been saved successfully.", "success")
            return render_template("username.html", form=form)
        flash("The password you entered is incorrect.", "danger")
    if form.username.errors:
        flash(form.username.errors[0], "danger")
    return render_template("username.html", form=form)


@app.route("/profile/password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.password.data):
            hashed_pass = bcrypt.generate_password_hash(form.new_password.data)
            current_user.password = hashed_pass
            db.session.commit()
            flash("Your changes have been saved successfully.", "success")
            return render_template("password.html", form=form)
        flash("The password you entered is incorrect.", "danger")
        return render_template("password.html", form=form)
    if form.confirm_password.errors:
        flash(form.confirm_password.errors[0], "danger")
    return render_template("password.html", form=form)


@app.route("/profile/delete", methods=["GET", "POST"])
@login_required
def delete_account():
    form = DeleteAccountForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.password.data):
            Results.query.filter_by(user_id=current_user.id).delete()
            Users.query.filter_by(id=current_user.id).delete()
            db.session.commit()
            flash("Your account was successfully deleted.", "success")
            return redirect("/login")
        flash("The password you entered is incorrect.", "danger")
    return render_template("delete.html", form=form)


@app.route("/download/<result_id>")
def download_pdf(result_id):
    if not current_user.is_authenticated and result_id == "guest":
        if not "search_query" in session:
            return render_template("error-404.html"), 404
        search_query = session["search_query"]
        pdf = generate_pdf(
            search_query, session["pmids"].split(","), session["result"])
    else:
        result_row = db.session.get(Results, result_id)
        if not result_row:
            return render_template("error-404.html"), 404
        else:
            search_query = result_row.search_query
            pdf = generate_pdf(
                search_query, result_row.pmids.split(","), result_row.result)

    response = Response(pdf)
    response.headers["Content-Disposition"] = f"attachment; filename={search_query}.pdf"
    response.mimetype = "application/pdf"
    return response


@app.route("/results/share/<result_id>")
def share_result(result_id):
    result_row = db.session.get(Results, result_id)
    if not result_row:
        return render_template("error-404.html"), 404
    return render_template("share.html", query=result_row.search_query, pmids=result_row.pmids.split(","),
                           titles=result_row.titles.split(","), result=result_row.result, result_id=result_id)


@app.route("/api/results/<result_id>")
@login_required
def result_api(result_id):
    result_row = db.session.get(Results, result_id)
    if not result_row:
        return render_template("error-404.html"), 404
    elif current_user.id != result_row.user_id:
        return render_template("error-403.html"), 403

    result = {
        'id': result_row.id,
        'query': result_row.search_query,
        'pmids': result_row.pmids,
        'titles': result_row.titles,
        'result': result_row.result,
        'favorite': result_row.favorite
    }
    return jsonify(result)


@app.errorhandler(404)
def error_404(error):
    return render_template("error-404.html"), 404


@app.errorhandler(403)
def error_403(error):
    return render_template("error-403.html"), 403


@app.errorhandler(500)
def error_500(error):
    return render_template("error-500.html"), 500


@app.errorhandler(502)
def error_502(error):
    return render_template("error-502.html"), 502


def send_reset_email(user):
    token = user.generate_token()
    msg = Message("PubSynth - Password Reset Request",
                  sender=os.getenv('EMAIL_USER'), recipients=[user.email])
    msg.body = f"""We have received a request to reset the password for your account.

Visit the following link to reset your password: {url_for("reset_password", token=token, _external=True)}

If you did not initiate this request, you may safely ignore this email.

Thank you,
The PubSynth Team
    """
    mail.send(msg)


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
    esearch_params = {"db": "pubmed", "term": search_query,
                      "retmax": "3", "retmode": "json", "sort": "relevance"}
    esearch = requests.get(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi", params=esearch_params)
    return ','.join(esearch.json()["esearchresult"]["idlist"])


def get_titles(pmids):
    esummary_params = {"db": "pubmed", "id": pmids, "retmode": "json"}
    esummary = requests.get(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi", params=esummary_params).json()
    titles = []
    for pmid in pmids.split(","):
        titles.append(esummary["result"][pmid]["title"].rstrip("."))
    return ','.join(titles)


def get_abstracts(pmids):
    efetch_params = {"db": "pubmed", "id": pmids,
                     "rettype": "medline", "retmode": "text"}
    efetch = requests.get(
        "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi", params=efetch_params)
    return parse_abstracts(efetch.text)


def get_summary(abstracts, detail=0, summary=None):
    if detail == 0:
        prompt = """Your job is to synthesize the key pieces of information from the following research paper abstracts into one coherent summary that is comprehensible to the 
average person. Each abstract you are being given starts with #####. Use this to help you isolate the topics of each abstract to create a more intelligible summary. Your 
summary should be around 10 sentences long: """

    elif detail == 1:
        prompt = f"""Your job is to synthesize the key pieces of information from the following research paper abstracts into one coherent summary that is comprehensible to the 
average person. The summary you gave last time was: "{summary}" Use details from the following abstracts to create a new summary with an increased level of detail and 
technicality. Your #1 priority is to make your response at least 20% longer than your last summary in terms of characters used. Each abstract begins with #####: """
    else:
        prompt = f"""Your job is to synthesize the key pieces of information from the following research paper abstracts into one coherent summary that is comprehensible to the 
average person. The summary you gave last time was: "{summary}" Use the following abstracts to create a new, more generalized summary with a decreased level of detail and 
shorter response length compared to last time. Each abstract begins with #####: """

    gpt_response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {
                "role": "assistant",
                "content": prompt + abstracts
            }
        ]
    )
    return gpt_response["choices"][0]["message"]["content"]


def generate_pdf(query, pmids, result):
    render = render_template(
        "download.html", query=query, pmids=pmids, result=result)
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
