from flask import Flask, request, render_template, redirect, url_for, session, flash
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import random
from flask_sqlalchemy import SQLAlchemy
import os
import string
import uuid
import hashlib
import time
from datetime import datetime

app = Flask(__name__)

application = app

apicode = "something"

website = "https://localhost:8000"

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

basedir = os.path.abspath(os.path.dirname(__file__))

app.secret_key = os.urandom(24)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "data.sqlite")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class Accounts(db.Model):
        __tablename__ = "accounts"

        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.Text)
        password = db.Column(db.Text)
        salt = db.Column(db.Text)

        def __init__(self, username, password, salt):
                self.username = username
                self.password = password
                self.salt = salt

        def __repr__(self):
                return  "{}§{}§{}".format(self.username, self.password, self.salt)

class Transactions(db.Model):
        __tablename__ = "transactions"

        id = db.Column(db.Integer, primary_key=True)
        payer = db.Column(db.Text)
        receiver = db.Column(db.Text)
        amount = db.Column(db.Text)
        date = db.Column(db.Text)
        reason = db.Column(db.Text)

        def __init__(self, payer, receiver, amount, date, reason):
                self.payer = payer
                self.receiver = receiver
                self.amount = amount
                self.date = date
                self.reason = reason

        def __repr__(self):
                return  "{}§{}§{}§{}§{}".format(self.payer, self.receiver, self.amount, self.date, self.reason)


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/home")
def home():
    try:
        if session["logged"] == True:
            return render_template("home.html")
        else:
            return redirect(url_for("login"))
    except:
        return redirect(url_for("login"))

@app.route("/pay", methods=["POST", "GET"])
def pay():
    if request.method == "POST":
        try:
            if session["logged"] == True:
                payer = session["username"]
                receiver = request.form.get("username")
                amount = request.form.get("money")
                reason = request.form.get("reason")
                print(reason)
                paid_search = Transactions.query.filter_by(payer=payer).all()
                received_search = Transactions.query.filter_by(receiver=payer).all()
                checkmoney = requests.get(website + "/playerinfo?apikey={code}&player={user}".format(code=apicode, user=payer), verify=False).text.replace("$", "").replace(",", "")
                if receiver != "":
                    if amount != None:
                        if int(checkmoney) >= int(amount):
                            paymoney = requests.get(website + "/transfermoney?apicode={code}&player1={user}&player2={user2}&money={amount}".format(code=apicode, user=payer, user2=receiver, amount=amount), verify=False).text
                            if paymoney == "True":
                                checkmoney = requests.get(website + "/playerinfo?apikey={code}&player={user}".format(code=apicode, user=payer), verify=False).text.replace("$", "").replace(",", "")
                                now = datetime.now()
                                transaction = Transactions(str(payer), str(receiver), str(amount), str(now.strftime("%Y-%m-%d %H:%M")), str(reason))
                                db.session.add(transaction)
                                db.session.commit()
                                paid_search = Transactions.query.filter_by(payer=payer).all()
                                received_search = Transactions.query.filter_by(receiver=payer).all()
                                checkmoney = requests.get(website + "/playerinfo?apikey={code}&player={user}".format(code=apicode, user=payer), verify=False).text.replace("$", "").replace(",", "")
                                return render_template("pay.html", error="Het geld is overgemaakt!", money=checkmoney, paid=paid_search, received=received_search)
                            else:
                                checkmoney = requests.get(website + "/playerinfo?apikey={code}&player={user}".format(code=apicode, user=payer), verify=False).text.replace("$", "").replace(",", "")
                                return render_template("pay.html", error="Er is iets fout gegaan!", money=checkmoney, paid=paid_search, received=received_search)
                        else:
                            checkmoney = requests.get(website + "/playerinfo?apikey={code}&player={user}".format(code=apicode, user=payer), verify=False).text.replace("$", "").replace(",", "")
                            return render_template("pay.html", error="Je hebt niet genoeg geld!", money=checkmoney, paid=paid_search, received=received_search)
                    else:
                        checkmoney = requests.get(website + "/playerinfo?apikey={code}&player={user}".format(code=apicode, user=payer), verify=False).text.replace("$", "").replace(",", "")
                        return render_template("pay.html", error="Je hebt geen aantal euro's opgegeven!", money=checkmoney, paid=paid_search, received=received_search)
                else:
                    checkmoney = requests.get(website + "/playerinfo?apikey={code}&player={user}".format(code=apicode, user=payer), verify=False).text.replace("$", "").replace(",", "")
                    return render_template("pay.html", error="Je hebt geen ontvanger opgegeven!", money=checkmoney, paid=paid_search, received=received_search)
            else:
                return redirect(url_for("login"))
        except Exception as e:
            print(str(e))
            return redirect(url_for("login"))
    else:
        try:
            if session["logged"] == True:
                username = session["username"]
                paid_search = Transactions.query.filter_by(payer=username).all()
                received_search = Transactions.query.filter_by(receiver=username).all()
                checkmoney = requests.get(website + "/playerinfo?apikey={code}&player={user}".format(code=apicode, user=username), verify=False).text.replace("$", "").replace(",", "")
                return render_template("pay.html", money=checkmoney, paid=paid_search, received=received_search)
            else:
                return redirect(url_for("login"))
        except Exception as e:
            print(str(e))
            return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        usersearch = Accounts.query.filter_by(username=username).first()
        if usersearch != None:
            userpass = Accounts.query.filter_by(id=usersearch.id).first()
            salt = userpass.salt
            hashed_password = hashlib.sha512(password.encode('utf-8') + salt.encode('utf-8')).hexdigest()
            if str(hashed_password) == str(userpass.password):
                session["logged"] = True
                session["username"] = str(userpass.username)
                return redirect(url_for("home"))
            else:
                print("password fout")
                return render_template("login.html", error="Oeps, het lijkt er op dat jouw ingevulde wachtwoord niet het zelfde is als het wachtwoord die wij voor deze gebruiker hebben!")
        else:
            print("user niet gevonden")
            return render_template("login.html", error="Oeps, het lijkt er op dat deze gebruiker niet is gevonden!")
    else:
        return render_template("login.html")

@app.route("/changepassword", methods=["GET", "POST"])
def changepassword():
    if request.method == "POST":
        username = request.form.get("username")
        usersearch = Accounts.query.filter_by(username=username).first()
        if usersearch != None:
            userpass = Accounts.query.filter_by(id=usersearch.id).first()
            playercode = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(12)])
            playercodes[username] = playercode
            sendmessage = requests.get(website + "/changepassword?apikey={code}&player={user}&code={playercode}".format(code=apicode, user=username, playercode=playercode), verify=False).text
            if sendmessage == "True":
                return render_template("changepassword.html", error="De eerste stap om jouw wachtwoord te resetten is gelukt! Kijk in minecraft en klik op de link om je wachtwoord te veranderen!")
            else:
                return render_template("changepassword.html", error="Oeps, het lijkt er op dat je niet online bent op minecraft!")
        else:
            print("user niet gevonden")
            return render_template("changepassword_success.html", error="Oeps, het lijkt er op dat deze gebruiker niet is gevonden!")
    else:
        return render_template("changepassword.html")

@app.route("/changepasswordchoose", methods=["GET", "POST"])
def changepasswordchoose():
    if request.method == "POST":
        code = request.form.get("code")
        username_got = request.form.get("username")
        print(username_got)
        password = request.form.get("password")
        try:
            playercode = playercodes[username_got]
        except:
            return render_template("error.html", error="Geen geldige verificatie code meegegeven!")
        if str(code) == str(playercode):
            usersearch = Accounts.query.filter_by(username=username_got).first()
            if usersearch != None:
                usersearch.password = hashlib.sha512(password.encode('utf-8') + usersearch.salt.encode('utf-8')).hexdigest()
                db.session.commit()
                return render_template("error.html", error="Wachtwoord succesvol veranderd!")
            else:
                return render_template("error.html", error="Account bestaat nog niet!")
        else:
            return render_template("error.html", error="Geen geldige code meegegeven!")
    else:
        code = request.args.get("code")
        username = request.args.get("username")
        return render_template("changepasswordchoose.html", username=username, code=code)

@app.route("/verify")
def verify():
    code = request.args.get("code")
    username_got = request.args.get("username")
    username_record = session["username"]
    print(username_record)
    if str(username_record) == str(username_got):
        if str(session["code"]) == str(code):
            usersearch = Accounts.query.filter_by(username=username_record).first()
            if session.get("register_verify") == True:
                if usersearch == None:
                    account = Accounts(username_record, session["password"], session["salt"])
                    db.session.add(account)
                    db.session.commit()
                    session.pop("register_verify")
                    return render_template("verify_success.html")
                else:
                    return render_template("error.html", error="Account is al gemaakt!")
            else:
                return render_template("error.html", error="Account is al gemaakt!")
        else:
            return render_template("error.html", error="Geen geldige code meegegeven!")
    else:
        return render_template("error.html", error="Geen geldige username!")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        print(username)
        if str(username) != "":
            if str(password) != "":
                usersearch = Accounts.query.filter_by(username=username).first()
                if usersearch == None:
                    if len(str(password)) > 4 and len(str(password)) < 16:
                        code = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(12)])
                        r = requests.get(website + "/verifyaccount?apicode={apicode}&user={user}&code={code}".format(apicode=apicode, user=username, code=code), verify=False)
                        if r.text == "True":
                            salt = uuid.uuid4().hex
                            hashed_password = hashlib.sha512(password.encode('utf-8') + salt.encode('utf-8')).hexdigest()
                            session["password"] = hashed_password
                            session["salt"] = salt
                            session["username"] = username
                            session["code"] = code
                            session["register_verify"] = True
                            session.modified = True
                            return render_template("register.html", error="De eerste stap van jouw registratie is gelukt! Klik nu op de link in minecraft om de registratie af te ronden!")
                        else:
                            return render_template("register.html", error="Oeps, het lijkt er op dat jij niet online bent op minecraft!")
                    else:
                        return render_template("register.html", error="Oeps, het lijkt er op dat jouw gekozen wachtwoord niet tussen de 4 en 16 karakters is!")
                else:
                    return render_template("register.html", error="Oeps, het lijkt er op dat deze username al is gekozen!")
            else:
                return render_template("register.html", error="Oeps, het lijkt er op dat je geen geldig wachtwoord in hebt gevuld")
        else:
            return render_template("register.html", error="Oeps, het lijkt er op dat je geen geldige username in hebt gevuld!")
    else:
        return render_template("register.html")

if __name__ == "__main__":
    global playercodes
    playercodes = {}
    app.run(debug=True, threaded=True, host="0.0.0.0")
