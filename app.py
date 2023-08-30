import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Show user's stocks and shares
    stocks = db.execute("SELECT symbol, SUM(shares) as totalShares FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING totalShares > 0",
                    user_id = session["user_id"])

    # Get user´s cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])[0]["cash"]

    totalValue = cash
    grandTotal = cash

    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["value"] = quote["price"] * stock ["totalShares"]
        totalValue += stock["value"]
        grandTotal += stock ["value"]

    return render_template("index.html", stocks = stocks, cash = cash, totalValue = totalValue, grandTotal = grandTotal)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Check data and place them into variables
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        # Check for any missing credentials
        if not symbol:
            return apology("Missing symbol", 400)

        elif not shares or not shares.isdigit() or int(shares) <= 0 or not int(shares):
            return apology("shares must be a positive integer", 400)

        quote = lookup(symbol)

        if not quote:
            return apology("Invalid Symbol", 400)

        price = quote["price"]
        cost = int(shares) * price
        cash = usd(db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])[0]["cash"])

        if cash < cost:
            return apology("Insufficient Founds", 400)

        # Update users table
        db.execute("UPDATE users SET cash = cash - :cost WHERE id = :user_id", cost = cost, user_id = session ["user_id"])

        # Add purchase to history table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)", user_id = session["user_id"], symbol = symbol, shares = shares, price = price)


        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Check database for transactions and ordered by descending order
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = :user_id ORDER BY timestamp DESC", user_id = session["user_id"])

    return render_template("history.html", transactions = transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return render_template("login.html")

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Check symbol submitted by user and place it into 'symbol' variable
        symbol = request.form.get("symbol")

        #Check if the symbol exist
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid Symbol", 400)
        return render_template("quote.html", quote = quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Check credentials and place them into variables
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check for any missing credentials
        if not username or not password or not confirmation:
            return apology("Missing Credentials", 400)

        # Check if passwords match
        elif not password == confirmation:
            return apology("Passwords do not match", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Check username does not already exist
        if len(rows) != 0:
            return apology("Username already exist", 400)

        # Cretate hash code for user password
        hashcode = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Insert user credentials into database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashcode)

        # Query database for new username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect use to home page
        return redirect("/")

        # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    stocks = db.execute("SELECT symbol, SUM(shares) as totalShares FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING totalShares > 0",user_id = session["user_id"])

    if request.method == "POST":

        # Check data and place them into variables
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Check for any missing credentials
        if not symbol or not shares:
            return apology("Missing Credentials", 400)

        elif not shares.isdigit() or int(shares) <= 0:

            return apology("shares of shares must be a positive integer", 400)

        else:
            shares = int(shares)

        for stock in stocks:
            if stock["symbol"] == symbol:
                if stock["totalShares"] < shares:
                    return apology("Not enough shares")
                else:
                    # Get quote
                    quote = lookup(symbol)
                    if not quote:
                        return apology("Invalid Symbol")
                    price = quote["price"]
                    totalSale = shares * price

                    # Update users table
                    db.execute("UPDATE users SET cash = cash + :totalSale WHERE id = :user_id", totalSale = totalSale, user_id = session["user_id"])

                    # Add sale to history table
                    db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)", user_id = session["user_id"], symbol = symbol, shares =- shares, price = price)

                    return redirect("/")

        return apology("Invalid symbol")

    else:
        return render_template("sell.html")