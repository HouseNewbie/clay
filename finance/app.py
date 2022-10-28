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
    # Get purchases info to turn into summary at index
    purchases = db.execute(
        "SELECT symbol, name, SUM(shares) AS shares, price, SUM(price) as total FROM purchases WHERE user_id = ? GROUP BY name HAVING SUM(shares) > 0", session["user_id"])

    # Get updated price of share
    for purchase in purchases:
        symbol = lookup(purchase["symbol"])
        purchase["price"] = symbol["price"]
        purchase["total"] = purchase["price"] * purchase["shares"]
        
    # Get total cash in user account
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

    # Total money from cash and shares
    total = cash[0]["cash"] + sum(purchase["total"] for purchase in purchases)
    return render_template("index.html", purchases=purchases, cash=cash[0]["cash"], total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User input via GET
    if request.method == "GET":
        return render_template("buy.html")

    # User input via POST
    else:
        # Safety checks

        # No empty symbol name
        if not request.form.get("symbol"):
            return apology("missing symbol")

        # No empty shares
        if not request.form.get("shares"):
            return apology("missing shares")

        # Making sure shares is a valid number
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("invalid shares")

        # Making sure shares are positive
        if shares <= 0:
            return apology("invalid shares")

        # Get symbol's data with lookup
        symbol = lookup(request.form.get("symbol"))

        # Check if it's a valid symbol
        if not symbol:
            return apology("invalid symbol")

        # Look find how much cash current user has
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

        # Check if user has enough cash
        cost = symbol["price"] * shares
        if cash[0]["cash"] < cost:
            return apology("can't afford")

        # Update user cash
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", cost, session["user_id"])

        # Register purchase
        db.execute("INSERT INTO purchases (name, symbol, shares, price, datetime, user_id) VALUES(?, ?, ?, ?, CURRENT_TIMESTAMP, ?)",
                   symbol["name"], symbol["symbol"], shares, symbol["price"], session["user_id"])

        # Flash a message promting user bought a share
        flash("Bought!")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Load user history
    purchases = db.execute("SELECT * FROM purchases WHERE user_id = ?", session["user_id"])
    return render_template("history.html", purchases=purchases)


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
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User request via GET
    if request.method == "GET":
        # Only load the page
        return render_template("quote.html")

    # User request via POST
    else:
        # Fetch symbols with lookup
        symbol = lookup(request.form.get("symbol"))

        # Check if valid symbol
        if not symbol:
            return apology("Invalid Symbol")

        # Render data from fetched symbol
        return render_template("quoted.html", symbol=symbol)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User request via POST
    if request.method == "POST":

        # check if there's a username
        if not request.form.get("username"):
            return apology("missing username")

        # check if there's a password
        if not request.form.get("password"):
            return apology("missing password")

        # check if password match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords don't match")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username doesn't exist
        if len(rows) >= 1:
            return apology("Username is not available")

        # Change password to hash and add username and hashed password into the database
        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

        # Login user with their new account
        return login()

    # User reached route via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User request via GET
    if request.method == "GET":
        symbol = db.execute(
            "SELECT symbol FROM purchases WHERE user_id = ? GROUP BY symbol HAVING sum(shares) > 0", session["user_id"])
        return render_template("sell.html", symbol=symbol)

    # User request via POST
    else:
        # check if there's a symbol
        if not request.form.get("symbol"):
            return apology("missing symbol")
        symbol = request.form.get("symbol")

        # check if there's a share
        if not request.form.get("shares"):
            return apology("missing shares")

        # Making sure shares is a valid number
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("invalid shares")

        # Making sure shares are positive
        if shares <= 0:
            return apology("shares must be positive")

        # Load share info in a variable
        owned_share = db.execute(
            "SELECT *, SUM(shares) AS total_shares FROM purchases WHERE user_id = ? AND symbol = ? GROUP BY symbol", session["user_id"], symbol)
        if not owned_share:
            return apology("symbol not owned")

        # Verify if user has enough shares
        if (shares > owned_share[0]["total_shares"]):
            return apology("too many shares")

        # Update user cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", owned_share[0]["price"] * shares, session["user_id"])

        # Register sale
        db.execute("INSERT INTO purchases (name, symbol, shares, price, datetime, user_id) VALUES(?, ?, ?, ?, CURRENT_TIMESTAMP, ?)",
                   owned_share[0]["name"], owned_share[0]["symbol"], -shares, owned_share[0]["price"], session["user_id"])

        # Redirect to index
        flash("Sold!")
        return redirect("/")


@app.route("/account", methods=["GET", "POST"])
@login_required
def Account():
    """Change password"""
    # User request via GET
    if request.method == "GET":
        return render_template("account.html")

    # User request via POST
    else:
        # Check if password is empty
        if not request.form.get("old_password"):
            return apology("Enter your current password")

        if not request.form.get("new_password") or not request.form.get("confirmation"):
            return apology("Enter New password")

        password = request.form.get("new_password")

        # Check if confirmation password is the same as password
        if password != request.form.get("confirmation"):
            return apology("Your new password does not match")

        # Query database
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
            return apology("current password is invalid")

        # Generate new hash for new password
        password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Update user password
        db.execute("UPDATE users SET hash = ? WHERE id = ?", password, session["user_id"])

        # Redirect to index
        flash("Password Has been changed!")
        return redirect("/")