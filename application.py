from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == "GET":
        # Extract cash
        cash = db.execute("SELECT cash FROM users WHERE id=:id",
                          id=session["user_id"])
        # Extract stocks and shares
        stocks_shares = db.execute("SELECT symbol, shares FROM total WHERE id=:id ORDER BY symbol",
                                    id=session["user_id"])
        if not stocks_shares:
            stock_shares = {'symbol': "No shares", 'shares': 0, 'price': 0, 'sums': 0}
            return render_template("index.html", stock_shares=stock_shares, cash=cash[0]["cash"], budget=cash[0]["cash"])
        else:
            # Lookup for current prices
            for stock_share in stocks_shares:
                q = lookup(stock_share["symbol"])
                if q == None:
                    return apology("API is not responding", 400)
                price = q["price"]
                stock_share.update({'price': price})

            # Calculate current total sums per stock
            for stock_share in stocks_shares:
                total = float(stock_share["price"]) * int(stock_share["shares"])
                stock_share.update({'sums': total})

            # Calculate budget (total sum of all stocks + cash)
            total_sum = 0
            for stock_share in stocks_shares:
                total_sum += float(stock_share["sums"])

            budget = total_sum + float(cash[0]["cash"])

            return render_template("index.html", stocks_shares=stocks_shares, cash=cash[0]["cash"], budget=budget)
    # Change password
    else:
        if not request.form.get("password_1") or request.form.get("password_2"):
            return apology("must provide passwords", 403)
        elif request.form.get("password_1") != request.form.get("password_2"):
            return apology("passwords are not the same", 403)
        else:
            hsh = generate_password_hash(request.form.get("password_1"))
            rows = db.execute("UPDATE users SET hash=:new_hash WHERE id=:id",
                                new_hash=hsh, id=session["user_id"])
            return render_template("/password-changed.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    cash = db.execute("SELECT cash FROM users WHERE id=:id",
                      id=session["user_id"])

    if request.method == "POST":
        # Check if all fields filled in and number of shares positive
        if not request.form.get("symbol"):
            return apology("must provide stock name", 400)

        elif not request.form.get("shares"):
            return apology("must provide number of stocks", 400)

        elif not request.form.get("shares").isnumeric():
            return apology("not numeric", 400)

        elif int(request.form.get("shares")) < 1:
            return apology("number of stocks is less zero", 400)

        else:
            # Check current price of stock
            symbol = request.form.get("symbol")
            quote = lookup(symbol)
            if not quote:
                return apology("The stock does not exist", 400)
            price = quote["price"]

            # Check if user has enough cash
            if float(price) * int(request.form.get("shares")) > float(cash[0]["cash"]):
                return apology("You don't have enough cash", 400)
            else:
                # Update info about user cash, transactions and total
                # Check if user already has this stock
                rows = db.execute("SELECT symbol FROM total WHERE id=:id AND symbol=:symbol",
                                  id=session["user_id"], symbol=symbol)
                # Insert new stock or update existed stock
                if not rows:
                    rows = db.execute("INSERT INTO total (id, symbol, shares) VALUES (:id, :symbol, :shares)",
                                      id=session["user_id"], symbol=symbol, shares=request.form.get("shares"))
                else:
                    shares_before = db.execute("SELECT shares FROM total where id=:id AND symbol=:symbol",
                                                id=session["user_id"], symbol=symbol)
                    rows = db.execute("UPDATE total SET shares=:new_shares WHERE id=:id AND symbol=:symbol",
                                      new_shares=int(shares_before[0]["shares"])+int(request.form.get("shares")), id=session["user_id"], symbol=symbol)
                # Update user cash
                rows1 = db.execute("UPDATE users SET cash=:new_cash WHERE id=:id",
                                    new_cash=float(cash[0]["cash"])-(float(price)*int(request.form.get("shares"))), id=session["user_id"])
                # Log transaction
                rows2 = db.execute("INSERT INTO transactions (symbol, shares, price, id, action) VALUES (:symbol, :shares, :price, :id, :action)",
                                    symbol=symbol, shares=request.form.get("shares"), price=price, id=session["user_id"], action="buy")

                return redirect("/")
    else:
        return render_template("buy.html", cash=cash[0]["cash"])


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    if request.method == "GET":
        # Extract history
        history = db.execute("SELECT * FROM transactions WHERE id=:id ORDER BY action",
                              id=session["user_id"])
        if not history:
            return render_template("history.html")
        else:
            return render_template("history.html", history=history)
    else:
        return render_template("history.html")


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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

    if request.method == "POST":
        # Check if all fields filled in
        if not request.form.get("symbol"):
            return apology("must provide stock name", 400)
        else:
            # Check current price
            symbol = request.form.get("symbol")
            quote = lookup(symbol)
            if not quote:
                return apology("The stock does not exist", 400)
            # Return page with quotation
            return render_template("quoted.html", name=quote["name"], price=quote["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords do not the same", 400)

        pw_hash = generate_password_hash(request.form.get("password"))

        # Check if the username UNIQUE
        result = db.execute("SELECT username FROM users WHERE username=:username",
                            username=request.form.get("username"))
        if result:
            return apology("Username already exists", 400)

        # Save user in database
        rows = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                          username=request.form.get("username"), hash=pw_hash)

        # Query database for username
        rows1 = db.execute("SELECT * FROM users WHERE username=:username",
                            username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows1[0]["id"]

        # Extract cash
        cash = db.execute("SELECT cash FROM users WHERE id=:id",
                            id=session["user_id"])

        # Redirect user to home page
        return render_template("index.html", cash=cash[0]["cash"], budget=cash[0]["cash"])

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")
    return apology("Register first", 403)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Check how much cash and what stocks user have
    cash = db.execute("SELECT cash FROM users WHERE id=:id",
                       id=session["user_id"])
    symbols = db.execute("SELECT symbol FROM total WHERE id=:id",
                          id=session["user_id"])
    if not symbols:
        return apology("You don't have any stocks", 400)

    # Check if all fields are filled in and number of shares is positive
    if request.method == "POST":
        if not request.form.get("shares"):
            return apology("must provide number of stocks", 400)
        elif not request.form.get("shares").isnumeric():
            return apology("not numeric", 400)
        elif int(request.form.get("shares")) < 1:
            return apology("number of stocks is less than zero", 400)
        else:
            # Check current price of this stock
            symbol_sell = request.form.get("symbol")
            if not symbol_sell:
                return apology("didnt choose", 400)

            quote = lookup(symbol_sell)
            if not quote:
                return apology("The stock does not exist", 400)
            price = quote["price"]

            # Calculate how many shares of this stock user has
            share_qty = db.execute("SELECT shares FROM total WHERE symbol=:symbol AND id=:id",
                                   symbol=symbol_sell, id=session["user_id"])
            total_share = share_qty[0]["shares"]

            # Check if user has enough shares of the stock
            if int(total_share) < int(request.form.get("shares")):
                return apology("You don't have enough stocks", 400)
            else:
                # Calcalute how much cash user now has
                new_cash = float(cash[0]["cash"]) + (int(request.form.get("shares")) * float(price))

                # Log in updated cash
                rows3 = db.execute("UPDATE users SET cash=:new_cash WHERE id=:id",
                                   new_cash=new_cash, id=session["user_id"])
                # Log in transactions
                rows4 = db.execute("INSERT INTO transactions (symbol, shares, price, id, action) VALUES (:symbol, :shares, :price, :id, :action)",
                                   symbol=symbol_sell, shares=int(request.form.get("shares")), price=price, id=session["user_id"], action="sell")
                # Update total.db
                if int(total_share) == int(request.form.get("shares")):
                    rows5 = db.execute("DELETE FROM total WHERE symbol=:symbol AND id=:id",
                                       symbol=symbol_sell, id=session["user_id"])
                else:
                    new_total = int(total_share)-int(request.form.get("shares"))
                    rows6 = db.execute("UPDATE total SET shares=:new_share WHERE id=:id",
                                        new_share=new_total, id=session["user_id"])

                # Redirect to index page
                return redirect("/")

    # If request method GET
    else:
        return render_template("sell.html", cash=cash[0]["cash"], symbols=symbols)


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
