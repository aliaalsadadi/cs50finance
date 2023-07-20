import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
import json
from tempfile import mkdtemp
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd, current_shares


# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

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
    user = db.execute('SELECT username FROM users WHERE id = ?', session['user_id'])[0]['username']
    symbols = db.execute('SELECT DISTINCT symbol FROM Buy WHERE person_id = ?', session['user_id'])
    balance = db.execute('SELECT cash FROM users WHERE id = ?', session['user_id'])[0]['cash']
    rows=[]
    total_stocks_price = 0
    for symbol in symbols:
        symbol = symbol['symbol']
        Buy_shares = db.execute('SELECT SUM(shares) FROM Buy WHERE person_id = ? AND symbol = ?',session['user_id'] ,symbol)[0]['SUM(shares)']
        sell_shares =db.execute('SELECT SUM(shares) FROM sell WHERE person_id = ? AND symbol = ?',session['user_id'] ,symbol)[0]['SUM(shares)']
        if sell_shares is None:
            sell_shares = 0
        current_shares = Buy_shares - sell_shares
        price = lookup(symbol)['price']
        if current_shares is not None:
            stocks_value = int(current_shares) * price
        else:
            stocks_value = 0
        total_stocks_price += stocks_value
        rows.append({'symbol': symbol, 'shares': current_shares, 'price': price})
    networth = total_stocks_price + balance
    return render_template('index.html', user=user,rows=rows,balance=balance, networth=networth)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    #reminder: create TABLE for stocks  
    if request.method == 'POST':
        shares = request.form.get('shares')
        symbol = request.form.get('symbol')
        if not shares:
            return apology('enter value for shares to buy')
        if int(shares) < 0:
            return apology('shares can\'t be negative')
        if not lookup(symbol):
            return apology('None existent stock symbol')
        price = lookup(symbol)['price']*int(shares)
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])[0]['cash']
        if price > balance:
            return apology('not enough money in your balance')
        else:
            current_time = datetime.now()
            purchase_date = current_time.strftime("%Y-%m-%d %H:%M:%S")
            db.execute('UPDATE users SET cash = (?) WHERE id = ?', (balance-price), session['user_id'])
            db.execute('INSERT INTO Buy (shares, symbol, purchase_price, purchase_date, person_id) VALUES (?, ?, ?, ?,?)',int(shares),symbol,price, purchase_date, session['user_id'])
        return redirect('/')
        #check for negative number of shares and stock symbol is valid

    else:
        return render_template('buy.html')
        #display form to buy a stock
        #purchase stock as long as user affords it
        
    """Buy shares of stock"""
    return apology("TODO")


@app.route("/history")
@login_required
def history():
    stocks_bought = db.execute('SELECT shares, symbol,purchase_price,purchase_date FROM Buy WHERE person_id = ?', session['user_id'])
    stocks_sold = db.execute('SELECT shares, symbol,purchase_price,purchase_date FROM sell WHERE person_id = ?', session['user_id'])

    return render_template('history.html',stocks_bought=stocks_bought, stocks_sold=stocks_sold)
    #display html table with all transactions
    #row contains type of transaction(buy or sell),number (sold or bought), when transaction happened
    """Show history of transactions"""
    return apology("TODO")


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
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        if lookup(symbol):
            stock_info = lookup(symbol)
            price = stock_info['price']
            return  render_template('quoted.html',symbol=symbol, price=usd(price))
        else:
            return apology('None existent stock symbol')
        #use lookup to get stock price
        #render quoted.html
    else:
        return render_template('quote.html')
        # display form to request a stock quote
        #render quote.html
    """Get stock quote."""
    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')
        check_user = db.execute('SELECT username FROM users WHERE username = (?);', username)
        #render apology if username exists or field is blank
        if len(check_user) > 0:
            return apology('Username exists')
        if len(username) == 0:
            return apology('Username cannot be blank')
        #render apology if either passwords are blank or do not match
        if len(password) == 0 or len(confirmation) == 0:
            return apology('password and confirmation cannot be blank')
        elif password != confirmation:
            return apology('passowrds do not match')
        else:
        #insert username and hash password to database and log in
            password_hash = generate_password_hash(password)
            db.execute('INSERT INTO users (username, hash) VALUES(?,?);', username, password_hash)
        id = db.execute('SELECT id FROM users WHERE username = ? AND hash = ?;', username, password_hash)
        session["user_id"] = id[0]['id']
        return redirect('/')
    else:
        return render_template('register.html')

@app.route('/trade', methods=['GET','POST'])
@login_required
def trade():
    if request.method == 'POST':
        content_type = request.content_type
        if content_type == 'application/json':
            rowData = request.get_json()
            seller_id = rowData['seller_id']
            seller_stock = rowData['seller_stock'] #stock to give
            seller_shares = rowData['seller_shares'] # shares to give
            buyer_stock = rowData['buyer_stock'] # stock to get
            buyer_shares = rowData['buyer_shares'] # shares to get
            if not current_shares(seller_stock):
                return apology('cannot sell more shares than you have')
            available_shares = current_shares(seller_stock)
            if int(seller_shares) > available_shares:
                return apology('cannot sell more shares than you have')
            current_time = datetime.now()
            trade_date = current_time.strftime("%Y-%m-%d %H:%M:%S")
            print(seller_stock)
            db.execute("INSERT INTO traded_seller (seller_id,seller_stock,seller_shares,buyer_stock,buyer_shares,trade_date) VALUES(?,?,?,?,?,?)",seller_id, seller_stock, seller_shares, buyer_stock,buyer_shares,trade_date)
            db.execute("INSERT INTO traded_buyer (buyer_id,seller_stock,seller_shares,buyer_stock,buyer_shares,trade_date) VALUES(?,?,?,?,?,?)",session['user_id'], seller_stock, seller_shares, buyer_stock,buyer_shares,trade_date)
            db.execute('INSERT INTO Buy (shares, symbol, purchase_price, purchase_date, person_id) VALUES (?, ?, ?, ?,?)',buyer_shares,buyer_stock,int(0), trade_date, session['user_id'])
            db.execute('INSERT INTO sell (shares, symbol, purchase_price, purchase_date, person_id) VALUES (?, ?, ?, ?,?)',seller_shares,seller_stock,int(0), trade_date, session['user_id'])
            db.execute('INSERT INTO Buy (shares, symbol, purchase_price, purchase_date, person_id) VALUES (?, ?, ?, ?,?)',seller_shares,seller_stock,int(0), trade_date, seller_id)
            db.execute('INSERT INTO sell (shares, symbol, purchase_price, purchase_date, person_id) VALUES (?, ?, ?, ?,?)',buyer_shares,buyer_stock,int(0), trade_date, seller_id)
            db.execute('DELETE FROM trading WHERE seller_id = ? AND seller_stock = ? AND seller_shares = ? AND buyer_stock = ? AND buyer_shares = ?;',seller_id,buyer_stock,buyer_shares,seller_stock, seller_shares)
            return redirect(url_for('trade'))
        else:
                seller_stock = request.form.get("stock") #stock t0 give
                if not seller_stock:
                    return apology("enter stock to sell")
                seller_shares = request.form.get("seller_shares")
                if not seller_shares:
                    return apology('enter value for shares to sell')
                available_shares = current_shares(seller_stock)
                if int(seller_shares) > available_shares:
                    return apology('cannot sell more shares than you have')
                buyer_stock = request.form.get('buyer_symbol')
                buyer_shares = request.form.get('buyer_shares')
                if not buyer_shares:
                    return apology('enter value for shares to get')
                if int(buyer_shares) < 0:
                    return apology('shares can\'t be negative')
                if not lookup(buyer_stock):
                    return apology('None existent stock symbol for stock to get')
                db.execute('INSERT INTO trading (seller_id, seller_stock,buyer_stock, seller_shares, buyer_shares) VALUES (?,?,?,?,?)',session['user_id'], seller_stock,buyer_stock,seller_shares,buyer_shares)
                return redirect(url_for('trade'))

    else:
        trades = db.execute('SELECT seller_id, seller_stock,buyer_stock, seller_shares, buyer_shares FROM trading WHERE seller_id != ?;', session['user_id'])
        symbols = db.execute('SELECT DISTINCT symbol FROM Buy WHERE person_id = ?', session['user_id'])
        return render_template('trade.html', symbols=symbols, trades=trades)
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == 'POST':
        symbol = request.form.get('stock')
        shares = request.form.get('shares')
        if not shares:
            return apology("enter shares to sell")
        Buy_shares = db.execute('SELECT SUM(shares) FROM Buy WHERE person_id = ? AND symbol = ?',session['user_id'] ,symbol)[0]['SUM(shares)']
        sell_shares =db.execute('SELECT SUM(shares) FROM sell WHERE person_id = ? AND symbol = ?',session['user_id'] ,symbol)[0]['SUM(shares)']
        if sell_shares is None:
            sell_shares = 0
        current_shares = Buy_shares - sell_shares
        #sell the number of shares of stock and update users cash
        #check if user owns the number of stocks
        if int(shares) > current_shares:
            return apology('cannot sell more shares than you have')
        #check for negative number of stocks
        if int(shares) < 0:
            return apology('cannot sell negative shares')
        price_of_share = lookup(symbol)['price']
        selling_price = price_of_share * int(shares)
        current_time = datetime.now()
        sell_date = current_time.strftime("%Y-%m-%d %H:%M:%S")
        balance = db.execute('SELECT cash FROM users WHERE id = ?', session['user_id'])[0]['cash']
        person_id = session['user_id']
        db.execute('UPDATE users SET cash = ? WHERE id = ?', (balance+selling_price), session['user_id'])
        db.execute('INSERT INTO sell (shares, symbol, purchase_price, purchase_date, person_id) VALUES (?, ?, ?, ?,?)',int(shares),symbol,selling_price, sell_date, session['user_id'])
        return redirect('/')
    else:
        symbols = db.execute('SELECT DISTINCT symbol FROM Buy WHERE person_id = ?', session['user_id'])
        return render_template('sell.html', symbols=symbols)
        #display form to sell stock, 
    """Sell shares of stock"""
    return apology("TODO")
@app.route("/change",methods=['GET', 'POST'])
@login_required
def change():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        hash = db.execute('SELECT hash FROM users WHERE id = ?;', session['user_id'])[0]['hash']
        if check_password_hash(hash, current_password):
            new_password = request.form.get('new_password')
            if len(new_password) == 0:
                return apology("password cannot be blank")
            else:
                passwd_hash = generate_password_hash(new_password)
                db.execute("UPDATE users SET hash = ? WHERE id = ?",passwd_hash, session['user_id'])
                return redirect("/")
        else:
            return apology('wrong password')
    else:
        return render_template("change_password.html")
    return apology("something is wrong")


if __name__ == '__main__':
    app.run(debug=True)
