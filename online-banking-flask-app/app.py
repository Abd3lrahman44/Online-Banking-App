from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
import bcrypt
import os
import jwt

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATABASE = 'bank.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  
    return g.db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()
        
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        db = get_db()
        db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_pw))
        db.commit()

        return redirect('/login')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)

        if user and bcrypt.checkpw(password.encode(), user['password']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            token = jwt.encode({'username': username}, app.config['SECRET_KEY'], algorithm='HS256')
            session['token'] = token
            return redirect('/dashboard')
        else:
            return 'Invalid credentials', 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    conn = get_db()
    transactions = conn.execute("SELECT * FROM transactions WHERE user_id = ?", (session['user_id'],)).fetchall()
    user = conn.execute("SELECT balance FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    all_users = conn.execute("SELECT id, username FROM users WHERE id != ?", (session['user_id'],)).fetchall()
    conn.close()

    return render_template('dashboard.html', username=session['username'], balance=user['balance'], transactions=transactions, all_users=all_users)

@app.route('/transfer', methods=['POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    sender_id = session['user_id']

    try:
        recipient_id = int(request.form['recipient_id'])
        amount = float(request.form['amount'])
    except (KeyError, ValueError):
        flash("Invalid form data.", "danger")
        return redirect(url_for('dashboard'))

    if recipient_id == sender_id:
        flash("You can't transfer to yourself.", "danger")
        return redirect(url_for('dashboard'))

    if amount <= 0:
        flash("Transfer amount must be greater than zero.", "danger")
        return redirect(url_for('dashboard'))

    conn = get_db()
    cur = conn.cursor()

    recipient = cur.execute("SELECT username FROM users WHERE id = ?", (recipient_id,)).fetchone()
    if recipient is None:
        flash("Recipient does not exist.", "danger")
        return redirect(url_for('dashboard'))

    cur.execute("SELECT balance FROM users WHERE id = ?", (sender_id,))
    sender_balance = cur.fetchone()['balance']

    if sender_balance >= amount:
        cur.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, sender_id))
        cur.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, recipient_id))

        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, description) VALUES (?, 'debit', ?, ?)",
            (sender_id, amount, f"Transfer to {recipient['username']}")
        )
        cur.execute(
            "INSERT INTO transactions (user_id, type, amount, description) VALUES (?, 'credit', ?, ?)",
            (recipient_id, amount, f"Transfer from {session['username']}")
        )

        conn.commit()
        flash("Transfer successful.", "success")
    else:
        flash("Insufficient funds.", "danger")

    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/security')
def security():
    return render_template('security.html')

@app.route('/tech')
def tech():
    return render_template('tech.html')

if __name__ == '__main__':
    app.run(debug=True)


