from flask import Flask, render_template, request, flash, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

import sqlite3


# DataBase Initialization


with sqlite3.connect('database.db') as con:
    print("Opened database successfully")
    con.execute('''
    CREATE TABLE IF NOT EXISTS user(
        id integer PRIMARY KEY AUTOINCREMENT,
        name text NOT NULL,
        email text NOT NULL UNIQUE,
        password text NOT NULL
    )
    ''')
    con.execute('''
    CREATE TABLE IF NOT EXISTS gym(
        id integer PRIMARY KEY AUTOINCREMENT,
        name text NOT NULL,
        contact text NOT NULL,
        foundation text NOT NULL,
        phone text NOT NULL,
        description text NOT NULL,
        instagram text DEFAULT " ",
        facebook text DEFAULT " "
    )
    ''')
    con.execute('''
    CREATE TABLE IF NOT EXISTS review(
        id integer PRIMARY KEY AUTOINCREMENT,
        gid integer NOT NULL,
        gname text NOT NULL,
        uid integer NOT NULL,
        uname text NOT NULL,
        message text NOT NULL
    )
    ''')
    print("Table created successfully")


# Application Initialization


app = Flask(__name__)
app.config['SECRET_KEY'] = "random_string"
bcrypt = Bcrypt(app)


# Login Manager Start


login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, id, name, email, password):
        self.id = id
        self.name = name
        self.email = email
        self.password = password


@login_manager.user_loader
def load_user(id):
    with sqlite3.connect('database.db') as con:
        cur = con.cursor()
        cur.execute("SELECT * FROM user WHERE id = (?)", [id])
        row = cur.fetchone()
        if row:
            usr = User(row[0], row[1], row[2], row[3])
            return usr
        else:
            return


# Login Manager End


# Routes Start


@app.route('/')
@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    else:
        return render_template('login.html')


@app.route('/logging_in', methods=["POST"])
def logging_in():

    email = request.form["email"]
    password = request.form["password"]

    with sqlite3.connect('database.db') as con:
        cur = con.cursor()
        cur.execute("SELECT * From user WHERE email = ?", [email])
        row = cur.fetchone()

        if row is None:
            flash('Invalid Login')
            return redirect(url_for('login'))

        elif bcrypt.check_password_hash(row[3], password):
            usr = User(row[0], row[1], row[2], row[3])
            login_user(user=usr, remember=True)
            flash('Logged in')
            return redirect(url_for('index'))

        else:
            flash('Incorrect Login Credentials')
            return redirect(url_for('login'))


@app.route('/signup')
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    else:
        return render_template('signup.html')


@app.route('/signing_up', methods=["POST"])
def signing_up():

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    with sqlite3.connect('database.db') as con:
        cur = con.cursor()
        cur.execute("SELECT * From user WHERE email = ?", [email])
        rows = cur.fetchall()
        if rows:
            flash("Email Already Exist")
            return redirect(url_for('signup'))
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('UTF-8')
            cur.execute("INSERT INTO user (name,email,password) VALUES (?, ?, ?)", (name, email, hashed_password))
            con.commit()
            flash("Account Created Successfully. Log in to Continue.")
            return redirect(url_for('login'))


@app.route('/change_password')
@login_required
def change_password():
    return render_template('change_password.html')


@app.route('/changing_password', methods=["POST"])
@login_required
def changing_password():

    current_pwd = request.form["current_password"]
    new_pwd = request.form["new_password"]
    re_new_pwd = request.form["re_new_password"]

    if bcrypt.check_password_hash(current_user.password, current_pwd):
        if new_pwd == re_new_pwd:
            if bcrypt.check_password_hash(current_user.password, new_pwd):
                flash('Password must varies from current Password')
                return redirect(url_for('change_password'))
            else:
                hashed_password = bcrypt.generate_password_hash(new_pwd).decode('UTF-8')
                current_user.password = hashed_password
                with sqlite3.connect('database.db') as con:
                    cur = con.cursor()
                    cur.execute("UPDATE user SET password = ? WHERE id = ?", [hashed_password, current_user.id])
                    con.commit()
                flash('Password is Updated.')
                return redirect(url_for('index'))
        else:
            flash('Password is Mismatch.')
            return redirect(url_for('change_password'))
    else:
        flash('Incorrect Password')
        return redirect(url_for('change_password'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/index')
@login_required
def index():
    return render_template('index.html')


@app.route('/search', methods=["POST"])
@login_required
def search():

    search_choice = request.form['search_choice']
    search_keyword = request.form['search']

    with sqlite3.connect('database.db') as con:
        cur = con.cursor()
        query = "SELECT * From gym WHERE LOWER(REPLACE({0}, ' ', '')) LIKE '%{1}%' ;".format(search_choice, (search_keyword.replace(" ", "%")).lower())
        cur.execute(query)
        rows = cur.fetchall()

    return render_template('search_result.html', rows=rows)


@app.route('/result', methods=["GET", "POST"])
@login_required
def result():

    if request.method == "POST":
        id = request.form['id']
    else:
        id = request.args.get('id')

    with sqlite3.connect('database.db') as con:
        cur = con.cursor()
        cur.execute("SELECT * From gym WHERE id = ? ;", [id])
        row = cur.fetchone()
        cur.execute("SELECT * From review WHERE gid = ? ;", [id])
        reviews = cur.fetchall()

    return render_template('result.html', row=row, reviews=reviews, reviews_count=len(reviews))


@app.route('/add_review', methods=["POST"])
@login_required
def add_review():

    gid = request.form['gid']
    gname = request.form['gname']
    uid = request.form['uid']
    uname = request.form['uname']
    review = request.form['review']

    with sqlite3.connect('database.db') as con:
        cur = con.cursor()
        cur.execute("SELECT * From review WHERE uid = ? and gid = ?", [uid,gid])
        rows = cur.fetchall()
        if rows:
            flash("One Review Per User is allowed")
        else:
            cur.execute("INSERT INTO review(gid,gname,uid,uname,message) values (?,?,?,?,?)", [gid, gname, uid, uname, review])
            con.commit()
            flash('Review Added Successfully.')
        return redirect(url_for('result', id=gid))


if __name__ == "__main__":
    app.run(debug=True)
