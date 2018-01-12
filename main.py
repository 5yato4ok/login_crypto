import os

from flask import Flask, g, session, flash, redirect, url_for, abort, request, render_template

from utils import is_password_valid, get_db_connect, get_users_props, is_user, handle_signup_request


app = Flask(__name__)
app.config["DATABASE"] = os.path.join(app.root_path, "signup.db")
app.config["SECRET_KEY"] = "DEVELOPMENT KEY"


@app.before_first_request
def init_db():
    db = get_db_connect(app)
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db_connect'):
        g.db_connect.close()


# ------------------ VIEW FUNCTIONS ------------------


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("username", None)
    flash("You were logged out")
    return redirect(url_for('index'))


@app.route("/login", methods=["POST", "GET"])
def login():
    error = None
    if session.get("logget_in"):
        abort(401)
    if request.method == "POST":
        db = get_db_connect(app)
        if not is_user(request.form['username'], db):
            error = "Invalid username"
        elif not is_password_valid(username=request.form['username'], password=request.form['password'],
                               db_connection=db, app=app):
            error = 'Invalid password'
        else:
            session["logged_in"] = True
            session["username"] = request.form['username']
            flash("You were logged in")
            return redirect(url_for("index"))
    return render_template('index.html', error=error)


@app.route("/signup", methods=["POST"])
def signup():
    if session.get("logged_in"):
        abort(401)
    db = get_db_connect(app)
    if is_user(request.form['username'], db):
        flash("User {} already exists!!!".format(request.form['username']), category='error')
    else:
        handle_signup_request(request.form, db, app)
        session['logged_in'] = True
        session['username'] = request.form['username']
        session['password'] = request.form['password']
        flash("You have successfully registered!")
    return redirect(url_for("index"))


@app.route('/')
def index():
    creds = None
    if session.get('logged_in'):
        creds = get_users_props(session["username"], session['password'], get_db_connect(app))
    return render_template("index.html", creds=creds)


if __name__ == '__main__':
    app.run()
