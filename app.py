from flask import Flask, render_template, url_for, redirect, request, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from flask_mysqldb import MySQL
import bcrypt

app = Flask(__name__)
app.secret_key = "secret123"   # needed for WTForms + sessions

# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'wtf'
mysql = MySQL(app)

# ---------------- WTForms ---------------- #
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Login")

# ---------------- Create Table ---------------- #
# ---------------- Create Table ---------------- #
with app.app_context():
    cur = mysql.connection.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(100),
            email VARCHAR(100) UNIQUE,
            password VARCHAR(200)
        )
    """)
    mysql.connection.commit()
    cur.close()


# ---------------- Routes ---------------- #
@app.route('/')
def home():
    return redirect(url_for('login'))

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()   # ✅ fixed
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        # Hash password
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        if user:
            flash('Email already registered!', 'danger')
        else:
            cur.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                        (name, email, hashed_pw.decode('utf-8')))
            mysql.connection.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        cur.close()
    return render_template('register.html', form=form)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()   # ✅ fixed
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['loggedin'] = True
            session['name'] = user[1]
            session['email'] = user[2]
            flash("Login Successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Credentials!', 'danger')
    return render_template('login.html', form=form)

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name, email FROM users")
        users = cur.fetchall()
        cur.close()
        return render_template("dashboard.html", name=session['name'], users=users)
    return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("You have logged out.", "info")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
