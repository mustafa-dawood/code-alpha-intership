from flask import Flask, request, render_template, redirect, url_for
from werkzeug.security import check_password_hash
import os

app = Flask(__name__)

username = 'admin'
password_hash = 'pbkdf2:sha256:260000$kJF4s8Xf$a93e5b3a3e5b3a3e5b3a3e5b3a3e5b3a3e5b3a3e5b3a3e5b3a3e5b3a3e5b3a'

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] == username and check_password_hash(password_hash, request.form['password']):
            return redirect(url_for('success'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)

@app.route('/success')
def success():
    return 'Login Successful!'

if __name__ == '__main__':
    app.run(debug=False)