from flask import Flask, render_template, redirect, url_for
from auth import register, login, demo_same_password_diff_hashes, demo_brute_force_explain, show_hash_info

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register')
def route_register():
    register()
    return redirect(url_for('home'))

@app.route('/login')
def route_login():
    login()
    return redirect(url_for('home'))

@app.route('/demo1')
def route_demo1():
    demo_same_password_diff_hashes()
    return redirect(url_for('home'))

@app.route('/demo2')
def route_demo2():
    demo_brute_force_explain()
    return redirect(url_for('home'))

@app.route('/analyze')
def route_analyze():
    show_hash_info()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
