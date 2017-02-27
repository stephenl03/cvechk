from flask import render_template, flash, redirect, session, url_for, request


@app.route('/')
def display_index():
    return render_template('index.html')