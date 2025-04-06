# decorators.py
from functools import wraps
from flask import redirect, url_for, flash
from flask_login import current_user

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.role != 'student':
            flash("This page is only accessible to students", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.role != 'teacher':
            flash("This page is only accessible to teachers", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function
