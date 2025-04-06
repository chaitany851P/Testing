import base64
import smtplib
import string
import uuid
from email.message import EmailMessage
from random import random
from venv import logger
import random
from utils import characters
import firebase_admin
import length
from pytz import utc
from firebase_admin import credentials, firestore , initialize_app
from flask import Flask, flash, render_template, request, redirect, url_for, session, jsonify, current_app, logging
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import logging
from datetime import datetime, timedelta, date, timezone
import re
from functools import wraps
import json
from firebase_admin import credentials

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MAIL_USERNAME'] = 'innerlightadvisor@gmail.com'
app.config['MAIL_PASSWORD'] = 'rtbd qmce vzdu dzip'
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB limit (Firestore constraint)
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587  # For TLS
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'innerlightadvisor@gmail.com'

# Initialize Flask-Mail
mail = Mail(app)

# Initialize Firebase
cred_json = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS_JSON')
cred_dict = json.loads(cred_json)
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)
db = firestore.client()

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Role-based decorators (assumed from fs.py)
def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'student':
            flash("This page is only accessible to students.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'teacher':
            flash("This page is only accessible to teachers.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# User Classes
class User(UserMixin):
    def __init__(self, id, name, email, role, enrolled_courses=None, completed_courses=None, learning_style=None):
        self.id = id
        self.name = name
        self.email = email
        self.role = role
        self.enrolled_courses = enrolled_courses if enrolled_courses is not None else []
        self.completed_courses = completed_courses if completed_courses is not None else []
        self.learning_style = learning_style

    def get_id(self):
        return self.id

class Student(User):
    def __init__(self, id, name, dob, phone, username, email, password, learning_style, img=None):
        super().__init__(
            id=id,
            name=name,
            email=email,
            role='student',
            enrolled_courses=[],
            completed_courses=[],
            learning_style=learning_style
        )
        self.dob = dob
        self.phone = phone
        self.username = username
        self.password = password
        self.img = img

    def enroll_course(self, course_id, transaction=None):
        updates = {
            f'courses_enrolled.{course_id}': {
                'completed_chapters': [],
                'enrolled_at': firestore.SERVER_TIMESTAMP
            },
            'last_updated': firestore.SERVER_TIMESTAMP
        }
        if transaction:
            student_ref = db.collection("students").document(self.id)
            transaction.update(student_ref, updates)
        else:
            db.collection("students").document(self.id).update(updates)

    def complete_chapter(self, course_id, chapter_index, transaction=None):
        updates = {
            f'courses_enrolled.{course_id}.completed_chapters': firestore.ArrayUnion([chapter_index]),
            'last_updated': firestore.SERVER_TIMESTAMP
        }
        if transaction:
            student_ref = db.collection("students").document(self.id)
            transaction.update(student_ref, updates)
        else:
            db.collection("students").document(self.id).update(updates)

class Teacher(User):
    def __init__(self, id, name, dob, phone, username, email, password, learning_style, education=None, img=None, signature=None):
        super().__init__(id=id, name=name, email=email, role='teacher', learning_style=learning_style)
        self.dob = dob
        self.phone = phone
        self.username = username
        self.password = password
        self.education = education if education else []
        self.img = img
        self.signature = signature
        self.courses_taught = []
        self.tasks = []
        self.upi_qr = None

class Admin(UserMixin):
    def __init__(self, id, username, email, password, permissions=None, img=None):
        self.id = id
        self.username = username
        self.email = email
        self.password = password
        self.permissions = permissions or []
        self.img = img
        self.role = "admin"

    def get_id(self):
        return str(self.id)

    @property
    def is_admin(self):
        return True

    def has_permission(self, permission):
        return permission in self.permissions

# Task Class
class Task:
    def __init__(self, title, description, teacher_id, due_date, status="Pending"):
        self.title = title
        self.description = description
        self.teacher_id = teacher_id
        self.due_date = due_date
        self.status = status

    def save_to_firestore(self):
        task_data = {
            "title": self.title,
            "description": self.description,
            "teacher_id": self.teacher_id,
            "due_date": self.due_date,
            "status": self.status
        }
        db.collection("tasks").add(task_data)

    @staticmethod
    def get_task(task_id):
        task_ref = db.collection("tasks").document(task_id)
        task = task_ref.get()
        if task.exists:
            return task.to_dict()
        return None

# Admin Creation
def create_admin(username, email, password, permissions=None, img_url=None):
    try:
        for collection in ['admins', 'teachers', 'students']:
            if db.collection(collection).where('email', '==', email).get():
                return False, f"Email {email} already exists in {collection}", None
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        if not permissions:
            permissions = ['manage_users', 'manage_courses', 'view_reports']
        admin_data = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'permissions': permissions,
            'role': 'admin',
            'created_at': firestore.SERVER_TIMESTAMP,
            'last_updated': firestore.SERVER_TIMESTAMP
        }
        if img_url:
            admin_data['img'] = img_url
        admin_ref = db.collection('admins').document()
        admin_ref.set(admin_data)
        return True, "Admin created successfully", admin_ref.id
    except Exception as e:
        return False, f"Error creating admin: {str(e)}", None

# User Loader
@login_manager.user_loader
def load_user(user_id):
    admin_ref = db.collection("admins").document(user_id).get()
    if admin_ref.exists:
        admin_data = admin_ref.to_dict()
        return Admin(
            id=user_id,
            username=admin_data.get("username"),
            email=admin_data.get("email"),
            password=admin_data.get("password"),
            permissions=admin_data.get("permissions", []),
            img=admin_data.get("img", None)
        )
    teacher_ref = db.collection("teachers").document(user_id).get()
    if teacher_ref.exists:
        user_data = teacher_ref.to_dict()
        return Teacher(
            id=user_id,
            name=user_data.get("username"),
            dob=user_data.get("dob", ""),
            phone=user_data.get("phone", ""),
            username=user_data.get("username"),
            email=user_data.get("email"),
            password=user_data.get("password"),
            learning_style=user_data.get("learning_style"),
            education=user_data.get("education", []),
            img=user_data.get("img"),
            signature=user_data.get("signature")
        )
    student_ref = db.collection("students").document(user_id).get()
    if student_ref.exists:
        user_data = student_ref.to_dict()
        return Student(
            id=user_id,
            name=user_data.get("username"),
            dob=user_data.get("dob", ""),
            phone=user_data.get("phone", ""),
            username=user_data.get("username"),
            email=user_data.get("email"),
            password=user_data.get("password"),
            learning_style=user_data.get("learning_style", "Unassigned"),
            img=user_data.get("img")
        )
    return None

# Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        collection_name = "students" if role == "student" else "teachers"
        users_ref = db.collection(collection_name)
        
        # Check if email already exists in either students or teachers collection
        existing_email_students = db.collection("students").where("email", "==", email).stream()
        existing_email_teachers = db.collection("teachers").where("email", "==", email).stream()
        
        if any(existing_email_students) or any(existing_email_teachers):
            flash('Email already exists!', 'danger')
            return redirect(url_for('signup'))
            
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        if role == "teacher":
            user_data = {
                "username": username,
                "email": email,
                "password": hashed_password,
                "role": role,
                "learning_style": "Unassigned",
                "courses_taught": [],
                "dob": request.form.get("dob", ""),
                "phone": request.form.get("phone", ""),
                "education": request.form.get("education", ""),
                "img": None,
                "signature": None
            }
        else:
            user_data = {
                "username": username,
                "email": email,
                "password": hashed_password,
                "role": role,
                "learning_style": "Unassigned",
                "courses_enrolled": [],
                "courses_completed": []
            }
            
        # Use email as document ID instead of username
        users_ref.document(email).set(user_data)
        session['email'] = email  # Store email in session instead of username
        session['role'] = role
        flash('Signup successful!', 'success')
        return redirect(url_for('learning_style_test'))
    
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if not email or not password:
            flash('Please enter both email and password', 'danger')
            return redirect(url_for('login'))
        user_obj = None
        user_role = None
        for collection in ['admins', 'teachers', 'students']:
            users_ref = db.collection(collection).where('email', '==', email).limit(1).stream()
            for user in users_ref:
                user_data = user.to_dict()
                if not check_password_hash(user_data.get('password', ''), password):
                    continue
                if collection == 'admins':
                    user_obj = Admin(
                        id=user.id,
                        username=user_data.get('username', ''),
                        email=email,
                        password=user_data.get('password'),
                        permissions=user_data.get('permissions', []),
                        img=user_data.get('img')
                    )
                    user_role = 'admin'
                elif collection == 'teachers':
                    user_obj = Teacher(
                        id=user.id,
                        name=user_data.get('username', ''),
                        dob=user_data.get('dob'),
                        phone=user_data.get('phone', ''),
                        username=user_data.get('username', ''),
                        email=email,
                        password=user_data.get('password'),
                        learning_style=user_data.get('learning_style'),
                        education=user_data.get('education', []),
                        img=user_data.get('img'),
                        signature=user_data.get('signature')
                    )
                    user_role = 'teacher'
                elif collection == 'students':
                    user_obj = Student(
                        id=user.id,
                        name=user_data.get('username', ''),
                        dob=user_data.get('dob'),
                        phone=user_data.get('phone', ''),
                        username=user_data.get('username', ''),
                        email=email,
                        password=user_data.get('password'),
                        learning_style=user_data.get('learning_style'),
                        img=user_data.get('img')
                    )
                    user_role = 'student'
                break
            if user_obj:
                break
        if not user_obj:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
        login_user(user_obj)
        session['role'] = user_role
        db.collection('login_activity').add({
            'user_id': user_obj.id,
            'email': email,
            'role': user_role,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'ip_address': request.remote_addr
        })
        flash("Login successful!", "success")
        next_page = request.args.get('next')
        return redirect(next_page or url_for('dashboard'))
    return render_template('login.html')

@app.route('/courses', methods=['GET', 'POST'])
@login_required
def courses():
    try:
        level = request.args.get('level', '')
        domain = request.args.get('domain', '')
        language = request.args.get('language', '')
        payment = request.args.get('payment', '')
        current_filters = {'level': level, 'domain': domain, 'language': language, 'payment': payment}

        if current_user.role == 'admin':
            query = db.collection('courses')
        elif current_user.role == 'student':
            # For students, only show active courses unless enrolled
            user_data = db.collection('students').document(current_user.id).get().to_dict()
            enrolled_course_ids = user_data.get('courses_enrolled', [])
            query = db.collection('courses').where("status", "==", "active")
            if current_user.learning_style in ['Visual', 'Auditory', 'Kinesthetic']:
                query = query.where("learner_type", "==", current_user.learning_style)
        elif current_user.role == 'teacher':
            query = db.collection('courses').where("teacher_id", "==", current_user.id)

        if level:
            query = query.where("level", "==", level)
        if domain:
            query = query.where("domain", "==", domain)
        if language:
            query = query.where("language", "==", language)
        if payment:
            query = query.where("payment", "==", payment)

        docs = query.order_by("timestamp", direction=firestore.Query.DESCENDING).stream()
        courses = []
        if current_user.role == 'student':
            for doc in docs:
                course_data = doc.to_dict()
                course_id = doc.id
                # Show pending courses only if student is enrolled
                if course_data['status'] == 'pending' and course_id not in enrolled_course_ids:
                    continue
                courses.append({
                    'id': course_id,
                    'name': course_data['name'],
                    'description': course_data['description'],
                    'thumbnail_img': course_data.get('thumbnail_img'),
                    'status': course_data['status']
                })
        else:
            # Admins and teachers see all their courses regardless of status
            for doc in docs:
                course_data = doc.to_dict()
                courses.append({
                    'id': doc.id,
                    'name': course_data['name'],
                    'description': course_data['description'],
                    'thumbnail_img': course_data.get('thumbnail_img'),
                    'status': course_data['status']
                })

        domains = [{'name': doc.to_dict().get('name', '')} for doc in db.collection('domains').stream()] or [{'name': 'Technology'}, {'name': 'Science'}]
        languages = [{'name': doc.to_dict().get('name', '')} for doc in db.collection('languages').stream()] or [{'name': 'English'}, {'name': 'Spanish'}]
        return render_template('courses.html', courses=courses, domains=domains, languages=languages, current_filters=current_filters)
    except Exception as e:
        flash(f"Error loading courses: {str(e)}", "error")
        return redirect(url_for('index'))

def extract_youtube_id(url):
    patterns = [
        r'(?:https?:\/\/)?(?:www\.)?youtu\.be\/([a-zA-Z0-9_-]+)',
        r'(?:https?:\/\/)?(?:www\.)?youtube\.com\/watch\?v=([a-zA-Z0-9_-]+)',
        r'(?:https?:\/\/)?(?:www\.)?youtube\.com\/embed\/([a-zA-Z0-9_-]+)',
        r'(?:https?:\/\/)?(?:www\.)?youtube\.com\/v\/([a-zA-Z0-9_-]+)',
        r'(?:https?:\/\/)?(?:www\.)?youtube\.com\/shorts\/([a-zA-Z0-9_-]+)'
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None


def generate_room_id(length=8):
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))



@app.route('/add_course', methods=['GET', 'POST'])
@login_required
def add_course():
    if request.method == 'GET':
        domains = [{'name': 'Technology'}, {'name': 'Science'}]
        languages = [{'name': 'English'}, {'name': 'Spanish'}]
        return render_template('add_course.html', domains=domains, languages=languages)

    if request.method == 'POST':
        try:
            logging.info(f"Form data: {request.form}")
            logging.info(f"Files: {request.files}")
            required_fields = ['name', 'description', 'level', 'domain', 'language', 'payment', 'mode_of_class', 'learner_type', 'chapter_count']
            for field in required_fields:
                if field not in request.form or not request.form[field]:
                    raise ValueError(f"Missing or empty required field: {field}")

            domain = request.form['domain']
            if domain == 'Add New' and 'new_domain' in request.form and request.form['new_domain']:
                domain = request.form['new_domain'].strip()

            language = request.form['language']
            if language == 'Add New' and 'new_language' in request.form and request.form['new_language']:
                language = request.form['new_language'].strip()

            mode_of_class = request.form['mode_of_class']
            room_id = generate_room_id() if mode_of_class == 'Live' else None

            course_data = {
                'name': request.form['name'],
                'description': request.form['description'],
                'level': request.form['level'],
                'domain': domain,
                'language': language,
                'payment': request.form['payment'],
                'mode_of_class': mode_of_class,
                'learner_type': request.form['learner_type'],
                'chapter_count': int(request.form['chapter_count']),
                'quiz_count': int(request.form.get('quiz_count', 0)),
                'teacher_id': current_user.id,
                'teacher_name': current_user.name,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'status': 'pending',
                'rating': 0.0,
                'rating_count': 0,
                'enrollment_count': 0,
                'room_id': room_id,  # Store room ID at root
            }

            if course_data['payment'] == 'Paid':
                if 'price' not in request.form or not request.form['price']:
                    raise ValueError("Price is required for paid courses")
                course_data['price'] = float(request.form['price'])
            else:
                course_data['price'] = 0.0

            file = request.files.get('thumbnail_img')
            if file and file.filename:
                if file.content_length and file.content_length < app.config['MAX_CONTENT_LENGTH']:
                    filename = secure_filename(file.filename)
                    image_data = base64.b64encode(file.read()).decode('utf-8')
                    course_data['thumbnail_img'] = {
                        'name': filename,
                        'data': image_data,
                        'content_type': file.content_type or 'image/jpeg'
                    }
                else:
                    file_content = file.read()
                    if len(file_content) < app.config['MAX_CONTENT_LENGTH']:
                        filename = secure_filename(file.filename)
                        image_data = base64.b64encode(file_content).decode('utf-8')
                        course_data['thumbnail_img'] = {
                            'name': filename,
                            'data': image_data,
                            'content_type': file.content_type or 'image/jpeg'
                        }
                    else:
                        raise ValueError("Thumbnail image exceeds 1MB limit")
            else:
                course_data['thumbnail_img'] = None

            sample_video_url = request.form.get('temp_video', '').strip()
            course_data['sample_video'] = extract_youtube_id(sample_video_url) if sample_video_url else None

            chapters = []
            for i in range(1, course_data['chapter_count'] + 1):
                chapter = {
                    'title': request.form[f'chapter_{i}_title'],
                    'description': request.form[f'chapter_{i}_description'],
                    'note': request.form.get(f'chapter_{i}_note', '')
                }
                if mode_of_class == 'Live':
                    # Use the course-level meeting link instead of chapter-specific
                    chapter['date'] = request.form.get(f'chapter_{i}_date', '')
                    chapter['time'] = request.form.get(f'chapter_{i}_time', '')
                else:
                    video_url = request.form.get(f'chapter_{i}_course_link', '')
                    chapter['video_id'] = extract_youtube_id(video_url) if video_url else None

                assignment_link = request.form.get(f'chapter_{i}_assignment_link', '')
                if assignment_link:
                    chapter['assignment'] = {
                        'link': assignment_link,
                        'name': request.form.get(f'chapter_{i}_assignment_name', f'Chapter {i} Assignment')
                    }
                resource_link = request.form.get(f'chapter_{i}_resources_link', '')
                if resource_link:
                    chapter['resources'] = {
                        'link': resource_link,
                        'name': request.form.get(f'chapter_{i}_resources_name', f'Chapter {i} Resources')
                    }
                chapters.append(chapter)
            course_data['chapters'] = chapters

            quizzes = []
            for i in range(1, course_data['quiz_count'] + 1):
                quiz_type = request.form[f'quiz_{i}_type']
                quiz = {
                    'type': quiz_type,
                    'question': request.form[f'quiz_{i}_question'],
                    'options': {
                        '1': request.form.get(f'quiz_{i}_option_1', ''),
                        '2': request.form.get(f'quiz_{i}_option_2', ''),
                        '3': request.form.get(f'quiz_{i}_option_3', ''),
                        '4': request.form.get(f'quiz_{i}_option_4', '')
                    }
                }
                if quiz_type == 'Multiple Choices':
                    correct_answers = request.form.getlist(f'quiz_{i}_correct_answers')
                    quiz['correct_answers'] = correct_answers
                else:
                    correct_answer = request.form.get(f'quiz_{i}_correct_answer', '')
                    quiz['correct_answer'] = correct_answer
                quizzes.append(quiz)
            course_data['quizzes'] = quizzes

            msg = Message(
                subject="Your Course Submission is Being Reviewed",
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[current_user.email],
                bcc=['chaitanyathaker777@gmail.com'],
                body=f"""Dear {current_user.name},
Your course, {request.form['name']}, has been submitted for review.
It will be available to students once approved.
Best,
The Inner Light Advisor Team"""
            )
            mail.send(msg)

            doc_ref = db.collection('courses').add(course_data)
            flash("Course added successfully! It's now under review.", "success")
            return redirect(url_for('courses'))

        except ValueError as ve:
            flash(f"Validation error: {str(ve)}", "error")
            return redirect(url_for('add_course'))
        except Exception as e:
            flash(f"Unexpected error: {str(e)}", "error")
            return redirect(url_for('add_course'))

MOTIVATIONAL_QUOTES = [
    "You're a teaching rockstar—keep shining!",
    "Another masterpiece updated—way to go!",
    "Education just got cooler thanks to you!",
    "Your course edits are pure genius—bravo!",
    "The world’s a smarter place because of you!"
]


@app.route('/edit_course/<course_id>', methods=['GET', 'POST'])
@login_required
def edit_course(course_id):
    course_ref = db.collection('courses').document(course_id)
    course_doc = course_ref.get()

    if not course_doc.exists:
        flash("Course not found.", "error")
        return redirect(url_for('courses'))

    course_data = course_doc.to_dict()
    if course_data['teacher_id'] != current_user.id:
        flash("You don’t have permission to edit this course.", "error")
        return redirect(url_for('courses'))

    if request.method == 'GET':
        domains = [{'name': 'Technology'}, {'name': 'Science'}]
        languages = [{'name': 'English'}, {'name': 'Spanish'}]
        return render_template('edit_course.html', course=course_data, domains=domains, languages=languages)

    if request.method == 'POST':
        try:
            required_fields = ['name', 'description', 'level', 'domain', 'language',
                               'payment', 'mode_of_class', 'learner_type']
            for field in required_fields:
                if field not in request.form or not request.form[field]:
                    raise ValueError(f"Missing or empty required field: {field}")

            domain = request.form['domain']
            if domain == 'Add New' and 'new_domain' in request.form and request.form['new_domain']:
                domain = request.form['new_domain'].strip()

            language = request.form['language']
            if language == 'Add New' and 'new_language' in request.form and request.form['new_language']:
                language = request.form['new_language'].strip()

            updated_course_data = {
                'name': request.form['name'],
                'description': request.form['description'],
                'level': request.form['level'],
                'domain': domain,
                'language': language,
                'payment': request.form['payment'],
                'mode_of_class': request.form['mode_of_class'],
                'learner_type': request.form['learner_type'],
                'teacher_id': current_user.id,
                'teacher_name': current_user.name,
                'timestamp': course_data['timestamp'],
                'status': 'pending',  # Set status to pending after edit
                'rating': course_data.get('rating', 0.0),
                'rating_count': course_data.get('rating_count', 0),
                'enrollment_count': course_data.get('enrollment_count', 0),
                'last_updated': firestore.SERVER_TIMESTAMP  # Track last update time
            }

            if updated_course_data['payment'] == 'Paid':
                if 'price' not in request.form or not request.form['price']:
                    raise ValueError("Price is required for paid courses")
                updated_course_data['price'] = float(request.form['price'])
            else:
                updated_course_data['price'] = 0.0

            file = request.files.get('thumbnail_img')
            if file and file.filename:
                if file.content_length and file.content_length < app.config['MAX_CONTENT_LENGTH']:
                    filename = secure_filename(file.filename)
                    image_data = base64.b64encode(file.read()).decode('utf-8')
                    updated_course_data['thumbnail_img'] = {
                        'name': filename,
                        'data': image_data,
                        'content_type': file.content_type or 'image/jpeg'
                    }
                else:
                    file_content = file.read()
                    if len(file_content) < app.config['MAX_CONTENT_LENGTH']:
                        filename = secure_filename(file.filename)
                        image_data = base64.b64encode(file_content).decode('utf-8')
                        updated_course_data['thumbnail_img'] = {
                            'name': filename,
                            'data': image_data,
                            'content_type': file.content_type or 'image/jpeg'
                        }
                    else:
                        raise ValueError(f"Thumbnail image exceeds size limit")
            else:
                updated_course_data['thumbnail_img'] = course_data.get('thumbnail_img')

            sample_video_url = request.form.get('temp_video', '').strip()
            updated_course_data['sample_video'] = extract_youtube_id(
                sample_video_url) if sample_video_url else course_data.get('sample_video')

            # Dynamically process chapters and quizzes (unchanged for brevity)
            chapters = []
            i = 1
            while f'chapter_{i}_title' in request.form:
                chapter = {
                    'title': request.form[f'chapter_{i}_title'],
                    'description': request.form[f'chapter_{i}_description'],
                    'note': request.form.get(f'chapter_{i}_note', '')
                }
                if updated_course_data['mode_of_class'] == 'Live':
                    chapter['meeting_link'] = request.form.get(f'chapter_{i}_meeting_link', '')
                    chapter['date'] = request.form.get(f'chapter_{i}_date', '')
                    chapter['time'] = request.form.get(f'chapter_{i}_time', '')
                else:
                    video_url = request.form.get(f'chapter_{i}_course_link', '')
                    chapter['video_id'] = extract_youtube_id(video_url) if video_url else None

                assignment_link = request.form.get(f'chapter_{i}_assignment_link', '')
                if assignment_link:
                    chapter['assignment'] = {
                        'link': assignment_link,
                        'name': request.form.get(f'chapter_{i}_assignment_name', f'Chapter {i} Assignment')
                    }

                resource_link = request.form.get(f'chapter_{i}_resources_link', '')
                if resource_link:
                    chapter['resources'] = {
                        'link': resource_link,
                        'name': request.form.get(f'chapter_{i}_resources_name', f'Chapter {i} Resources')
                    }

                chapters.append(chapter)
                i += 1
            updated_course_data['chapter_count'] = len(chapters)
            updated_course_data['chapters'] = chapters

            quizzes = []
            i = 1
            while f'quiz_{i}_type' in request.form:
                quiz_type = request.form[f'quiz_{i}_type']
                quiz = {
                    'type': quiz_type,
                    'question': request.form[f'quiz_{i}_question'],
                    'options': {
                        '1': request.form.get(f'quiz_{i}_option_1', ''),
                        '2': request.form.get(f'quiz_{i}_option_2', ''),
                        '3': request.form.get(f'quiz_{i}_option_3', ''),
                        '4': request.form.get(f'quiz_{i}_option_4', '')
                    }
                }
                if quiz_type == 'Multiple Choices':
                    correct_answers = request.form.getlist(f'quiz_{i}_correct_answers')
                    quiz['correct_answers'] = correct_answers
                else:
                    correct_answer = request.form.get(f'quiz_{i}_correct_answer', '')
                    quiz['correct_answer'] = correct_answer
                quizzes.append(quiz)
                i += 1
            updated_course_data['quiz_count'] = len(quizzes)
            updated_course_data['quizzes'] = quizzes

            # Notify teacher and admin
            msg = Message(
                subject="Your Course Update is Being Reviewed",
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[current_user.email],
                bcc=['chaitanyathaker777@gmail.com'],  # Admin email
                body=f"""Dear {current_user.name},

Your updated course "{request.form['name']}" has been submitted for review. It will be hidden from new students until approved by an admin. Enrolled students can still access the current version.

Best regards,
The Inner Light Advisor Team"""
            )
            mail.send(msg)

            # Notify enrolled students (optional)
            enrolled_students = db.collection('students').where('courses_enrolled', 'array_contains', course_id).stream()
            for student_doc in enrolled_students:
                student_data = student_doc.to_dict()
                student_msg = Message(
                    subject="Course Update Notification",
                    sender=app.config['MAIL_DEFAULT_SENDER'],
                    recipients=[student_data['email']],
                    body=f"""Dear {student_data['username']},

The course "{course_data['name']}" you are enrolled in has been updated by the teacher. The updated version is under review and will be available once approved. You can continue accessing the current version until then.

Best regards,
The Inner Light Advisor Team"""
                )
                mail.send(student_msg)

            course_ref.update(updated_course_data)
            flash("Course updated successfully! It’s under review and hidden from new students until approved.", "success")
            return redirect(url_for('courses'))

        except ValueError as ve:
            flash(f"Validation error: {str(ve)}", "error")
            return redirect(url_for('edit_course', course_id=course_id))
        except Exception as e:
            flash(f"Unexpected error: {str(e)}", "error")
            return redirect(url_for('edit_course', course_id=course_id))


@app.route('/course/<string:course_id>')
@login_required
def course_detail(course_id):
    try:
        # Fetch course data
        course_ref = db.collection('courses').document(course_id)
        course_data = course_ref.get()
        if not course_data.exists:
            flash("Course not found", "error")
            return redirect(url_for('courses'))
        course = course_data.to_dict()
        course['id'] = course_id

        # Fetch user data
        user_collection = f"{current_user.role}s"  # e.g., "students" or "teachers"
        user_ref = db.collection(user_collection).document(current_user.id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            logger.warning(f"User document not found for {current_user.id} in {user_collection}")
            user_data = {}
        else:
            user_data = user_doc.to_dict()
        enrolled = course_id in user_data.get('courses_enrolled', [])
        completed = course_id in user_data.get('completed_courses', [])

        # Fetch teacher data
        teacher_id = course.get('teacher_id')
        if not teacher_id:
            logger.error(f"No teacher_id found in course {course_id}")
            teacher = {'name': 'Unknown Teacher', 'email': 'N/A'}
        else:
            teacher_ref = db.collection('teachers').document(teacher_id)
            teacher_doc = teacher_ref.get()
            if not teacher_doc.exists:
                logger.warning(f"Teacher document not found for {teacher_id}")
                teacher = {'name': 'Unknown Teacher', 'email': 'N/A'}
            else:
                teacher = teacher_doc.to_dict()

        # Calculate enrolled count (example: count documents referencing this course)
        enrolled_count = db.collection('students').where('courses_enrolled', 'array_contains', course_id).get()
        enrolled_count = len([doc for doc in enrolled_count])

        # Pass all required data to template
        return render_template(
            'course_detail.html',
            course=course,
            teacher=teacher,
            enrolled=enrolled,
            completed=completed,
            chapters=course.get('chapters', []),
            enrolled_count=enrolled_count,
            is_enrolled=enrolled  # Alias for template consistency
        )
    except Exception as e:
        logger.error(f"Error loading course detail for {course_id}: {str(e)}", exc_info=True)
        flash("Error loading course details", "error")
        return redirect(url_for('courses'))

@app.route('/enroll/<course_id>', methods=['POST'])
@login_required
def enroll(course_id):
    try:
        if current_user.role != 'student':
            flash("Only students can enroll in courses.", "error")
            return redirect(url_for('course_detail', course_id=course_id))
        course_ref = db.collection('courses').document(course_id)
        course_doc = course_ref.get()
        if not course_doc.exists:
            flash("Course not found.", "error")
            return redirect(url_for('courses'))
        course = course_doc.to_dict()
        student_ref = db.collection('students').document(current_user.id)
        student_doc = student_ref.get()
        if not student_doc.exists:
            flash("Student profile not found.", "error")
            return redirect(url_for('logout'))
        student_data = student_doc.to_dict()
        courses_enrolled = student_data.get('courses_enrolled', [])
        if course_id in courses_enrolled:
            flash("You are already enrolled in this course.", "error")
            return redirect(url_for('course_detail', course_id=course_id))
        course_ref.update({
            'enrollment_count': firestore.Increment(1)
        })
        student_ref.update({
            'courses_enrolled': firestore.ArrayUnion([course_id])
        })
        flash("Successfully enrolled in the course!", "success")
        return redirect(url_for('course_detail', course_id=course_id))
    except Exception as e:
        flash(f"Error enrolling in course: {str(e)}", "error")
        return redirect(url_for('course_detail', course_id=course_id))

@app.route('/rate_course/<course_id>', methods=['POST'])
@login_required
@student_required
def rate_course(course_id):
    try:
        rating = int(request.form.get('rating', 0))
        if not 1 <= rating <= 5:
            flash("Rating must be between 1 and 5", "error")
            return redirect(url_for('course_detail', course_id=course_id))
        student_ref = db.collection('students').document(current_user.id)
        student_data = student_ref.get().to_dict()
        if course_id not in student_data.get('courses_enrolled', []):
            flash("You must be enrolled to rate this course", "error")
            return redirect(url_for('course_detail', course_id=course_id))
        rating_ref = db.collection('ratings').where('user_id', '==', current_user.id).where('course_id', '==', course_id)
        existing_ratings = list(rating_ref.stream())
        if existing_ratings:
            rating_id = existing_ratings[0].id
            db.collection('ratings').document(rating_id).update({
                'rating': rating,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
        else:
            rating_data = {
                'user_id': current_user.id,
                'course_id': course_id,
                'rating': rating,
                'created_at': firestore.SERVER_TIMESTAMP,
                'updated_at': firestore.SERVER_TIMESTAMP
            }
            db.collection('ratings').add(rating_data)
        ratings_ref = db.collection('ratings').where('course_id', '==', course_id)
        ratings = list(ratings_ref.stream())
        total_ratings = len(ratings)
        sum_ratings = sum(r.to_dict().get('rating', 0) for r in ratings)
        average_rating = sum_ratings / total_ratings if total_ratings > 0 else 0
        db.collection('courses').document(course_id).update({
            'rating': average_rating,
            'rating_count': total_ratings
        })
        flash("Thank you for rating this course!", "success")
        return redirect(url_for('course_detail', course_id=course_id))
    except Exception as e:
        flash(f"Error submitting rating: {str(e)}", "error")
        return redirect(url_for('course_detail', course_id=course_id))


ZEGO_APP_ID = os.getenv('ZEGO_APP_ID', '1801082928')  # Default for testing, replace with your actual ID
ZEGO_SERVER_SECRET = os.getenv('ZEGO_SERVER_SECRET',
                               '0d03fcf2fc1cf09f3198751083b06d2f')  # Default for testing, replace with your actual secret

app.config['ZEGO_APP_ID'] = ZEGO_APP_ID
app.config['ZEGO_SERVER_SECRET'] = ZEGO_SERVER_SECRET

@app.route('/view_chapter/<course_id>/', defaults={'chapter_index': 0})
@app.route('/view_chapter/<course_id>/<int:chapter_index>')
@login_required
def view_chapter(course_id, chapter_index):
    try:
        # Fetch the course from Firestore
        course_ref = db.collection('courses').document(course_id)
        course_doc = course_ref.get()
        current_app.logger.info(f"Fetching course - Course ID: {course_id}, Exists: {course_doc.exists}")

        if not course_doc.exists:
            flash("🚀 Course not found!", "error")
            current_app.logger.warning(f"Course not found: {course_id}")
            return redirect(url_for('courses'))

        # Convert course document to dictionary and add ID
        course = course_doc.to_dict()
        course['id'] = course_id

        # Validate chapter index
        if 'chapters' not in course or chapter_index < 0 or chapter_index >= len(course['chapters']):
            flash("📖 Invalid chapter!", "warning")
            current_app.logger.warning(f"Invalid chapter index: {chapter_index} for course {course_id}")
            return redirect(url_for('course_detail', course_id=course_id))

        chapter = course['chapters'][chapter_index]
        current_app.logger.info(f"Chapter loaded: {chapter.get('title', 'Untitled Chapter')}")

        # Handle enrollment and progress for students
        if current_user.role == 'student':
            enrollment_ref = db.collection('enrollments').where('user_id', '==', current_user.id).where('course_id', '==', course_id).limit(1).stream()
            enrollment = next(enrollment_ref, None)
            if enrollment:
                enrollment_data = enrollment.to_dict()
                completed_chapters = enrollment_data.get('completed_chapters', [])
                if chapter_index not in completed_chapters:
                    completed_chapters.append(chapter_index)
                    db.collection('enrollments').document(enrollment.id).update({
                        'completed_chapters': completed_chapters,
                        'progress': int((len(completed_chapters) / len(course['chapters'])) * 100),
                        'last_accessed': firestore.SERVER_TIMESTAMP
                    })
                    current_app.logger.info(
                        f"Updated enrollment for user {current_user.id}: Progress {int((len(completed_chapters) / len(course['chapters'])) * 100)}%")

        # Get room ID from URL query parameter
        room_id = request.args.get('roomID')
        current_app.logger.info(f"Room ID from URL: '{room_id}'")

        # Fallback to chapter's meeting_link if room_id is not provided
        if not room_id and 'meeting_link' in chapter:
            room_id = chapter['meeting_link']
            current_app.logger.info(f"Using chapter meeting_link as room_id: '{room_id}'")
        # Fallback to course-level room_id if neither URL param nor chapter meeting_link is available
        elif not room_id and 'room_id' in course:
            room_id = course['room_id']
            current_app.logger.info(f"Using course-level room_id as fallback: '{room_id}'")
        else:
            current_app.logger.info("No room_id provided via URL, chapter, or course")

        # Calculate XP earned
        xp_earned = 10 * (chapter_index + 1) + (5 if 'quiz' in chapter else 0)
        current_app.logger.info(f"XP earned for chapter {chapter_index}: {xp_earned}")

        # Verify Zego credentials are available
        if not app.config.get('ZEGO_APP_ID') or not app.config.get('ZEGO_SERVER_SECRET'):
            current_app.logger.error("Zego credentials missing in app config")
            flash("⚠️ Meeting feature unavailable due to configuration error.", "error")
        else:
            current_app.logger.info(
                f"Zego App ID: {app.config['ZEGO_APP_ID']}, Server Secret: {app.config['ZEGO_SERVER_SECRET']}")

        # Render the template with all necessary data
        return render_template(
            'view_chapter.html',
            course=course,
            course_id=course_id,
            chapter=chapter,
            chapter_index=chapter_index,
            xp_earned=xp_earned,
            total_chapters=len(course['chapters']),
            room_id=room_id,  # Pass room_id for JavaScript fallback
            zego_app_id=app.config['ZEGO_APP_ID'],
            zego_server_secret=app.config['ZEGO_SERVER_SECRET']
        )

    except Exception as e:
        current_app.logger.error(f"Chapter view error: {str(e)}", exc_info=True)
        flash("😢 Oops! Something went wrong while loading the chapter.", "error")
        return redirect(url_for('course_detail', course_id=course_id))


@app.route('/join/<course_id>/<int:chapter_index>', methods=['POST'])
@login_required
def join(course_id, chapter_index):
    try:
        course_ref = db.collection('courses').document(course_id)
        course_doc = course_ref.get()
        if not course_doc.exists:
            flash("🚀 Course not found!", "error")
            return redirect(url_for('courses'))

        course = course_doc.to_dict()
        if 'chapters' not in course or chapter_index >= len(course['chapters']):
            flash("📖 Invalid chapter!", "warning")
            return redirect(url_for('course_detail', course_id=course_id))

        chapter = course['chapters'][chapter_index]
        room_id = request.form.get('roomID')

        if not room_id:
            # If no roomID is provided in the form, fallback to chapter.meeting_link
            if 'meeting_link' in chapter:
                room_id = chapter['meeting_link']
                current_app.logger.info(f"No roomID in form, using chapter meeting_link: '{room_id}'")
            else:
                flash("🔑 Room ID is required!", "error")
                return redirect(url_for('view_chapter', course_id=course_id, chapter_index=chapter_index))

        current_app.logger.info(f"Joining meeting with Room ID: {room_id}")
        return redirect(
            url_for('view_chapter', course_id=course_id, chapter_index=chapter_index) + f'?roomID={room_id}')

    except Exception as e:
        current_app.logger.error(f"Join error: {str(e)}")
        flash("😢 Failed to join meeting!", "error")
        return redirect(url_for('view_chapter', course_id=course_id, chapter_index=chapter_index))




@app.route('/learning_style_test', methods=['GET', 'POST'])
@login_required
def learning_style_test():
    if request.method == 'GET':
        return render_template('test.html')
    form_data = request.form
    answers = {f'q{i}': form_data.get(f'q{i}') for i in range(1, 6)}
    if not all(answers.values()):
        flash("Please answer all questions.", "error")
        return redirect(url_for('learning_style_test'))
    visual = sum(1 for ans in answers.values() if ans == 'A')
    auditory = sum(1 for ans in answers.values() if ans == 'B')
    kinesthetic = sum(1 for ans in answers.values() if ans == 'C')
    style = 'Visual' if visual > max(auditory, kinesthetic) else 'Auditory' if auditory > kinesthetic else 'Kinesthetic'
    db.collection('students').document(current_user.id).update({
        'learning_style': style,
        'learning_style_scores': {'visual': visual, 'auditory': auditory, 'kinesthetic': kinesthetic}
    })
    flash(f"Your learning style is {style}!", "success")
    return redirect(url_for('dashboard'))

@app.route('/submit_feedback/<course_id>', methods=['POST'])
@login_required
def submit_feedback(course_id):
    app.logger.debug(f"Received course_id in submit_feedback: {course_id}")
    try:
        course_ref = db.collection('courses').document(course_id)
        course_doc = course_ref.get()
        if not course_doc.exists:
            flash("Course not found.", "error")
            return redirect(url_for('courses'))

        course_data = course_doc.to_dict()
        name = current_user.username
        email = current_user.email
        message = request.form.get('message', '').strip()

        if not message:
            flash("Please provide feedback.", "warning")
            return redirect(url_for('view_chapter', course_id=course_id, chapter_index=course_data.get('chapters', [])|length - 1))

        try:
            msg = EmailMessage()
            msg['From'] = 'innerlightadvisor@gmail.com'
            msg['To'] = email
            msg['Bcc'] = f'chaitanyathaker777@gmail.com, {course_data.get("teacher_email", "")}'
            msg['Subject'] = 'Thank you for your feedback'
            msg.set_content(f"Hi {name},\n\nThanks for your feedback!\nAbout: {message}\nWe'll get back to you soon.\n\nBest,\nInner Light Advisor Team")

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login('innerlightadvisor@gmail.com', app.config['MAIL_PASSWORD'])
                smtp.send_message(msg)

            flash("Feedback sent successfully!", "success")
        except (ConnectionRefusedError, smtplib.SMTPException) as e:
            app.logger.error(f"Error sending email: {str(e)}", exc_info=True)
            flash("There was a problem sending your feedback. Please try again later.", "error")

        return redirect(url_for('quiz', course_id=course_id))

    except Exception as e:
        app.logger.error(f"Error in submit_feedback: {str(e)}", exc_info=True)
        flash(f"An error occurred: {str(e)}", "error")
        return redirect(url_for('courses'))

@app.route('/quiz/<course_id>', methods=['GET', 'POST'])
@login_required
def quiz(course_id):
    app.logger.debug(f"Received course_id in quiz route: {course_id}, method: {request.method}")
    try:
        course_ref = db.collection('courses').document(course_id)
        course_doc = course_ref.get()
        if not course_doc.exists:
            flash("Course not found.", "error")
            return redirect(url_for('courses'))

        course_data = course_doc.to_dict()
        course_data['id'] = course_id

        app.logger.debug(f"Quizzes data: {course_data.get('quizzes', [])}")

        if request.method == 'POST':
            app.logger.debug(f"Raw form data: {request.form}")
            quizzes = course_data.get('quizzes', [])
            total_questions = len(quizzes)
            if total_questions == 0:
                flash("No quizzes available for this course.", "warning")
                return jsonify({"passed": False, "message": "No quizzes available", "course_id": course_id})

            correct_count = 0
            for i, quiz in enumerate(quizzes, 1):
                quiz_type = quiz.get('type', 'MCQ')
                if quiz_type == 'Multiple Choices':
                    question_key = f"question{i}[]"
                    submitted_answers = request.form.getlist(question_key)
                    correct_answers = quiz.get('correct_answers', [])
                    if sorted(submitted_answers) == sorted(correct_answers):
                        correct_count += 1
                    app.logger.debug(
                        f"Q{i} Multiple Choices - Submitted: {submitted_answers}, Correct: {correct_answers}")
                else:  # MCQ or True/False (single answer type)
                    question_key = f"question{i}"
                    submitted_key = request.form.get(question_key)  # directly gets the key
                    correct_answer = quiz.get('correct_answer')     # key like "1", "4", etc.
                    if submitted_key == correct_answer:
                        correct_count += 1
                    app.logger.debug(
                        f"Q{i} {quiz_type} - Submitted key: {submitted_key}, Correct: {correct_answer}")

            score = (correct_count / total_questions) * 100 if total_questions > 0 else 0
            passed = score >= 60
            app.logger.debug(f"Score: {score:.1f}%, Correct: {correct_count}/{total_questions}")

            if passed:
                # Fetch current user's completed_courses
                user_ref = db.collection('students').document(current_user.id)
                user_doc = user_ref.get()
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    completed_courses = user_data.get('completed_courses', [])
                    if course_id not in completed_courses:
                        completed_courses.append(course_id)
                        user_ref.set({'completed_courses': completed_courses}, merge=True)
                        app.logger.debug(f"Added course {course_id} to completed_courses: {completed_courses}")
                else:
                    # If user document doesn't exist, create it
                    user_ref.set({'completed_courses': [course_id], 'name': current_user.username}, merge=True)
                    app.logger.debug(f"Created user document with completed_courses: {[course_id]}")

                return jsonify({
                    "passed": True,
                    "message": f"Your score: {score:.1f}%. Congratulations, you passed!",
                    "course_id": course_id
                })
            else:
                return jsonify({
                    "passed": False,
                    "message": f"Your score: {score:.1f}%. Sorry, you didn’t pass. Try again!",
                    "course_id": course_id
                })

        return render_template('quiz.html', course=course_data, course_id=course_id)

    except Exception as e:
        app.logger.error(f"Error in quiz: {str(e)}", exc_info=True)
        flash(f"An error occurred: {str(e)}", "error")
        return redirect(url_for('courses'))


@app.route('/delete_course/<course_id>', methods=['POST'])
@login_required
def delete_course(course_id):
    course_ref = db.collection('courses').document(course_id)
    course_doc = course_ref.get()
    if not course_doc.exists:
        return jsonify({'message': 'Course not found'}), 404
    course = course_doc.to_dict()
    if course.get('teacher_id') != current_user.id:
        return jsonify({'message': 'You do not have permission to delete this course.'}), 403
    def delete_file(file_path):
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
    if 'thumbnail_img' in course:
        delete_file(course['thumbnail_img'])
    if 'temp_video' in course:
        delete_file(course['temp_video'])
    if 'chapters' in course:
        for chapter in course['chapters']:
            if 'resources_files' in chapter:
                for resource in chapter['resources_files']:
                    delete_file(resource)
            if 'assignment_file' in chapter:
                delete_file(chapter['assignment_file'])
            if 'course_file' in chapter:
                delete_file(chapter['course_file'])
    try:
        course_ref.delete()
        enrolled_students = db.collection('student_courses_enrolled').where('course_id', '==', course_id).stream()
        for doc in enrolled_students:
            doc.reference.delete()
        completed_students = db.collection('student_courses_completed').where('course_id', '==', course_id).stream()
        for doc in completed_students:
            doc.reference.delete()
    except Exception as e:
        return jsonify({'message': f'Failed to delete course from Firestore: {str(e)}'}), 500
    return redirect(url_for('courses'))

@app.route('/approve-course/<course_id>', methods=['POST'])
@login_required
def approve_course(course_id):
    if current_user.role != 'admin':
        flash("Unauthorized action!", "danger")
        return redirect(url_for('dashboard'))
    try:
        course_ref = db.collection("courses").document(course_id)
        course = course_ref.get()
        if not course.exists:
            flash("Course not found", "danger")
            return redirect(url_for('dashboard'))
        course_data = course.to_dict()
        if course_data.get('status') != 'pending':
            flash("Course is not in pending state", "warning")
            return redirect(url_for('course_detail', course_id=course_id))
        teacher_ref = db.collection("teachers").document(course_data['teacher_id'])
        teacher = teacher_ref.get()
        if not teacher.exists:
            flash("Teacher not found", "danger")
            return redirect(url_for('course_detail', course_id=course_id))
        teacher_data = teacher.to_dict()
        msg = Message(
            "Your Course Has Been Approved",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[teacher_data['email']]
        )
        msg.body = f"""Dear {teacher_data.get('username', 'Teacher')},
Your course "{course_data['name']}" has been approved and is now live!
Best regards,
The Learning Platform Team"""
        mail.send(msg)
        updates = {
            "status": "active",
            "approved_at": firestore.SERVER_TIMESTAMP,
            "approved_by": current_user.id,
            "last_updated": firestore.SERVER_TIMESTAMP
        }
        course_ref.update(updates)
        db.collection("notifications").add({
            "user_id": course_data['teacher_id'],
            "type": "course_approval",
            "title": "Course Approved",
            "message": f"Your course '{course_data['name']}' has been approved",
            "read": False,
            "created_at": firestore.SERVER_TIMESTAMP,
            "course_id": course_id
        })
        flash("Course approved successfully! Notification sent to teacher.", "success")
    except Exception as e:
        logger.error(f"Course approval error: {str(e)}")
        flash(f"Error approving course: {str(e)}", "danger")
    return redirect(url_for('dashboard'))

@app.route('/disapprove-course/<course_id>', methods=['POST'])
@login_required
def disapprove_course(course_id):
    if current_user.role != 'admin':
        flash("Unauthorized action!", "danger")
        return redirect(url_for('dashboard'))
    remarks = request.form.get('rejection_remarks')
    if not remarks or not remarks.strip():
        flash("Please provide valid remarks for disapproval", "warning")
        return redirect(url_for('course_detail', course_id=course_id))
    try:
        course_ref = db.collection("courses").document(course_id)
        course = course_ref.get()
        if not course.exists:
            flash("Course not found", "danger")
            return redirect(url_for('dashboard'))
        course_data = course.to_dict()
        teacher_ref = db.collection("teachers").document(course_data['teacher_id'])
        teacher = teacher_ref.get()
        if not teacher.exists:
            flash("Teacher not found", "danger")
            return redirect(url_for('course_detail', course_id=course_id))
        teacher_data = teacher.to_dict()
        msg = Message(
            "Course Submission Update",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[teacher_data['email']]
        )
        msg.body = f"""Dear {teacher_data.get('username', 'Teacher')},
Your course "{course_data['name']}" has not been approved.
Reason: {remarks.strip()}
Please review and resubmit.
Best regards,
The Learning Platform Team"""
        mail.send(msg)
        updates = {
            "status": "rejected",
            "rejected_at": firestore.SERVER_TIMESTAMP,
            "rejected_by": current_user.id,
            "rejection_remarks": remarks.strip(),
            "last_updated": firestore.SERVER_TIMESTAMP
        }
        course_ref.update(updates)
        db.collection("notifications").add({
            "user_id": course_data['teacher_id'],
            "type": "course_re'use strict';jection",
            "title": "Course Rejected",
            "message": f"Your course '{course_data['name']}' was rejected",
            "read": False,
            "created_at": firestore.SERVER_TIMESTAMP,
            "course_id": course_id
        })
        flash("Course rejected successfully. Feedback sent to teacher.", "success")
    except Exception as e:
        logger.error(f"Course rejection error: {str(e)}")
        flash(f"Error rejecting course: {str(e)}", "danger")
    return redirect(url_for('dashboard'))

@app.route('/admin/add', methods=['GET', 'POST'])
@login_required
def add_admin_route():
    if current_user.role != 'admin' or not current_user.has_permission('manage_users'):
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        permissions = request.form.getlist('permissions')
        img_url = request.form.get('img_url')
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for('add_admin_route'))
        success, message, admin_id = create_admin(
            username=username,
            email=email,
            password=password,
            permissions=permissions if permissions else None,
            img_url=img_url if img_url else None
        )
        if success:
            flash(f"Admin created successfully! ID: {admin_id}", "success")
            return redirect(url_for('dashboard'))
        else:
            flash(message, "danger")
    return render_template('add_admin.html')

@app.route('/teachers')
@login_required
def teachers():
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    try:
        teachers_ref = db.collection("teachers").stream()
        teacher_list = []
        for teacher in teachers_ref:
            teacher_data = teacher.to_dict()
            teacher_list.append({
                'id': teacher.id,
                'name': teacher_data.get('username', ''),
                'email': teacher_data.get('email', ''),
                'phone': teacher_data.get('phone', ''),
                'courses_count': len(teacher_data.get('courses_taught', [])),
                'status': teacher_data.get('status', 'active')
            })
        return render_template('teachers.html', teachers=teacher_list)
    except Exception as e:
        flash(f"Error loading teachers: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/edit_teacher/<teacher_id>', methods=['GET', 'POST'])
@login_required
def edit_teacher(teacher_id):
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    try:
        teacher_ref = db.collection("teachers").document(teacher_id)
        teacher = teacher_ref.get()
        if not teacher.exists:
            flash("Teacher not found", "danger")
            return redirect(url_for('teachers'))
        if request.method == 'POST':
            update_data = {
                'username': request.form['name'],
                'email': request.form['email'],
                'phone': request.form['phone'],
                'status': request.form['status'],
                'last_updated': firestore.SERVER_TIMESTAMP
            }
            if 'dob' in request.form:
                update_data['dob'] = request.form['dob']
            if 'learning_style' in request.form:
                update_data['learning_style'] = request.form['learning_style']
            teacher_ref.update(update_data)
            flash("Teacher updated successfully", "success")
            return redirect(url_for('teachers'))
        teacher_data = teacher.to_dict()
        return render_template('edit_teacher.html', teacher={**teacher_data, 'id': teacher_id})
    except Exception as e:
        flash(f"Error editing teacher: {str(e)}", "danger")
        return redirect(url_for('teachers'))

@app.route('/delete_teacher/<teacher_id>', methods=['POST'])
@login_required
def delete_teacher(teacher_id):
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    try:
        teacher_courses = db.collection("courses").where("teacher_id", "==", teacher_id).limit(1).stream()
        if any(teacher_courses):
            flash("Cannot delete teacher with assigned courses", "danger")
            return redirect(url_for('teachers'))
        db.collection("teachers").document(teacher_id).delete()
        flash("Teacher deleted successfully", "success")
        return redirect(url_for('teachers'))
    except Exception as e:
        flash(f"Error deleting teacher: {str(e)}", "danger")
        return redirect(url_for('teachers'))

@app.route('/students')
@login_required
def students():
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    try:
        students_ref = db.collection("students").stream()
        student_list = []
        for student in students_ref:
            student_data = student.to_dict()
            student_list.append({
                'id': student.id,
                'name': student_data.get('username', ''),
                'email': student_data.get('email', ''),
                'phone': student_data.get('phone', ''),
                'enrolled_courses': len(student_data.get('courses_enrolled', [])),
                'completed_courses': len(student_data.get('completed_courses', [])),
                'status': student_data.get('status', 'active')
            })
        return render_template('students.html', students=student_list)
    except Exception as e:
        flash(f"Error loading students: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/edit_student/<student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    try:
        student_ref = db.collection("students").document(student_id)
        student = student_ref.get()
        if not student.exists:
            flash("Student not found", "danger")
            return redirect(url_for('students'))
        if request.method == 'POST':
            update_data = {
                'username': request.form['name'],
                'email': request.form['email'],
                'phone': request.form['phone'],
                'status': request.form['status'],
                'learning_style': request.form['learning_style'],
                'last_updated': firestore.SERVER_TIMESTAMP
            }
            if 'dob' in request.form:
                update_data['dob'] = request.form['dob']
            student_ref.update(update_data)
            flash("Student updated successfully", "success")
            return redirect(url_for('students'))
        student_data = student.to_dict()
        return render_template('edit_student.html', student={**student_data, 'id': student_id})
    except Exception as e:
        flash(f"Error editing student: {str(e)}", "danger")
        return redirect(url_for('students'))



@app.route('/delete_student/<student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    if current_user.role != 'admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('dashboard'))
    try:
        student_ref = db.collection("students").document(student_id)
        student = student_ref.get()
        if not student.exists:
            flash("Student not found", "danger")
            return redirect(url_for('students'))
        student_ref.delete()
        flash("Student deleted successfully", "success")
        return redirect(url_for('students'))
    except Exception as e:
        flash(f"Error deleting student: {str(e)}", "danger")
        return redirect(url_for('students'))

@app.route('/schedule_live_class', methods=['GET', 'POST'])
@login_required
@teacher_required
def schedule_live_class():
    if request.method == 'GET':
        courses = []
        courses_ref = db.collection("courses").where("teacher_id", "==", current_user.id).where("mode_of_class", "==", "Live").stream()
        for course in courses_ref:
            course_data = course.to_dict()
            course_data['id'] = course.id
            course_data['chapters'] = course_data.get('chapters', [])
            courses.append(course_data)
        min_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        default_time = datetime.now(timezone.utc).strftime('%H:%M')
        return render_template('schedule_live_class.html',
                              courses=courses,
                              min_date=min_date,
                              default_time=default_time)

    elif request.method == 'POST':
        app.logger.debug(f"Received POST to schedule_live_class: {request.form}")
        try:
            course_id = request.form.get('course_id')
            if not course_id:
                flash("Please select a course.", "danger")
                return redirect(url_for('dashboard'))

            # Fetch the course to get its meeting_link
            course_ref = db.collection("courses").document(course_id)
            course_doc = course_ref.get()
            if not course_doc.exists:
                flash("Course not found", "danger")
                return redirect(url_for('dashboard'))
            course_data = course_doc.to_dict()
            if course_data['teacher_id'] != current_user.id:
                flash("You can only schedule live classes for your own courses", "danger")
                return redirect(url_for('course_detail', course_id=course_id))

            # Use the course's meeting_link (guaranteed to exist since it's set when course is created)
            meeting_link = course_data.get('meeting_link', None)
            if not meeting_link:
                flash("No meeting link found for this course. Please update the course.", "danger")
                return redirect(url_for('course_detail', course_id=course_id))

            title = request.form.get('title')
            description = request.form.get('description', '')
            chapter_id = request.form.get('chapter_id', '')
            scheduled_time_str = request.form.get('scheduled_time')
            duration = request.form.get('duration')

            if not all([title, scheduled_time_str, duration]):
                flash("Title, scheduled time, and duration are required", "warning")
                return redirect(url_for('course_detail', course_id=course_id))

            scheduled_time = datetime.strptime(scheduled_time_str, '%Y-%m-%dT%H:%M').replace(tzinfo=utc)
            now = datetime.now(timezone.utc)
            if scheduled_time <= now:
                flash("Scheduled time must be in the future", "warning")
                return redirect(url_for('course_detail', course_id=course_id))

            duration = int(duration)
            if duration < 15 or duration > 240:
                flash("Duration must be between 15 and 240 minutes", "warning")
                return redirect(url_for('course_detail', course_id=course_id))

            live_class_data = {
                'course_id': course_id,
                'teacher_id': current_user.id,
                'title': title,
                'description': description,
                'chapter_id': chapter_id if chapter_id else None,
                'meeting_link': meeting_link,  # Use the course's meeting link
                'scheduled_time': scheduled_time,
                'duration': duration,
                'created_at': firestore.SERVER_TIMESTAMP,
                'status': 'scheduled'
            }
            app.logger.debug(f"Saving live class data: {live_class_data}")
            live_class_ref = db.collection("live_classes").add(live_class_data)
            app.logger.debug(f"Live class saved with ID: {live_class_ref[1].id}")

            flash("Live class scheduled successfully!", "success")
            return redirect(url_for('course_detail', course_id=course_id))
        except Exception as e:
            app.logger.error(f"Error scheduling live class: {str(e)}", exc_info=True)
            flash(f"Error scheduling live class: {str(e)}", "danger")
            return redirect(url_for('dashboard'))


@app.route('/certificate/<course_id>', methods=['GET'])
@login_required
def certificate(course_id):
    app.logger.debug(f"Generating certificate for course_id: {course_id}")
    try:
        # Fetch course data from Firestore
        course_ref = db.collection('courses').document(course_id)
        course_doc = course_ref.get()
        if not course_doc.exists:
            flash("Course not found.", "error")
            return redirect(url_for('courses'))

        course_data = course_doc.to_dict()
        course_name = course_data.get('name', 'Unnamed Course')
        app.logger.debug(f"Course data: {course_data}")

        # Fetch user data
        user_ref = db.collection('students').document(current_user.id)
        user_doc = user_ref.get()
        if not user_doc.exists:
            flash("User not found.", "error")
            return redirect(url_for('courses'))

        user_data = user_doc.to_dict()
        user_name = user_data.get('name', current_user.username)
        completed_courses = user_data.get('completed_courses', [])
        app.logger.debug(f"User data - Name: {user_name}, Completed Courses: {completed_courses}")

        # Check if user completed the course
        if course_id not in completed_courses:
            flash("You have not completed this course yet.", "warning")
            return redirect(url_for('view_chapter',
                                    course_id=course_id,
                                    chapter_index=len(course_data.get('chapters', [])) - 1))

        # Fetch teacher data from teachers collection
        teacher_id = course_data.get('teacher_id')
        app.logger.debug(f"Teacher ID from course: {teacher_id}")

        if teacher_id:
            teacher_ref = db.collection('teachers').document(teacher_id)
            teacher_doc = teacher_ref.get()
            if teacher_doc.exists:
                teacher_data = teacher_doc.to_dict()
                teacher_name = teacher_data.get('name', teacher_id)
                teacher_signature = teacher_data.get('signature', None)

                # Print teacher name and signature to console for debugging
                print(f"Teacher Name: {teacher_name}")
                print(f"Teacher Signature Path: {teacher_signature}")

                if not teacher_name:
                    app.logger.warning(f"Teacher name missing for ID: {teacher_id}")
                    teacher_name = 'Unknown Instructor'
                if not teacher_signature:
                    app.logger.warning(f"Teacher signature missing for ID: {teacher_id}")
                    teacher_signature = None
            else:
                app.logger.warning(f"Teacher document not found for ID: {teacher_id}")
                teacher_name = 'UnknownInstructor'
                teacher_signature = None
        else:
            app.logger.warning(f"No teacher_id found in course document: {course_id}")
            teacher_name = 'Unknown Instructor'
            teacher_signature = None

        # Prepare URLs for images with defaults
        teacher_signature_url = url_for('static', filename=teacher_signature) if teacher_signature else url_for(
            'static', filename='img/default_signature.png')
        provider_stamp_url = url_for('static', filename='img/ila.png')

        app.logger.debug(f"Certificate data - User: {user_name}, Course: {course_name}, "
                         f"Teacher: {teacher_name}, Signature URL: {teacher_signature_url}")

        return render_template(
            'certificate.html',
            user_name=user_name,
            course_name=course_name,
            teacher_name=teacher_name,
            teacher_signature_url=teacher_signature_url,
            provider_stamp_url=provider_stamp_url,
            course_id=course_id
        )

    except Exception as e:
        app.logger.error(f"Error generating certificate: {str(e)}", exc_info=True)
        flash(f"An error occurred: {str(e)}", "error")
        return redirect(url_for('courses'))

from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
import logging

app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)

# Assuming db is your Firestore database instance
# from google.cloud import firestore
# db = firestore.Client()

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        if current_user.role == 'admin':
            total_courses = len(list(db.collection("courses").stream()))
            pending_courses_count = len(list(db.collection("courses").where("status", "==", "pending").stream()))
            total_teachers = len(list(db.collection("teachers").stream()))
            active_teachers = len(list(db.collection("teachers").where("status", "==", "active").stream()))
            total_students = len(list(db.collection("students").stream()))
            active_students = len(list(db.collection("students").where("status", "==", "active").stream()))

            pending_courses_ref = db.collection("courses").where("status", "==", "pending").stream()
            pending_courses = []
            for course in pending_courses_ref:
                course_data = course.to_dict()
                teacher_ref = db.collection("teachers").document(course_data["teacher_id"]).get()
                if teacher_ref.exists:
                    teacher_data = teacher_ref.to_dict()
                    course_data.update({
                        "id": course.id,
                        "teacher": {
                            "username": teacher_data.get("username", "Unknown"),
                            "email": teacher_data.get("email", "")
                        },
                        "thumbnail_url": course_data.get('thumbnail_img', {}).get('data', url_for('static', filename='img/default_thumbnail.jpg')) if isinstance(course_data.get('thumbnail_img'), dict) else url_for('static', filename='img/default_thumbnail.jpg')
                    })
                    pending_courses.append(course_data)

            return render_template('dashboard.html',
                                 stats={
                                     'total_courses': total_courses,
                                     'pending_courses': pending_courses_count,
                                     'total_teachers': total_teachers,
                                     'active_teachers': active_teachers,
                                     'total_students': total_students,
                                     'active_students': active_students
                                 },
                                 pending_courses=pending_courses)

        elif current_user.role == 'teacher':
            courses_ref = db.collection("courses").where("teacher_id", "==", current_user.id).stream()
            courses_list = []
            live_classes = []
            tasks = []

            # Fetch courses
            for course in courses_ref:
                course_data = course.to_dict()
                course_data['id'] = course.id
                course_data['thumbnail_url'] = course_data.get('thumbnail_img', {}).get('data', url_for('static', filename='img/default_thumbnail.jpg')) if isinstance(course_data.get('thumbnail_img'), dict) else url_for('static', filename='img/default_thumbnail.jpg')
                course_data.update({
                    'students': course_data.get('enrollment_count', 0),
                    'status': course_data.get('status', 'pending')
                })
                courses_list.append(course_data)

                # Fetch live classes
                if course_data.get('mode_of_class') == 'Live':
                    for index, chapter in enumerate(course_data.get('chapters', [])):
                        if 'date' in chapter and 'time' in chapter and 'meeting_link' in chapter:
                            try:
                                meeting_date = datetime.strptime(chapter['date'], '%Y-%m-%d')
                                live_classes.append({
                                    'course_id': course.id,
                                    'course_name': course_data['name'],
                                    'chapter_title': chapter.get('title', 'Untitled'),
                                    'chapter_index': index,
                                    'date': chapter['date'],
                                    'time': chapter['time'],
                                    'meeting_link': chapter['meeting_link']
                                })
                            except ValueError:
                                app.logger.warning(f"Invalid date format in course {course.id}")

            # Fetch tasks (assuming a tasks collection)
            tasks_ref = db.collection("tasks").where("teacher_id", "==", current_user.id).stream()
            for task in tasks_ref:
                task_data = task.to_dict()
                task_data['id'] = task.id
                tasks.append(task_data)

            return render_template('dashboard.html',
                                 courses=courses_list,
                                 live_classes=live_classes,
                                 upcoming_tasks=tasks,
                                 stats={
                                     'total_courses': len(courses_list),
                                     'total_enrollments': sum(c.get('enrollment_count', 0) for c in courses_list)
                                 })

        elif current_user.role == 'student':
            student_ref = db.collection("students").document(current_user.id).get()
            if not student_ref.exists:
                flash("Student profile not found!", "danger")
                return redirect(url_for('logout'))

            student_data = student_ref.to_dict()
            enrolled_course_ids = student_data.get("courses_enrolled", [])
            completed_course_ids = student_data.get("completed_courses", [])

            enrolled_courses = []
            completed_courses = []
            live_classes = []

            for course_id in enrolled_course_ids:
                course_ref = db.collection("courses").document(course_id).get()
                if course_ref.exists:
                    course_data = course_ref.to_dict()
                    course_data['id'] = course_id
                    course_data['thumbnail_url'] = course_data.get('thumbnail_img', {}).get('data', url_for('static', filename='img/default_thumbnail.jpg')) if isinstance(course_data.get('thumbnail_img'), dict) else url_for('static', filename='img/default_thumbnail.jpg')
                    progress = student_data.get('course_progress', {}).get(course_id, {})
                    total_chapters = len(course_data.get('chapters', []))
                    completed_chapters = len(progress.get('completed_chapters', []))
                    percentage = int((completed_chapters / total_chapters * 100)) if total_chapters > 0 else 0
                    course_data['progress'] = {
                        'completed_chapters': completed_chapters,
                        'total_chapters': total_chapters,
                        'percentage': percentage
                    }
                    if course_id in completed_course_ids:
                        completed_courses.append(course_data)
                    else:
                        enrolled_courses.append(course_data)

                    # Fetch live classes for enrolled courses
                    if course_data.get('mode_of_class') == 'Live':
                        for index, chapter in enumerate(course_data.get('chapters', [])):
                            if 'date' in chapter and 'time' in chapter and 'meeting_link' in chapter:
                                try:
                                    meeting_date = datetime.strptime(chapter['date'], '%Y-%m-%d')
                                    live_classes.append({
                                        'course_id': course_id,
                                        'course_name': course_data['name'],
                                        'chapter_title': chapter.get('title', 'Untitled'),
                                        'chapter_index': index,
                                        'date': chapter['date'],
                                        'time': chapter['time'],
                                        'meeting_link': chapter['meeting_link']
                                    })
                                except ValueError:
                                    app.logger.warning(f"Invalid date format in course {course_id}")

            return render_template('dashboard.html',
                                 enrolled_courses=enrolled_courses,
                                 completed_courses=completed_courses,
                                 live_classes=live_classes,
                                 stats={
                                     'enrolled_courses': len(enrolled_courses),
                                     'completed_courses': len(completed_courses)
                                 })

    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}", exc_info=True)
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return redirect(url_for('logout'))

    flash("You are not authorized to access this page!", "danger")
    return redirect(url_for('login'))



@app.route('/add_task', methods=['GET', 'POST'])
@login_required
def add_task():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date_str = request.form['due_date']
        due_date = datetime.strptime(due_date_str, '%Y-%m-%d').replace(tzinfo=utc)
        task = Task(title=title, description=description, teacher_id=current_user.id, due_date=due_date)
        task.save_to_firestore()
        flash('Task added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_task.html')

@app.route('/edit_task/<task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task_ref = db.collection('tasks').document(task_id)
    task = task_ref.get()
    if not task.exists:
        flash('Task not found!', 'error')
        return redirect(url_for('dashboard'))
    task_data = task.to_dict()
    if task_data['teacher_id'] != current_user.id:
        flash('You can only edit your own tasks!', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date_str = request.form['due_date']
        due_date = datetime.strptime(due_date_str, '%Y-%m-%d').replace(tzinfo=utc)
        status = request.form['status']
        updated_task = {
            'title': title,
            'description': description,
            'due_date': due_date,
            'status': status,
            'teacher_id': current_user.id
        }
        task_ref.update(updated_task)
        flash('Task updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_task.html', task=task_data, task_id=task_id)

@app.route('/delete_task/<task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task_ref = db.collection('tasks').document(task_id)
    task = task_ref.get()
    if not task.exists:
        flash('Task not found!', 'error')
        return redirect(url_for('dashboard'))
    if task.to_dict()['teacher_id'] != current_user.id:
        flash('You can only delete your own tasks!', 'error')
        return redirect(url_for('dashboard'))
    task_ref.delete()
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_ref = db.collection(f"{current_user.role}s").document(current_user.id)
    user_data = user_ref.get().to_dict() or {}

    if request.method == 'POST':
        update_data = {}

        # Handle file uploads (optional, can upload one or many)
        img = request.files.get('img')
        signature = request.files.get('signature')
        upi_qr = request.files.get('upi_qr')

        # Profile Image
        if img and img.filename:
            file_content = img.read()
            if len(file_content) <= app.config['MAX_CONTENT_LENGTH']:
                filename = secure_filename(img.filename)
                image_data = base64.b64encode(file_content).decode('utf-8')
                update_data['img'] = {
                    'name': filename,
                    'data': image_data,
                    'content_type': img.content_type or 'image/jpeg'
                }
            else:
                flash("Profile image exceeds 1MB limit", "error")
                return redirect(url_for('profile'))

        # Signature (for teachers only)
        if signature and signature.filename and current_user.role == 'teacher':
            file_content = signature.read()
            if len(file_content) <= app.config['MAX_CONTENT_LENGTH']:
                filename = secure_filename(signature.filename)
                signature_data = base64.b64encode(file_content).decode('utf-8')
                update_data['signature'] = {
                    'name': filename,
                    'data': signature_data,
                    'content_type': signature.content_type or 'image/jpeg'
                }
            else:
                flash("Signature image exceeds 1MB limit", "error")
                return redirect(url_for('profile'))

        # UPI QR (for teachers only)
        if upi_qr and upi_qr.filename and current_user.role == 'teacher':
            file_content = upi_qr.read()
            if len(file_content) <= app.config['MAX_CONTENT_LENGTH']:
                filename = secure_filename(upi_qr.filename)
                upi_qr_data = base64.b64encode(file_content).decode('utf-8')
                update_data['upi_qr'] = {
                    'name': filename,
                    'data': upi_qr_data,
                    'content_type': upi_qr.content_type or 'image/jpeg'
                }
            else:
                flash("UPI QR image exceeds 1MB limit", "error")
                return redirect(url_for('profile'))

        # Editable User Info
        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')

        if name and name != user_data.get('name'):
            update_data['name'] = name
        if username and username != user_data.get('username'):
            update_data['username'] = username
        if email and email != user_data.get('email'):
            update_data['email'] = email

        # Educational Information (for teachers only)
        if current_user.role == 'teacher':
            degree = request.form.get('degree')
            institution = request.form.get('institution')
            year = request.form.get('year')

            if degree and institution and year:
                education = user_data.get('education', [])
                if isinstance(education, str):
                    education = [education]
                elif not isinstance(education, list):
                    education = []
                education.append({
                    'degree': degree,
                    'institution': institution,
                    'year': year
                })
                update_data['education'] = education

        # Update Firestore if there's anything to update
        if update_data:
            user_ref.update(update_data)
            # Update current_user object (assuming it’s mutable)
            if 'name' in update_data:
                current_user.name = update_data['name']
            if 'username' in update_data:
                current_user.username = update_data['username']
            if 'email' in update_data:
                current_user.email = update_data['email']
            flash("Profile updated successfully!", "success")
            return redirect(url_for('profile'))
        else:
            flash("No changes made.", "info")

    # Prepare image sources for template
    profile_img_src = f"data:{user_data.get('img', {}).get('content_type', 'image/jpeg')};base64,{user_data.get('img', {}).get('data')}" if user_data.get('img') else None
    signature_img_src = f"data:{user_data.get('signature', {}).get('content_type', 'image/jpeg')};base64,{user_data.get('signature', {}).get('data')}" if user_data.get('signature') else None
    upi_qr_img_src = f"data:{user_data.get('upi_qr', {}).get('content_type', 'image/jpeg')};base64,{user_data.get('upi_qr', {}).get('data')}" if user_data.get('upi_qr') else None

    return render_template(
        'profile.html',
        user=user_data,
        role=current_user.role,
        profile_img_src=profile_img_src,
        signature_img_src=signature_img_src,
        upi_qr_img_src=upi_qr_img_src,
        current_user=current_user
)
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = None
        user_id = None
        collection = None
        for coll in ['students', 'teachers']:
            users_ref = db.collection(coll).where('email', '==', email).limit(1).stream()
            for u in users_ref:
                user = u.to_dict()
                user_id = u.id
                collection = coll
                break
            if user:
                break
        if not user:
            flash('Email not found!', 'error')
            return redirect(url_for('forgot_password'))
        reset_token = str(uuid.uuid4())
        db.collection(collection).document(user_id).update({
            'reset_token': reset_token,
            'reset_token_expiry': datetime.now(timezone.utc) + timedelta(hours=1)
        })
        msg = EmailMessage()
        msg['Subject'] = 'Password Reset Request'
        msg['From'] = 'innerlightadvisor@gmail.com'
        msg['To'] = email
        reset_link = url_for('reset_password', token=reset_token, _external=True)
        msg.set_content(f"Click this link to reset your password: {reset_link}\nThis link will expire in 1 hour.")
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login('innerlightadvisor@gmail.com', 'rtbd qmce vzdu dzip')
            smtp.send_message(msg)
        flash('Password reset link sent to your email!', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('reset_password', token=token))
        user = None
        user_id = None
        collection = None
        for coll in ['students', 'teachers']:
            users_ref = db.collection(coll).where('reset_token', '==', token).limit(1).stream()
            for u in users_ref:
                user = u.to_dict()
                user_id = u.id
                collection = coll
                break
            if user:
                break
        if not user:
            flash('Invalid or expired token!', 'error')
            return redirect(url_for('forgot_password'))
        expiry = user.get('reset_token_expiry')
        if expiry and datetime.now(timezone.utc) > expiry:
            flash('Token has expired!', 'error')
            return redirect(url_for('forgot_password'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        db.collection(collection).document(user_id).update({
            'password': hashed_password,
            'reset_token': None,
            'reset_token_expiry': None
        })
        flash('Password reset successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        message = request.form.get('message', '')
        if not name or not email or not message:
            flash('All fields are required!', 'error')
            return redirect(url_for('contact'))
        msg = EmailMessage()
        msg['Subject'] = 'New Contact Form Submission'
        msg['From'] = 'innerlightadvisor@gmail.com'
        msg['To'] = 'innerlightadvisor@gmail.com'
        msg['Bcc'] = 'chaitanyathaker777@gmail.com'
        msg.set_content(f"Name: {name}\nEmail: {email}\nMessage: {message}")
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login('innerlightadvisor@gmail.com', 'rtbd qmce vzdu dzip')
            smtp.send_message(msg)
        flash('Message sent successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('contect.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/test')
def test():
    return redirect(url_for('learning_style_test'))


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/base')
def base():
    return render_template('base.html')

@app.route('/FAQs')
def FAQs():
    return render_template('faqs.html')

@app.route('/meeting', methods=['GET'])
@login_required
@teacher_required  # Restrict to teachers
def meeting():
    chapter_index = request.args.get('chapter_index', None)
    # Generate a unique Room ID (you can use a more sophisticated method if needed)
    room_id = str(uuid.uuid4())[:8]  # Shortened UUID for simplicity
    return render_template('meeting.html', roomID=room_id, chapter_index=chapter_index, username=current_user.username)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
application = app