from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify, json, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
from sqlalchemy import UniqueConstraint
from sqlalchemy import func
import uuid
import base64
from datetime import datetime, timezone, timedelta
import time
import re
from sqlalchemy import create_engine
import mediapipe as mp
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from scipy.spatial.distance import cosine
import cv2
import numpy as np
from flask_sqlalchemy import SQLAlchemy
from deepface import DeepFace
from dotenv import load_dotenv
import logging
import platform
from flask_cors import CORS
from sqlalchemy.orm import joinedload
from flask_mail import Mail, Message
import random
import string
import jwt  # Import PyJWT for JWT handling
import pytesseract
from PIL import Image, ImageEnhance, ImageFilter
import logging
utc_now = datetime.fromtimestamp(time.time(), tz=timezone.utc)
logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
load_dotenv()

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

mail = Mail(app)

DATABASE_URL = "postgresql://postgres.xixilmbyopeqmyrueaxv:Aster#123#@aws-0-eu-central-1.pooler.supabase.com:5432/postgres"
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))  # Separate key for JWT
db = SQLAlchemy(app)

migrate = Migrate(app, db)

# Database Models
class SuperUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='superuser')


class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    facial_data = db.Column(db.Text, nullable=True)
    blocked = db.Column(db.Boolean, default=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'))
    role = db.Column(db.String(50), default='voter')
    phone_number = db.Column(db.String(20), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    national_id = db.Column(db.String(19), unique=True, nullable=True)
    gender = db.Column(db.String(20), nullable=True)
    state = db.Column(db.String(100), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    address = db.Column(db.Text, nullable=True)

    vote = db.relationship('Vote', backref='voter', cascade='all, delete-orphan', uselist=False)


class PendingVoter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    facial_data = db.Column(db.Text, nullable=True)
    invitation_code = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    phone_number = db.Column(db.String(20), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    national_id = db.Column(db.String(19), unique=True, nullable=True)
    gender = db.Column(db.String(20), nullable=True)
    state = db.Column(db.String(100), nullable=True)
    country = db.Column(db.String(100), nullable=True)
    address = db.Column(db.Text, nullable=True)


class ElectionOfficer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)
    blocked = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), default='eadmin')
    invitation_code = db.Column(db.String(10), nullable=True)


class SystemAdmin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(50), default='sysadmin')
    invitation_code = db.Column(db.String(10), nullable=True)


class Election(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(255))

    candidates = db.relationship('Candidate', backref='election', lazy=True, cascade='all, delete-orphan')
    voters = db.relationship('Voter', backref='election', lazy=True, cascade='all, delete-orphan')
    votes_cast = db.relationship('Vote', backref='election', lazy=True, cascade='all, delete-orphan')


class Party(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    candidates = db.relationship('Candidate', backref='party', lazy=True, cascade='all, delete-orphan')


class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    party_id = db.Column(db.Integer, db.ForeignKey('party.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    votes = db.Column(db.Integer, default=0)
    date_of_birth = db.Column(db.Date, nullable=False)
    bio = db.Column(db.Text, nullable=True)
    photo_url = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    eligibility_status = db.Column(db.String(50), default='Pending', nullable=False)
    national_id = db.Column(db.String(19), nullable=False, unique=True)

    votes_received = db.relationship('Vote', backref='candidate', lazy=True, cascade='all, delete-orphan')

    __table_args__ = (
        db.CheckConstraint(
            "national_id ~ '^[0-9]{4} [0-9]{4} [0-9]{4} [0-9]{4}$'",
            name='national_id_format'
        ),
    )


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('voter.id'), unique=True, nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


@property
def is_active(self):
    now = datetime.now(timezone.utc)
    return self.start_time <= now <= self.end_time

# JWT Helper Functions
def generate_jwt_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.now(timezone.utc) + timedelta(hours=1),  # Token expires in 1 hour
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

def get_current_user():
    token = None
    # Check for token in Authorization header (for Flutter)
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
    # Fallback to cookie for HTML frontend
    elif 'jwt_token' in request.cookies:
        token = request.cookies.get('jwt_token')

    if not token:
        return None

    payload = decode_jwt_token(token)
    if not payload:
        return None

    user_id = payload.get('user_id')
    role = payload.get('role')

    # Fetch user based on role
    model_map = {
        'superuser': SuperUser,
        'voter': Voter,
        'eadmin': ElectionOfficer,
        'sysadmin': SystemAdmin
    }
    model = model_map.get(role)
    if not model:
        return None

    user = model.query.get(user_id)
    if user:
        user.role = role  # Ensure role is set
    return user

# Custom JWT Required Decorator
def jwt_required(allowed_roles=None):
    def decorator(f):
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'Authentication required'}), 401
                flash('Please log in to access this page.', 'danger')
                return redirect(url_for('login'))

            if allowed_roles and user.role not in allowed_roles:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'Access denied'}), 403
                flash('Access denied!', 'danger')
                return redirect(url_for('home'))

            # Attach user to request context for use in route
            request.current_user = user
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__  # Preserve function name
        return wrapper
    return decorator

def generate_invitation_code(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

# SuperUser Routes
@app.route('/superuser/login', methods=['GET', 'POST'])
def superuser_login():
    if request.method == 'POST':
        data = request.form if request.form else request.json
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        superuser = SuperUser.query.filter_by(username=username).first()
        if superuser and check_password_hash(superuser.password, password):
            token = generate_jwt_token(superuser.id, 'superuser')
            if request.headers.get('Accept') == 'application/json':
                return jsonify({
                    'success': True,
                    'token': token,
                    'message': 'Superuser login successful'
                }), 200
            response = redirect(url_for('superuser_dashboard'))
            response.set_cookie('jwt_token', token, httponly=True, samesite='Strict')
            flash('Superuser login successful!', 'success')
            return response
        else:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            flash('Invalid credentials!', 'danger')
    
    return render_template('superuser_login.html')

@app.route('/sysadmin/register', methods=['GET', 'POST'])
def sysadmin_register():
    if request.method == 'POST':
        data = request.form if request.form else request.json
        action = data.get('action')
        
        if action == 'request_invite':
            name = data.get('name', '').strip()
            email = data.get('email', '').strip()
            
            if not all([name, email]):
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'Name and email are required'}), 400
                flash('Name and email are required to request an invitation!', 'danger')
                return redirect(url_for('sysadmin_register'))
            
            if SystemAdmin.query.filter_by(email=email).first():
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'Email already registered or pending'}), 400
                flash('This email is already registered or has a pending invitation!', 'warning')
                return redirect(url_for('sysadmin_register'))
            
            superuser_email = os.getenv('SUPERUSER_EMAIL')
            if not superuser_email:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'No SuperUser email configured'}), 500
                flash('No SuperUser email configured in the system! Contact administrator.', 'danger')
                return redirect(url_for('sysadmin_register'))
            
            try:
                msg = Message('System Admin Invitation Request',
                              recipients=[superuser_email],
                              sender=os.getenv('MAIL_USERNAME'))
                msg.body = f'Hello SuperUser,\n\n{name} ({email}) has requested an invitation code to register as a System Admin.\nPlease generate one from your dashboard at {url_for("superuser_dashboard", _external=True)}.'
                mail.send(msg)
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': True, 'message': 'Invitation request sent'}), 200
                flash('Invitation request sent to the SuperUser! Check your email later for the code.', 'success')
            except Exception as e:
                logging.error(f"Mail send error: {str(e)}", exc_info=True)
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': f'Failed to send invitation request: {str(e)}'}), 500
                flash(f'Failed to send invitation request: {str(e)}', 'danger')
            return redirect(url_for('sysadmin_register'))
        
        elif action == 'register':
            name = data.get('name', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '').strip()
            invitation_code = data.get('invitation_code', '').strip()

            if not all([name, email, password, invitation_code]):
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'All fields are required'}), 400
                flash('All fields are required for registration!', 'danger')
                return redirect(url_for('sysadmin_register'))

            admin = SystemAdmin.query.filter_by(email=email).first()
            if admin:
                if admin.invitation_code != invitation_code:
                    if request.headers.get('Accept') == 'application/json':
                        return jsonify({'success': False, 'message': 'Invalid invitation code'}), 400
                    flash('Invalid invitation code!', 'danger')
                    return redirect(url_for('sysadmin_register'))
                hashed_password = generate_password_hash(password)
                admin.password = hashed_password
                admin.invitation_code = None
                db.session.commit()
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': True, 'message': 'System Admin registered successfully'}), 201
                flash('System Admin registered successfully!', 'success')
                return redirect(url_for('sysadmin_login'))
            else:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'Please request an invitation code'}), 400
                flash('Please request an invitation code from the Superuser!', 'warning')
                return redirect(url_for('sysadmin_register'))
    
    return render_template('sysadmin_register.html')

@app.route('/sysadmin/delete_voter/<int:voter_id>', methods=['POST'])
@jwt_required(allowed_roles=['sysadmin'])
def delete_voter(voter_id):
    voter = Voter.query.get_or_404(voter_id)
    db.session.delete(voter)
    db.session.commit()
    if request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'message': 'Voter deleted successfully'}), 200
    flash('Voter deleted successfully!', 'success')
    return redirect(url_for('sysadmin_dashboard'))

@app.route('/sysadmin/delete_officer/<int:officer_id>', methods=['POST'])
@jwt_required(allowed_roles=['sysadmin'])
def delete_officer(officer_id):
    officer = ElectionOfficer.query.get_or_404(officer_id)
    db.session.delete(officer)
    db.session.commit()
    if request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'message': 'Election Officer deleted successfully'}), 200
    flash('Election Officer deleted successfully!', 'success')
    return redirect(url_for('sysadmin_dashboard'))

@app.route('/eadmin/register', methods=['GET', 'POST'])
def eadmin_register():
    if request.method == 'POST':
        data = request.form if request.form else request.json
        action = data.get('action')
        
        if action == 'request_invite':
            name = data.get('name', '').strip()
            email = data.get('email', '').strip()
            
            if not all([name, email]):
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'Name and email are required'}), 400
                flash('Name and email are required to request an invitation!', 'danger')
                return redirect(url_for('eadmin_register'))
            
            if ElectionOfficer.query.filter_by(email=email).first():
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'Email already registered or pending'}), 400
                flash('This email is already registered or has a pending invitation!', 'warning')
                return redirect(url_for('eadmin_register'))
            
            superuser_email = os.getenv('SUPERUSER_EMAIL')
            if not superuser_email:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'No SuperUser email configured'}), 500
                flash('No SuperUser email configured in the system! Contact administrator.', 'danger')
                return redirect(url_for('eadmin_register'))
            
            try:
                msg = Message('Election Officer Invitation Request',
                              recipients=[superuser_email],
                              sender=os.getenv('MAIL_USERNAME'))
                msg.body = f'Hello SuperUser,\n\n{name} ({email}) has requested an invitation code to register as an Election Officer.\nPlease generate one from your dashboard at {url_for("superuser_dashboard", _external=True)}.'
                mail.send(msg)
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': True, 'message': 'Invitation request sent'}), 200
                flash('Invitation request sent to the SuperUser! Check your email later for the code.', 'success')
            except Exception as e:
                logging.error(f"Mail send error: {str(e)}", exc_info=True)
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': f'Failed to send invitation request: {str(e)}'}), 500
                flash(f'Failed to send invitation request: {str(e)}', 'danger')
            return redirect(url_for('eadmin_register'))
        
        elif action == 'register':
            name = data.get('name', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '').strip()
            invitation_code = data.get('invitation_code', '').strip()

            if not all([name, email, password, invitation_code]):
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'All fields are required'}), 400
                flash('All fields are required for registration!', 'danger')
                return redirect(url_for('eadmin_register'))

            officer = ElectionOfficer.query.filter_by(email=email).first()
            if officer:
                if officer.invitation_code != invitation_code:
                    if request.headers.get('Accept') == 'application/json':
                        return jsonify({'success': False, 'message': 'Invalid invitation code'}), 400
                    flash('Invalid invitation code!', 'danger')
                    return redirect(url_for('eadmin_register'))
                hashed_password = generate_password_hash(password)
                officer.password = hashed_password
                officer.invitation_code = None
                db.session.commit()
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': True, 'message': 'Election Officer registered successfully'}), 201
                flash('Election Officer registered successfully!', 'success')
                return redirect(url_for('eadmin_login'))
            else:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'Please request an invitation code'}), 400
                flash('Please request an invitation code from the Superuser!', 'warning')
                return redirect(url_for('eadmin_register'))
    
    return render_template('eadmin_register.html')

@app.route('/sysadmin/login', methods=['GET', 'POST'])
def sysadmin_login():
    if request.method == 'POST':
        data = request.form if request.form else request.json
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()

        admin = SystemAdmin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password, password):
            token = generate_jwt_token(admin.id, 'sysadmin')
            if request.headers.get('Accept') == 'application/json':
                return jsonify({
                    'success': True,
                    'token': token,
                    'message': 'Login successful'
                }), 200
            response = redirect(url_for('sysadmin_dashboard'))
            response.set_cookie('jwt_token', token, httponly=True, samesite='Strict')
            flash('Login successful!', 'success')
            return response
        else:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            flash('Invalid credentials!', 'danger')
    
    return render_template('sysadmin_login.html')

@app.route('/sysadmin/dashboard')
@jwt_required(allowed_roles=['sysadmin', 'superuser'])
def sysadmin_dashboard():
    voters = Voter.query.all()
    officers = ElectionOfficer.query.all()
    admins = SystemAdmin.query.all()
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'success': True,
            'voters': [{'id': v.id, 'name': v.name, 'email': v.email} for v in voters],
            'officers': [{'id': o.id, 'name': o.name, 'email': o.email} for o in officers],
            'admins': [{'id': a.id, 'name': a.name, 'email': a.email} for a in admins]
        }), 200
    return render_template('sysadmin_dashboard.html', voters=voters, officers=officers, admins=admins)

@app.route('/sysadmin/block_voter/<int:voter_id>', methods=['POST'])
@jwt_required(allowed_roles=['sysadmin'])
def block_voter(voter_id):
    voter = Voter.query.get(voter_id)
    if voter:
        voter.blocked = True
        db.session.commit()
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': True, 'message': 'Voter blocked successfully'}), 200
        flash('Voter blocked successfully', 'success')
    return redirect(url_for('sysadmin_dashboard'))

@app.route('/sysadmin/unblock_voter/<int:voter_id>', methods=['POST'])
@jwt_required(allowed_roles=['sysadmin'])
def unblock_voter(voter_id):
    voter = Voter.query.get(voter_id)
    if voter:
        voter.blocked = False
        db.session.commit()
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': True, 'message': 'Voter unblocked successfully'}), 200
        flash('Voter unblocked successfully', 'success')
    return redirect(url_for('sysadmin_dashboard'))

@app.route('/eadmin/login', methods=['GET', 'POST'])
def eadmin_login():
    if request.method == 'POST':
        data = request.form if request.form else request.json
        email = data.get('email', "").strip()
        password = data.get('password', "").strip()
        officer = ElectionOfficer.query.filter_by(email=email).first()
        if officer and check_password_hash(officer.password, password) and officer.role == 'eadmin':
            token = generate_jwt_token(officer.id, 'eadmin')
            if request.headers.get('Accept') == 'application/json':
                return jsonify({
                    'success': True,
                    'token': token,
                    'message': 'Login successful'
                }), 200
            response = redirect(url_for('eadmin_dashboard'))
            response.set_cookie('jwt_token', token, httponly=True, samesite='Strict')
            flash('Login successful!', 'success')
            return response
        else:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
            flash('Invalid email or password!', 'danger')
    return render_template('eadmin_login.html')
@app.route('/eadmin/dashboard')
@jwt_required(allowed_roles=['eadmin'])
def eadmin_dashboard():
    voters = Voter.query.all()
    candidates = Candidate.query.all()
    elections = Election.query.all()

    # Check if the election is active based on current time
    current_time = datetime.now(timezone.utc)

    for election in elections:
        # Convert naive datetimes to offset-aware if necessary
        start_time = election.start_time
        end_time = election.end_time

        # If start_time or end_time is naive, assume it's in UTC and make it offset-aware
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)

        # Set is_active based on comparison
        election.is_active = start_time <= current_time <= end_time

    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'success': True,
            'voters': [{'id': v.id, 'name': v.name, 'email': v.email} for v in voters],
            'candidates': [{'id': c.id, 'name': c.name} for c in candidates],
            'elections': [{
                'id': e.id,
                'name': e.name,
                'start_time': e.start_time.isoformat(),
                'end_time': e.end_time.isoformat(),
                'is_active': e.is_active,
                'description': e.description or ''
            } for e in elections],
            'delete_election_endpoint': 'Use POST /eadmin/delete_election/<election_id> to delete an election'
        }), 200

    return render_template('eadmin_dashboard.html', voters=voters, candidates=candidates, elections=elections)



@app.route('/eadmin/add_election', methods=['GET', 'POST'])
@jwt_required(allowed_roles=['eadmin'])
def add_election():
    if request.method == 'POST':
        data = request.form if request.form else request.json
        name = data.get('name', '').strip()
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        description = data.get('description', '').strip()

        if not name or not start_time or not end_time:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': 'All fields are required'}), 400
            flash('All fields are required!', 'danger')
            return redirect(url_for('add_election'))

        try:
            start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')
        except ValueError:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': 'Invalid date format. Use YYYY-MM-DDTHH:MM'}), 400
            flash('Invalid date format! Use YYYY-MM-DDTHH:MM', 'danger')
            return redirect(url_for('add_election'))

        # Validate that end_time is after start_time
        if end_time <= start_time:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': 'End time must be after start time'}), 400
            flash('End time must be after start time!', 'danger')
            return redirect(url_for('add_election'))

        try:
            new_election = Election(name=name, start_time=start_time, end_time=end_time, description=description)
            db.session.add(new_election)
            db.session.commit()
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': True, 'message': f'Election "{name}" created successfully'}), 201
            flash(f'Election "{name}" created successfully!', 'success')
            return redirect(url_for('eadmin_dashboard'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error creating election: {str(e)}")
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': 'Failed to create election'}), 500
            flash('Failed to create election!', 'danger')
            return redirect(url_for('add_election'))

    # GET: Render form with list of existing elections
    elections = Election.query.all()
    return render_template('add_election.html', elections=elections)

@app.route('/eadmin/delete_election/<int:election_id>', methods=['POST'])
@jwt_required(allowed_roles=['eadmin'])
def delete_election(election_id):
    election = Election.query.get(election_id)
    if not election:
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': False, 'message': 'Election not found'}), 404
        flash('Election not found!', 'danger')
        return redirect(url_for('eadmin_dashboard'))

    try:
        # Delete associated candidates
        candidates = Candidate.query.filter_by(election_id=election_id).all()
        for candidate in candidates:
            db.session.delete(candidate)

        # Delete associated votes
        votes = Vote.query.filter_by(election_id=election_id).all()
        for vote in votes:
            db.session.delete(vote)

        # Delete the election
        db.session.delete(election)
        db.session.commit()

        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': True, 'message': f'Election "{election.name}" deleted successfully'}), 200
        flash(f'Election "{election.name}" deleted successfully!', 'success')
        return redirect(url_for('eadmin_dashboard'))

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error deleting election {election_id}: {str(e)}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': False, 'message': 'Failed to delete election'}), 500
        flash('Failed to delete election!', 'danger')
        return redirect(url_for('eadmin_dashboard'))

@app.route('/eadmin/add_party', methods=['GET', 'POST'])
@jwt_required(allowed_roles=['eadmin'])
def add_party():
    if request.method == 'POST':
        data = request.form if request.form else request.json
        name = data.get('name', '').strip()
        if not name:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': 'Party name cannot be empty'}), 400
            flash('Party name cannot be empty!', 'danger')
            return redirect(url_for('add_party'))

        new_party = Party(name=name)
        db.session.add(new_party)
        db.session.commit()
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': True, 'message': f'Party "{name}" added successfully'}), 201
        flash(f'Party "{name}" added successfully!', 'success')
        return redirect(url_for('eadmin_dashboard'))

    return render_template('add_party.html')

@app.route('/superuser/dashboard')
@jwt_required(allowed_roles=['superuser'])
def superuser_dashboard():
    voters = Voter.query.all()
    officers = ElectionOfficer.query.all()
    admins = SystemAdmin.query.all()
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'success': True,
            'voters': [{'id': v.id, 'name': v.name, 'email': v.email} for v in voters],
            'officers': [{'id': o.id, 'name': o.name, 'email': o.email} for o in officers],
            'admins': [{'id': a.id, 'name': a.name, 'email': a.email} for a in admins]
        }), 200
    return render_template('superuser_dashboard.html', voters=voters, officers=officers, admins=admins)

@app.route('/superuser/generate_invite', methods=['POST'])
@jwt_required(allowed_roles=['superuser'])
def generate_invite():
    data = request.form if request.form else request.json
    user_type = data.get('user_type')
    email = data.get('email', '').strip()
    name = data.get('name', '').strip()

    if user_type == 'sysadmin':
        existing = SystemAdmin.query.filter_by(email=email).first()
        if existing:
            if existing.invitation_code:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'An invitation code has already been generated for this email'}), 400
                flash('An invitation code has already been generated for this email!', 'warning')
            else:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'This email is already registered'}), 400
                flash('This email is already registered!', 'warning')
            return redirect(url_for('superuser_dashboard'))
        code = generate_invitation_code()
        new_admin = SystemAdmin(name=name, email=email, invitation_code=code)
        db.session.add(new_admin)
    elif user_type == 'eadmin':
        existing = ElectionOfficer.query.filter_by(email=email).first()
        if existing:
            if existing.invitation_code:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'An invitation code has already been generated for this email'}), 400
                flash('An invitation code has already been generated for this email!', 'warning')
            else:
                if request.headers.get('Accept') == 'application/json':
                    return jsonify({'success': False, 'message': 'This email is already registered'}), 400
                flash('This email is already registered!', 'warning')
            return redirect(url_for('superuser_dashboard'))
        code = generate_invitation_code()
        new_officer = ElectionOfficer(name=name, email=email, invitation_code=code)
        db.session.add(new_officer)
    else:
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': False, 'message': 'Invalid user type'}), 400
        flash('Invalid user type!', 'danger')
        return redirect(url_for('superuser_dashboard'))

    db.session.commit()
    
    try:
        msg = Message(f'Your {user_type} Invitation Code',
                      recipients=[email],
                      sender=os.getenv('MAIL_USERNAME'))
        msg.body = f'Hello {name},\n\nYour invitation code is: {code}\nPlease use this code to complete your registration at {url_for("sysadmin_register" if user_type == "sysadmin" else "eadmin_register", _external=True)}.'
        mail.send(msg)
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': True, 'message': f'Invitation code sent to {email}'}), 200
        flash(f'Invitation code sent to {email}!', 'success')
    except Exception as e:
        db.session.rollback()
        logging.error(f"Mail send error: {str(e)}", exc_info=True)
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': False, 'message': f'Failed to send invitation code: {str(e)}'}), 500
        flash(f'Failed to send invitation code: {str(e)}', 'danger')
    
    return redirect(url_for('superuser_dashboard'))

@app.route('/superuser/delete_admin/<int:admin_id>', methods=['POST'])
@jwt_required(allowed_roles=['superuser'])
def superuser_delete_admin(admin_id):
    admin = SystemAdmin.query.get_or_404(admin_id)
    db.session.delete(admin)
    db.session.commit()
    if request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'message': f'Admin {admin.name} deleted successfully'}), 200
    flash(f'Admin {admin.name} deleted successfully', 'success')
    return redirect(url_for('superuser_dashboard'))

@app.route('/superuser/delete_officer/<int:officer_id>', methods=['POST'])
@jwt_required(allowed_roles=['superuser'])
def superuser_delete_officer(officer_id):
    officer = ElectionOfficer.query.get_or_404(officer_id)
    db.session.delete(officer)
    db.session.commit()
    if request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'message': f'Officer {officer.name} deleted successfully'}), 200
    flash(f'Officer {officer.name} deleted successfully', 'success')
    return redirect(url_for('superuser_dashboard'))

@app.route('/')
def home():
    return render_template('home.html')

face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

def normalize_lighting(img):
    try:
        lab = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
        l_channel, a, b = cv2.split(lab)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        cl = clahe.apply(l_channel)
        limg = cv2.merge((cl, a, b))
        final = cv2.cvtColor(limg, cv2.COLOR_LAB2BGR)
        return final
    except Exception as e:
        logging.error(f"Lighting normalization error: {str(e)}")
        return img


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        filename = None
        id_filename = None
        try:
            step = request.form.get('step') if request.form else request.json.get('step')

            if step == 'request_code':
                # Expect form data with optional file upload
                email = request.form.get('email', '').strip()
                name = request.form.get('name', '').strip()
                password = request.form.get('password', '').strip()
                phone_number = request.form.get('phone_number', '').strip()
                date_of_birth = request.form.get('date_of_birth', '').strip()
                gender = request.form.get('gender', '').strip()
                state = request.form.get('state', '').strip()
                country = request.form.get('country', '').strip()
                address = request.form.get('address', '').strip()
                id_card = request.files.get('id_card')

                if not all([email, name, password]):
                    return jsonify({'success': False, 'message': 'Email, name, and password are required'}), 400

                # Validate new fields
                if phone_number and len(phone_number) > 20:
                    return jsonify({'success': False, 'message': 'Phone number too long'}), 400

                try:
                    if date_of_birth:
                        dob = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
                        if dob > datetime.now().date():
                            return jsonify({'success': False, 'message': 'Date of birth cannot be in the future'}), 400
                except ValueError:
                    return jsonify({'success': False, 'message': 'Invalid date of birth format (use YYYY-MM-DD)'}), 400

                if gender and gender not in ['Male', 'Female', 'Other']:
                    return jsonify({'success': False, 'message': 'Invalid gender (use Male, Female, or Other)'}), 400

                if state and len(state) > 100:
                    return jsonify({'success': False, 'message': 'State name too long'}), 400
                if country and len(country) > 100:
                    return jsonify({'success': False, 'message': 'Country name too long'}), 400
                if address and len(address) > 1000:
                    return jsonify({'success': False, 'message': 'Address too long'}), 400

                # Process national ID from uploaded ID card
                national_id = None
                if id_card and allowed_file(id_card.filename):
                    id_filename = secure_filename(id_card.filename)
                    id_path = os.path.join(app.config['ID_CARD_UPLOAD_FOLDER'], id_filename)
                    id_card.save(id_path)
                    logger.debug(f"Saved ID card to: {id_path}")
                    national_id, error = extract_national_id_from_image(id_path)
                    os.remove(id_path)  # Clean up uploaded file
                    if not national_id:
                        return jsonify({'success': False, 'message': f'Could not extract national ID: {error}'}), 400
                    if not re.match(r'^\d{4} \d{4} \d{4} \d{4}$', national_id):
                        return jsonify({'success': False, 'message': 'Invalid national ID format'}), 400
                else:
                    return jsonify({'success': False, 'message': 'Valid ID card image required (PNG/JPEG)'}), 400

                # Check for existing records
                if Voter.query.filter_by(email=email).first():
                    return jsonify({'success': False, 'message': 'Email already registered'}), 400
                if national_id and Voter.query.filter_by(national_id=national_id).first():
                    return jsonify({'success': False, 'message': 'National ID already registered as voter'}), 400
                if national_id and Candidate.query.filter_by(national_id=national_id).first():
                    return jsonify({'success': False, 'message': 'National ID already registered as candidate'}), 400
                if PendingVoter.query.filter_by(email=email).first():
                    return jsonify({'success': False, 'message': 'Verification code already sent'}), 400
                if national_id and PendingVoter.query.filter_by(national_id=national_id).first():
                    return jsonify({'success': False, 'message': 'National ID already pending'}), 400

                invitation_code = generate_invitation_code()
                new_pending = PendingVoter(
                    email=email,
                    name=name,
                    password=generate_password_hash(password),
                    facial_data='',
                    invitation_code=invitation_code,
                    phone_number=phone_number or None,
                    date_of_birth=dob if date_of_birth else None,
                    national_id=national_id,
                    gender=gender or None,
                    state=state or None,
                    country=country or None,
                    address=address or None
                )
                db.session.add(new_pending)
                db.session.commit()

                msg = Message(
                    subject='Your Voter Registration Code',
                    recipients=[email],
                    body=f'Your verification code: {invitation_code}'
                )
                mail.send(msg)

                return jsonify({'success': True, 'message': 'Verification code sent'}), 200

            elif step == 'verify_code':
                # Expect form data with facial image and ID card
                email = request.form.get('email', '').strip()
                code = request.form.get('code', '').strip()
                name = request.form.get('name', '').strip()
                password = request.form.get('password', '').strip()
                phone_number = request.form.get('phone_number', '').strip()
                date_of_birth = request.form.get('date_of_birth', '').strip()
                gender = request.form.get('gender', '').strip()
                state = request.form.get('state', '').strip()
                country = request.form.get('country', '').strip()
                address = request.form.get('address', '').strip()
                id_card = request.files.get('id_card')
                image = request.files.get('image')  # Facial image

                if not all([email, code, name, password, image]):
                    return jsonify({'success': False, 'message': 'Email, code, name, password, and facial image are required'}), 400

                # Validate new fields
                if phone_number and len(phone_number) > 20:
                    return jsonify({'success': False, 'message': 'Phone number too long'}), 400

                try:
                    if date_of_birth:
                        dob = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
                        if dob > datetime.now().date():
                            return jsonify({'success': False, 'message': 'Date of birth cannot be in the future'}), 400
                except ValueError:
                    return jsonify({'success': False, 'message': 'Invalid date of birth format (use YYYY-MM-DD)'}), 400

                if gender and gender not in ['Male', 'Female', 'Other']:
                    return jsonify({'success': False, 'message': 'Invalid gender (use Male, Female, or Other)'}), 400

                if state and len(state) > 100:
                    return jsonify({'success': False, 'message': 'State name too long'}), 400
                if country and len(country) > 100:
                    return jsonify({'success': False, 'message': 'Country name too long'}), 400
                if address and len(address) > 1000:
                    return jsonify({'success': False, 'message': 'Address too long'}), 400

                # Process national ID
                national_id = None
                if id_card and allowed_file(id_card.filename):
                    id_filename = secure_filename(id_card.filename)
                    id_path = os.path.join(app.config['ID_CARD_UPLOAD_FOLDER'], id_filename)
                    id_card.save(id_path)
                    logger.debug(f"Saved ID card to: {id_path}")
                    national_id, error = extract_national_id_from_image(id_path)
                    os.remove(id_path)
                    if not national_id:
                        return jsonify({'success': False, 'message': f'Could not extract national ID: {error}'}), 400
                    if not re.match(r'^\d{4} \d{4} \d{4} \d{4}$', national_id):
                        return jsonify({'success': False, 'message': 'Invalid national ID format'}), 400
                else:
                    return jsonify({'success': False, 'message': 'Valid ID card image required (PNG/JPEG)'}), 400

                # Verify pending voter
                pending_voter = PendingVoter.query.filter_by(email=email, invitation_code=code).first()
                if not pending_voter:
                    return jsonify({'success': False, 'message': 'Invalid code or email'}), 400

                # Validate national ID consistency
                if pending_voter.national_id and national_id != pending_voter.national_id:
                    return jsonify({'success': False, 'message': 'National ID does not match the one provided in request_code'}), 400

                # Process facial image
                if not allowed_file(image.filename):
                    return jsonify({'success': False, 'message': 'Invalid facial image format (PNG/JPEG)'}), 400

                filename = f"temp_{uuid.uuid4()}.jpg"
                image.save(filename)

                img = cv2.imread(filename)
                if img is None:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Invalid facial image'}), 400

                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                avg_brightness = np.mean(gray)
                if avg_brightness < 50 or avg_brightness > 200:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Adjust lighting conditions'}), 400

                img = normalize_lighting(img)
                mp_face_mesh = mp.solutions.face_mesh
                face_mesh = mp_face_mesh.FaceMesh(
                    static_image_mode=True,
                    max_num_faces=1,
                    refine_landmarks=True,
                    min_detection_confidence=0.7
                )

                results = face_mesh.process(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
                if not results.multi_face_landmarks:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'No face detected'}), 400

                landmarks = results.multi_face_landmarks[0].landmark
                h, w = img.shape[:2]

                # Head pose estimation
                nose_tip = landmarks[1]
                chin = landmarks[152]
                left_ear = landmarks[234]
                right_ear = landmarks[454]

                nose_tip_x, nose_tip_y = nose_tip.x * w, nose_tip.y * h
                chin_x, chin_y = chin.x * w, chin.y * h
                left_ear_x, right_ear_x = left_ear.x * w, right_ear.x * w

                ear_distance = abs(left_ear_x - right_ear_x)
                nose_offset = (nose_tip_x - (left_ear_x + right_ear_x) / 2) / (ear_distance + 1e-6)
                yaw_threshold = 0.2
                if abs(nose_offset) > yaw_threshold:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Please face the camera directly'}), 400

                # Eye landmarks
                left_eye_outer = landmarks[33]
                left_eye_inner = landmarks[133]
                left_iris_center = landmarks[468]
                left_eye_upper = landmarks[159]
                left_eye_lower = landmarks[145]
                right_eye_outer = landmarks[362]
                right_eye_inner = landmarks[263]
                right_iris_center = landmarks[473]
                right_eye_upper = landmarks[386]
                right_eye_lower = landmarks[374]

                left_eye_outer_x = left_eye_outer.x * w
                left_eye_inner_x = left_eye_inner.x * w
                left_iris_x = left_iris_center.x * w
                left_eye_upper_y = left_eye_upper.y * h
                left_eye_lower_y = left_eye_lower.y * h
                right_eye_outer_x = right_eye_outer.x * w
                right_eye_inner_x = right_eye_inner.x * w
                right_iris_x = right_iris_center.x * w
                right_eye_upper_y = right_eye_upper.y * h
                right_eye_lower_y = right_eye_lower.y * h

                if any(coord < 0 or coord > w for coord in [left_eye_outer_x, left_eye_inner_x, left_iris_x,
                                                            right_eye_outer_x, right_eye_inner_x, right_iris_x]):
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Invalid eye landmarks detected'}), 400

                left_eye_width = left_eye_inner_x - left_eye_outer_x
                right_eye_width = right_eye_inner_x - right_eye_outer_x

                if left_eye_width <= 0 or right_eye_width <= 0:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Invalid eye landmarks'}), 400

                left_eye_center_y = (left_eye_upper_y + left_eye_lower_y) / 2
                right_eye_center_y = (right_eye_upper_y + right_eye_lower_y) / 2

                left_gaze_ratio = (left_iris_x - left_eye_outer_x) / left_eye_width
                right_gaze_ratio = (right_iris_x - right_eye_outer_x) / right_eye_width

                gaze_threshold_min = 0.4
                gaze_threshold_max = 0.6
                if not (gaze_threshold_min <= left_gaze_ratio <= gaze_threshold_max and
                        gaze_threshold_min <= right_gaze_ratio <= gaze_threshold_max):
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Please look directly at the camera'}), 400

                x_coords = [int(lm.x * w) for lm in landmarks]
                y_coords = [int(lm.y * h) for lm in landmarks]
                
                x_min, x_max = max(0, min(x_coords)), min(w, max(x_coords))
                y_min, y_max = max(0, min(y_coords)), min(h, max(y_coords))
                
                margin = int(0.2 * max(x_max - x_min, y_max - y_min))
                x_min = max(0, x_min - margin)
                x_max = min(w, x_max + margin)
                y_min = max(0, y_min - margin)
                y_max = min(h, y_max + margin)

                face_img = img[y_min:y_max, x_min:x_max]

                try:
                    embedding_data = DeepFace.represent(
                        cv2.cvtColor(face_img, cv2.COLOR_BGR2RGB),
                        model_name='ArcFace',
                        detector_backend='skip',
                        enforce_detection=False,
                        align=False
                    )
                except ValueError as e:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Face processing failed'}), 400

                if len(embedding_data) != 1:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Multiple faces detected'}), 400

                embedding = np.array(embedding_data[0]["embedding"])
                if not embedding.size or np.isnan(embedding).any():
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Invalid face embedding'}), 400

                embedding = embedding / np.linalg.norm(embedding)

                threshold = 0.3
                voters = Voter.query.with_entities(Voter.id, Voter.email, Voter.facial_data).all()
                for voter_id, voter_email, facial_data in voters:
                    try:
                        existing_embedding = np.array(json.loads(facial_data))
                        if not existing_embedding.size or np.isnan(existing_embedding).any():
                            continue
                        existing_embedding = existing_embedding / np.linalg.norm(existing_embedding)
                        similarity = cosine(existing_embedding, embedding)
                        if similarity < threshold:
                            os.remove(filename)
                            return jsonify({'success': False, 'message': 'Face already registered'}), 400
                    except (ValueError, json.JSONDecodeError):
                        continue

                new_voter = Voter(
                    name=name,
                    email=email,
                    password=generate_password_hash(password),
                    facial_data=json.dumps(embedding.tolist()),
                    phone_number=phone_number or None,
                    date_of_birth=dob if date_of_birth else None,
                    national_id=national_id,
                    gender=gender or None,
                    state=state or None,
                    country=country or None,
                    address=address or None
                )
                db.session.add(new_voter)
                db.session.delete(pending_voter)
                db.session.commit()

                if os.path.exists(filename):
                    os.remove(filename)

                return jsonify({'success': True, 'message': 'Registration successful'}), 201

            else:
                return jsonify({'success': False, 'message': 'Invalid step'}), 400

        except Exception as e:
            logging.error(f"Registration error: {str(e)}", exc_info=True)
            if filename and os.path.exists(filename):
                os.remove(filename)
            if id_filename and os.path.exists(os.path.join(app.config['ID_CARD_UPLOAD_FOLDER'], id_filename)):
                os.remove(os.path.join(app.config['ID_CARD_UPLOAD_FOLDER'], id_filename))
            return jsonify({'success': False, 'message': 'Registration failed'}), 500

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        logging.info("Rendering login page")
        return render_template('login.html')

    filename = None
    try:
        if request.is_json:
            data = request.json
        else:
            data = request.form.to_dict()
            image_file = request.files.get('image')
            image_data = base64.b64encode(image_file.read()).decode('utf-8') if image_file else None
            data['image'] = f'data:image/jpeg;base64,{image_data}' if image_data else None

        email = data.get('email')
        password = data.get('password')
        image_data = data.get('image', '').split(',')[1] if data.get('image') else None

        if not all([email, password, image_data]):
            logging.error(f"Missing fields: email={email}, password={'*' * len(password) if password else None}, image_data={'present' if image_data else 'missing'}")
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        user = Voter.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            logging.error(f"Invalid credentials for email: {email}")
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

        filename = f"temp_{uuid.uuid4()}.jpg"
        with open(filename, 'wb') as f:
            f.write(base64.b64decode(image_data))

        img = cv2.imread(filename)
        if img is None:
            os.remove(filename)
            logging.error("Invalid image format")
            return jsonify({'success': False, 'message': 'Invalid image format'}), 400

        img = normalize_lighting(img)
        mp_face_mesh = mp.solutions.face_mesh
        face_mesh = mp_face_mesh.FaceMesh(
            static_image_mode=True,
            max_num_faces=1,
            refine_landmarks=True,
            min_detection_confidence=0.7
        )

        results = face_mesh.process(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
        if not results.multi_face_landmarks:
            os.remove(filename)
            logging.error("No face detected")
            return jsonify({'success': False, 'message': 'No face detected'}), 400

        landmarks = results.multi_face_landmarks[0].landmark
        h, w = img.shape[:2]
        x_coords = [int(lm.x * w) for lm in landmarks]
        y_coords = [int(lm.y * h) for lm in landmarks]
        
        x_min, x_max = max(0, min(x_coords)), min(w, max(x_coords))
        y_min, y_max = max(0, min(y_coords)), min(h, max(y_coords))
        
        margin = int(0.2 * max(x_max - x_min, y_max - y_min))
        x_min = max(0, x_min - margin)
        x_max = min(w, x_max + margin)
        y_min = max(0, y_min - margin)
        y_max = min(h, y_max + margin)

        face_img = img[y_min:y_max, x_min:x_max]

        try:
            embeddings = DeepFace.represent(
                cv2.cvtColor(face_img, cv2.COLOR_BGR2RGB),
                model_name='ArcFace',
                detector_backend='skip',
                enforce_detection=False,
                align=False
            )
        except ValueError as e:
            os.remove(filename)
            logging.error(f"Error processing face features: {str(e)}")
            return jsonify({'success': False, 'message': 'Error processing face features'}), 400

        if len(embeddings) != 1:
            os.remove(filename)
            logging.error("Multiple faces detected")
            return jsonify({'success': False, 'message': 'Multiple faces detected'}), 400

        current_embedding = np.array(embeddings[0]["embedding"])
        stored_embedding = np.array(json.loads(user.facial_data))

        current_embedding = current_embedding / np.linalg.norm(current_embedding)
        stored_embedding = stored_embedding / np.linalg.norm(stored_embedding)

        similarity = 1 - cosine(current_embedding, stored_embedding)
        os.remove(filename)

        if similarity < 0.6:
            logging.error(f"Face not recognized for user {email}, similarity: {similarity:.2f}")
            return jsonify({
                'success': False,
                'message': f'Face not recognized (similarity: {similarity:.2f})'
            }), 401

        token = generate_jwt_token(user.id, 'voter')

        current_time = datetime.now(timezone.utc)
        election = Election.query.filter(
            Election.start_time <= current_time,
            Election.end_time >= current_time
        ).first()
        has_voted = False
        if election:
            has_voted = Vote.query.filter_by(voter_id=user.id, election_id=election.id).first() is not None
            logging.info(f"Checked voting status for {email}: has_voted={has_voted}, election_id={election.id}")
        else:
            logging.info(f"No active election for {email}, redirecting to /home")
            return jsonify({
                'success': True,
                'token': token,
                'redirect_url': url_for('home'),
                'message': 'No active election available'
            }), 200

        redirect_endpoint = 'results' if has_voted else 'vote'
        redirect_url = url_for(redirect_endpoint)
        logging.info(f"User {email} login successful, has_voted: {has_voted}, redirecting to: {redirect_url}")

        response = jsonify({
            'success': True,
            'token': token,
            'redirect_url': redirect_url,
            'message': f'Welcome back, {user.name}!'
        })
        response.set_cookie(
            'jwt_token',
            token,
            httponly=True,
            samesite='Strict',
            path='/',
            secure=False,  # For local development
            max_age=3600
        )
        logging.info(f"Set jwt_token cookie for {email}, redirect_url: {redirect_url}")
        return response

    except Exception as e:
        if filename and os.path.exists(filename):
            os.remove(filename)
        logging.error(f"Login error for email {email if 'email' in locals() else 'unknown'}: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': 'Authentication failed'}), 500
    
@app.route('/vote', methods=['GET', 'POST'])
@jwt_required(allowed_roles=['voter'])
def vote():
    current_time = datetime.now(timezone.utc)
    election = Election.query.filter(
        Election.start_time <= current_time,
        Election.end_time >= current_time
    ).first()

    if not election:
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': False, 'message': 'No active election available'}), 400
        flash("No active election available!", "warning")
        return redirect(url_for('home'))

    voter = Voter.query.get(request.current_user.id)
    if not voter:
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': False, 'message': 'Voter not found'}), 404
        flash("Voter not found!", "danger")
        return redirect(url_for('home'))
    
    existing_vote = Vote.query.filter_by(voter_id=request.current_user.id, election_id=election.id).first()
    if existing_vote:
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': False, 'message': 'You have already cast your vote'}), 400
        flash("You've already cast your vote!", "danger")
        return redirect(url_for('results'))

    # Use joinedload to eagerly load party and election details
    candidates = Candidate.query.filter_by(election_id=election.id).options(
        joinedload(Candidate.party),
        joinedload(Candidate.election)
    ).all()
    
    if not candidates:
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'success': False, 'message': 'No candidates available for this election'}), 400
        flash("No candidates available for this election!", "warning")
        return redirect(url_for('home'))

    if request.method == 'POST':
        data = request.form if request.form else request.json
        candidate_id = data.get('candidate')
        candidate = Candidate.query.get(candidate_id)
        
        if not candidate or candidate.election_id != election.id:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': 'Invalid candidate selection'}), 400
            flash("Invalid candidate selection!", "danger")
            return redirect(url_for('vote'))

        new_vote = Vote(
            voter_id=request.current_user.id,
            candidate_id=candidate.id,
            election_id=election.id,
            timestamp=current_time
        )
        
        try:
            db.session.add(new_vote)
            db.session.commit()
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': True, 'message': 'Vote successfully cast'}), 201
            flash("Vote successfully cast!", "success")
            return redirect(url_for('results'))
        except Exception as e:
            db.session.rollback()
            if request.headers.get('Accept') == 'application/json':
                return jsonify({'success': False, 'message': f'Error casting vote: {str(e)}'}), 500
            flash(f"Error casting vote: {str(e)}", "danger")
            return redirect(url_for('vote'))  # Redirect back to vote page on error

    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'success': True,
            'election': {'id': election.id, 'name': election.name},
            'candidates': [{
                'id': c.id,
                'name': c.name,
                'party': c.party.name if c.party else 'Independent',
                'photo_url': c.photo_url or None,
                'bio': c.bio or '',
                'national_id': c.national_id
            } for c in candidates]
        }), 200
    return render_template('vote.html', candidates=candidates, election=election)
# Configure Tesseract path based on OS
try:
    pytesseract.get_tesseract_version()  # Verify Tesseract is accessible
except EnvironmentError:
    # If Tesseract not found in PATH, try setting default Windows path
    if platform.system() == "Windows":
        windows_path = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
        if os.path.exists(windows_path):
            pytesseract.pytesseract.tesseract_cmd = windows_path
        else:
            error_msg = (
                "Tesseract not found at default path. Please install it from "
                "https://github.com/UB-Mannheim/tesseract/wiki and ensure it's in your PATH "
                "or update the path in the code."
            )
            logging.error(error_msg)
    else:
        error_msg = (
            "Tesseract not found in PATH. Install with:\n"
            "macOS: brew install tesseract\n"
            "Linux: sudo apt install tesseract-ocr"
        )
        logging.error(error_msg)

# Configure logging
logging.basicConfig(
    filename='ocr_debug.log',  # Save logs to file for easier debugging
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Upload configuration
ID_CARD_UPLOAD_FOLDER = 'static/uploads/id_cards'
PHOTO_UPLOAD_FOLDER = 'static/uploads/candidate_photos'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config.update({
    'ID_CARD_UPLOAD_FOLDER': ID_CARD_UPLOAD_FOLDER,
    'PHOTO_UPLOAD_FOLDER': PHOTO_UPLOAD_FOLDER,
    'MAX_CONTENT_LENGTH': 5 * 1024 * 1024  # 5MB
})
os.makedirs(ID_CARD_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PHOTO_UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def preprocess_image(image_path):
    """Enhance image quality for OCR processing."""
    try:
        with Image.open(image_path) as img:
            # Convert to grayscale and enhance contrast
            img = img.convert('L')
            enhancer = ImageEnhance.Contrast(img)
            img = enhancer.enhance(2.0)
            
            # Resize and sharpen
            img = img.resize((img.width * 2, img.height * 2), Image.LANCZOS)
            img = img.filter(ImageFilter.SHARPEN)
            
            # Thresholding
            img = img.point(lambda x: 0 if x < 140 else 255)
            
            # Save processed image for debugging
            debug_path = os.path.join(app.config['ID_CARD_UPLOAD_FOLDER'], 
                                    f"processed_{os.path.basename(image_path)}")
            img.save(debug_path)
            logger.debug(f"Saved preprocessed image to: {debug_path}")
            return img
    except Exception as e:
        logger.error(f"Image processing failed: {str(e)}")
        return None

def extract_national_id_from_image(image_path):
    """Extract FCN national ID using OCR with robust pattern matching."""
    try:
        img = preprocess_image(image_path)
        if not img:
            return None, "Image processing failed"

        # OCR with multiple configurations
        configs = [
            '--psm 6 --oem 3 -c tessedit_char_whitelist=0123456789FCN ',  # Block text
            '--psm 11 --oem 3 -c tessedit_char_whitelist=0123456789FCN ',  # Sparse text
            '--psm 3 --oem 3 -c tessedit_char_whitelist=0123456789FCN '   # Default
        ]
        full_text = ""
        for cfg in configs:
            ocr_text = pytesseract.image_to_string(img, config=cfg)
            full_text += ocr_text + "\n"
            logger.debug(f"OCR text with config {cfg}: {ocr_text}")
        
        # Normalize text and search for ID patterns
        clean_text = re.sub(r'\s+', ' ', full_text).upper()
        logger.debug(f"OCR Text: {clean_text}")
        
        # Flexible ID patterns (FCN prefix with various spacings)
        patterns = [
            r'FCN[\s:]*(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})\b',
            r'\b(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})[\s-]*(\d{4})\b(?!.*\d)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, clean_text)
            if match:
                national_id = f"{match.group(1)} {match.group(2)} {match.group(3)} {match.group(4)}"
                if len(national_id.replace(" ", "")) == 16:
                    logger.debug(f"Found national ID: {national_id}")
                    return national_id, None
        
        return None, "No valid 16-digit ID found in FCN format"
    
    except pytesseract.TesseractNotFoundError:
        error_msg = (
            "Tesseract OCR not installed or not in PATH. Please install:\n"
            "Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki\n"
            "macOS: brew install tesseract\n"
            "Linux: sudo apt install tesseract-ocr"
        )
        logger.error(error_msg)
        return None, error_msg
    except Exception as e:
        logger.error(f"OCR Error: {str(e)}")
        return None, f"OCR processing failed: {str(e)}"

@app.route('/add_candidate', methods=['GET', 'POST'])
def add_candidate():
    if request.method == 'POST':
        # Handle file uploads first
        id_card = request.files.get('id_card')
        photo = request.files.get('candidate_photo')
        
        # Validate files
        if not all([id_card, photo]) or \
           not allowed_file(id_card.filename) or \
           not allowed_file(photo.filename):
            flash('Valid ID card and photo required (PNG/JPEG)', 'error')
            return redirect(url_for('add_candidate'))
        
        try:
            # Save files
            id_filename = secure_filename(id_card.filename)
            id_path = os.path.join(app.config['ID_CARD_UPLOAD_FOLDER'], id_filename)
            id_card.save(id_path)
            logger.debug(f"Saved ID card to: {id_path}")
            
            photo_filename = secure_filename(photo.filename)
            photo_path = os.path.join(app.config['PHOTO_UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            logger.debug(f"Saved candidate photo to: {photo_path}")
        except Exception as e:
            logger.error(f"File save error: {str(e)}")
            flash('Error saving uploaded files', 'error')
            return redirect(url_for('add_candidate'))

        # Extract national ID
        national_id, error = extract_national_id_from_image(id_path)
        if not national_id:
            flash(
                f'Could not extract a valid national ID from the ID card: {error}. '
                'Ensure the ID is clear, labeled as FCN, and in the format XXXX XXXX XXXX XXXX.',
                'error'
            )
            return redirect(url_for('add_candidate'))
        
        # Validate national_id format
        national_id_regex = r'^\d{4} \d{4} \d{4} \d{4}$'
        if not re.match(national_id_regex, national_id):
            logger.warning(f"Invalid national_id format: {national_id}")
            flash('Extracted national ID must be in format XXXX XXXX XXXX XXXX.', 'error')
            return redirect(url_for('add_candidate'))

        # Validate form data
        try:
            candidate_data = {
                'name': request.form['name'].strip(),
                'party_id': int(request.form['party_id']),
                'election_id': int(request.form['election_id']),
                'date_of_birth': datetime.strptime(request.form['date_of_birth'], '%Y-%m-%d').date(),
                'bio': request.form.get('bio', '').strip(),
                'eligibility_status': request.form.get('eligibility_status', 'Pending'),
                'national_id': national_id,
                'photo_url': f"uploads/candidate_photos/{photo_filename}"
            }
            
            # Age validation
            if (datetime.now().date() - candidate_data['date_of_birth']).days < 365*18:
                flash('Candidate must be at least 18 years old', 'error')
                return redirect(url_for('add_candidate'))
                
        except (KeyError, ValueError) as e:
            logger.error(f"Invalid form data: {str(e)}")
            flash('Invalid form submission', 'error')
            return redirect(url_for('add_candidate'))

        # Check for existing national ID
        if Candidate.query.filter_by(national_id=national_id).first():
            flash('National ID already registered', 'error')
            return redirect(url_for('add_candidate'))

        # Create and save candidate
        try:
            new_candidate = Candidate(**candidate_data)
            db.session.add(new_candidate)
            db.session.commit()
            logger.info(f"Added candidate: {new_candidate.name}, ID: {new_candidate.id}")
            flash('Candidate added successfully!', 'success')
            return redirect(url_for('candidates_list'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database error: {str(e)}")
            flash('Error saving candidate to database', 'error')
            return redirect(url_for('add_candidate'))

    # GET request - show form
    try:
        parties = Party.query.all()
        elections = Election.query.all()
        return render_template(
            'add_candidate.html',
            parties=parties,
            elections=elections,
            min_date=datetime.now().date().replace(year=datetime.now().year-100),
            max_date=datetime.now().date().replace(year=datetime.now().year-18)
        )
    except Exception as e:
        logger.error(f"Error rendering form: {str(e)}")
        flash(f'Error loading form: {str(e)}', 'error')
        return redirect(url_for('eadmin_dashboard'))
# Route to display candidates list (GET only)
@app.route('/candidates_list', methods=['GET'])
def candidates_list():
    print(f"Request to /candidates_list: {request.method} {request.form}")  # Debug request method and form data
    candidates = Candidate.query.options(
        joinedload(Candidate.party),
        joinedload(Candidate.election)
    ).all()
    parties = Party.query.all()
    elections = Election.query.all()
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'success': True,
            'candidates': [{'id': c.id, 'name': c.name, 'party': c.party.name, 'election': c.election.name} for c in candidates],
            'parties': [{'id': p.id, 'name': p.name} for p in parties],
            'elections': [{'id': e.id, 'name': e.name} for e in elections]
        }), 200
    return render_template('candidates_list.html', candidates=candidates, parties=parties, elections=elections)



@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    if request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'message': 'Logged out successfully'}), 200
    response = redirect(url_for('home'))
    response.delete_cookie('jwt_token')
    flash('You have been successfully logged out.', 'success')
    return response


@app.route('/results', methods=['GET'])
def results():
    # Query candidates with their party and election details
    candidates = Candidate.query.options(
        joinedload(Candidate.party),
        joinedload(Candidate.election)
    ).all()

    # Initialize results dictionary for candidate and party data
    results = {}
    for candidate in candidates:
        party_name = candidate.party.name if candidate.party else "No Party"
        election_name = candidate.election.name if candidate.election else "No Election"
        
        if election_name not in results:
            results[election_name] = {}

        if party_name not in results[election_name]:
            results[election_name][party_name] = {
                "party_votes": 0,
                "candidates": []
            }

        total_votes = Vote.query.filter_by(candidate_id=candidate.id).count()

        results[election_name][party_name]["candidates"].append({
            "candidate_name": candidate.name,
            "votes": total_votes
        })

        results[election_name][party_name]["party_votes"] += total_votes

    # Statistical data for charts
    stats = {
        "by_state": {},
        "by_gender": {},
        "by_age": {},
        "by_candidate": []
    }

    # Aggregate votes by state
    votes_by_state = db.session.query(
        Voter.state, db.func.count(Vote.id)
    ).join(Vote, Voter.id == Vote.voter_id).group_by(Voter.state).all()
    stats["by_state"] = [{"state": state, "votes": count} for state, count in votes_by_state]

    # Aggregate votes by gender
    votes_by_gender = db.session.query(
        Voter.gender, db.func.count(Vote.id)
    ).join(Vote, Voter.id == Vote.voter_id).group_by(Voter.gender).all()
    stats["by_gender"] = [{"gender": gender, "votes": count} for gender, count in votes_by_gender]

    # Aggregate votes by age group (calculated from date_of_birth)
    current_year = datetime.utcnow().year
    votes_by_age = db.session.query(
        func.floor((current_year - func.extract('year', Voter.date_of_birth)) / 10) * 10,
        db.func.count(Vote.id)
    ).join(Vote, Voter.id == Vote.voter_id).group_by(
        func.floor((current_year - func.extract('year', Voter.date_of_birth)) / 10)
    ).all()
    stats["by_age"] = [
        {"age_group": f"{int(age)}-{int(age)+9}", "votes": count}
        for age, count in votes_by_age
    ]

    # Aggregate votes by candidate
    votes_by_candidate = db.session.query(
        Candidate.name, db.func.count(Vote.id)
    ).join(Vote, Candidate.id == Vote.candidate_id).group_by(Candidate.id).all()
    stats["by_candidate"] = [{"candidate": name, "votes": count} for name, count in votes_by_candidate]

    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'success': True,
            'results': results,
            'stats': stats
        }), 200

    return render_template('results.html', results=results, stats=stats)

if __name__ == '__main__':
    with app.app_context():
        db.session.close()
        db.create_all()
        
        if not SuperUser.query.filter_by(username='superuser').first():
            default_superuser = SuperUser(
                username='superuser',
                password=generate_password_hash('superpass123')
            )
            db.session.add(default_superuser)
            db.session.commit()
    app.run(debug=True)
