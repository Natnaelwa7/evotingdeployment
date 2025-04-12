from flask import Flask, render_template, request, redirect, url_for, flash, Response, jsonify, json, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import os
from sqlalchemy import UniqueConstraint
from sqlalchemy import func
import uuid
import base64
from datetime import datetime, timezone
import time
import re
from sqlalchemy import create_engine
import mediapipe as mp
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask_login import UserMixin
from scipy.spatial.distance import cosine
import cv2
import numpy as np
from flask_sqlalchemy import SQLAlchemy
from deepface import DeepFace
from dotenv import load_dotenv
import logging
from flask_cors import CORS
from sqlalchemy.orm import joinedload
from flask_mail import Mail, Message
import random
import string

utc_now = datetime.fromtimestamp(time.time(), tz=timezone.utc)
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
load_dotenv()

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Correct Outlook SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False  # Outlook uses TLS, not SSL
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # Fetch from .env
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # Fetch from .env
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')  # Sender email should match username

mail = Mail(app)

DATABASE_URL = "postgresql://postgres.xixilmbyopeqmyrueaxv:Aster#123#@aws-0-eu-central-1.pooler.supabase.com:5432/postgres"
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SECRET_KEY'] = secrets.token_hex(16)
db = SQLAlchemy(app)

migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)

class SuperUser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='superuser')

class Voter(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    facial_data = db.Column(db.Text, nullable=True)
    blocked = db.Column(db.Boolean, default=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'))
    role = db.Column(db.String(50), default='voter')
class PendingVoter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    facial_data = db.Column(db.Text, nullable=True)
    invitation_code = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
class ElectionOfficer(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)
    blocked = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), default='eadmin')
    invitation_code = db.Column(db.String(10), nullable=True)

class SystemAdmin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(50), default='sysadmin')
    invitation_code = db.Column(db.String(10), nullable=True)

class Election(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(255))
    candidates = db.relationship('Candidate', backref='election', lazy=True)
    voters = db.relationship('Voter', backref='election', lazy=True)

class Party(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    candidates = db.relationship('Candidate', backref='party', lazy=True)

class Candidate(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    party_id = db.Column(db.Integer, db.ForeignKey('party.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    votes = db.Column(db.Integer, default=0)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey('voter.id'), unique=True, nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    voter = db.relationship('Voter', backref=db.backref('vote', uselist=False))
    candidate = db.relationship('Candidate', backref='votes_received')
    election = db.relationship('Election', backref='votes_cast')

@property
def is_active(self):
    now = datetime.now()
    return self.start_time <= now <= self.end_time

@login_manager.user_loader
def load_user(user_id):
    for model in [SuperUser, Voter, ElectionOfficer, SystemAdmin]:
        user = model.query.get(int(user_id))
        if user:
            return user
    return None

def generate_invitation_code(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

# SuperUser Routes
@app.route('/superuser/login', methods=['GET', 'POST'])
def superuser_login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        superuser = SuperUser.query.filter_by(username=username).first()
        if superuser and check_password_hash(superuser.password, password):
            login_user(superuser)
            flash('Superuser login successful!', 'success')
            return redirect(url_for('superuser_dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
    
    return render_template('superuser_login.html')


@app.route('/sysadmin/register', methods=['GET', 'POST'])
def sysadmin_register():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'request_invite':
            name = request.form['name'].strip()
            email = request.form['email'].strip()
            
            if not all([name, email]):
                flash('Name and email are required to request an invitation!', 'danger')
                return redirect(url_for('sysadmin_register'))
            
            # Check if email already exists
            if SystemAdmin.query.filter_by(email=email).first():
                flash('This email is already registered or has a pending invitation!', 'warning')
                return redirect(url_for('sysadmin_register'))
            
            # Get SuperUser email from .env
            superuser_email = os.getenv('SUPERUSER_EMAIL')
            if not superuser_email:
                flash('No SuperUser email configured in the system! Contact administrator.', 'danger')
                return redirect(url_for('sysadmin_register'))
            
            # Send notification to SuperUser
            try:
                msg = Message('System Admin Invitation Request',
                              recipients=[superuser_email],  # SuperUser’s email from .env
                              sender=os.getenv('MAIL_USERNAME'))
                msg.body = f'Hello SuperUser,\n\n{name} ({email}) has requested an invitation code to register as a System Admin.\nPlease generate one from your dashboard at {url_for("superuser_dashboard", _external=True)}.'
                mail.send(msg)
                flash('Invitation request sent to the SuperUser! Check your email later for the code.', 'success')
            except Exception as e:
                flash(f'Failed to send invitation request: {str(e)}', 'danger')
                logging.error(f"Mail send error: {str(e)}", exc_info=True)
            return redirect(url_for('sysadmin_register'))
        
        elif action == 'register':
            name = request.form['name'].strip()
            email = request.form['email'].strip()
            password = request.form['password'].strip()
            invitation_code = request.form['invitation_code'].strip()

            if not all([name, email, password, invitation_code]):
                flash('All fields are required for registration!', 'danger')
                return redirect(url_for('sysadmin_register'))

            admin = SystemAdmin.query.filter_by(email=email).first()
            if admin:
                if admin.invitation_code != invitation_code:
                    flash('Invalid invitation code!', 'danger')
                    return redirect(url_for('sysadmin_register'))
                hashed_password = generate_password_hash(password)
                admin.password = hashed_password
                admin.invitation_code = None
                db.session.commit()
                flash('System Admin registered successfully!', 'success')
                return redirect(url_for('sysadmin_login'))
            else:
                flash('Please request an invitation code from the Superuser!', 'warning')
                return redirect(url_for('sysadmin_register'))
    
    return render_template('sysadmin_register.html')


@app.route('/sysadmin/delete_voter/<int:voter_id>', methods=['POST'])
@login_required
def delete_voter(voter_id):
    if current_user.role != 'sysadmin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    
    voter = Voter.query.get_or_404(voter_id)
    db.session.delete(voter)
    db.session.commit()
    flash('Voter deleted successfully!', 'success')
    return redirect(url_for('sysadmin_dashboard'))




@app.route('/sysadmin/delete_officer/<int:officer_id>', methods=['POST'])
@login_required
def delete_officer(officer_id):
    if current_user.role != 'sysadmin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('home'))
    
    officer = ElectionOfficer.query.get_or_404(officer_id)
    db.session.delete(officer)
    db.session.commit()
    flash('Election Officer deleted successfully!', 'success')
    return redirect(url_for('sysadmin_dashboard'))




@app.route('/eadmin/register', methods=['GET', 'POST'])
def eadmin_register():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'request_invite':
            name = request.form['name'].strip()
            email = request.form['email'].strip()
            
            if not all([name, email]):
                flash('Name and email are required to request an invitation!', 'danger')
                return redirect(url_for('eadmin_register'))
            
            # Check if email already exists
            if ElectionOfficer.query.filter_by(email=email).first():
                flash('This email is already registered or has a pending invitation!', 'warning')
                return redirect(url_for('eadmin_register'))
            
            # Get SuperUser email from .env
            superuser_email = os.getenv('SUPERUSER_EMAIL')
            if not superuser_email:
                flash('No SuperUser email configured in the system! Contact administrator.', 'danger')
                return redirect(url_for('eadmin_register'))
            
            # Send notification to SuperUser
            try:
                msg = Message('Election Officer Invitation Request',
                              recipients=[superuser_email],  # SuperUser’s email from .env
                              sender=os.getenv('MAIL_USERNAME'))
                msg.body = f'Hello SuperUser,\n\n{name} ({email}) has requested an invitation code to register as an Election Officer.\nPlease generate one from your dashboard at {url_for("superuser_dashboard", _external=True)}.'
                mail.send(msg)
                flash('Invitation request sent to the SuperUser! Check your email later for the code.', 'success')
            except Exception as e:
                flash(f'Failed to send invitation request: {str(e)}', 'danger')
                logging.error(f"Mail send error: {str(e)}", exc_info=True)
            return redirect(url_for('eadmin_register'))
        
        elif action == 'register':
            name = request.form['name'].strip()
            email = request.form['email'].strip()
            password = request.form['password'].strip()
            invitation_code = request.form['invitation_code'].strip()

            if not all([name, email, password, invitation_code]):
                flash('All fields are required for registration!', 'danger')
                return redirect(url_for('eadmin_register'))

            officer = ElectionOfficer.query.filter_by(email=email).first()
            if officer:
                if officer.invitation_code != invitation_code:
                    flash('Invalid invitation code!', 'danger')
                    return redirect(url_for('eadmin_register'))
                hashed_password = generate_password_hash(password)
                officer.password = hashed_password
                officer.invitation_code = None
                db.session.commit()
                flash('Election Officer registered successfully!', 'success')
                return redirect(url_for('eadmin_login'))
            else:
                flash('Please request an invitation code from the Superuser!', 'warning')
                return redirect(url_for('eadmin_register'))
    
    return render_template('eadmin_register.html')


@app.route('/sysadmin/login', methods=['GET', 'POST'])
def sysadmin_login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        admin = SystemAdmin.query.filter_by(email=email).first()
        if admin and check_password_hash(admin.password, password):
            login_user(admin)
            flash('Login successful!', 'success')
            return redirect(url_for('sysadmin_dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
    
    return render_template('sysadmin_login.html')

@app.route('/sysadmin/dashboard')
@login_required
def sysadmin_dashboard():
    if current_user.role not in ['sysadmin', 'superuser']:
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))
    
    voters = Voter.query.all()
    officers = ElectionOfficer.query.all()
    admins = SystemAdmin.query.all()
    return render_template('sysadmin_dashboard.html', voters=voters, officers=officers, admins=admins)



@app.route('/sysadmin/block_voter/<int:voter_id>', methods=['POST'])
@login_required
def block_voter(voter_id):
    voter = Voter.query.get(voter_id)
    if voter:
        voter.blocked = True
        db.session.commit()
        flash('Voter blocked successfully', 'success')
    return redirect(url_for('sysadmin_dashboard'))

@app.route('/sysadmin/unblock_voter/<int:voter_id>', methods=['POST'])
@login_required
def unblock_voter(voter_id):
    voter = Voter.query.get(voter_id)
    if voter:
        voter.blocked = False
        db.session.commit()
        flash('Voter unblocked successfully', 'success')
    return redirect(url_for('sysadmin_dashboard'))



@app.route('/eadmin/login', methods=['GET', 'POST'])
def eadmin_login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()
        officer = ElectionOfficer.query.filter_by(email=email).first()
        if officer and check_password_hash(officer.password, password) and officer.role == 'eadmin':
            login_user(officer)
            flash('Login successful!', 'success')
            return redirect(url_for('eadmin_dashboard'))
        else:
            flash('Invalid email or password!', 'danger')
    return render_template('eadmin_login.html')

@app.route('/eadmin/dashboard')
@login_required
def eadmin_dashboard():
    voters = Voter.query.all()
    candidates = Candidate.query.all()
    elections = Election.query.all()
    return render_template('eadmin_dashboard.html', voters=voters, candidates=candidates, elections=elections)

@app.route('/eadmin/add_election', methods=['GET', 'POST'])
@login_required
def add_election():
    if request.method == 'POST':
        name = request.form['name'].strip()
        start_time = request.form['start_time']
        end_time = request.form['end_time']
        description = request.form['description'].strip()

        if not name or not start_time or not end_time:
            flash('All fields are required!', 'danger')
            return redirect(url_for('add_election'))

        start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
        end_time = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')

        new_election = Election(name=name, start_time=start_time, end_time=end_time, description=description)
        db.session.add(new_election)
        db.session.commit()
        
        flash(f'Election "{name}" created successfully!', 'success')
        return redirect(url_for('eadmin_dashboard'))
    
    return render_template('add_election.html')

@app.route('/eadmin/add_party', methods=['GET', 'POST'])
@login_required
def add_party():
    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash('Party name cannot be empty!', 'danger')
            return redirect(url_for('add_party'))

        new_party = Party(name=name)
        db.session.add(new_party)
        db.session.commit()
        flash(f'Party "{name}" added successfully!', 'success')
        return redirect(url_for('eadmin_dashboard'))

    return render_template('add_party.html')

# Superuser Dashboard and Management Routes
@app.route('/superuser/dashboard')
@login_required
def superuser_dashboard():
    if current_user.role != 'superuser':
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))
    
    voters = Voter.query.all()
    officers = ElectionOfficer.query.all()
    admins = SystemAdmin.query.all()
    return render_template('superuser_dashboard.html', voters=voters, officers=officers, admins=admins)
@app.route('/superuser/generate_invite', methods=['POST'])
@login_required
def generate_invite():
    if current_user.role != 'superuser':
        return redirect(url_for('home'))

    user_type = request.form['user_type']
    email = request.form['email'].strip()
    name = request.form['name'].strip()

    if user_type == 'sysadmin':
        existing = SystemAdmin.query.filter_by(email=email).first()
        if existing:
            if existing.invitation_code:
                flash('An invitation code has already been generated for this email!', 'warning')
            else:
                flash('This email is already registered!', 'warning')
            return redirect(url_for('superuser_dashboard'))
        code = generate_invitation_code()
        new_admin = SystemAdmin(name=name, email=email, invitation_code=code)
        db.session.add(new_admin)
    elif user_type == 'eadmin':
        existing = ElectionOfficer.query.filter_by(email=email).first()
        if existing:
            if existing.invitation_code:
                flash('An invitation code has already been generated for this email!', 'warning')
            else:
                flash('This email is already registered!', 'warning')
            return redirect(url_for('superuser_dashboard'))
        code = generate_invitation_code()
        new_officer = ElectionOfficer(name=name, email=email, invitation_code=code)
        db.session.add(new_officer)
    else:
        flash('Invalid user type!', 'danger')
        return redirect(url_for('superuser_dashboard'))

    db.session.commit()
    
    # Send the invitation code to the requester’s email
    try:
        msg = Message(f'Your {user_type} Invitation Code',
                      recipients=[email],  # Send to requester’s email (e.g., natna6434@gmail.com)
                      sender=os.getenv('MAIL_USERNAME'))
        msg.body = f'Hello {name},\n\nYour invitation code is: {code}\nPlease use this code to complete your registration at {url_for("sysadmin_register" if user_type == "sysadmin" else "eadmin_register", _external=True)}.'
        mail.send(msg)
        flash(f'Invitation code sent to {email}!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to send invitation code: {str(e)}', 'danger')
        logging.error(f"Mail send error: {str(e)}", exc_info=True)
    
    return redirect(url_for('superuser_dashboard'))

@app.route('/superuser/delete_admin/<int:admin_id>', methods=['POST'])
@login_required
def superuser_delete_admin(admin_id):
    if current_user.role != 'superuser':
        return redirect(url_for('home'))
    
    admin = SystemAdmin.query.get_or_404(admin_id)
    db.session.delete(admin)
    db.session.commit()
    flash(f'Admin {admin.name} deleted successfully', 'success')
    return redirect(url_for('superuser_dashboard'))

@app.route('/superuser/delete_officer/<int:officer_id>', methods=['POST'])
@login_required
def superuser_delete_officer(officer_id):
    if current_user.role != 'superuser':
        return redirect(url_for('home'))
    
    officer = ElectionOfficer.query.get_or_404(officer_id)
    db.session.delete(officer)
    db.session.commit()
    flash(f'Officer {officer.name} deleted successfully', 'success')
    return redirect(url_for('superuser_dashboard'))

# Main Routes
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
        try:
            data = request.json
            step = data.get('step')

            if step == 'request_code':
                email = data.get('email')
                if not email:
                    return jsonify({'success': False, 'message': 'Email is required'}), 400

                if Voter.query.filter_by(email=email).first():
                    return jsonify({'success': False, 'message': 'Email already registered'}), 400

                pending_voter = PendingVoter.query.filter_by(email=email).first()
                if pending_voter:
                    return jsonify({'success': False, 'message': 'Verification code already sent'}), 400

                invitation_code = generate_invitation_code()
                new_pending = PendingVoter(
                    email=email,
                    name=data.get('name', ''),
                    password=generate_password_hash(data.get('password', '')),
                    facial_data='',
                    invitation_code=invitation_code
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
                email = data.get('email')
                code = data.get('code')
                name = data.get('name')
                password = data.get('password')
                image_data = data.get('image', '').split(',')[1] if data.get('image') else None

                if not all([email, code, name, password, image_data]):
                    return jsonify({'success': False, 'message': 'All fields are required'}), 400

                pending_voter = PendingVoter.query.filter_by(email=email, invitation_code=code).first()
                if not pending_voter:
                    return jsonify({'success': False, 'message': 'Invalid code or email'}), 400

                # Process facial image
                filename = f"temp_{uuid.uuid4()}.jpg"
                with open(filename, 'wb') as f:
                    f.write(base64.b64decode(image_data))

                img = cv2.imread(filename)
                if img is None:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Invalid image'}), 400

                # Lighting check
                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                avg_brightness = np.mean(gray)
                if avg_brightness < 50 or avg_brightness > 200:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Adjust lighting conditions'}), 400

                # Face detection and processing
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

                # Extract face region with margin
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

                # Generate facial embedding
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
                threshold = 0.4  # Adjusted similarity threshold

                # Check against existing registrations
                duplicate = False
                for voter in Voter.query.all():
                    existing_embedding = np.array(json.loads(voter.facial_data))
                    if cosine(existing_embedding, embedding) < threshold:
                        duplicate = True
                        break

                if duplicate:
                    os.remove(filename)
                    return jsonify({'success': False, 'message': 'Face already registered'}), 400

                # Complete registration
                new_voter = Voter(
                    name=name,
                    email=email,
                    password=generate_password_hash(password),
                    facial_data=json.dumps(embedding.tolist())
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
            return jsonify({'success': False, 'message': 'Registration failed'}), 500

    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    filename = None
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        image_data = data.get('image', '').split(',')[1] if data.get('image') else None

        if not all([email, password, image_data]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400

        user = Voter.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 400

        filename = f"temp_{uuid.uuid4()}.jpg"
        with open(filename, 'wb') as f:
            f.write(base64.b64decode(image_data))

        img = cv2.imread(filename)
        if img is None:
            os.remove(filename)
            return jsonify({'success': False, 'message': 'Invalid image format'}), 400

        # Consistent preprocessing with registration
        img = normalize_lighting(img)
        mp_face_mesh = mp.solutions.face_mesh
        face_mesh = mp_face_mesh.FaceMesh(
            static_image_mode=True,
            max_num_faces=1,
            refine_landmarks=True,
            min_detection_confidence=0.7  # Increased from 0.5 to match registration
        )

        results = face_mesh.process(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
        if not results.multi_face_landmarks:
            os.remove(filename)
            return jsonify({'success': False, 'message': 'No face detected'}), 400

        # Consistent face cropping with registration
        landmarks = results.multi_face_landmarks[0].landmark
        h, w = img.shape[:2]
        x_coords = [int(lm.x * w) for lm in landmarks]
        y_coords = [int(lm.y * h) for lm in landmarks]
        
        x_min, x_max = max(0, min(x_coords)), min(w, max(x_coords))
        y_min, y_max = max(0, min(y_coords)), min(h, max(y_coords))
        
        # Use same margin calculation as registration
        margin = int(0.2 * max(x_max - x_min, y_max - y_min))
        x_min = max(0, x_min - margin)
        x_max = min(w, x_max + margin)
        y_min = max(0, y_min - margin)
        y_max = min(h, y_max + margin)

        face_img = img[y_min:y_max, x_min:x_max]
        
        # Resize to match registration processing (remove 224x224 resize if not used in registration)
        # face_img = cv2.resize(face_img, (112, 112))  # Add if used in registration

        try:
            # Match registration's DeepFace parameters exactly
            embeddings = DeepFace.represent(
                cv2.cvtColor(face_img, cv2.COLOR_BGR2RGB),
                model_name='ArcFace',
                detector_backend='skip',
                enforce_detection=False,
                align=False
            )
        except ValueError as e:
            os.remove(filename)
            return jsonify({'success': False, 'message': 'Error processing face features'}), 400

        if len(embeddings) != 1:
            os.remove(filename)
            return jsonify({'success': False, 'message': 'Multiple faces detected'}), 400

        current_embedding = np.array(embeddings[0]["embedding"])
        stored_embedding = np.array(json.loads(user.facial_data))

        # Normalize embeddings for cosine similarity
        current_embedding = current_embedding / np.linalg.norm(current_embedding)
        stored_embedding = stored_embedding / np.linalg.norm(stored_embedding)

        similarity = 1 - cosine(current_embedding, stored_embedding)
        os.remove(filename)

        # Corrected threshold logic (0.6 matches registration's 0.4 distance threshold)
        if similarity < 0.6:  # Changed from > 0.5 to < 0.6
            return jsonify({
                'success': False,
                'message': f'Face not recognized (similarity: {similarity:.2f})'
            }), 400

        login_user(user)
        return jsonify({
            'success': True,
            'redirect': url_for('vote', voter_id=user.id),
            'message': f'Welcome back, {user.name}!'
        })

    except Exception as e:
        logging.error(f"Login error: {str(e)}", exc_info=True)
        if filename and os.path.exists(filename):
            os.remove(filename)
        return jsonify({'success': False, 'message': 'Authentication failed'}), 500

@app.route('/vote', methods=['GET', 'POST'])
@login_required
def vote():
    # Ensure proper datetime handling with timezone awareness
    current_time = datetime.now(timezone.utc)  

    # Fetch active election
    election = Election.query.filter(
        Election.start_time <= current_time,
        Election.end_time >= current_time
    ).first()

    if not election:
        flash("No active election available!", "warning")
        return redirect(url_for('home'))

    # Fetch voter information
    voter = Voter.query.get(current_user.id)
    if not voter:
        flash("Voter not found!", "danger")
        return redirect(url_for('home'))
    
    # Check if the user has already voted
    existing_vote = Vote.query.filter_by(voter_id=current_user.id, election_id=election.id).first()
    if existing_vote:
        flash("You've already cast your vote!", "danger")
        return redirect(url_for('results'))

    # Get candidates for the active election
    candidates = Candidate.query.filter_by(election_id=election.id).all()
    if not candidates:
        flash("No candidates available for this election!", "warning")
        return redirect(url_for('home'))

    if request.method == 'POST':
        candidate_id = request.form.get('candidate')
        candidate = Candidate.query.get(candidate_id)
        
        # Validate candidate selection
        if not candidate or candidate.election_id != election.id:
            flash("Invalid candidate selection!", "danger")
            return redirect(url_for('vote'))

        # Record the vote
        new_vote = Vote(
            voter_id=current_user.id,
            candidate_id=candidate.id,
            election_id=election.id,
            timestamp=current_time  # Maintain timezone consistency
        )
        
        try:
            # Save the vote
            db.session.add(new_vote)
            db.session.commit()
            flash("Vote successfully cast!", "success")
            return redirect(url_for('results'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error casting vote: {str(e)}", "danger")
        
        return redirect(url_for('home'))

    return render_template('vote.html', candidates=candidates, election=election)

@app.route('/add_candidate', methods=['GET', 'POST'])
def add_candidate():
    if request.method == 'POST':
        name = request.form.get('name')
        party_id = request.form.get('party_id')
        election_id = request.form.get('election_id')

        if not party_id or not election_id:
            flash('Party and Election must be selected.', 'error')
            return redirect(url_for('add_candidate'))

        new_candidate = Candidate(name=name, votes=0, party_id=party_id, election_id=election_id)
        db.session.add(new_candidate)
        db.session.commit()
        flash('Candidate added successfully!', 'success')
        return redirect(url_for('candidates_list'))

    parties = Party.query.all()
    elections = Election.query.all()
    return render_template('add_candidate.html', parties=parties, elections=elections)

@app.route('/candidates_list', methods=['GET', 'POST'])
def candidates_list():
    if request.method == 'POST':
        candidate_name = request.form['candidate_name']
        party_id = request.form['party_id']
        election_id = request.form['election_id']

        new_candidate = Candidate(name=candidate_name, party_id=party_id, election_id=election_id)
        db.session.add(new_candidate)
        db.session.commit()
        return redirect(url_for('candidates_list'))

    candidates = Candidate.query.options(
        joinedload(Candidate.party),
        joinedload(Candidate.election)
    ).all()
    parties = Party.query.all()
    elections = Election.query.all()
    return render_template('candidates_list.html', candidates=candidates, parties=parties, elections=elections)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('home'))


@app.route('/results', methods=['GET'])
def results():
    # Eager load candidates, parties, and elections to avoid N+1 queries
    candidates = Candidate.query.options(
        joinedload(Candidate.party),
        joinedload(Candidate.election)
    ).all()

    # Retrieve election results by candidate and party
    results = {}
    for candidate in candidates:
        party_name = candidate.party.name if candidate.party else "No Party"
        election_name = candidate.election.name if candidate.election else "No Election"
        
        # Initialize election results if not present
        if election_name not in results:
            results[election_name] = {}

        # Initialize party results if not present
        if party_name not in results[election_name]:
            results[election_name][party_name] = {
                "party_votes": 0,
                "candidates": []
            }

        # Count the total votes for each candidate
        total_votes = Vote.query.filter_by(candidate_id=candidate.id).count()

        # Add the candidate to the results with their vote count
        results[election_name][party_name]["candidates"].append({
            "candidate_name": candidate.name,
            "votes": total_votes
        })

        # Sum up the total votes for the party in this election
        results[election_name][party_name]["party_votes"] += total_votes

    return render_template('results.html', results=results)


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
