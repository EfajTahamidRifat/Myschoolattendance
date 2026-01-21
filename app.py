import os
import json
import hashlib
import hmac
import base64
import time
import re
import io
from datetime import datetime, timedelta, timezone
from functools import wraps
from threading import Thread
import requests
import secrets
from urllib.parse import urlparse

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from concurrent.futures import ThreadPoolExecutor, as_completed
import qrcode
from io import StringIO
import traceback
import segno  # Alternative QR code library without Pillow
from weasyprint import HTML  # For PDF generation

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

# FIXED: Use absolute path for SQLite database in instance folder
base_dir = os.path.abspath(os.path.dirname(__file__))
instance_path = os.path.join(base_dir, 'instance')
database_path = os.path.join(instance_path, 'dewra_school.db')

# Ensure instance directory exists
os.makedirs(instance_path, exist_ok=True)

# Set database URI - use SQLite in instance folder
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Ensure all directories exist
def ensure_directories():
    """Create all necessary directories"""
    directories = [
        app.config['UPLOAD_FOLDER'],
        os.path.join(app.config['UPLOAD_FOLDER'], 'teachers'),
        os.path.join(app.config['UPLOAD_FOLDER'], 'signatures'),
        os.path.join(app.config['UPLOAD_FOLDER'], 'students'),
        os.path.join(app.config['UPLOAD_FOLDER'], 'pdfs'),
        os.path.join(app.config['UPLOAD_FOLDER'], 'qrcodes'),
        os.path.join(app.config['UPLOAD_FOLDER'], 'html_pdfs'),
        instance_path,
        os.path.join(instance_path, 'backups'),
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        try:
            os.chmod(directory, 0o755)
        except:
            pass

ensure_directories()

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please login to access this page.'
login_manager.login_message_category = 'warning'

# ============= SMSGate Configuration =============
SMSGATE_BASE_URL = os.getenv("SMSGATE_BASE_URL", "https://api.sms-gate.app")
SMSGATE_USERNAME = os.getenv("SMSGATE_USERNAME")
SMSGATE_PASSWORD = os.getenv("SMSGATE_PASSWORD")

TOKEN_CACHE = {
    "token": None,
    "expires_at": None
}

# ============= DATABASE MODELS =============
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='teacher')
    profile_image = db.Column(db.String(200))
    assigned_classes = db.Column(db.Text, default='{}')
    assigned_subjects = db.Column(db.Text, default='{}')
    phone = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def get_assigned_classes_dict(self):
        try:
            return json.loads(self.assigned_classes) if self.assigned_classes else {}
        except:
            return {}

    def get_assigned_subjects_dict(self):
        try:
            return json.loads(self.assigned_subjects) if self.assigned_subjects else {}
        except:
            return {}

    def is_assigned_to(self, class_name, section=None, subject_id=None):
        try:
            assigned_classes = self.get_assigned_classes_dict()
            assigned_subjects = self.get_assigned_subjects_dict()

            if class_name not in assigned_classes:
                return False

            if section and section not in assigned_classes[class_name]:
                return False

            if subject_id and str(subject_id) not in assigned_subjects.get(class_name, []):
                return False

            return True
        except:
            return False

class Student(db.Model):
    __tablename__ = 'student'
    id = db.Column(db.Integer, primary_key=True)
    roll_number = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    father_name = db.Column(db.String(100))
    father_phone = db.Column(db.String(20), nullable=False)
    mother_name = db.Column(db.String(100))
    mother_phone = db.Column(db.String(20))
    class_name = db.Column(db.String(10), nullable=False)
    section = db.Column(db.String(5), nullable=False)
    address = db.Column(db.Text)
    date_of_birth = db.Column(db.Date)
    photo = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('class_name', 'section', 'roll_number', name='unique_student_roll'),
    )

class Class(db.Model):
    __tablename__ = 'class'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(10), unique=True, nullable=False)
    sections = db.Column(db.Text, nullable=False)
    description = db.Column(db.String(200))
    class_teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    class_teacher = db.relationship('User', foreign_keys=[class_teacher_id])

class Subject(db.Model):
    __tablename__ = 'subject'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), unique=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class TeacherAssignment(db.Model):
    __tablename__ = 'teacher_assignment'
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_name = db.Column(db.String(10), nullable=False)
    section = db.Column(db.String(5), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    teacher = db.relationship('User', backref='assignments')
    subject = db.relationship('Subject', backref='assignments')

    __table_args__ = (
        db.UniqueConstraint('teacher_id', 'class_name', 'section', 'subject_id', name='unique_teacher_assignment'),
    )

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_name = db.Column(db.String(10), nullable=False)
    section = db.Column(db.String(5), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    date = db.Column(db.Date, nullable=False)
    day = db.Column(db.String(20), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    sms_status = db.Column(db.String(20), default='pending')
    pdf_path = db.Column(db.String(500))
    pdf_url = db.Column(db.String(500))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    student = db.relationship('Student', backref='attendances')
    teacher = db.relationship('User', backref='attendances')
    subject = db.relationship('Subject', backref='attendances')

    __table_args__ = (
        db.UniqueConstraint('student_id', 'date', 'subject_id', name='unique_daily_attendance'),
    )

class AttendanceSession(db.Model):
    __tablename__ = 'attendance_session'
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_name = db.Column(db.String(10), nullable=False)
    section = db.Column(db.String(5), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    total_students = db.Column(db.Integer, default=0)
    present_count = db.Column(db.Integer, default=0)
    absent_count = db.Column(db.Integer, default=0)
    pdf_generated = db.Column(db.Boolean, default=False)
    pdf_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    teacher = db.relationship('User', backref='attendance_sessions')
    subject = db.relationship('Subject', backref='attendance_sessions')

class SMSLog(db.Model):
    __tablename__ = 'sms_log'
    id = db.Column(db.Integer, primary_key=True)
    attendance_id = db.Column(db.Integer, db.ForeignKey('attendance.id'))
    phone = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    response = db.Column(db.Text)
    message_id = db.Column(db.String(100))
    retry_count = db.Column(db.Integer, default=0)
    sent_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    attendance = db.relationship('Attendance', backref='sms_logs')

class CustomMessage(db.Model):
    __tablename__ = 'custom_message'
    id = db.Column(db.Integer, primary_key=True)
    message_type = db.Column(db.String(20), nullable=False)
    message_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class SMSConfig(db.Model):
    __tablename__ = 'sms_config'
    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(200))
    device_id = db.Column(db.String(100))
    signing_secret = db.Column(db.String(200))
    max_concurrent = db.Column(db.Integer, default=5)
    rate_limit_per_minute = db.Column(db.Integer, default=60)
    enabled = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class DropboxConfig(db.Model):
    __tablename__ = 'dropbox_config'
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(200))
    refresh_token = db.Column(db.String(200))
    folder_path = db.Column(db.String(200), default='/attendance')
    enabled = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class SystemSettings(db.Model):
    __tablename__ = 'system_settings'
    id = db.Column(db.Integer, primary_key=True)
    school_name = db.Column(db.String(200), default='Dewra High School')
    school_logo = db.Column(db.String(500), default='https://i.supaimg.com/5838a1ce-b184-48bc-b370-5250b7e25a58.png')
    school_address = db.Column(db.Text, default='Bhanga, Faridpur')
    established_year = db.Column(db.Integer, default=1970)
    head_teacher_name = db.Column(db.String(100), default='Head Teacher')
    head_teacher_signature = db.Column(db.String(200))
    motto = db.Column(db.Text, default='Every student is nuclear energy — capable of changing society, the state, the entire world. — Saiful Howlader')
    theme_color = db.Column(db.String(20), default='#00d4ff')
    secondary_color = db.Column(db.String(20), default='#ff00ea')
    accent_color = db.Column(db.String(20), default='#00ff88')
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

class DailyQuote(db.Model):
    __tablename__ = 'daily_quote'
    id = db.Column(db.Integer, primary_key=True)
    quote = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(100))
    category = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class ActivityLog(db.Model):
    __tablename__ = 'activity_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(50), nullable=False)
    module = db.Column(db.String(50))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='activities')

class BackupLog(db.Model):
    __tablename__ = 'backup_log'
    id = db.Column(db.Integer, primary_key=True)
    backup_type = db.Column(db.String(20))
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    status = db.Column(db.String(20))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# ============= HELPER FUNCTIONS =============
@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except:
        return None

def log_activity(action, module=None, details=None):
    """Log user activity"""
    if current_user.is_authenticated:
        try:
            log = ActivityLog(
                user_id=current_user.id,
                action=action,
                module=module,
                details=details,
                ip_address=request.remote_addr if request else '127.0.0.1',
                user_agent=request.user_agent.string if request else 'System'
            )
            db.session.add(log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error logging activity: {str(e)}")

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'teacher':
            flash('Access denied. Teacher only.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'super_admin':
            flash('Access denied. Super Admin only.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename, allowed_extensions=None):
    if allowed_extensions is None:
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def get_today_quote():
    """Get random motivational quote"""
    try:
        quote = DailyQuote.query.filter_by(is_active=True).order_by(db.func.random()).first()
        return quote
    except Exception as e:
        return None

def generate_qr_code(data, filename):
    """Generate QR code for attendance using segno"""
    try:
        qr = segno.make_qr(data)

        # Save to file as SVG
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'qrcodes', filename.replace('.png', '.svg'))
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        # Save as SVG
        qr.save(filepath, scale=10)

        # Also save as PNG using segno's built-in PNG support
        png_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'qrcodes', filename)
        qr.save(png_filepath, scale=10, dark='black', light='white')

        return f'uploads/qrcodes/{filename}'
    except Exception as e:
        app.logger.error(f"Error generating QR code: {str(e)}")
        return None

# ============= JINJA2 FILTERS =============
@app.template_filter('from_json')
def from_json_filter(value):
    """Convert JSON string to Python object"""
    if not value:
        return {}
    try:
        return json.loads(value)
    except:
        return {}

@app.template_filter('to_json')
def to_json_filter(value):
    """Convert Python object to JSON string"""
    try:
        return json.dumps(value)
    except:
        return '{}'

@app.template_filter('format_date')
def format_date_filter(value, format='%d %b, %Y'):
    """Format date"""
    if not value:
        return ''
    try:
        if isinstance(value, str):
            value = datetime.strptime(value, '%Y-%m-%d')
        return value.strftime(format)
    except:
        return value

@app.template_filter('format_phone')
def format_phone_filter(phone):
    """Format phone number"""
    if not phone:
        return ''
    phone = re.sub(r'\D', '', phone)
    if len(phone) == 11 and phone.startswith('01'):
        return f'+880{phone[1:]}'
    elif len(phone) == 10:
        return f'+880{phone}'
    elif phone.startswith('880') and len(phone) == 13:
        return f'+{phone}'
    return phone

# ============= CONTEXT PROCESSORS =============
@app.context_processor
def inject_datetime():
    """Make datetime module available in all templates"""
    return dict(datetime=datetime, timezone=timezone)

@app.context_processor
def inject_system_settings():
    """Make system settings available in all templates"""
    try:
        settings = SystemSettings.query.first()
        if not settings:
            settings = SystemSettings()
            try:
                db.session.add(settings)
                db.session.commit()
            except:
                db.session.rollback()
                return dict(school_settings=None)
        return dict(school_settings=settings)
    except Exception as e:
        return dict(school_settings=None)

@app.context_processor
def inject_current_year():
    """Inject current year for copyright"""
    return dict(current_year=datetime.now(timezone.utc).year)

@app.context_processor  
def inject_quote():
    """Inject motivational quote for all pages"""
    try:
        quote = get_today_quote()
        return dict(daily_quote=quote)
    except Exception as e:
        return dict(daily_quote=None)

# ============= SMSGATE HELPER FUNCTIONS =============
def format_phone_e164(phone: str):
    """Format Bangladesh phone number to E.164 format"""
    if not phone:
        return None

    # Remove all non-digit characters
    phone = "".join(filter(str.isdigit, phone))

    # Handle Bangladesh numbers
    if phone.startswith("01") and len(phone) == 11:
        return f"+880{phone[1:]}"
    elif phone.startswith("1") and len(phone) == 10:
        return f"+880{phone}"
    elif phone.startswith("880") and len(phone) == 13:
        return f"+{phone}"
    elif phone.startswith("0") and len(phone) == 11:
        return f"+880{phone[1:]}"
    elif phone.startswith("0") and len(phone) == 10:
        return f"+880{phone}"
    elif len(phone) == 11 and phone.startswith("01"):
        return f"+880{phone[1:]}"
    elif len(phone) == 10:
        return f"+880{phone}"

    # If already in E.164 format with +880
    if phone.startswith("880") and len(phone) >= 13:
        return f"+{phone}"

    # If nothing matches, try to extract last 10 digits
    if len(phone) >= 10:
        last_10 = phone[-10:]
        return f"+880{last_10}"

    return None

def get_jwt_token():
    """Get JWT token from SMSGate (cached)"""
    global TOKEN_CACHE

    if TOKEN_CACHE["token"] and TOKEN_CACHE["expires_at"]:
        if datetime.now(timezone.utc) < TOKEN_CACHE["expires_at"]:
            return TOKEN_CACHE["token"], None

    if not SMSGATE_USERNAME or not SMSGATE_PASSWORD:
        return None, "SMSGate credentials not configured in environment variables"

    auth_string = f"{SMSGATE_USERNAME}:{SMSGATE_PASSWORD}"
    auth_encoded = base64.b64encode(auth_string.encode()).decode()

    headers = {
        "Authorization": f"Basic {auth_encoded}",
        "Content-Type": "application/json"
    }

    payload = {
        "scopes": ["messages:send", "messages:read"],
        "ttl": 3600
    }

    try:
        response = requests.post(
            f"{SMSGATE_BASE_URL}/3rdparty/v1/auth/token",
            headers=headers,
            json=payload,
            timeout=20
        )

        if response.status_code in (200, 201):
            data = response.json()
            token = data.get("access_token")

            TOKEN_CACHE["token"] = token
            TOKEN_CACHE["expires_at"] = datetime.now(timezone.utc) + timedelta(seconds=3500)

            return token, None

        return None, f"HTTP {response.status_code}: {response.text}"

    except Exception as e:
        return None, str(e)

def send_sms_via_smsgate(phone_numbers, message, retry=1):
    """Send SMS using SMSGate API with improved error handling"""

    token, error = get_jwt_token()
    if error:
        app.logger.error(f"SMSGate Token Error: {error}")
        return {
            "success": False,
            "error": error,
            "results": []
        }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    results = []

    for phone in phone_numbers:
        formatted_phone = format_phone_e164(phone)

        if not formatted_phone:
            results.append({
                "phone": phone,
                "success": False,
                "status": "Invalid",
                "error": "Invalid phone format"
            })
            continue

        payload = {
            "textMessage": {
                "text": message
            },
            "phoneNumbers": [formatted_phone]
        }

        try:
            app.logger.info(f"Sending SMS to {formatted_phone}")
            response = requests.post(
                f"{SMSGATE_BASE_URL}/3rdparty/v1/messages",
                headers=headers,
                json=payload,
                timeout=30
            )

            if response.status_code in (200, 201, 202):
                status = "Processing" if response.status_code == 202 else "Sent"

                # Parse response to get message ID
                response_data = {}
                try:
                    response_data = response.json()
                except:
                    response_data = {"raw": response.text}

                message_id = response_data.get("messageId") or response_data.get("id") or response_data.get("message_id")

                results.append({
                    "phone": formatted_phone,
                    "success": True,
                    "status": status,
                    "provider_status_code": response.status_code,
                    "response": response_data,
                    "message_id": message_id
                })
                app.logger.info(f"SMS sent successfully to {formatted_phone}: {message_id}")

            else:
                error_msg = f"HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    error_msg = error_data.get("error", str(error_data))
                except:
                    error_msg = response.text[:200]

                if retry > 0 and response.status_code in [500, 502, 503, 504, 429]:
                    time.sleep(2)
                    app.logger.warning(f"Retrying SMS to {formatted_phone}, Status: {response.status_code}")
                    retry_results = send_sms_via_smsgate([phone], message, retry-1)
                    if retry_results["results"]:
                        results.extend(retry_results["results"])
                else:
                    results.append({
                        "phone": formatted_phone,
                        "success": False,
                        "status": "Failed",
                        "provider_status_code": response.status_code,
                        "error": error_msg
                    })
                    app.logger.error(f"SMS failed to {formatted_phone}: {error_msg}")

        except requests.exceptions.RequestException as e:
            app.logger.error(f"Network error for SMS to {formatted_phone}: {str(e)}")
            if retry > 0:
                time.sleep(2)
                app.logger.warning(f"Retrying SMS to {formatted_phone} due to network error")
                retry_results = send_sms_via_smsgate([phone], message, retry-1)
                if retry_results["results"]:
                    results.extend(retry_results["results"])
            else:
                results.append({
                    "phone": phone,
                    "success": False,
                    "status": "NetworkError",
                    "error": str(e)
                })

    return {
        "success": any(r["success"] for r in results),
        "results": results
    }

def send_single_sms(phone, message, config=None, max_retries=2):
    """Send single SMS via SMSGate with improved error handling"""
    try:
        formatted_phone = format_phone_e164(phone)
        if not formatted_phone:
            return False, "Invalid phone number format", None, None

        app.logger.info(f"Sending SMS to {phone} -> Formatted: {formatted_phone}")

        result = send_sms_via_smsgate([formatted_phone], message, retry=max_retries)

        if result["results"]:
            sms_result = result["results"][0]

            message_id = sms_result.get("message_id")
            response_data = sms_result.get("response", {})

            return (
                sms_result["success"],
                sms_result.get("error", sms_result.get("status", "Unknown")),
                json.dumps(response_data) if isinstance(response_data, dict) else str(response_data),
                message_id
            )

        return False, "No result from SMSGate", None, None

    except Exception as e:
        app.logger.error(f"SMS sending error for {phone}: {str(e)}")
        if max_retries > 0:
            time.sleep(2)
            return send_single_sms(phone, message, config, max_retries-1)
        else:
            return False, str(e), None, None

# ============= ENHANCED PROFESSIONAL OFFICE-STYLE PDF GENERATION =============
def generate_office_style_pdf(attendance_session):
    """
    Generate a professional office-style attendance PDF with school branding.
    Returns the relative URL to the saved PDF.
    """
    try:
        # Get data
        subject = db.session.get(Subject, attendance_session.subject_id)
        teacher = db.session.get(User, attendance_session.teacher_id)
        school = SystemSettings.query.first()

        if not school:
            # Create default settings if none exist
            school = SystemSettings()
            db.session.add(school)
            db.session.commit()

        # Get attendance records for this session
        attendance_records = Attendance.query.filter_by(
            date=attendance_session.date,
            class_name=attendance_session.class_name,
            section=attendance_session.section,
            subject_id=attendance_session.subject_id,
            teacher_id=attendance_session.teacher_id
        ).order_by(Attendance.student_id).all()

        # Get all students in class
        students = Student.query.filter_by(
            class_name=attendance_session.class_name,
            section=attendance_session.section,
            is_active=True
        ).order_by(Student.roll_number).all()

        attendance_dict = {record.student_id: record.status for record in attendance_records}

        # Prepare data for template
        attendance_list = []
        for idx, student in enumerate(students, 1):
            status = attendance_dict.get(student.id, "absent")
            record = next((r for r in attendance_records if r.student_id == student.id), None)
            attendance_list.append({
                'serial': idx,
                'student': student,
                'status': status,
                'remarks': record.notes[:30] + "..." if record and record.notes and len(record.notes) > 30 else (record.notes if record and record.notes else ""),
                'phone': format_phone_e164(student.father_phone or student.mother_phone or "")
            })

        # Calculate statistics
        total_students = len(students) if students else 0
        present_count = sum(1 for a in attendance_records if a.status == 'present')
        absent_count = total_students - present_count
        attendance_rate = (present_count / total_students * 100) if total_students > 0 else 0.0

        # Update session statistics
        attendance_session.total_students = total_students
        attendance_session.present_count = present_count
        attendance_session.absent_count = absent_count

        # Generate enhanced HTML content with professional design
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Attendance Report - {school.school_name}</title>
            <style>
                @page {{
                    size: A4;
                    margin: 20mm;
                    
                    @top-left {{
                        content: "{school.school_name}";
                        font-size: 10pt;
                        color: #666;
                        font-family: 'Arial', sans-serif;
                    }}
                    @top-right {{
                        content: "Page " counter(page) " of " counter(pages);
                        font-size: 10pt;
                        color: #666;
                        font-family: 'Arial', sans-serif;
                    }}
                    @bottom-center {{
                        content: "Confidential - {school.school_name} Attendance System";
                        font-size: 8pt;
                        color: #999;
                        font-family: 'Arial', sans-serif;
                    }}
                }}
                
                body {{
                    font-family: 'Arial', 'Helvetica', sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 0;
                    background-color: #ffffff;
                }}
                
                .watermark {{
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%) rotate(-45deg);
                    font-size: 120px;
                    opacity: 0.03;
                    z-index: -1;
                    color: #0b3d91;
                    font-weight: bold;
                    white-space: nowrap;
                    font-family: 'Arial', sans-serif;
                }}
                
                .letterhead {{
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 2px solid #0b3d91;
                    position: relative;
                }}
                
                .school-name {{
                    font-size: 32px;
                    font-weight: bold;
                    color: #0b3d91;
                    margin: 10px 0 5px 0;
                    text-transform: uppercase;
                    letter-spacing: 2px;
                    font-family: 'Arial', sans-serif;
                }}
                
                .school-address {{
                    font-size: 14px;
                    color: #666;
                    margin: 5px 0;
                    font-weight: normal;
                    font-family: 'Arial', sans-serif;
                }}
                
                .established {{
                    font-size: 12px;
                    color: #888;
                    margin: 5px 0;
                    font-style: italic;
                    font-family: 'Arial', sans-serif;
                }}
                
                .report-title {{
                    text-align: center;
                    font-size: 24px;
                    font-weight: bold;
                    color: #0b3d91;
                    margin: 25px 0;
                    padding: 15px;
                    background: linear-gradient(90deg, rgba(11, 61, 145, 0.1) 0%, rgba(0, 212, 255, 0.1) 100%);
                    border-radius: 10px;
                    border-left: 5px solid #0b3d91;
                    font-family: 'Arial', sans-serif;
                }}
                
                .document-info {{
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 8px;
                    margin: 20px 0;
                    border: 1px solid #e0e0e0;
                }}
                
                .info-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 15px;
                    margin-bottom: 20px;
                }}
                
                .info-item {{
                    margin-bottom: 10px;
                }}
                
                .info-label {{
                    font-weight: bold;
                    color: #0b3d91;
                    display: block;
                    font-size: 13px;
                    margin-bottom: 3px;
                    font-family: 'Arial', sans-serif;
                }}
                
                .info-value {{
                    color: #333;
                    font-size: 14px;
                    padding: 8px;
                    background: white;
                    border-radius: 4px;
                    border: 1px solid #e0e0e0;
                    font-family: 'Arial', sans-serif;
                }}
                
                .attendance-table {{
                    width: 100%;
                    margin: 25px 0;
                    border-collapse: collapse;
                    background: white;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    border-radius: 8px;
                    overflow: hidden;
                }}
                
                .attendance-table thead {{
                    background: linear-gradient(90deg, #0b3d91 0%, #1e5ac9 100%);
                    color: white;
                }}
                
                .attendance-table th {{
                    padding: 16px;
                    text-align: left;
                    font-weight: bold;
                    font-size: 14px;
                    font-family: 'Arial', sans-serif;
                    border-bottom: 2px solid #0b3d91;
                }}
                
                .attendance-table td {{
                    padding: 14px 16px;
                    border-bottom: 1px solid #e0e0e0;
                    font-size: 13px;
                    font-family: 'Arial', sans-serif;
                }}
                
                .attendance-table tr:nth-child(even) {{
                    background-color: #f8f9fa;
                }}
                
                .attendance-table tr:hover {{
                    background-color: rgba(11, 61, 145, 0.05);
                }}
                
                .status-present {{
                    color: #28a745;
                    font-weight: bold;
                    background-color: rgba(40, 167, 69, 0.1);
                    padding: 6px 14px;
                    border-radius: 20px;
                    display: inline-block;
                    font-size: 12px;
                    text-transform: uppercase;
                    font-family: 'Arial', sans-serif;
                }}
                
                .status-absent {{
                    color: #dc3545;
                    font-weight: bold;
                    background-color: rgba(220, 53, 69, 0.1);
                    padding: 6px 14px;
                    border-radius: 20px;
                    display: inline-block;
                    font-size: 12px;
                    text-transform: uppercase;
                    font-family: 'Arial', sans-serif;
                }}
                
                .status-late {{
                    color: #ffc107;
                    font-weight: bold;
                    background-color: rgba(255, 193, 7, 0.1);
                    padding: 6px 14px;
                    border-radius: 20px;
                    display: inline-block;
                    font-size: 12px;
                    text-transform: uppercase;
                    font-family: 'Arial', sans-serif;
                }}
                
                .summary-section {{
                    display: grid;
                    grid-template-columns: repeat(4, 1fr);
                    gap: 20px;
                    margin: 30px 0;
                }}
                
                .summary-card {{
                    padding: 20px;
                    border-radius: 10px;
                    text-align: center;
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                    transition: transform 0.3s ease;
                }}
                
                .summary-card:hover {{
                    transform: translateY(-5px);
                }}
                
                .card-total {{ 
                    background: linear-gradient(135deg, #0b3d91 0%, #1e5ac9 100%); 
                    color: white; 
                }}
                
                .card-present {{ 
                    background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
                    color: white; 
                }}
                
                .card-absent {{ 
                    background: linear-gradient(135deg, #dc3545 0%, #e83e8c 100%); 
                    color: white; 
                }}
                
                .card-rate {{ 
                    background: linear-gradient(135deg, #ffc107 0%, #fd7e14 100%); 
                    color: white; 
                }}
                
                .summary-number {{
                    font-size: 36px;
                    font-weight: bold;
                    margin: 10px 0;
                    font-family: 'Arial', sans-serif;
                }}
                
                .summary-label {{
                    font-size: 14px;
                    opacity: 0.9;
                    font-family: 'Arial', sans-serif;
                }}
                
                .footer-section {{
                    margin-top: 50px;
                    padding-top: 20px;
                    border-top: 2px solid #0b3d91;
                    display: flex;
                    justify-content: space-between;
                    align-items: flex-start;
                }}
                
                .signature-block {{
                    text-align: center;
                    width: 300px;
                }}
                
                .signature-line {{
                    width: 250px;
                    border-top: 2px solid #333;
                    margin: 60px auto 10px;
                }}
                
                .signature-name {{
                    font-weight: bold;
                    margin-top: 10px;
                    font-size: 16px;
                    color: #0b3d91;
                    font-family: 'Arial', sans-serif;
                }}
                
                .signature-title {{
                    font-size: 13px;
                    color: #666;
                    margin-top: 5px;
                    font-family: 'Arial', sans-serif;
                }}
                
                .footer-note {{
                    font-size: 11px;
                    color: #888;
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 15px;
                    border-top: 1px solid #e0e0e0;
                    font-family: 'Arial', sans-serif;
                }}
                
                .report-code {{
                    background-color: #f8f9fa;
                    padding: 10px;
                    border-radius: 5px;
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                    color: #666;
                    margin-top: 10px;
                }}
                
                .qr-code {{
                    text-align: center;
                    margin: 20px 0;
                }}
                
                .qr-code img {{
                    width: 100px;
                    height: 100px;
                }}
            </style>
        </head>
        <body>
            <div class="watermark">{school.school_name}</div>
            
            <div class="letterhead">
                <div class="school-name">{school.school_name}</div>
                <div class="school-address">{school.school_address}</div>
                <div class="established">Established: {school.established_year} | Location: Bhanga, Faridpur</div>
            </div>
            
            <div class="report-title">
                OFFICIAL ATTENDANCE REPORT
            </div>
            
            <div class="document-info">
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">Class & Section</span>
                        <div class="info-value">{attendance_session.class_name}-{attendance_session.section}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Subject</span>
                        <div class="info-value">{subject.name if subject else 'N/A'}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Date</span>
                        <div class="info-value">{attendance_session.date.strftime('%d %B, %Y')}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Day</span>
                        <div class="info-value">{attendance_session.date.strftime('%A')}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Teacher</span>
                        <div class="info-value">{teacher.username if teacher else 'N/A'}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Report Generated</span>
                        <div class="info-value">{datetime.now(timezone.utc).strftime('%d/%m/%Y %I:%M %p')} UTC</div>
                    </div>
                </div>
            </div>
            
            <table class="attendance-table">
                <thead>
                    <tr>
                        <th>SL</th>
                        <th>Roll No.</th>
                        <th>Student Name</th>
                        <th>Parent's Phone</th>
                        <th>Status</th>
                        <th>Remarks</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join([f'''
                    <tr>
                        <td>{item['serial']}</td>
                        <td><strong>{item['student'].roll_number}</strong></td>
                        <td>{item['student'].name}</td>
                        <td>{item['phone'] or 'N/A'}</td>
                        <td><span class="status-{item['status']}">{item['status'].upper()}</span></td>
                        <td>{item['remarks']}</td>
                    </tr>
                    ''' for item in attendance_list])}
                </tbody>
            </table>
            
            <div class="summary-section">
                <div class="summary-card card-total">
                    <div class="summary-number">{total_students}</div>
                    <div class="summary-label">TOTAL STUDENTS</div>
                </div>
                <div class="summary-card card-present">
                    <div class="summary-number">{present_count}</div>
                    <div class="summary-label">PRESENT</div>
                </div>
                <div class="summary-card card-absent">
                    <div class="summary-number">{absent_count}</div>
                    <div class="summary-label">ABSENT</div>
                </div>
                <div class="summary-card card-rate">
                    <div class="summary-number">{attendance_rate:.1f}%</div>
                    <div class="summary-label">ATTENDANCE RATE</div>
                </div>
            </div>
            
            <div class="footer-section">
                <div class="signature-block">
                    <div class="signature-line"></div>
                    <div class="signature-name">{school.head_teacher_name}</div>
                    <div class="signature-title">Head Teacher</div>
                    <div class="signature-title">{school.school_name}</div>
                </div>
                
                <div class="signature-block">
                    <div class="signature-line"></div>
                    <div class="signature-name">{teacher.username if teacher else 'N/A'}</div>
                    <div class="signature-title">Subject Teacher</div>
                    <div class="signature-title">{subject.name if subject else 'N/A'}</div>
                </div>
            </div>
            
            <div class="footer-note">
                <p>This is an official document generated by Dewra High School Smart Attendance System.</p>
                <p>Report ID: ATT-{attendance_session.class_name}{attendance_session.section}-{attendance_session.date.strftime('%Y%m%d')}-{attendance_session.id}</p>
                <p>Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Document Version: 1.0</p>
            </div>
        </body>
        </html>
        """

        # Generate PDF with WeasyPrint
        buffer = io.BytesIO()
        HTML(string=html_content).write_pdf(buffer)
        buffer.seek(0)

        # Save PDF locally
        timestamp = int(datetime.now(timezone.utc).timestamp())
        pdf_basename = f"ATTENDANCE_{attendance_session.class_name}_{attendance_session.section}_{attendance_session.date.strftime('%Y%m%d')}_{timestamp}.pdf"
        pdf_dir = os.path.join(app.config['UPLOAD_FOLDER'], "pdfs")
        os.makedirs(pdf_dir, exist_ok=True)
        pdf_path = os.path.join(pdf_dir, pdf_basename)

        with open(pdf_path, "wb") as f:
            f.write(buffer.getvalue())

        # Update database records
        attendance_session.pdf_generated = True
        attendance_session.pdf_url = f"/uploads/pdfs/{pdf_basename}"

        # Update attendance records with PDF path
        for attendance in Attendance.query.filter_by(
            teacher_id=attendance_session.teacher_id,
            class_name=attendance_session.class_name,
            section=attendance_session.section,
            subject_id=attendance_session.subject_id,
            date=attendance_session.date
        ):
            attendance.pdf_path = pdf_path
            attendance.pdf_url = f"/uploads/pdfs/{pdf_basename}"

        db.session.commit()
        app.logger.info(f"Professional PDF generated successfully: {pdf_basename}")

        return buffer, f"/uploads/pdfs/{pdf_basename}"

    except Exception as e:
        app.logger.error(f"PDF generation error: {str(e)}\n{traceback.format_exc()}")
        db.session.rollback()

        # Try alternative simple PDF
        try:
            return generate_simple_pdf_fallback(attendance_session)
        except Exception as fallback_error:
            app.logger.error(f"Fallback PDF generation failed: {str(fallback_error)}")
            return None, None

def generate_simple_pdf_fallback(attendance_session):
    """Generate a simple PDF as fallback when enhanced PDF fails"""
    try:
        from reportlab.lib.pagesizes import A4, letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import inch, cm
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

        # Get data
        subject = db.session.get(Subject, attendance_session.subject_id)
        teacher = db.session.get(User, attendance_session.teacher_id)
        school = SystemSettings.query.first()

        # Get attendance records
        attendance_records = Attendance.query.filter_by(
            date=attendance_session.date,
            class_name=attendance_session.class_name,
            section=attendance_session.section,
            subject_id=attendance_session.subject_id,
            teacher_id=attendance_session.teacher_id
        ).all()

        # Get students
        students = Student.query.filter_by(
            class_name=attendance_session.class_name,
            section=attendance_session.section,
            is_active=True
        ).order_by(Student.roll_number).all()

        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, 
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=72)

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor('#0b3d91'),
            alignment=TA_CENTER,
            spaceAfter=20
        )

        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#666666'),
            alignment=TA_CENTER,
            spaceAfter=30
        )

        header_style = ParagraphStyle(
            'CustomHeader',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#0b3d91'),
            spaceAfter=10
        )

        # Build story
        story = []

        # School header
        story.append(Paragraph(school.school_name if school else "DEWRA HIGH SCHOOL", title_style))
        story.append(Paragraph(school.school_address if school else "Bhanga, Faridpur", subtitle_style))
        story.append(Paragraph(f"Established: {school.established_year if school else '1970'}", subtitle_style))
        story.append(Spacer(1, 20))

        # Report title
        story.append(Paragraph("OFFICIAL ATTENDANCE REPORT", header_style))
        story.append(Spacer(1, 20))

        # Details table
        details_data = [
            ['Class & Section', f"{attendance_session.class_name}-{attendance_session.section}", 
             'Date', attendance_session.date.strftime('%d/%m/%Y')],
            ['Subject', subject.name if subject else 'N/A', 
             'Day', attendance_session.date.strftime('%A')],
            ['Teacher', teacher.username if teacher else 'N/A', 
             'Report Time', datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M')]
        ]

        details_table = Table(details_data, colWidths=[2*inch, 2*inch, 1.5*inch, 2*inch])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))

        story.append(details_table)
        story.append(Spacer(1, 20))

        # Attendance table
        attendance_data = [['SL', 'Roll No.', 'Student Name', 'Status', 'Phone']]

        for idx, student in enumerate(students, 1):
            attendance = next((a for a in attendance_records if a.student_id == student.id), None)
            status = attendance.status if attendance else "Absent"
            phone = format_phone_e164(student.father_phone or student.mother_phone or "")
            attendance_data.append([
                str(idx),
                student.roll_number,
                student.name,
                status.upper(),
                phone if phone else "N/A"
            ])

        attendance_table = Table(attendance_data, repeatRows=1)
        attendance_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0b3d91')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))

        story.append(attendance_table)
        story.append(Spacer(1, 20))

        # Summary
        present_count = sum(1 for a in attendance_records if a.status == 'present')
        absent_count = len(students) - present_count
        attendance_rate = (present_count / len(students) * 100) if students else 0

        summary_data = [
            ['Total Students:', str(len(students))],
            ['Present:', str(present_count)],
            ['Absent:', str(absent_count)],
            ['Attendance Rate:', f"{attendance_rate:.1f}%"]
        ]

        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
        ]))

        story.append(summary_table)
        story.append(Spacer(1, 30))

        # Signatures
        signature_data = [
            ['_________________________', '_________________________'],
            [school.head_teacher_name if school else 'Head Teacher', teacher.username if teacher else 'Class Teacher'],
            ['Head Teacher', 'Class Teacher'],
            [school.school_name if school else 'Dewra High School', '']
        ]

        signature_table = Table(signature_data, colWidths=[3*inch, 3*inch])
        signature_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
        ]))

        story.append(signature_table)
        story.append(Spacer(1, 20))

        # Footer
        footer = Paragraph(
            f"Report generated on {datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M')} UTC | Dewra High School Smart Attendance System",
            ParagraphStyle(
                'Footer',
                parent=styles['Normal'],
                fontSize=8,
                textColor=colors.grey,
                alignment=TA_CENTER
            )
        )
        story.append(footer)

        # Build PDF
        doc.build(story)
        buffer.seek(0)

        # Save PDF locally
        timestamp = int(datetime.now(timezone.utc).timestamp())
        pdf_basename = f"Simple_Attendance_{attendance_session.class_name}_{attendance_session.section}_{attendance_session.date.strftime('%Y%m%d')}_{timestamp}.pdf"
        pdf_dir = os.path.join(app.config['UPLOAD_FOLDER'], "pdfs")
        os.makedirs(pdf_dir, exist_ok=True)
        pdf_path = os.path.join(pdf_dir, pdf_basename)

        with open(pdf_path, "wb") as f:
            f.write(buffer.getvalue())

        # Update database
        attendance_session.pdf_generated = True
        attendance_session.pdf_url = f"/uploads/pdfs/{pdf_basename}"
        db.session.commit()

        app.logger.info(f"Simple PDF fallback generated: {pdf_basename}")
        return buffer, f"/uploads/pdfs/{pdf_basename}"

    except Exception as e:
        app.logger.error(f"Simple PDF fallback error: {str(e)}")
        return None, None

# ============= SMS FUNCTIONS WITH BANGLA MESSAGES =============
def send_sms_bulk_with_delay(sms_tasks):
    """Send multiple SMS with improved error handling and 10 second delay"""
    # Check if SMSGate is configured via environment variables
    if not SMSGATE_USERNAME or not SMSGATE_PASSWORD:
        app.logger.error("SMSGate credentials not configured")
        for phone, message, att_id in sms_tasks:
            if att_id:
                try:
                    log = SMSLog(
                        attendance_id=att_id,
                        phone=phone,
                        message=message,
                        status='failed',
                        response='SMSGate credentials not configured in environment variables'
                    )
                    db.session.add(log)
                except Exception as e:
                    app.logger.error(f"Error creating SMS log: {str(e)}")

        try:
            db.session.commit()
        except:
            db.session.rollback()
        return {'success': 0, 'failed': len(sms_tasks), 'error': 'SMSGate credentials not configured'}

    # Also check database config
    try:
        config = SMSConfig.query.first()
    except:
        config = None

    if not config or not config.enabled:
        app.logger.warning("SMS service is disabled in settings")
        for phone, message, att_id in sms_tasks:
            if att_id:
                try:
                    log = SMSLog(
                        attendance_id=att_id,
                        phone=phone,
                        message=message,
                        status='failed',
                        response='SMS service is disabled in settings'
                    )
                    db.session.add(log)
                except Exception as e:
                    app.logger.error(f"Error creating SMS log: {str(e)}")

        try:
            db.session.commit()
        except:
            db.session.rollback()
        return {'success': 0, 'failed': len(sms_tasks), 'error': 'SMS service is disabled'}

    results = {'success': 0, 'failed': 0, 'logs': []}

    # Send SMS with 10 second delay between each
    for i, (phone, message, att_id) in enumerate(sms_tasks):
        try:
            success, response_msg, response_data, message_id = send_single_sms(phone, message, config)

            # Create log with detailed information
            try:
                log = SMSLog(
                    attendance_id=att_id,
                    phone=phone,
                    message=message[:500],  # Limit message length
                    status='sent' if success else 'failed',
                    response=str(response_data)[:500] if response_data else response_msg[:500],
                    message_id=message_id,
                    retry_count=0
                )
                db.session.add(log)

                # Update attendance status
                if att_id:
                    attendance = db.session.get(Attendance, att_id)
                    if attendance:
                        attendance.sms_status = 'sent' if success else 'failed'

                        # If failed, log the specific error
                        if not success:
                            app.logger.error(f"SMS failed for attendance {att_id}: {response_msg}")
            except Exception as e:
                app.logger.error(f"Error creating SMS log: {str(e)}")

            if success:
                results['success'] += 1
                app.logger.info(f"SMS sent successfully to {phone}")
            else:
                results['failed'] += 1
                app.logger.error(f"SMS failed to {phone}: {response_msg}")

            results['logs'].append({
                'phone': phone,
                'status': 'sent' if success else 'failed',
                'message': response_msg[:100] if response_msg else 'No response',
                'message_id': message_id
            })

            # 10 second delay between messages to avoid rate limiting
            if i < len(sms_tasks) - 1:  # Don't delay after the last message
                time.sleep(10)

        except Exception as e:
            results['failed'] += 1
            error_msg = str(e)[:200]
            results['logs'].append({
                'phone': phone,
                'status': 'failed',
                'message': error_msg,
                'message_id': None
            })
            app.logger.error(f"Unexpected error sending SMS to {phone}: {error_msg}")

            # 10 second delay even on error
            if i < len(sms_tasks) - 1:
                time.sleep(10)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error committing SMS logs: {str(e)}")

    app.logger.info(f"SMS sending results: {results['success']} sent, {results['failed']} failed")

    return results

def process_attendance_sms_with_delay(attendance_session_id):
    """Process SMS for attendance session with improved error handling"""
    with app.app_context():
        try:
            attendance_session = db.session.get(AttendanceSession, attendance_session_id)
            if not attendance_session:
                app.logger.error(f"Attendance session {attendance_session_id} not found")
                return

            app.logger.info(f"Processing SMS for attendance session {attendance_session_id}")

            # Get all students for attendance
            attendance_records = Attendance.query.filter_by(
                teacher_id=attendance_session.teacher_id,
                class_name=attendance_session.class_name,
                section=attendance_session.section,
                subject_id=attendance_session.subject_id,
                date=attendance_session.date
            ).all()

            if not attendance_records:
                app.logger.warning(f"No attendance records found for session {attendance_session_id}")
                return

            sms_tasks = []
            for record in attendance_records:
                student = record.student
                if student and student.father_phone:
                    try:
                        message = get_sms_message(
                            student, 
                            record.status, 
                            attendance_session.class_name, 
                            attendance_session.section, 
                            attendance_session.date
                        )
                        sms_tasks.append((student.father_phone, message, record.id))
                    except Exception as e:
                        app.logger.error(f"Error preparing SMS for student {student.id}: {str(e)}")
                        continue

            # Send SMS with 10 second delay between each
            if sms_tasks:
                app.logger.info(f"Starting to send {len(sms_tasks)} SMS messages with 10s delay")
                results = send_sms_bulk_with_delay(sms_tasks)
                app.logger.info(f"SMS sending completed. Results: {results}")

                # Log completion
                log_activity(
                    'sms_sent', 
                    'attendance', 
                    f"Sent {len(sms_tasks)} SMS for class {attendance_session.class_name}-{attendance_session.section} (with 10s delay)"
                )
            else:
                app.logger.warning("No SMS tasks to process")

        except Exception as e:
            app.logger.error(f"Error processing attendance SMS with delay: {str(e)}\n{traceback.format_exc()}")

def get_sms_message(student, status, class_name, section, date=None):
    """Get SMS message template in Bangla with proper formatting"""
    if date is None:
        date = datetime.now(timezone.utc).date()

    try:
        custom_msg = CustomMessage.query.filter_by(message_type=status).first()
    except Exception as e:
        custom_msg = None
        app.logger.error(f"Error fetching custom message: {str(e)}")

    if custom_msg:
        msg = custom_msg.message_text
    else:
        if status == 'present':
            msg = "প্রিয় অভিভাবক, আপনার সন্তান [Student Name], রোল [Roll], আজ [Date] তারিখে [Class] শ্রেণিতে উপস্থিত ছিল। - দেওড়া উচ্চ বিদ্যালয়, ভাংগা, ফরিদপুর"
        elif status == 'absent':
            msg = "প্রিয় অভিভাবক, আপনার সন্তান [Student Name], রোল [Roll], আজ [Date] তারিখে [Class] শ্রেণিতে অনুপস্থিত ছিল। অনুগ্রহ করে যোগাযোগ করুন। - দেওড়া উচ্চ বিদ্যালয়, ভাংগা, ফরিদপুর"
        else:
            msg = "প্রিয় অভিভাবক, আপনার সন্তান [Student Name], রোল [Roll], আজ [Date] তারিখে [Class] শ্রেণিতে [Status] ছিল। - দেওড়া উচ্চ বিদ্যালয়, ভাংগা, ফরিদপুর"

    # Replace placeholders with Bangla formatting
    try:
        day_name_bangla = {
            'Monday': 'সোমবার',
            'Tuesday': 'মঙ্গলবার',
            'Wednesday': 'বুধবার',
            'Thursday': 'বৃহস্পতিবার',
            'Friday': 'শুক্রবার',
            'Saturday': 'শনিবার',
            'Sunday': 'রবিবার'
        }

        day_bangla = day_name_bangla.get(date.strftime('%A'), date.strftime('%A'))

        # Convert date to Bangla format (DD/MM/YYYY)
        date_bangla = date.strftime('%d/%m/%Y')

        status_bangla = {
            'present': 'উপস্থিত',
            'absent': 'অনুপস্থিত',
            'late': 'লেট'
        }.get(status, status)

        msg = msg.replace('[Student Name]', student.name)\
                 .replace('[Roll]', str(student.roll_number))\
                 .replace('[Class]', f"{class_name}-{section}")\
                 .replace('[Date]', date_bangla)\
                 .replace('[Day]', day_bangla)\
                 .replace('[Status]', status_bangla)
    except Exception as e:
        app.logger.error(f"Error formatting SMS message: {str(e)}")
        # Fallback to English if Bangla formatting fails
        msg = f"Dear Guardian, {student.name} (Roll: {student.roll_number}) is {status} in class {class_name}-{section} on {date.strftime('%d/%m/%Y')}. - Dewra High School, Bhanga, Faridpur"

    return msg

# ============= CUSTOM MESSAGE SENDING FUNCTION =============
def send_custom_sms_bulk(phone_numbers, message):
    """Send custom SMS messages to multiple numbers"""
    sms_tasks = []
    for phone in phone_numbers:
        sms_tasks.append((phone, message, None))

    return send_sms_bulk_with_delay(sms_tasks)

# ============= ROUTES =============
@app.route('/')
def index():
    """Homepage with motivational quote"""
    try:
        quote = None
        try:
            quote = get_today_quote()
        except:
            pass

        joy_messages = [
            "🎉 Welcome to Dewra High School Smart System!",
            "🌟 Education is the passport to the future!",
            "💡 Every student is a star waiting to shine!",
            "🚀 Let's make learning fun and effective!",
            "🌈 Together we can build a better tomorrow!"
        ]

        import random
        joy_message = random.choice(joy_messages)

        return render_template('index.html', 
                             quote=quote,
                             joy_message=joy_message)
    except Exception as e:
        app.logger.error(f"Error in index route: {str(e)}")
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dewra High School</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #0b3d91 0%, #1e5ac9 100%); color: white; }
                h1 { font-size: 36px; margin-bottom: 20px; }
                p { font-size: 18px; opacity: 0.9; }
                .btn { display: inline-block; padding: 12px 30px; background: #d4af37; color: #0b3d91; text-decoration: none; border-radius: 30px; font-weight: bold; margin-top: 30px; }
                .btn:hover { background: #e8c452; }
            </style>
        </head>
        <body>
            <h1>Welcome to Dewra High School Smart Attendance System</h1>
            <p>Every student is nuclear energy — capable of changing the world!</p>
            <a href="/login" class="btn">Login to System</a>
        </body>
        </html>
        """

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        try:
            user = User.query.filter(
                db.func.lower(User.email) == email,
                User.is_active == True
            ).first()

            if user and check_password_hash(user.password, password):
                login_user(user)
                log_activity('login', 'auth', f"User {user.email} logged in")

                if user.role == 'teacher':
                    try:
                        quote = get_today_quote()
                        if quote:
                            flash(f'✨ "{quote.quote}" - {quote.author}', 'info')
                        else:
                            flash('🌟 Welcome back! Ready to inspire minds today?', 'success')
                    except:
                        flash('🌟 Welcome back! Ready to inspire minds today?', 'success')
                else:
                    flash('🔧 Admin dashboard loaded successfully!', 'success')

                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('❌ Invalid email or password', 'danger')
                try:
                    log_activity('failed_login', 'auth', f"Failed login attempt for {email}")
                except:
                    pass

        except Exception as e:
            flash('❌ Database error. Please try again.', 'danger')
            app.logger.error(f"Login error: {str(e)}")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    try:
        log_activity('logout', 'auth', f"User {current_user.email} logged out")
    except:
        pass
    logout_user()
    flash('👋 You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard based on role"""
    today = datetime.now(timezone.utc).date()

    try:
        if current_user.role == 'super_admin':
            stats = {
                'total_students': Student.query.filter_by(is_active=True).count(),
                'total_teachers': User.query.filter_by(role='teacher', is_active=True).count(),
                'today_attendance': Attendance.query.filter_by(date=today).count(),
                'pending_sms': SMSLog.query.filter_by(status='pending').count(),
                'active_classes': Class.query.count(),
                'total_subjects': Subject.query.count(),
            }

            recent_activities = ActivityLog.query.order_by(
                ActivityLog.created_at.desc()
            ).limit(15).all()

            today_summary = db.session.query(
                db.func.count(Attendance.id).label('total'),
                db.func.sum(db.case((Attendance.status == 'present', 1), else_=0)).label('present'),
                db.func.sum(db.case((Attendance.status == 'absent', 1), else_=0)).label('absent')
            ).filter(Attendance.date == today).first()

            return render_template('admin/dashboard.html', 
                                 stats=stats, 
                                 recent_activities=recent_activities,
                                 today_summary=today_summary)

        else:
            assigned_classes = current_user.get_assigned_classes_dict()

            today_attendance = Attendance.query.filter_by(
                teacher_id=current_user.id,
                date=today
            ).count()

            week_start = today - timedelta(days=today.weekday())
            week_attendance = Attendance.query.filter(
                Attendance.teacher_id == current_user.id,
                Attendance.date >= week_start,
                Attendance.date <= today
            ).count()

            recent_sessions = AttendanceSession.query.filter_by(
                teacher_id=current_user.id
            ).order_by(AttendanceSession.date.desc()).limit(10).all()

            quote = get_today_quote()

            classes_with_stats = []
            for class_name, sections in assigned_classes.items():
                for section in sections:
                    total_students = Student.query.filter_by(
                        class_name=class_name,
                        section=section,
                        is_active=True
                    ).count()

                    today_present = Attendance.query.filter_by(
                        teacher_id=current_user.id,
                        class_name=class_name,
                        section=section,
                        date=today,
                        status='present'
                    ).count()

                    classes_with_stats.append({
                        'class': class_name,
                        'section': section,
                        'total': total_students,
                        'present': today_present,
                        'absent': total_students - today_present if total_students > 0 else 0
                    })

            return render_template('teacher/dashboard.html',
                                 assigned_classes=assigned_classes,
                                 today_attendance=today_attendance,
                                 week_attendance=week_attendance,
                                 recent_sessions=recent_sessions,
                                 classes_with_stats=classes_with_stats,
                                 quote=quote)
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard. Please try again.', 'danger')
        return redirect(url_for('index'))

# ============= TEACHER ROUTES =============
@app.route('/attendance/take', methods=['GET', 'POST'])
@login_required
@teacher_required
def take_attendance():
    """Take attendance for assigned classes and subjects - FIXED VERSION"""

    if request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'error': 'No data received'}), 400

            class_name = data.get('class_name')
            section = data.get('section')
            subject_id = data.get('subject_id')
            attendance_data = data.get('attendance', [])
            date_str = data.get('date', datetime.now(timezone.utc).date().isoformat())

            # Validate inputs
            if not class_name or not section or not subject_id:
                return jsonify({'success': False, 'error': 'Missing required fields'}), 400

            if not current_user.is_assigned_to(class_name, section, subject_id):
                return jsonify({'success': False, 'error': 'You are not assigned to this class/subject'}), 403

            try:
                attendance_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            except:
                attendance_date = datetime.now(timezone.utc).date()

            subject = db.session.get(Subject, subject_id)
            if not subject:
                return jsonify({'success': False, 'error': 'Invalid subject'}), 400

            # Get all active students in the class
            students = Student.query.filter_by(
                class_name=class_name,
                section=section,
                is_active=True
            ).order_by(Student.roll_number).all()

            if not students:
                return jsonify({'success': False, 'error': 'No students found in this class'}), 400

            # Check for existing attendance
            existing_attendance = {}
            existing_records = Attendance.query.filter_by(
                teacher_id=current_user.id,
                class_name=class_name,
                section=section,
                subject_id=subject_id,
                date=attendance_date
            ).all()

            for record in existing_records:
                existing_attendance[record.student_id] = record

            sms_tasks = []
            present_count = 0
            absent_count = 0

            # Process each student's attendance
            for student in students:
                # Find attendance data for this student
                student_attendance = None
                for item in attendance_data:
                    if str(item.get('student_id')) == str(student.id):
                        student_attendance = item
                        break

                status = student_attendance.get('status') if student_attendance else 'absent'
                notes = student_attendance.get('notes', '') if student_attendance else ''

                if status == 'present':
                    present_count += 1
                else:
                    absent_count += 1

                existing = existing_attendance.get(student.id)

                if existing:
                    # Update existing record
                    existing.status = status
                    existing.notes = notes
                    existing.sms_status = 'pending'
                else:
                    # Create new record
                    attendance = Attendance(
                        student_id=student.id,
                        teacher_id=current_user.id,
                        class_name=class_name,
                        section=section,
                        subject_id=subject_id,
                        status=status,
                        date=attendance_date,
                        day=attendance_date.strftime('%A'),
                        year=attendance_date.year,
                        sms_status='pending',
                        notes=notes
                    )
                    db.session.add(attendance)
                    db.session.flush()  # Get the ID

                    # Prepare SMS task if parent phone exists
                    if student.father_phone:
                        try:
                            message = get_sms_message(
                                student, 
                                status, 
                                class_name, 
                                section, 
                                attendance_date
                            )
                            sms_tasks.append((student.father_phone, message, attendance.id))
                        except Exception as e:
                            app.logger.error(f"Error preparing SMS for student {student.id}: {str(e)}")

            # Update or create attendance session
            attendance_session = AttendanceSession.query.filter_by(
                teacher_id=current_user.id,
                class_name=class_name,
                section=section,
                subject_id=subject_id,
                date=attendance_date
            ).first()

            if attendance_session:
                attendance_session.total_students = len(students)
                attendance_session.present_count = present_count
                attendance_session.absent_count = absent_count
            else:
                attendance_session = AttendanceSession(
                    teacher_id=current_user.id,
                    class_name=class_name,
                    section=section,
                    subject_id=subject_id,
                    date=attendance_date,
                    total_students=len(students),
                    present_count=present_count,
                    absent_count=absent_count,
                    pdf_generated=False
                )
                db.session.add(attendance_session)

            db.session.commit()
            app.logger.info(f"Attendance saved: {class_name}-{section}, Subject: {subject.name}, Students: {len(students)}")

            # Generate PDF
            pdf_url = None
            pdf_download_url = None
            try:
                pdf_buffer, pdf_url = generate_office_style_pdf(attendance_session)

                if pdf_url:
                    pdf_download_url = url_for('download_attendance_pdf', 
                                              class_name=class_name, 
                                              section=section,
                                              date=attendance_date.strftime('%Y-%m-%d'),
                                              subject_id=subject_id)
                    app.logger.info(f"PDF generated: {pdf_url}")
                else:
                    app.logger.warning("PDF could not be generated")
                    flash('⚠️ PDF could not be generated, but attendance was saved', 'warning')
            except Exception as e:
                app.logger.error(f"PDF generation error: {str(e)}")
                flash('⚠️ PDF generation failed, but attendance was saved', 'warning')

            # Send SMS in background thread
            if sms_tasks:
                Thread(target=process_attendance_sms_with_delay, args=(attendance_session.id,)).start()
                flash(f'📱 SMS will be sent with 10s delay to {len(sms_tasks)} guardians', 'success')

            log_activity('take_attendance', 'attendance', 
                        f"Marked attendance for {class_name}-{section}, {subject.name}, {len(students)} students")

            return jsonify({
                'success': True,
                'message': f'✅ Attendance saved for {len(students)} students',
                'stats': {
                    'total': len(students),
                    'present': present_count,
                    'absent': absent_count,
                    'rate': f"{(present_count/len(students)*100 if len(students) > 0 else 0):.1f}%"
                },
                'pdf_url': pdf_url,
                'pdf_download_url': pdf_download_url,
                'attendance_session_id': attendance_session.id
            })

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Attendance save error: {str(e)}\n{traceback.format_exc()}")
            return jsonify({'success': False, 'error': str(e)}), 500

    # GET request - show attendance form
    try:
        assigned_classes = current_user.get_assigned_classes_dict()

        # Get default class and section for initial load
        default_class = None
        default_section = None
        default_subject = None

        if assigned_classes:
            for class_name, sections in assigned_classes.items():
                if sections:
                    default_class = class_name
                    default_section = sections[0]

                    # Get first subject for this class
                    subject_ids = current_user.get_assigned_subjects_dict().get(class_name, [])
                    if subject_ids:
                        default_subject = subject_ids[0]
                    break

        # Get subjects for each class
        class_subjects = {}
        for class_name in assigned_classes:
            subject_ids = current_user.get_assigned_subjects_dict().get(class_name, [])
            if subject_ids:
                subjects = Subject.query.filter(Subject.id.in_(subject_ids)).all()
                class_subjects[class_name] = subjects

        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')

        recent_sessions = AttendanceSession.query.filter_by(
            teacher_id=current_user.id
        ).order_by(AttendanceSession.date.desc()).limit(5).all()

        messages = [
            "🌟 Make every student feel special today!",
            "💫 Your attention builds their confidence!",
            "🎯 Today's attendance shapes tomorrow's leaders!",
            "🌈 Every mark matters in a student's journey!",
            "🚀 Let's make today's class unforgettable!"
        ]
        import random
        motivational_msg = random.choice(messages)

        return render_template('teacher/take_attendance.html',
                             assigned_classes=assigned_classes,
                             class_subjects=class_subjects,
                             today=today,
                             recent_sessions=recent_sessions,
                             motivational_msg=motivational_msg,
                             default_class=default_class,
                             default_section=default_section,
                             default_subject=default_subject)
    except Exception as e:
        app.logger.error(f"Error loading attendance form: {str(e)}")
        flash(f'Error loading attendance form: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

# ============= FIXED STUDENT LOADING API ENDPOINT =============
@app.route('/api/students/<class_name>/<section>')
@login_required
def get_students_by_class(class_name, section):
    """API to get students by class and section - FIXED VERSION"""
    try:
        if not class_name or not section:
            return jsonify({'success': False, 'error': 'Class and section are required'}), 400

        app.logger.info(f"Fetching students for class: {class_name}, section: {section}")

        # Convert section to uppercase for consistency
        section = section.upper()

        if current_user.role == 'teacher':
            # Check if teacher is assigned to this class/section
            assigned_classes = current_user.get_assigned_classes_dict()
            if class_name not in assigned_classes or section not in assigned_classes[class_name]:
                app.logger.warning(f"Teacher {current_user.id} not assigned to {class_name}-{section}")
                return jsonify({'success': False, 'error': 'You are not assigned to this class/section'}), 403

        # Get active students
        students = Student.query.filter_by(
            class_name=class_name,
            section=section,
            is_active=True
        ).order_by(Student.roll_number).all()

        app.logger.info(f"Found {len(students)} students for {class_name}-{section}")

        student_list = []
        for student in students:
            # Build photo URL if exists
            photo_url = None
            if student.photo:
                if student.photo.startswith('http'):
                    photo_url = student.photo
                else:
                    photo_url = url_for('uploaded_file', filename=student.photo.replace('uploads/', ''))

            student_list.append({
                'id': student.id,
                'roll_number': student.roll_number,
                'name': student.name,
                'father_name': student.father_name or '',
                'father_phone': format_phone_e164(student.father_phone) if student.father_phone else '',
                'mother_name': student.mother_name or '',
                'mother_phone': format_phone_e164(student.mother_phone) if student.mother_phone else '',
                'class_name': student.class_name,
                'section': student.section,
                'photo_url': photo_url
            })

        return jsonify({
            'success': True,
            'students': student_list,
            'count': len(student_list),
            'class': f"{class_name}-{section}",
            'message': f'Found {len(student_list)} students'
        })
    except Exception as e:
        app.logger.error(f"Error getting students: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============= ALTERNATIVE STUDENT LOADING ENDPOINT =============
@app.route('/api/get-students')
@login_required
def get_students_alternative():
    """Alternative endpoint to get students by class and section"""
    try:
        class_name = request.args.get('class')
        section = request.args.get('section')

        if not class_name or not section:
            return jsonify({'success': False, 'error': 'Class and section are required'}), 400

        # Convert section to uppercase for consistency
        section = section.upper()

        app.logger.info(f"Alternative endpoint: Fetching students for {class_name}-{section}")

        # Check if teacher is assigned (for teachers only)
        if current_user.role == 'teacher':
            assigned_classes = current_user.get_assigned_classes_dict()
            if class_name not in assigned_classes or section not in assigned_classes[class_name]:
                return jsonify({'success': False, 'error': 'Not assigned to this class'}), 403

        # Query students
        students = Student.query.filter(
            Student.class_name == class_name,
            Student.section == section,
            Student.is_active == True
        ).order_by(Student.roll_number).all()

        student_list = []
        for student in students:
            student_list.append({
                'id': student.id,
                'roll_number': student.roll_number,
                'name': student.name,
                'father_phone': student.father_phone,
                'mother_phone': student.mother_phone,
                'class_name': student.class_name,
                'section': student.section
            })

        app.logger.info(f"Alternative endpoint: Found {len(student_list)} students")

        return jsonify({
            'success': True,
            'students': student_list,
            'count': len(student_list)
        })

    except Exception as e:
        app.logger.error(f"Alternative endpoint error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============= ADDED: MISSING API ENDPOINT FOR STUDENT BY ID =============
@app.route('/api/student/<int:student_id>')
@login_required
def get_student_by_id(student_id):
    """API to get a single student by ID for editing"""
    try:
        if current_user.role == 'teacher':
            # For teachers, they can only access students in their assigned classes
            student = db.session.get(Student, student_id)
            if not student:
                return jsonify({'success': False, 'error': 'Student not found'}), 404
            
            if not current_user.is_assigned_to(student.class_name, student.section):
                return jsonify({'success': False, 'error': 'You are not assigned to this student\'s class'}), 403
        
        # Super admin can access any student
        student = db.session.get(Student, student_id)
        if not student:
            return jsonify({'success': False, 'error': 'Student not found'}), 404

        # Build photo URL if exists
        photo_url = None
        if student.photo:
            if student.photo.startswith('http'):
                photo_url = student.photo
            else:
                photo_url = url_for('uploaded_file', filename=student.photo.replace('uploads/', ''))

        student_data = {
            'id': student.id,
            'roll_number': student.roll_number,
            'name': student.name,
            'father_name': student.father_name or '',
            'father_phone': student.father_phone or '',
            'mother_name': student.mother_name or '',
            'mother_phone': student.mother_phone or '',
            'class_name': student.class_name,
            'section': student.section,
            'address': student.address or '',
            'date_of_birth': student.date_of_birth.isoformat() if student.date_of_birth else None,
            'photo_url': photo_url,
            'is_active': student.is_active
        }

        return jsonify({
            'success': True,
            'student': student_data
        })
    except Exception as e:
        app.logger.error(f"Error getting student by ID: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/attendance/history')
@login_required
@teacher_required
def attendance_history():
    """View attendance history"""

    try:
        page = request.args.get('page', 1, type=int)
        class_filter = request.args.get('class', 'all')
        date_filter = request.args.get('date', '')
        subject_filter = request.args.get('subject', 'all')

        query = AttendanceSession.query.filter_by(teacher_id=current_user.id)

        if class_filter != 'all':
            query = query.filter_by(class_name=class_filter)

        if subject_filter != 'all':
            query = query.filter_by(subject_id=subject_filter)

        if date_filter:
            try:
                filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
                query = query.filter_by(date=filter_date)
            except:
                pass

        attendance_history = query.order_by(AttendanceSession.date.desc())\
                                 .paginate(page=page, per_page=15, error_out=False)

        assigned_classes = current_user.get_assigned_classes_dict()

        all_subjects = []
        for class_name in assigned_classes:
            subject_ids = current_user.get_assigned_subjects_dict().get(class_name, [])
            if subject_ids:
                subjects = Subject.query.filter(Subject.id.in_(subject_ids)).all()
                all_subjects.extend(subjects)

        all_subjects = list({subject.id: subject for subject in all_subjects}.values())

        return render_template('teacher/attendance_history.html',
                             attendance_history=attendance_history,
                             assigned_classes=assigned_classes,
                             all_subjects=all_subjects,
                             class_filter=class_filter,
                             date_filter=date_filter,
                             subject_filter=subject_filter)
    except Exception as e:
        flash(f'Error loading attendance history: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/attendance/download/<class_name>/<section>/<date>/<subject_id>')
@login_required
def download_attendance_pdf(class_name, section, date, subject_id):
    """Download PDF for specific attendance"""

    try:
        attendance_date = datetime.strptime(date, '%Y-%m-%d').date()
    except:
        flash('Invalid date format', 'danger')
        return redirect(url_for('attendance_history'))

    try:
        attendance_session = AttendanceSession.query.filter_by(
            class_name=class_name,
            section=section,
            date=attendance_date,
            subject_id=subject_id
        ).first()

        if not attendance_session:
            flash('Attendance record not found', 'danger')
            return redirect(url_for('attendance_history'))

        if current_user.role == 'teacher' and attendance_session.teacher_id != current_user.id:
            flash('Access denied', 'danger')
            return redirect(url_for('dashboard'))

        pdf_filename = f"Attendance_{class_name}_{section}_{attendance_date.strftime('%Y%m%d')}.pdf"
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], 'pdfs', pdf_filename)

        if os.path.exists(pdf_path):
            return send_from_directory(
                os.path.join(app.config['UPLOAD_FOLDER'], 'pdfs'),
                pdf_filename,
                as_attachment=True,
                download_name=pdf_filename
            )

        try:
            pdf_buffer, pdf_url = generate_office_style_pdf(attendance_session)

            if pdf_buffer:
                return send_file(
                    pdf_buffer,
                    as_attachment=True,
                    download_name=pdf_filename,
                    mimetype='application/pdf'
                )
            else:
                flash('PDF could not be generated', 'danger')
                return redirect(url_for('attendance_history'))
        except Exception as e:
            flash(f'Error generating office-style PDF: {str(e)}', 'danger')
            return redirect(url_for('attendance_history'))
    except Exception as e:
        flash(f'Error downloading PDF: {str(e)}', 'danger')
        return redirect(url_for('attendance_history'))

@app.route('/attendance/pdf/<int:session_id>')
@login_required
def view_attendance_pdf(session_id):
    """View attendance PDF by session ID"""
    try:
        attendance_session = db.session.get(AttendanceSession, session_id)
        if not attendance_session:
            flash('Attendance session not found', 'danger')
            return redirect(url_for('attendance_history'))

        if current_user.role == 'teacher' and attendance_session.teacher_id != current_user.id:
            flash('Access denied', 'danger')
            return redirect(url_for('dashboard'))

        pdf_filename = f"Attendance_{attendance_session.class_name}_{attendance_session.section}_{attendance_session.date.strftime('%Y%m%d')}.pdf"
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], 'pdfs', pdf_filename)

        if os.path.exists(pdf_path):
            return send_from_directory(
                os.path.join(app.config['UPLOAD_FOLDER'], 'pdfs'),
                pdf_filename,
                as_attachment=False
            )

        try:
            pdf_buffer, pdf_url = generate_office_style_pdf(attendance_session)
            if pdf_buffer:
                return send_file(
                    pdf_buffer,
                    as_attachment=False,
                    download_name=pdf_filename,
                    mimetype='application/pdf'
                )
            else:
                flash('PDF could not be generated', 'danger')
                return redirect(url_for('attendance_history'))
        except Exception as e:
            flash(f'Error generating office-style PDF: {str(e)}', 'danger')
            return redirect(url_for('attendance_history'))
    except Exception as e:
        flash(f'Error viewing PDF: {str(e)}', 'danger')
        return redirect(url_for('attendance_history'))

@app.route('/api/generate-pdf/<int:session_id>', methods=['POST'])
@login_required
def generate_pdf_on_demand(session_id):
    """Generate office-style PDF for attendance session on demand"""

    try:
        attendance_session = db.session.get(AttendanceSession, session_id)
        if not attendance_session:
            return jsonify({'success': False, 'error': 'Attendance session not found'}), 404

        if current_user.role == 'teacher' and attendance_session.teacher_id != current_user.id:
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        try:
            pdf_buffer, pdf_url = generate_office_style_pdf(attendance_session)

            if pdf_url:
                download_url = url_for('download_attendance_pdf', 
                                      class_name=attendance_session.class_name, 
                                      section=attendance_session.section,
                                      date=attendance_session.date.strftime('%Y-%m-%d'),
                                      subject_id=attendance_session.subject_id)

                return jsonify({
                    'success': True,
                    'message': '✅ Office-Style PDF generated successfully',
                    'download_url': download_url,
                    'view_url': pdf_url
                })
            else:
                return jsonify({'success': False, 'error': 'PDF generation failed'}), 500

        except Exception as e:
            app.logger.error(f"Office PDF generation error: {str(e)}")
            return jsonify({'success': False, 'error': str(e)}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/students/my-classes')
@login_required
@teacher_required
def my_students():
    """View students in assigned classes"""

    try:
        assigned_classes = current_user.get_assigned_classes_dict()

        class_name = request.args.get('class', '')
        section = request.args.get('section', '')

        students = []
        selected_class = None
        selected_section = None

        if class_name and section and class_name in assigned_classes and section in assigned_classes[class_name]:
            students = Student.query.filter_by(
                class_name=class_name,
                section=section,
                is_active=True
            ).order_by(Student.roll_number).all()
            selected_class = class_name
            selected_section = section

        return render_template('teacher/my_students.html',
                             assigned_classes=assigned_classes,
                             students=students,
                             selected_class=selected_class,
                             selected_section=selected_section)
    except Exception as e:
        flash(f'Error loading students: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/student/<int:student_id>')
@login_required
@teacher_required
def view_student(student_id):
    """View individual student profile and attendance history"""

    try:
        student = db.session.get(Student, student_id)
        if not student:
            flash('Student not found', 'danger')
            return redirect(url_for('my_students'))

        if not current_user.is_assigned_to(student.class_name, student.section):
            flash('Access denied. You are not assigned to this class.', 'danger')
            return redirect(url_for('my_students'))

        assigned_subjects = current_user.get_assigned_subjects_dict().get(student.class_name, [])

        if assigned_subjects:
            attendance_history = Attendance.query.filter(
                Attendance.student_id == student.id,
                Attendance.subject_id.in_(assigned_subjects),
                Attendance.teacher_id == current_user.id
            ).order_by(Attendance.date.desc()).limit(50).all()
        else:
            attendance_history = []

        total_classes = len(attendance_history)
        present_count = sum(1 for a in attendance_history if a.status == 'present')
        absent_count = sum(1 for a in attendance_history if a.status == 'absent')
        late_count = sum(1 for a in attendance_history if a.status == 'late')

        attendance_percentage = (present_count / total_classes * 100) if total_classes > 0 else 0

        subject_stats = {}
        for attendance in attendance_history:
            subject_name = attendance.subject.name if attendance.subject else 'Unknown'
            if subject_name not in subject_stats:
                subject_stats[subject_name] = {'total': 0, 'present': 0}
            subject_stats[subject_name]['total'] += 1
            if attendance.status == 'present':
                subject_stats[subject_name]['present'] += 1

        return render_template('teacher/view_student.html',
                             student=student,
                             attendance_history=attendance_history,
                             total_classes=total_classes,
                             present_count=present_count,
                             absent_count=absent_count,
                             late_count=late_count,
                             attendance_percentage=attendance_percentage,
                             subject_stats=subject_stats)
    except Exception as e:
        flash(f'Error loading student details: {str(e)}', 'danger')
        return redirect(url_for('my_students'))

@app.route('/teacher/profile', methods=['GET', 'POST'])
@login_required
@teacher_required
def teacher_profile():
    """Teacher profile management"""

    if request.method == 'POST':
        try:
            current_user.username = request.form.get('username', current_user.username)
            current_user.phone = request.form.get('phone', current_user.phone)

            if 'profile_image' in request.files:
                file = request.files['profile_image']
                if file and file.filename != '' and allowed_file(file.filename):
                    filename = secure_filename(f"teacher_{current_user.id}_{int(datetime.now(timezone.utc).timestamp())}.jpg")
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'teachers', filename)
                    file.save(filepath)

                    current_user.profile_image = f'uploads/teachers/{filename}'

            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if current_password and new_password and confirm_password:
                if not check_password_hash(current_user.password, current_password):
                    flash('Current password is incorrect', 'danger')
                elif new_password != confirm_password:
                    flash('New passwords do not match', 'danger')
                elif len(new_password) < 6:
                    flash('Password must be at least 6 characters long', 'danger')
                else:
                    current_user.password = generate_password_hash(new_password)
                    flash('Password changed successfully', 'success')

            db.session.commit()
            flash('Profile updated successfully', 'success')
            log_activity('update_profile', 'profile', 'Updated teacher profile')

            return redirect(url_for('teacher_profile'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
            return redirect(url_for('teacher_profile'))

    try:
        assigned_classes = current_user.get_assigned_classes_dict()
        class_details = []

        for class_name, sections in assigned_classes.items():
            for section in sections:
                subject_ids = current_user.get_assigned_subjects_dict().get(class_name, [])
                subjects = Subject.query.filter(Subject.id.in_(subject_ids)).all()
                subject_names = [s.name for s in subjects]

                student_count = Student.query.filter_by(
                    class_name=class_name,
                    section=section,
                    is_active=True
                ).count()

                class_details.append({
                    'name': f"{class_name}-{section}",
                    'subjects': subject_names,
                    'students': student_count
                })

        return render_template('teacher/profile.html',
                             class_details=class_details)
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

# ============= SUPER ADMIN ROUTES =============
@app.route('/admin/teachers', methods=['GET', 'POST'])
@login_required
@super_admin_required
def manage_teachers():
    """Manage teachers - add, edit, deactivate"""

    if request.method == 'POST':
        action = request.form.get('action')

        try:
            if action == 'add':
                username = request.form.get('username', '').strip()
                email = request.form.get('email', '').strip().lower()
                phone = request.form.get('phone', '').strip()
                password = request.form.get('password', '')

                if not username or not email or not password:
                    flash('All fields are required', 'danger')
                elif User.query.filter_by(email=email).first():
                    flash('Email already exists', 'danger')
                elif len(password) < 6:
                    flash('Password must be at least 6 characters long', 'danger')
                else:
                    teacher = User(
                        username=username,
                        email=email,
                        phone=phone,
                        password=generate_password_hash(password),
                        role='teacher',
                        is_active=True
                    )
                    db.session.add(teacher)
                    db.session.commit()

                    if 'profile_image' in request.files:
                        file = request.files['profile_image']
                        if file and file.filename != '' and allowed_file(file.filename):
                            filename = secure_filename(f"teacher_{teacher.id}_{int(datetime.now(timezone.utc).timestamp())}.jpg")
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'teachers', filename)
                            file.save(filepath)

                            teacher.profile_image = f'uploads/teachers/{filename}'
                            db.session.commit()

                    flash(f'Teacher {username} added successfully', 'success')
                    log_activity('add_teacher', 'teachers', f"Added teacher: {email}")

            elif action == 'edit':
                teacher_id = request.form.get('teacher_id')
                teacher = db.session.get(User, teacher_id)

                if teacher:
                    teacher.username = request.form.get('username', teacher.username)
                    teacher.email = request.form.get('email', teacher.email).lower()
                    teacher.phone = request.form.get('phone', teacher.phone)

                    if 'profile_image' in request.files:
                        file = request.files['profile_image']
                        if file and file.filename != '' and allowed_file(file.filename):
                            filename = secure_filename(f"teacher_{teacher.id}_{int(datetime.now(timezone.utc).timestamp())}.jpg")
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'teachers', filename)
                            file.save(filepath)

                            teacher.profile_image = f'uploads/teachers/{filename}'

                    new_password = request.form.get('new_password')
                    if new_password:
                        if len(new_password) >= 6:
                            teacher.password = generate_password_hash(new_password)
                        else:
                            flash('Password must be at least 6 characters', 'warning')

                    db.session.commit()
                    flash('Teacher updated successfully', 'success')
                    log_activity('update_teacher', 'teachers', f"Updated teacher: {teacher.email}")

            elif action == 'toggle_status':
                teacher_id = request.form.get('teacher_id')
                teacher = db.session.get(User, teacher_id)
                if teacher:
                    teacher.is_active = not teacher.is_active
                    db.session.commit()
                    status = "activated" if teacher.is_active else "deactivated"
                    flash(f'Teacher {status}', 'warning' if teacher.is_active else 'danger')
                    log_activity('toggle_teacher', 'teachers', f"{status} teacher: {teacher.email}")

            elif action == 'assign':
                teacher_id = request.form.get('teacher_id')
                teacher = db.session.get(User, teacher_id)

                if teacher:
                    assigned_classes = {}
                    assigned_subjects = {}

                    for key in request.form:
                        if key.startswith('class_'):
                            parts = key.split('_')
                            if len(parts) >= 3:
                                class_name = parts[1]
                                section = parts[2]

                                if class_name not in assigned_classes:
                                    assigned_classes[class_name] = []
                                if section not in assigned_classes[class_name]:
                                    assigned_classes[class_name].append(section)

                    for key in request.form:
                        if key.startswith('subject_'):
                            parts = key.split('_')
                            if len(parts) >= 3:
                                class_name = parts[1]
                                subject_id = parts[2]

                                if class_name not in assigned_subjects:
                                    assigned_subjects[class_name] = []
                                if subject_id not in assigned_subjects[class_name]:
                                    assigned_subjects[class_name].append(subject_id)

                    teacher.assigned_classes = json.dumps(assigned_classes)
                    teacher.assigned_subjects = json.dumps(assigned_subjects)
                    db.session.commit()

                    flash(f'Classes and subjects assigned to {teacher.username}', 'success')
                    log_activity('assign_teacher', 'teachers', f"Assigned classes to {teacher.username}")

            return redirect(url_for('manage_teachers'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('manage_teachers'))

    try:
        teachers = User.query.filter_by(role='teacher').order_by(
            db.case((User.is_active == True, 0), else_=1),
            User.created_at.desc()
        ).all()

        classes = Class.query.all()
        subjects = Subject.query.all()

        # Parse assigned classes and subjects for each teacher
        teachers_data = []
        for teacher in teachers:
            assigned_classes = teacher.get_assigned_classes_dict()
            assigned_subjects = teacher.get_assigned_subjects_dict()

            teachers_data.append({
                'id': teacher.id,
                'username': teacher.username,
                'email': teacher.email,
                'phone': teacher.phone,
                'profile_image': teacher.profile_image,
                'is_active': teacher.is_active,
                'created_at': teacher.created_at,
                'assigned_classes': assigned_classes,
                'assigned_subjects': assigned_subjects
            })

        return render_template('admin/manage_teachers.html', 
                             teachers=teachers_data,
                             classes=classes,
                             subjects=subjects)
    except Exception as e:
        flash(f'Error loading teachers: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/assign-teacher/<int:teacher_id>')
@login_required
@super_admin_required
def assign_teacher_form(teacher_id):
    """Form to assign classes and subjects to teacher"""

    try:
        teacher = db.session.get(User, teacher_id)
        if not teacher:
            flash('Teacher not found', 'danger')
            return redirect(url_for('manage_teachers'))

        classes = Class.query.all()
        subjects = Subject.query.all()

        assigned_classes = teacher.get_assigned_classes_dict()
        assigned_subjects = teacher.get_assigned_subjects_dict()

        return render_template('admin/assign_teacher.html',
                             teacher=teacher,
                             classes=classes,
                             subjects=subjects,
                             assigned_classes=assigned_classes,
                             assigned_subjects=assigned_subjects)
    except Exception as e:
        flash(f'Error loading assignment form: {str(e)}', 'danger')
        return redirect(url_for('manage_teachers'))

@app.route('/admin/students', methods=['GET', 'POST'])
@login_required
@super_admin_required
def manage_students():
    """Manage students - add, edit, deactivate"""

    if request.method == 'POST':
        action = request.form.get('action')

        try:
            if action == 'add':
                roll_number = request.form.get('roll_number', '').strip()
                name = request.form.get('name', '').strip()
                father_name = request.form.get('father_name', '').strip()
                father_phone = request.form.get('father_phone', '').strip()
                mother_name = request.form.get('mother_name', '').strip()
                mother_phone = request.form.get('mother_phone', '').strip()
                class_name = request.form.get('class_name', '').strip()
                section = request.form.get('section', '').strip().upper()
                address = request.form.get('address', '').strip()
                dob = request.form.get('date_of_birth', '')

                if not roll_number or not name or not father_phone or not class_name or not section:
                    flash('Required fields are missing', 'danger')
                else:
                    student = Student(
                        roll_number=roll_number,
                        name=name,
                        father_name=father_name,
                        father_phone=father_phone,
                        mother_name=mother_name,
                        mother_phone=mother_phone,
                        class_name=class_name,
                        section=section,
                        address=address,
                        is_active=True
                    )

                    if dob:
                        try:
                            student.date_of_birth = datetime.strptime(dob, '%Y-%m-%d').date()
                        except:
                            pass

                    db.session.add(student)
                    db.session.commit()

                    if 'photo' in request.files:
                        file = request.files['photo']
                        if file and file.filename != '' and allowed_file(file.filename):
                            filename = secure_filename(f"student_{student.id}_{int(datetime.now(timezone.utc).timestamp())}.jpg")
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'students', filename)
                            file.save(filepath)

                            student.photo = f'uploads/students/{filename}'
                            db.session.commit()

                    flash(f'Student {name} added successfully', 'success')
                    log_activity('add_student', 'students', f"Added student: {name}")

            elif action == 'edit':
                student_id = request.form.get('student_id')
                student = db.session.get(Student, student_id)

                if student:
                    student.roll_number = request.form.get('roll_number', student.roll_number)
                    student.name = request.form.get('name', student.name)
                    student.father_name = request.form.get('father_name', student.father_name)
                    student.father_phone = request.form.get('father_phone', student.father_phone)
                    student.mother_name = request.form.get('mother_name', student.mother_name)
                    student.mother_phone = request.form.get('mother_phone', student.mother_phone)
                    student.class_name = request.form.get('class_name', student.class_name)
                    student.section = request.form.get('section', student.section).upper()
                    student.address = request.form.get('address', student.address)

                    dob = request.form.get('date_of_birth')
                    if dob:
                        try:
                            student.date_of_birth = datetime.strptime(dob, '%Y-%m-%d').date()
                        except:
                            pass

                    if 'photo' in request.files:
                        file = request.files['photo']
                        if file and file.filename != '' and allowed_file(file.filename):
                            filename = secure_filename(f"student_{student.id}_{int(datetime.now(timezone.utc).timestamp())}.jpg")
                            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'students', filename)
                            file.save(filepath)

                            student.photo = f'uploads/students/{filename}'

                    db.session.commit()
                    flash('Student updated successfully', 'success')
                    log_activity('update_student', 'students', f"Updated student: {student.name}")

            elif action == 'toggle_status':
                student_id = request.form.get('student_id')
                student = db.session.get(Student, student_id)
                if student:
                    student.is_active = not student.is_active
                    db.session.commit()
                    status = "activated" if student.is_active else "deactivated"
                    flash(f'Student {status}', 'warning' if student.is_active else 'danger')
                    log_activity('toggle_student', 'students', f"{status} student: {student.name}")

            return redirect(url_for('manage_students'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('manage_students'))

    try:
        class_filter = request.args.get('class', 'all')
        section_filter = request.args.get('section', 'all')
        status_filter = request.args.get('status', 'active')

        query = Student.query

        if class_filter != 'all':
            query = query.filter_by(class_name=class_filter)

        if section_filter != 'all':
            query = query.filter_by(section=section_filter)

        if status_filter == 'active':
            query = query.filter_by(is_active=True)
        elif status_filter == 'inactive':
            query = query.filter_by(is_active=False)

        page = request.args.get('page', 1, type=int)
        per_page = 20

        students = query.order_by(
            Student.class_name, 
            Student.section, 
            Student.roll_number
        ).paginate(page=page, per_page=per_page, error_out=False)

        classes = Class.query.order_by(Class.name).all()

        sections = []
        if class_filter != 'all':
            class_obj = Class.query.filter_by(name=class_filter).first()
            if class_obj:
                try:
                    sections = json.loads(class_obj.sections)
                except:
                    sections = []

        return render_template('admin/manage_students.html',
                             students=students,
                             classes=classes,
                             sections=sections,
                             class_filter=class_filter,
                             section_filter=section_filter,
                             status_filter=status_filter)
    except Exception as e:
        flash(f'Error loading students: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

# ============= ADDED: ADMIN STUDENT VIEW ROUTE =============
@app.route('/admin/student/<int:student_id>')
@login_required
@super_admin_required
def admin_view_student(student_id):
    """Admin view for individual student profile"""
    try:
        student = db.session.get(Student, student_id)
        if not student:
            flash('Student not found', 'danger')
            return redirect(url_for('manage_students'))

        # Get all attendance records for this student (admin can see all)
        attendance_history = Attendance.query.filter(
            Attendance.student_id == student.id
        ).order_by(Attendance.date.desc()).limit(50).all()

        total_classes = len(attendance_history)
        present_count = sum(1 for a in attendance_history if a.status == 'present')
        absent_count = sum(1 for a in attendance_history if a.status == 'absent')
        late_count = sum(1 for a in attendance_history if a.status == 'late')

        attendance_percentage = (present_count / total_classes * 100) if total_classes > 0 else 0

        # Get class teacher info
        class_obj = Class.query.filter_by(name=student.class_name).first()
        class_teacher = class_obj.class_teacher if class_obj else None

        # Get subjects the student is taking
        subjects = Subject.query.all()

        # Calculate subject-wise attendance
        subject_stats = {}
        for attendance in attendance_history:
            subject_name = attendance.subject.name if attendance.subject else 'Unknown'
            if subject_name not in subject_stats:
                subject_stats[subject_name] = {'total': 0, 'present': 0}
            subject_stats[subject_name]['total'] += 1
            if attendance.status == 'present':
                subject_stats[subject_name]['present'] += 1

        # Get SMS logs for this student
        sms_logs = SMSLog.query.join(Attendance).filter(
            Attendance.student_id == student.id
        ).order_by(SMSLog.sent_at.desc()).limit(20).all()

        return render_template('admin/view_student.html',
                             student=student,
                             attendance_history=attendance_history,
                             total_classes=total_classes,
                             present_count=present_count,
                             absent_count=absent_count,
                             late_count=late_count,
                             attendance_percentage=attendance_percentage,
                             subject_stats=subject_stats,
                             class_teacher=class_teacher,
                             subjects=subjects,
                             sms_logs=sms_logs)
    except Exception as e:
        flash(f'Error loading student details: {str(e)}', 'danger')
        return redirect(url_for('manage_students'))

# ============= ADDITIONAL ADMIN ROUTES =============
@app.route('/admin/classes', methods=['GET', 'POST'])
@login_required
@super_admin_required
def manage_classes():
    """Manage classes and sections"""
    if request.method == 'POST':
        action = request.form.get('action')

        try:
            if action == 'add':
                name = request.form.get('name', '').strip()
                description = request.form.get('description', '').strip()
                sections_input = request.form.get('sections', '').strip().upper()

                if not name:
                    flash('Class name is required', 'danger')
                elif Class.query.filter_by(name=name).first():
                    flash(f'Class {name} already exists', 'danger')
                else:
                    sections = [s.strip() for s in sections_input.split(',') if s.strip()]
                    if not sections:
                        sections = ['A']

                    class_obj = Class(
                        name=name,
                        sections=json.dumps(sections),
                        description=description
                    )
                    db.session.add(class_obj)
                    db.session.commit()

                    flash(f'Class {name} added successfully', 'success')
                    log_activity('add_class', 'classes', f"Added class: {name}")

            elif action == 'edit':
                class_id = request.form.get('class_id')
                class_obj = db.session.get(Class, class_id)

                if class_obj:
                    class_obj.description = request.form.get('description', class_obj.description)
                    sections_input = request.form.get('sections', '').strip().upper()

                    if sections_input:
                        sections = [s.strip() for s in sections_input.split(',') if s.strip()]
                        if sections:
                            class_obj.sections = json.dumps(sections)

                    class_teacher_id = request.form.get('class_teacher_id')
                    if class_teacher_id:
                        class_obj.class_teacher_id = int(class_teacher_id) if class_teacher_id != '0' else None

                    db.session.commit()
                    flash('Class updated successfully', 'success')
                    log_activity('update_class', 'classes', f"Updated class: {class_obj.name}")

            elif action == 'delete':
                class_id = request.form.get('class_id')
                class_obj = db.session.get(Class, class_id)

                if class_obj:
                    # Check if there are students in this class
                    student_count = Student.query.filter_by(class_name=class_obj.name, is_active=True).count()
                    if student_count > 0:
                        flash(f'Cannot delete class {class_obj.name}. There are {student_count} students enrolled.', 'danger')
                    else:
                        db.session.delete(class_obj)
                        db.session.commit()
                        flash(f'Class {class_obj.name} deleted', 'success')
                        log_activity('delete_class', 'classes', f"Deleted class: {class_obj.name}")

            return redirect(url_for('manage_classes'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('manage_classes'))

    try:
        classes = Class.query.order_by(Class.name).all()
        teachers = User.query.filter_by(role='teacher', is_active=True).all()

        # Parse sections JSON for each class
        classes_data = []
        for class_obj in classes:
            try:
                sections = json.loads(class_obj.sections)
            except:
                sections = []

            classes_data.append({
                'id': class_obj.id,
                'name': class_obj.name,
                'sections': sections,
                'description': class_obj.description,
                'class_teacher': class_obj.class_teacher,
                'class_teacher_id': class_obj.class_teacher_id,
                'created_at': class_obj.created_at
            })

        return render_template('admin/manage_classes.html',
                             classes=classes_data,
                             teachers=teachers)
    except Exception as e:
        flash(f'Error loading classes: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/subjects', methods=['GET', 'POST'])
@login_required
@super_admin_required
def manage_subjects():
    """Manage subjects"""
    if request.method == 'POST':
        action = request.form.get('action')

        try:
            if action == 'add':
                name = request.form.get('name', '').strip()
                code = request.form.get('code', '').strip().upper()
                description = request.form.get('description', '').strip()

                if not name:
                    flash('Subject name is required', 'danger')
                elif Subject.query.filter_by(name=name).first():
                    flash(f'Subject {name} already exists', 'danger')
                elif code and Subject.query.filter_by(code=code).first():
                    flash(f'Subject code {code} already exists', 'danger')
                else:
                    subject = Subject(
                        name=name,
                        code=code if code else None,
                        description=description
                    )
                    db.session.add(subject)
                    db.session.commit()

                    flash(f'Subject {name} added successfully', 'success')
                    log_activity('add_subject', 'subjects', f"Added subject: {name}")

            elif action == 'edit':
                subject_id = request.form.get('subject_id')
                subject = db.session.get(Subject, subject_id)

                if subject:
                    subject.name = request.form.get('name', subject.name)
                    subject.code = request.form.get('code', subject.code).upper()
                    subject.description = request.form.get('description', subject.description)

                    db.session.commit()
                    flash('Subject updated successfully', 'success')
                    log_activity('update_subject', 'subjects', f"Updated subject: {subject.name}")

            elif action == 'delete':
                subject_id = request.form.get('subject_id')
                subject = db.session.get(Subject, subject_id)

                if subject:
                    # Check if subject is assigned to any teacher
                    assignment_count = TeacherAssignment.query.filter_by(subject_id=subject.id).count()
                    attendance_count = Attendance.query.filter_by(subject_id=subject.id).count()

                    if assignment_count > 0 or attendance_count > 0:
                        flash(f'Cannot delete subject {subject.name}. It is being used in {assignment_count} assignments and {attendance_count} attendance records.', 'danger')
                    else:
                        db.session.delete(subject)
                        db.session.commit()
                        flash(f'Subject {subject.name} deleted', 'success')
                        log_activity('delete_subject', 'subjects', f"Deleted subject: {subject.name}")

            return redirect(url_for('manage_subjects'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('manage_subjects'))

    try:
        subjects = Subject.query.order_by(Subject.name).all()

        return render_template('admin/manage_subjects.html',
                             subjects=subjects)
    except Exception as e:
        flash(f'Error loading subjects: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/system-settings', methods=['GET', 'POST'])
@login_required
@super_admin_required
def system_settings():
    """Manage system settings"""
    settings = SystemSettings.query.first()
    if not settings:
        settings = SystemSettings()
        db.session.add(settings)
        db.session.commit()

    if request.method == 'POST':
        try:
            settings.school_name = request.form.get('school_name', settings.school_name)
            settings.school_logo = request.form.get('school_logo', settings.school_logo)
            settings.school_address = request.form.get('school_address', settings.school_address)
            settings.established_year = int(request.form.get('established_year', settings.established_year))
            settings.head_teacher_name = request.form.get('head_teacher_name', settings.head_teacher_name)
            settings.motto = request.form.get('motto', settings.motto)
            settings.theme_color = request.form.get('theme_color', settings.theme_color)
            settings.secondary_color = request.form.get('secondary_color', settings.secondary_color)
            settings.accent_color = request.form.get('accent_color', settings.accent_color)

            # Handle head teacher signature upload
            if 'head_teacher_signature' in request.files:
                file = request.files['head_teacher_signature']
                if file and file.filename != '' and allowed_file(file.filename):
                    filename = secure_filename(f"signature_{int(datetime.now(timezone.utc).timestamp())}.png")
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'signatures', filename)
                    file.save(filepath)

                    settings.head_teacher_signature = f'uploads/signatures/{filename}'

            db.session.commit()
            flash('System settings updated successfully', 'success')
            log_activity('update_settings', 'system', 'Updated system settings')

            return redirect(url_for('system_settings'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating settings: {str(e)}', 'danger')
            return redirect(url_for('system_settings'))

    return render_template('admin/system_settings.html',
                         settings=settings)

@app.route('/admin/sms-config', methods=['GET', 'POST'])
@login_required
@super_admin_required
def sms_config():
    """Configure SMS settings"""
    config = SMSConfig.query.first()
    if not config:
        config = SMSConfig()
        db.session.add(config)
        db.session.commit()

    if request.method == 'POST':
        try:
            config.api_key = request.form.get('api_key', config.api_key)
            config.device_id = request.form.get('device_id', config.device_id)
            config.signing_secret = request.form.get('signing_secret', config.signing_secret)
            config.max_concurrent = int(request.form.get('max_concurrent', config.max_concurrent))
            config.rate_limit_per_minute = int(request.form.get('rate_limit_per_minute', config.rate_limit_per_minute))
            config.enabled = 'enabled' in request.form

            db.session.commit()
            flash('SMS configuration updated successfully', 'success')
            log_activity('update_sms_config', 'sms', 'Updated SMS configuration')

            return redirect(url_for('sms_config'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating SMS config: {str(e)}', 'danger')
            return redirect(url_for('sms_config'))

    return render_template('admin/sms_config.html',
                         config=config)

@app.route('/admin/messages', methods=['GET', 'POST'])
@login_required
@super_admin_required
def manage_messages():
    """Manage SMS message templates"""
    if request.method == 'POST':
        action = request.form.get('action')

        try:
            if action == 'add':
                message_type = request.form.get('message_type', '').strip()
                message_text = request.form.get('message_text', '').strip()

                if not message_type or not message_text:
                    flash('All fields are required', 'danger')
                else:
                    message = CustomMessage(
                        message_type=message_type,
                        message_text=message_text
                    )
                    db.session.add(message)
                    db.session.commit()

                    flash(f'Message template for {message_type} added successfully', 'success')
                    log_activity('add_message', 'messages', f"Added message template: {message_type}")

            elif action == 'edit':
                message_id = request.form.get('message_id')
                message = db.session.get(CustomMessage, message_id)

                if message:
                    message.message_type = request.form.get('message_type', message.message_type)
                    message.message_text = request.form.get('message_text', message.message_text)

                    db.session.commit()
                    flash('Message template updated successfully', 'success')
                    log_activity('update_message', 'messages', f"Updated message template: {message.message_type}")

            elif action == 'delete':
                message_id = request.form.get('message_id')
                message = db.session.get(CustomMessage, message_id)

                if message:
                    db.session.delete(message)
                    db.session.commit()
                    flash('Message template deleted', 'success')
                    log_activity('delete_message', 'messages', f"Deleted message template: {message.message_type}")

            return redirect(url_for('manage_messages'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('manage_messages'))

    try:
        messages = CustomMessage.query.order_by(CustomMessage.message_type).all()

        return render_template('admin/manage_messages.html',
                             messages=messages)
    except Exception as e:
        flash(f'Error loading messages: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/quotes', methods=['GET', 'POST'])
@login_required
@super_admin_required
def manage_quotes():
    """Manage daily motivational quotes"""
    if request.method == 'POST':
        action = request.form.get('action')

        try:
            if action == 'add':
                quote = request.form.get('quote', '').strip()
                author = request.form.get('author', '').strip()
                category = request.form.get('category', 'motivation').strip()

                if not quote:
                    flash('Quote text is required', 'danger')
                else:
                    daily_quote = DailyQuote(
                        quote=quote,
                        author=author,
                        category=category,
                        is_active=True
                    )
                    db.session.add(daily_quote)
                    db.session.commit()

                    flash('Quote added successfully', 'success')
                    log_activity('add_quote', 'quotes', 'Added new quote')

            elif action == 'edit':
                quote_id = request.form.get('quote_id')
                daily_quote = db.session.get(DailyQuote, quote_id)

                if daily_quote:
                    daily_quote.quote = request.form.get('quote', daily_quote.quote)
                    daily_quote.author = request.form.get('author', daily_quote.author)
                    daily_quote.category = request.form.get('category', daily_quote.category)
                    daily_quote.is_active = 'is_active' in request.form

                    db.session.commit()
                    flash('Quote updated successfully', 'success')
                    log_activity('update_quote', 'quotes', f"Updated quote ID: {quote_id}")

            elif action == 'delete':
                quote_id = request.form.get('quote_id')
                daily_quote = db.session.get(DailyQuote, quote_id)

                if daily_quote:
                    db.session.delete(daily_quote)
                    db.session.commit()
                    flash('Quote deleted', 'success')
                    log_activity('delete_quote', 'quotes', f"Deleted quote ID: {quote_id}")

            return redirect(url_for('manage_quotes'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('manage_quotes'))

    try:
        quotes = DailyQuote.query.order_by(DailyQuote.created_at.desc()).all()

        return render_template('admin/manage_quotes.html',
                             quotes=quotes)
    except Exception as e:
        flash(f'Error loading quotes: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

# ============= NEW CUSTOM MESSAGE SENDING ROUTE =============
@app.route('/admin/send-custom-message', methods=['GET', 'POST'])
@login_required
@super_admin_required
def send_custom_message():
    """Send custom SMS messages to students"""
    if request.method == 'POST':
        try:
            recipient_type = request.form.get('recipient_type')
            message = request.form.get('message', '').strip()

            if not message:
                flash('Message is required', 'danger')
                return redirect(url_for('send_custom_message'))

            phone_numbers = []
            student_ids = []

            if recipient_type == 'all':
                # Get all active students
                students = Student.query.filter_by(is_active=True).all()
                for student in students:
                    if student.father_phone:
                        phone_numbers.append(student.father_phone)
                        student_ids.append(student.id)
                    elif student.mother_phone:
                        phone_numbers.append(student.mother_phone)
                        student_ids.append(student.id)

                flash(f'Preparing to send message to all {len(phone_numbers)} students', 'info')

            elif recipient_type == 'class':
                class_name = request.form.get('class_name')
                section = request.form.get('section')

                if not class_name or not section:
                    flash('Class and section are required', 'danger')
                    return redirect(url_for('send_custom_message'))

                students = Student.query.filter_by(
                    class_name=class_name,
                    section=section,
                    is_active=True
                ).all()

                for student in students:
                    if student.father_phone:
                        phone_numbers.append(student.father_phone)
                        student_ids.append(student.id)
                    elif student.mother_phone:
                        phone_numbers.append(student.mother_phone)
                        student_ids.append(student.id)

                flash(f'Preparing to send message to {len(phone_numbers)} students in {class_name}-{section}', 'info')

            elif recipient_type == 'individual':
                student_id = request.form.get('student_id')
                student = db.session.get(Student, student_id)

                if student:
                    if student.father_phone:
                        phone_numbers.append(student.father_phone)
                        student_ids.append(student.id)
                    elif student.mother_phone:
                        phone_numbers.append(student.mother_phone)
                        student_ids.append(student.id)
                    else:
                        flash('Student has no phone number', 'warning')
                        return redirect(url_for('send_custom_message'))
                else:
                    flash('Student not found', 'danger')
                    return redirect(url_for('send_custom_message'))

                flash(f'Preparing to send message to {student.name}', 'info')

            # Remove duplicates
            phone_numbers = list(set(phone_numbers))

            if not phone_numbers:
                flash('No valid phone numbers found', 'warning')
                return redirect(url_for('send_custom_message'))

            # Send SMS in background thread
            Thread(target=send_custom_sms_in_background, args=(phone_numbers, message)).start()

            flash(f'Message will be sent to {len(phone_numbers)} recipients with 10 seconds delay between each', 'success')
            log_activity('send_custom_message', 'sms', f"Sent custom message to {len(phone_numbers)} recipients")

            return redirect(url_for('send_custom_message'))

        except Exception as e:
            flash(f'Error sending message: {str(e)}', 'danger')
            return redirect(url_for('send_custom_message'))

    # GET request - show form
    try:
        classes = Class.query.all()
        students = Student.query.filter_by(is_active=True).order_by(Student.class_name, Student.section, Student.roll_number).all()

        return render_template('admin/send_custom_message.html',
                             classes=classes,
                             students=students)
    except Exception as e:
        flash(f'Error loading form: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

def send_custom_sms_in_background(phone_numbers, message):
    """Send custom SMS in background"""
    with app.app_context():
        try:
            results = send_custom_sms_bulk(phone_numbers, message)
            app.logger.info(f"Custom SMS sending completed. Results: {results}")

            # Log the results
            for phone in phone_numbers:
                try:
                    log = SMSLog(
                        attendance_id=None,
                        phone=phone,
                        message=message[:500],
                        status='sent',
                        response='Custom message sent successfully',
                        retry_count=0
                    )
                    db.session.add(log)
                except Exception as e:
                    app.logger.error(f"Error creating SMS log: {str(e)}")

            db.session.commit()

        except Exception as e:
            app.logger.error(f"Error in custom SMS background task: {str(e)}")

@app.route('/admin/reports')
@login_required
@super_admin_required
def reports():
    """Generate various reports"""
    try:
        start_date_str = request.args.get('start_date', '')
        end_date_str = request.args.get('end_date', '')
        class_filter = request.args.get('class', 'all')
        report_type = request.args.get('report_type', 'attendance')

        today = datetime.now(timezone.utc).date()

        if start_date_str:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            except:
                start_date = today - timedelta(days=30)
        else:
            start_date = today - timedelta(days=30)

        if end_date_str:
            try:
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            except:
                end_date = today
        else:
            end_date = today

        # Ensure start_date is before end_date
        if start_date > end_date:
            start_date, end_date = end_date, start_date

        # Base query for attendance
        attendance_query = Attendance.query.filter(
            Attendance.date >= start_date,
            Attendance.date <= end_date
        )

        if class_filter != 'all':
            attendance_query = attendance_query.filter_by(class_name=class_filter)

        total_attendance = attendance_query.count()
        present_count = attendance_query.filter_by(status='present').count()
        absent_count = attendance_query.filter_by(status='absent').count()

        # Get class-wise statistics
        class_stats = []
        classes = Class.query.order_by(Class.name).all()

        for class_obj in classes:
            if class_filter == 'all' or class_obj.name == class_filter:
                class_attendance = Attendance.query.filter(
                    Attendance.class_name == class_obj.name,
                    Attendance.date >= start_date,
                    Attendance.date <= end_date
                )

                class_total = class_attendance.count()
                class_present = class_attendance.filter_by(status='present').count()
                class_absent = class_attendance.filter_by(status='absent').count()

                if class_total > 0:
                    attendance_rate = (class_present / class_total) * 100
                else:
                    attendance_rate = 0

                class_stats.append({
                    'class': class_obj.name,
                    'total': class_total,
                    'present': class_present,
                    'absent': class_absent,
                    'rate': attendance_rate
                })

        # Get daily attendance trend
        daily_trend = []
        current_date = start_date
        while current_date <= end_date:
            day_attendance = Attendance.query.filter_by(date=current_date).count()
            day_present = Attendance.query.filter_by(date=current_date, status='present').count()

            if day_attendance > 0:
                day_rate = (day_present / day_attendance) * 100
            else:
                day_rate = 0

            daily_trend.append({
                'date': current_date,
                'total': day_attendance,
                'present': day_present,
                'rate': day_rate
            })

            current_date += timedelta(days=1)

        # Get teacher statistics
        teacher_stats = []
        teachers = User.query.filter_by(role='teacher', is_active=True).all()

        for teacher in teachers:
            teacher_attendance = Attendance.query.filter_by(teacher_id=teacher.id).filter(
                Attendance.date >= start_date,
                Attendance.date <= end_date
            ).count()

            teacher_stats.append({
                'teacher': teacher.username,
                'total': teacher_attendance
            })

        return render_template('admin/reports.html',
                             start_date=start_date,
                             end_date=end_date,
                             class_filter=class_filter,
                             report_type=report_type,
                             total_attendance=total_attendance,
                             present_count=present_count,
                             absent_count=absent_count,
                             class_stats=class_stats,
                             daily_trend=daily_trend,
                             teacher_stats=teacher_stats,
                             classes=classes)
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/activity-log')
@login_required
@super_admin_required
def activity_log():
    """View system activity log"""
    try:
        page = request.args.get('page', 1, type=int)
        user_filter = request.args.get('user', 'all')
        action_filter = request.args.get('action', 'all')
        module_filter = request.args.get('module', 'all')

        query = ActivityLog.query

        if user_filter != 'all':
            query = query.filter_by(user_id=int(user_filter))

        if action_filter != 'all':
            query = query.filter_by(action=action_filter)

        if module_filter != 'all':
            query = query.filter_by(module=module_filter)

        logs = query.order_by(ActivityLog.created_at.desc())\
                   .paginate(page=page, per_page=50, error_out=False)

        users = User.query.all()

        # Get unique actions and modules for filter dropdowns
        actions = db.session.query(ActivityLog.action).distinct().all()
        modules = db.session.query(ActivityLog.module).distinct().all()

        return render_template('admin/activity_log.html',
                             logs=logs,
                             users=users,
                             actions=[a[0] for a in actions if a[0]],
                             modules=[m[0] for m in modules if m[0]],
                             user_filter=user_filter,
                             action_filter=action_filter,
                             module_filter=module_filter)
    except Exception as e:
        flash(f'Error loading activity log: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/admin/backup', methods=['GET', 'POST'])
@login_required
@super_admin_required
def backup_system():
    """Backup system data"""
    if request.method == 'POST':
        try:
            if backup_db():
                flash('✅ System backup completed successfully', 'success')
                log_activity('backup', 'system', 'Created system backup')
            else:
                flash('❌ System backup failed', 'danger')
                log_activity('backup_failed', 'system', 'Failed to create system backup')
        except Exception as e:
            flash(f'Backup error: {str(e)}', 'danger')

        return redirect(url_for('backup_system'))

    try:
        # Get backup logs
        backup_logs = BackupLog.query.order_by(BackupLog.created_at.desc()).limit(20).all()

        # Get database size
        db_size = get_database_size()

        return render_template('admin/backup.html',
                             backup_logs=backup_logs,
                             db_size=db_size)
    except Exception as e:
        flash(f'Error loading backup page: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

# ============= ADDITIONAL API ENDPOINTS =============
@app.route('/api/subjects/<class_name>')
@login_required
def get_subjects_by_class(class_name):
    """API to get subjects for a class"""

    try:
        if current_user.role == 'teacher':
            subject_ids = current_user.get_assigned_subjects_dict().get(class_name, [])
            if not subject_ids:
                return jsonify({'subjects': []})

            subjects = Subject.query.filter(Subject.id.in_(subject_ids)).all()
        else:
            subjects = Subject.query.all()

        subject_list = []
        for subject in subjects:
            subject_list.append({
                'id': subject.id,
                'name': subject.name,
                'code': subject.code
            })

        return jsonify({'subjects': subject_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attendance/check/<date>/<class_name>/<section>/<subject_id>')
@login_required
def check_attendance(date, class_name, section, subject_id):
    """Check if attendance already taken for given date, class, section, subject"""

    try:
        attendance_date = datetime.strptime(date, '%Y-%m-%d').date()
    except:
        return jsonify({'error': 'Invalid date format'}), 400

    try:
        if current_user.role == 'teacher':
            if not current_user.is_assigned_to(class_name, section, subject_id):
                return jsonify({'error': 'Not authorized'}), 403

        session = AttendanceSession.query.filter_by(
            teacher_id=current_user.id,
            class_name=class_name,
            section=section,
            subject_id=subject_id,
            date=attendance_date
        ).first()

        if session:
            attendance = Attendance.query.filter_by(
                teacher_id=current_user.id,
                class_name=class_name,
                section=section,
                subject_id=subject_id,
                date=attendance_date
            ).all()

            attendance_list = []
            for att in attendance:
                attendance_list.append({
                    'student_id': att.student_id,
                    'status': att.status,
                    'notes': att.notes or ''
                })

            return jsonify({
                'exists': True,
                'session_id': session.id,
                'pdf_generated': session.pdf_generated,
                'pdf_url': session.pdf_url,
                'attendance': attendance_list,
                'stats': {
                    'total': session.total_students,
                    'present': session.present_count,
                    'absent': session.absent_count
                }
            })

        return jsonify({'exists': False})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/random-quote')
def random_quote():
    """Get random motivational quote"""
    try:
        quote = get_today_quote()
        if quote:
            return jsonify({
                'success': True,
                'quote': quote.quote,
                'author': quote.author,
                'category': quote.category
            })
        return jsonify({'success': False, 'message': 'No quotes available'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ============= UTILITY FUNCTIONS =============
def get_database_size():
    """Get database file size"""
    try:
        db_path = database_path
        if os.path.exists(db_path):
            size_bytes = os.path.getsize(db_path)
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size_bytes < 1024.0:
                    return f"{size_bytes:.1f} {unit}"
                size_bytes /= 1024.0
        return "0 B"
    except:
        return "Unknown"

def backup_db():
    """Backup database"""
    try:
        if not os.path.exists(database_path):
            return False

        backup_dir = os.path.join(instance_path, 'backups')
        os.makedirs(backup_dir, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(backup_dir, f'dewra_backup_{timestamp}.db')

        import shutil
        shutil.copy2(database_path, backup_file)

        backup_size = os.path.getsize(backup_file)
        backup_log = BackupLog(
            backup_type='manual',
            file_path=backup_file,
            file_size=backup_size,
            status='success',
            details=f'Database backup created: {backup_file}'
        )
        db.session.add(backup_log)
        db.session.commit()

        cleanup_old_backups(backup_dir, days=30)

        return True

    except Exception as e:
        app.logger.error(f"Backup error: {str(e)}")

        try:
            backup_log = BackupLog(
                backup_type='manual',
                file_path='',
                file_size=0,
                status='failed',
                details=f'Backup failed: {str(e)}'
            )
            db.session.add(backup_log)
            db.session.commit()
        except:
            pass

        return False

def cleanup_old_backups(backup_dir, days=30):
    """Clean up old backup files"""
    try:
        now = datetime.now(timezone.utc)
        for filename in os.listdir(backup_dir):
            if filename.startswith('dewra_backup_') and filename.endswith('.db'):
                filepath = os.path.join(backup_dir, filename)
                file_time = datetime.fromtimestamp(os.path.getmtime(filepath), tz=timezone.utc)

                if (now - file_time).days > days:
                    os.remove(filepath)
                    app.logger.info(f"Removed old backup: {filename}")
    except Exception as e:
        app.logger.error(f"Cleanup error: {str(e)}")

# ============= STATIC FILES =============
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ============= DEBUG ROUTE =============
@app.route('/debug/students')
@login_required
def debug_students():
    """Debug route to check student data"""
    try:
        class_name = request.args.get('class', '6')
        section = request.args.get('section', 'A')

        # Convert section to uppercase
        section = section.upper()

        # Check database
        students_count = Student.query.filter_by(
            class_name=class_name,
            section=section,
            is_active=True
        ).count()

        # Get sample student
        sample_student = Student.query.filter_by(
            class_name=class_name,
            section=section,
            is_active=True
        ).first()

        return jsonify({
            'success': True,
            'class': class_name,
            'section': section,
            'student_count': students_count,
            'sample_student': {
                'id': sample_student.id if sample_student else None,
                'name': sample_student.name if sample_student else None,
                'roll_number': sample_student.roll_number if sample_student else None
            } if sample_student else None,
            'message': f'Found {students_count} students in {class_name}-{section}'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============= INITIALIZATION =============
def initialize_system():
    """Initialize system with default data"""

    with app.app_context():
        try:
            if not os.path.exists(database_path):
                print(f"Creating database file at: {database_path}")
                open(database_path, 'w').close()
                os.chmod(database_path, 0o644)

            print("Creating database tables...")
            db.create_all()
            print("✅ Database tables created")

            if not User.query.filter_by(role='super_admin').first():
                admin = User(
                    username='admin',
                    email='admin@dewra.edu.bd',
                    password=generate_password_hash('Admin@2025'),
                    role='super_admin',
                    phone='+8801234567890',
                    is_active=True
                )
                db.session.add(admin)
                db.session.commit()
                print("✅ Created super admin: admin@dewra.edu.bd / Admin@2025")
            else:
                print("✅ Super admin already exists")

            if SMSConfig.query.count() == 0:
                sms_config = SMSConfig(
                    api_key='',
                    device_id='',
                    signing_secret='',
                    max_concurrent=5,
                    rate_limit_per_minute=60,
                    enabled=True
                )
                db.session.add(sms_config)
                print("✅ Created default SMS config")

                if SMSGATE_USERNAME and SMSGATE_PASSWORD:
                    print("✅ SMSGate credentials found in environment")
                else:
                    print("⚠️  SMSGate credentials not configured")
                    print("   Set environment variables: SMSGATE_USERNAME and SMSGATE_PASSWORD")

            if Class.query.count() == 0:
                classes_data = [
                    {'name': '6', 'sections': ['A', 'B', 'C'], 'description': 'Class Six'},
                    {'name': '7', 'sections': ['A', 'B', 'C'], 'description': 'Class Seven'},
                    {'name': '8', 'sections': ['A', 'B', 'C'], 'description': 'Class Eight'},
                    {'name': '9', 'sections': ['A', 'B'], 'description': 'Class Nine'},
                    {'name': '10', 'sections': ['A', 'B'], 'description': 'Class Ten'},
                ]

                for class_data in classes_data:
                    class_obj = Class(
                        name=class_data['name'],
                        sections=json.dumps(class_data['sections']),
                        description=class_data['description']
                    )
                    db.session.add(class_obj)
                print("✅ Created default classes")

            if Subject.query.count() == 0:
                subjects = [
                    {'name': 'Bangla', 'code': 'BAN', 'description': 'Bangla Language and Literature'},
                    {'name': 'English', 'code': 'ENG', 'description': 'English Language and Literature'},
                    {'name': 'Mathematics', 'code': 'MAT', 'description': 'Mathematics'},
                    {'name': 'General Science', 'code': 'SCI', 'description': 'General Science'},
                    {'name': 'Social Science', 'code': 'SOC', 'description': 'Social Science'},
                    {'name': 'Religion', 'code': 'REL', 'description': 'Religion and Moral Education'},
                    {'name': 'ICT', 'code': 'ICT', 'description': 'Information and Communication Technology'},
                    {'name': 'Physical Education', 'code': 'PE', 'description': 'Physical Education and Health'},
                ]

                for subject_data in subjects:
                    subject = Subject(
                        name=subject_data['name'],
                        code=subject_data['code'],
                        description=subject_data['description']
                    )
                    db.session.add(subject)
                print("✅ Created default subjects")

            if SystemSettings.query.count() == 0:
                settings = SystemSettings()
                settings.school_name = 'Dewra High School'
                settings.school_address = 'Bhanga, Faridpur'
                settings.established_year = 1970
                db.session.add(settings)
                print("✅ Created system settings with Bhanga, Faridpur location")

            if CustomMessage.query.count() == 0:
                # Create Bangla SMS templates
                present_message = CustomMessage(
                    message_type='present',
                    message_text='প্রিয় অভিভাবক, আপনার সন্তান [Student Name], রোল [Roll], আজ [Date] তারিখে [Class] শ্রেণিতে উপস্থিত ছিল। - দেওড়া উচ্চ বিদ্যালয়, ভাংগা, ফরিদপুর'
                )
                db.session.add(present_message)

                absent_message = CustomMessage(
                    message_type='absent',
                    message_text='প্রিয় অভিভাবক, আপনার সন্তান [Student Name], রোল [Roll], আজ [Date] তারিখে [Class] শ্রেণিতে অনুপস্থিত ছিল। অনুগ্রহ করে যোগাযোগ করুন। - দেওড়া উচ্চ বিদ্যালয়, ভাংগা, ফরিদপুর'
                )
                db.session.add(absent_message)

                late_message = CustomMessage(
                    message_type='late',
                    message_text='প্রিয় অভিভাবক, আপনার সন্তান [Student Name], রোল [Roll], আজ [Date] তারিখে [Class] শ্রেণিতে লেট ছিল। - দেওড়া উচ্চ বিদ্যালয়, ভাংগা, ফরিদপুর'
                )
                db.session.add(late_message)
                print("✅ Created Bangla SMS templates")

            if DailyQuote.query.count() == 0:
                quotes = [
                    {
                        'quote': 'Every student is nuclear energy — capable of changing society, the state, the entire world.',
                        'author': 'Saiful Howlader',
                        'category': 'motivation'
                    },
                    {
                        'quote': 'Education is the most powerful weapon which you can use to change the world.',
                        'author': 'Nelson Mandela',
                        'category': 'education'
                    },
                    {
                        'quote': 'The beautiful thing about learning is that no one can take it away from you.',
                        'author': 'B.B. King',
                        'category': 'education'
                    },
                    {
                        'quote': 'A good teacher can inspire hope, ignite the imagination, and instill a love of learning.',
                        'author': 'Brad Henry',
                        'category': 'teacher'
                    },
                    {
                        'quote': 'Knowledge and hard work have no alternatives. To succeed in studies, you must combine these two.',
                        'author': '',
                        'category': 'success'
                    },
                    {
                        'quote': 'Teachers plant the seeds of knowledge that grow forever.',
                        'author': '',
                        'category': 'teacher'
                    },
                    {
                        'quote': 'He who knows himself knows the world.',
                        'author': 'Albert Einstein',
                        'category': 'motivation'
                    }
                ]

                for quote_data in quotes:
                    quote = DailyQuote(
                        quote=quote_data['quote'],
                        author=quote_data['author'],
                        category=quote_data['category'],
                        is_active=True
                    )
                    db.session.add(quote)
                print("✅ Created default quotes")

            # Create sample students if none exist
            if Student.query.count() == 0:
                print("⚠️  No students found. Creating sample students...")

                # Create sample student for class 6-A
                sample_student = Student(
                    roll_number='101',
                    name='Sample Student',
                    father_name='Sample Father',
                    father_phone='01712345678',
                    mother_name='Sample Mother',
                    mother_phone='01812345678',
                    class_name='6',
                    section='A',
                    address='Sample Address',
                    is_active=True
                )
                db.session.add(sample_student)

                print("✅ Created sample student for testing")

            # Create sample teacher if none exist (other than admin)
            if User.query.filter_by(role='teacher').count() == 0:
                teacher = User(
                    username='teacher1',
                    email='teacher@dewra.edu.bd',
                    password=generate_password_hash('Teacher@2025'),
                    role='teacher',
                    phone='01712345679',
                    is_active=True,
                    assigned_classes=json.dumps({'6': ['A', 'B'], '7': ['A']}),
                    assigned_subjects=json.dumps({'6': ['1', '2'], '7': ['1']})
                )
                db.session.add(teacher)
                print("✅ Created sample teacher: teacher@dewra.edu.bd / Teacher@2025")

            db.session.commit()
            print("🎉 System initialization complete!")

        except Exception as e:
            db.session.rollback()
            print(f"❌ System initialization failed: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            raise

# ============= ERROR HANDLERS =============
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# ============= MAIN =============
if __name__ == '__main__':
    try:
        print("Starting Dewra High School Smart Attendance System...")
        print(f"Database path: {database_path}")
        print(f"Instance path: {instance_path}")
        print(f"Current working directory: {os.getcwd()}")

        if not os.path.exists(database_path):
            print(f"Creating database file at: {database_path}")
            os.makedirs(os.path.dirname(database_path), exist_ok=True)
            open(database_path, 'w').close()

        with app.app_context():
            initialize_system()
    except Exception as e:
        print(f"⚠️  Initialization warning: {str(e)}")
        print("⚠️  Trying to continue anyway...")

    print("=" * 60)
    print("🎓 Dewra High School Smart Attendance System")
    print("=" * 60)
    print(f"📊 Database: {database_path}")
    print(f"🔐 Secret Key: {'✅ Set' if len(app.config['SECRET_KEY']) >= 32 else '⚠️ Weak'}")
    print(f"📁 Upload Folder: {app.config['UPLOAD_FOLDER']}")
    print(f"📱 SMS Service: {'✅ SMSGate' if SMSGATE_USERNAME and SMSGATE_PASSWORD else '⚠️ Not configured'}")
    print(f"📍 Location: Bhanga, Faridpur (Est. 1970)")
    print("=" * 60)
    print("🌐 Starting server on http://localhost:5000")
    print("👑 Super Admin: admin@dewra.edu.bd")
    print("🔑 Password: Admin@2025")
    print("👨‍🏫 Sample Teacher: teacher@dewra.edu.bd")
    print("🔑 Password: Teacher@2025")
    print("=" * 60)
    print("💡 Remember: Every student is nuclear energy!")
    print("✨ Made with ❤️ for Dewra High School, Bhanga, Faridpur")
    print("=" * 60)

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        scheduler = BackgroundScheduler()

        @scheduler.scheduled_job('cron', hour=2, minute=0)
        def scheduled_backup():
            with app.app_context():
                try:
                    backup_db()
                    print("✅ Scheduled backup completed")
                except:
                    print("⚠️ Scheduled backup failed")

        scheduler.start()
        print("✅ Backup scheduler started")
    except Exception as e:
        print(f"⚠️  Could not start backup scheduler: {str(e)}")
        print("⚠️  Continuing without scheduled backups...")

    app.run(
        debug=os.getenv('FLASK_DEBUG', 'True').lower() == 'true',
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        threaded=True
    )