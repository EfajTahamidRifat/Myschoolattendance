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
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback

import qrcode
import segno  # Alternative QR code library without Pillow
from weasyprint import HTML, CSS  # For PDF generation
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.units import inch, cm
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

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

class SystemSettings(db.Model):
    __tablename__ = 'system_settings'
    id = db.Column(db.Integer, primary_key=True)
    school_name = db.Column(db.String(200), default='Dewra High School')
    school_logo = db.Column(db.String(500), default='https://i.supaimg.com/5838a1ce-b184-48bc-b370-5250b7e25a58.png')
    school_address = db.Column(db.Text, default='ভাংগা, ফরিদপুর')
    established_year = db.Column(db.Integer, default=1970)
    head_teacher_name = db.Column(db.String(100), default='Head Teacher')
    head_teacher_signature = db.Column(db.String(200))
    motto = db.Column(db.Text, default='প্রত্যেকটা ছাত্র-ছাত্রী বাবা-মার কাছে সন্তান, শিক্ষকের কাছে আদর্শবান একজন ছাত্র, আর আমার কাছে তোমরা নিউক্লিয়ার শক্তি— চাইলে বদলে দিতে পারো সমাজ, রাষ্ট্র, পুরো পৃথিবী। — সাইফুল হাওলাদার')
    theme_color = db.Column(db.String(20), default='#00d4ff')
    secondary_color = db.Column(db.String(20), default='#ff00ea')
    accent_color = db.Column(db.String(20), default='#00ff88')
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

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

# ============= FIXED: SMS FUNCTIONS WITH BETTER ERROR HANDLING =============
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
            timeout=30
        )

        if response.status_code in (200, 201):
            data = response.json()
            token = data.get("access_token")

            TOKEN_CACHE["token"] = token
            TOKEN_CACHE["expires_at"] = datetime.now(timezone.utc) + timedelta(seconds=3500)

            return token, None
        else:
            app.logger.error(f"SMSGate token error: HTTP {response.status_code}: {response.text}")
            return None, f"HTTP {response.status_code}: {response.text}"

    except requests.exceptions.Timeout:
        return None, "SMSGate timeout - server took too long to respond"
    except requests.exceptions.ConnectionError:
        return None, "SMSGate connection error - cannot reach server"
    except Exception as e:
        return None, f"SMSGate error: {str(e)}"

def send_sms_via_smsgate(phone_numbers, message, retry=2):
    """Send SMS using SMSGate API with better error handling"""
    
    token, error = get_jwt_token()
    if error:
        app.logger.error(f"SMSGate token error: {error}")
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
            response = requests.post(
                f"{SMSGATE_BASE_URL}/3rdparty/v1/messages",
                headers=headers,
                json=payload,
                timeout=45
            )

            response.raise_for_status()  # Will raise HTTPError for 4xx/5xx responses
            
            if response.status_code in (200, 201, 202):
                data = response.json()
                status = "Processing" if response.status_code == 202 else "Sent"
                message_id = data.get("messageId") or data.get("id") or "N/A"

                results.append({
                    "phone": formatted_phone,
                    "success": True,
                    "status": status,
                    "message_id": message_id,
                    "provider_status_code": response.status_code,
                    "response": response.text[:200]
                })
            else:
                results.append({
                    "phone": formatted_phone,
                    "success": False,
                    "status": "Failed",
                    "provider_status_code": response.status_code,
                    "error": f"HTTP {response.status_code}: {response.text[:100]}"
                })

        except requests.exceptions.Timeout:
            if retry > 0:
                time.sleep(5)
                return send_sms_via_smsgate(phone_numbers, message, retry-1)
            results.append({
                "phone": formatted_phone,
                "success": False,
                "status": "Timeout",
                "error": "Request timeout after multiple retries"
            })
        except requests.exceptions.ConnectionError:
            if retry > 0:
                time.sleep(5)
                return send_sms_via_smsgate(phone_numbers, message, retry-1)
            results.append({
                "phone": formatted_phone,
                "success": False,
                "status": "ConnectionError",
                "error": "Cannot connect to SMS service"
            })
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401 and retry > 0:  # Token expired
                TOKEN_CACHE["token"] = None
                TOKEN_CACHE["expires_at"] = None
                time.sleep(2)
                return send_sms_via_smsgate(phone_numbers, message, retry-1)
            results.append({
                "phone": formatted_phone,
                "success": False,
                "status": "HTTPError",
                "error": f"HTTP {response.status_code}: {response.text[:100]}"
            })
        except Exception as e:
            results.append({
                "phone": formatted_phone,
                "success": False,
                "status": "Error",
                "error": f"Unexpected error: {str(e)}"
            })

    return {
        "success": any(r["success"] for r in results),
        "results": results
    }

def send_single_sms(phone, message, config=None):
    """Send single SMS via SMSGate with better error handling"""
    try:
        formatted_phone = format_phone_e164(phone)
        if not formatted_phone:
            app.logger.warning(f"Invalid phone format: {phone}")
            return False, "Invalid phone number format", None, None

        # Log the phone number before sending
        app.logger.info(f"Sending SMS to {phone} -> Formatted: {formatted_phone}")

        result = send_sms_via_smsgate([formatted_phone], message)

        if result["results"]:
            sms_result = result["results"][0]

            message_id = sms_result.get("message_id")
            if not message_id and sms_result.get("response"):
                try:
                    response_data = json.loads(sms_result["response"])
                    message_id = response_data.get("messageId") or response_data.get("id")
                except:
                    pass

            return (
                sms_result["success"],
                sms_result.get("error", sms_result.get("status", "Unknown")),
                sms_result.get("response"),
                message_id
            )

        app.logger.error(f"No results from SMSGate for {phone}")
        return False, "No result from SMSGate", None, None

    except Exception as e:
        app.logger.error(f"SMS sending error for {phone}: {str(e)}")
        return False, str(e), None, None

def send_sms_bulk_with_delay(sms_tasks):
    """Send multiple SMS with 10 second delay between batches"""
    # Check if SMSGate is configured via environment variables
    if not SMSGATE_USERNAME or not SMSGATE_PASSWORD:
        app.logger.error("SMSGate credentials not configured in environment variables")
        return {'success': 0, 'failed': len(sms_tasks), 'error': 'SMSGate credentials not configured'}

    # Also check database config
    try:
        config = SMSConfig.query.first()
    except:
        config = None

    if not config or not config.enabled:
        app.logger.warning("SMS service is disabled in settings")
        # If SMS is disabled, mark all as failed
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
                except:
                    pass

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

            # Create log
            try:
                log = SMSLog(
                    attendance_id=att_id,
                    phone=phone,
                    message=message,
                    status='sent' if success else 'failed',
                    response=str(response_data)[:500] if response_data else response_msg,
                    message_id=message_id,
                    retry_count=0
                )
                db.session.add(log)

                # Update attendance status
                if att_id:
                    attendance = db.session.get(Attendance, att_id)
                    if attendance:
                        attendance.sms_status = 'sent' if success else 'failed'
            except Exception as e:
                app.logger.error(f"Error creating SMS log: {str(e)}")

            if success:
                results['success'] += 1
                app.logger.info(f"SMS sent successfully to {phone}")
            else:
                results['failed'] += 1
                app.logger.error(f"Failed to send SMS to {phone}: {response_msg}")

            results['logs'].append({
                'phone': phone,
                'status': 'sent' if success else 'failed',
                'message': response_msg[:100] if response_msg else 'No response'
            })

            # 10 second delay between messages to avoid rate limiting
            if i < len(sms_tasks) - 1:  # Don't delay after the last message
                time.sleep(10)

        except Exception as e:
            results['failed'] += 1
            app.logger.error(f"Exception sending SMS to {phone}: {str(e)}")
            results['logs'].append({
                'phone': phone,
                'status': 'failed',
                'message': str(e)[:100]
            })

            # Create failed log entry
            try:
                log = SMSLog(
                    attendance_id=att_id,
                    phone=phone,
                    message=message,
                    status='failed',
                    response=str(e)[:500],
                    retry_count=1
                )
                db.session.add(log)
            except:
                pass

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

def get_sms_message(student, status, class_name, section, date=None):
    """Get SMS message template"""
    if date is None:
        date = datetime.now(timezone.utc).date()

    try:
        custom_msg = CustomMessage.query.filter_by(message_type=status).first()
    except:
        custom_msg = None

    if custom_msg:
        msg = custom_msg.message_text
    else:
        if status == 'present':
            msg = "Dear Guardian, your child [Student Name], Roll [Roll], is present today in class [Class]. - Dewra High School"
        elif status == 'absent':
            msg = "Dear Guardian, your child [Student Name], Roll [Roll], is absent today in class [Class]. - Dewra High School"
        else:
            msg = "Dear Guardian, your child [Student Name], Roll [Roll], is [Status] today in class [Class]. - Dewra High School"

    # Replace placeholders
    msg = msg.replace('[Student Name]', student.name)\
             .replace('[Roll]', str(student.roll_number))\
             .replace('[Class]', f"{class_name}-{section}")\
             .replace('[Date]', date.strftime('%d/%m/%Y'))\
             .replace('[Day]', date.strftime('%A'))\
             .replace('[Status]', status.capitalize())

    return msg

# ============= ENHANCED PDF GENERATION WITH SCHOOL BRANDING =============
def generate_enhanced_pdf(attendance_session):
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

        # Get all students in class - FIXED: Proper student query
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
                'phone': student.father_phone or student.mother_phone or "N/A"
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

        # Generate HTML content with enhanced styling
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Attendance Report - {school.school_name}</title>
            <style>
                @page {{
                    size: A4;
                    margin: 2cm;
                    @top-center {{
                        content: "Attendance Report";
                        font-size: 18px;
                        font-weight: bold;
                        color: #2c3e50;
                    }}
                    @bottom-center {{
                        content: "Page " counter(page) " of " counter(pages);
                        font-size: 10px;
                        color: #7f8c8d;
                    }}
                }}
                
                body {{
                    font-family: 'Arial', sans-serif;
                    color: #333;
                    line-height: 1.6;
                }}
                
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 3px solid #3498db;
                }}
                
                .school-name {{
                    font-size: 28px;
                    font-weight: bold;
                    color: #2c3e50;
                    margin-bottom: 5px;
                }}
                
                .school-address {{
                    font-size: 14px;
                    color: #7f8c8d;
                    margin-bottom: 10px;
                }}
                
                .report-title {{
                    font-size: 22px;
                    color: #e74c3c;
                    margin: 20px 0;
                    text-align: center;
                    padding: 10px;
                    background: linear-gradient(90deg, #f8f9fa, #e9ecef, #f8f9fa);
                    border-radius: 5px;
                    border-left: 5px solid #3498db;
                }}
                
                .details-table {{
                    width: 100%;
                    margin-bottom: 25px;
                    border-collapse: collapse;
                }}
                
                .details-table td {{
                    padding: 8px 15px;
                    border: 1px solid #dee2e6;
                }}
                
                .details-table td:first-child {{
                    font-weight: bold;
                    background-color: #f8f9fa;
                    width: 25%;
                }}
                
                .attendance-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 25px 0;
                    font-size: 12px;
                }}
                
                .attendance-table th {{
                    background: linear-gradient(45deg, #3498db, #2c3e50);
                    color: white;
                    padding: 12px 8px;
                    text-align: center;
                    font-weight: bold;
                    border: 1px solid #2980b9;
                }}
                
                .attendance-table td {{
                    padding: 10px 8px;
                    border: 1px solid #dee2e6;
                    text-align: center;
                }}
                
                .attendance-table tr:nth-child(even) {{
                    background-color: #f8f9fa;
                }}
                
                .attendance-table tr:hover {{
                    background-color: #e3f2fd;
                }}
                
                .status-present {{
                    color: #27ae60;
                    font-weight: bold;
                }}
                
                .status-absent {{
                    color: #e74c3c;
                    font-weight: bold;
                }}
                
                .summary-box {{
                    background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                    border: 2px solid #3498db;
                    border-radius: 10px;
                    padding: 20px;
                    margin: 25px 0;
                    display: flex;
                    justify-content: space-around;
                    text-align: center;
                }}
                
                .summary-item {{
                    padding: 15px;
                }}
                
                .summary-value {{
                    font-size: 32px;
                    font-weight: bold;
                    color: #2c3e50;
                }}
                
                .summary-label {{
                    font-size: 14px;
                    color: #7f8c8d;
                    margin-top: 5px;
                }}
                
                .signature-section {{
                    margin-top: 50px;
                    padding-top: 20px;
                    border-top: 2px solid #7f8c8d;
                    display: flex;
                    justify-content: space-between;
                }}
                
                .signature-box {{
                    text-align: center;
                    width: 45%;
                }}
                
                .signature-line {{
                    border-top: 1px solid #333;
                    width: 200px;
                    margin: 40px auto 10px;
                }}
                
                .watermark {{
                    position: fixed;
                    top: 40%;
                    left: 0;
                    width: 100%;
                    text-align: center;
                    font-size: 100px;
                    color: rgba(52, 152, 219, 0.05);
                    transform: rotate(-45deg);
                    z-index: -1000;
                    font-weight: bold;
                }}
                
                .footer {{
                    margin-top: 30px;
                    padding-top: 15px;
                    border-top: 1px solid #dee2e6;
                    text-align: center;
                    font-size: 10px;
                    color: #7f8c8d;
                }}
                
                .logo-container {{
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 20px;
                    margin-bottom: 20px;
                }}
                
                .logo-img {{
                    max-height: 80px;
                }}
            </style>
        </head>
        <body>
            <div class="watermark">{school.school_name}</div>
            
            <div class="header">
                <div class="logo-container">
                    <img src="{school.school_logo}" alt="School Logo" class="logo-img">
                    <div>
                        <div class="school-name">{school.school_name}</div>
                        <div class="school-address">{school.school_address}</div>
                        <div class="school-address">Established: {school.established_year}</div>
                    </div>
                </div>
            </div>
            
            <div class="report-title">
                Daily Attendance Report
            </div>
            
            <table class="details-table">
                <tr>
                    <td>Class & Section</td>
                    <td>{attendance_session.class_name} - {attendance_session.section}</td>
                </tr>
                <tr>
                    <td>Subject</td>
                    <td>{subject.name if subject else 'N/A'}</td>
                </tr>
                <tr>
                    <td>Teacher</td>
                    <td>{teacher.username if teacher else 'N/A'}</td>
                </tr>
                <tr>
                    <td>Date</td>
                    <td>{attendance_session.date.strftime('%A, %d %B %Y')}</td>
                </tr>
                <tr>
                    <td>Academic Year</td>
                    <td>{attendance_session.date.year}</td>
                </tr>
            </table>
            
            <div class="summary-box">
                <div class="summary-item">
                    <div class="summary-value">{total_students}</div>
                    <div class="summary-label">Total Students</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value" style="color: #27ae60;">{present_count}</div>
                    <div class="summary-label">Present</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value" style="color: #e74c3c;">{absent_count}</div>
                    <div class="summary-label">Absent</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value" style="color: #3498db;">{attendance_rate:.1f}%</div>
                    <div class="summary-label">Attendance Rate</div>
                </div>
            </div>
            
            <table class="attendance-table">
                <thead>
                    <tr>
                        <th>SL</th>
                        <th>Roll No</th>
                        <th>Student Name</th>
                        <th>Father's Name</th>
                        <th>Contact No</th>
                        <th>Status</th>
                        <th>Remarks</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join([f'''
                    <tr>
                        <td>{item['serial']}</td>
                        <td>{item['student'].roll_number}</td>
                        <td>{item['student'].name}</td>
                        <td>{item['student'].father_name or 'N/A'}</td>
                        <td>{item['phone']}</td>
                        <td class="status-{item['status']}">{item['status'].upper()}</td>
                        <td>{item['remarks']}</td>
                    </tr>
                    ''' for item in attendance_list])}
                </tbody>
            </table>
            
            <div class="signature-section">
                <div class="signature-box">
                    <div>Class Teacher</div>
                    <div class="signature-line"></div>
                    <div>{teacher.username if teacher else 'N/A'}</div>
                </div>
                <div class="signature-box">
                    <div>Head Teacher</div>
                    <div class="signature-line"></div>
                    <div>{school.head_teacher_name}</div>
                </div>
            </div>
            
            <div class="footer">
                <div>Generated on: {datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M:%S')}</div>
                <div>Report ID: ATT-{attendance_session.id}-{attendance_session.date.strftime('%Y%m%d')}</div>
                <div>{school.school_name} - Smart Attendance System</div>
            </div>
        </body>
        </html>
        """

        # Generate PDF with WeasyPrint
        buffer = io.BytesIO()
        
        # Add custom CSS for watermark
        css = CSS(string='''
            @page {
                size: A4;
                margin: 2cm;
                @top-center {
                    content: "Attendance Report";
                    font-size: 18px;
                    font-weight: bold;
                    color: #2c3e50;
                }
                @bottom-center {
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 10px;
                    color: #7f8c8d;
                }
            }
            
            .watermark {
                position: fixed;
                top: 40%;
                left: 0;
                width: 100%;
                text-align: center;
                font-size: 100px;
                color: rgba(52, 152, 219, 0.05);
                transform: rotate(-45deg);
                z-index: -1000;
                font-weight: bold;
            }
        ''')
        
        HTML(string=html_content).write_pdf(buffer, stylesheets=[css])
        buffer.seek(0)

        # Save PDF locally
        timestamp = int(datetime.now(timezone.utc).timestamp())
        pdf_basename = f"Enhanced_Attendance_{attendance_session.class_name}_{attendance_session.section}_{attendance_session.date.strftime('%Y%m%d')}_{timestamp}.pdf"
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

        return buffer, f"/uploads/pdfs/{pdf_basename}"

    except Exception as e:
        app.logger.error(f"Enhanced PDF generation error: {str(e)}")
        db.session.rollback()
        
        # Try fallback method
        try:
            return generate_simple_pdf_fallback(attendance_session)
        except Exception as fallback_error:
            app.logger.error(f"Fallback PDF generation also failed: {str(fallback_error)}")
            return None, None

def generate_simple_pdf_fallback(attendance_session):
    """Generate a simple PDF as fallback when WeasyPrint fails"""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import cm, inch
        from reportlab.lib.utils import ImageReader
        import urllib.request

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
        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4

        # Add watermark
        c.saveState()
        c.setFont("Helvetica-Bold", 80)
        c.setFillColorRGB(0.9, 0.9, 0.9)  # Light gray
        c.rotate(45)
        c.drawString(200, -100, school.school_name if school else "DEWRA SCHOOL")
        c.restoreState()

        # Add header with logo
        try:
            # Download school logo
            logo_url = school.school_logo if school and school.school_logo else "https://i.supaimg.com/5838a1ce-b184-48bc-b370-5250b7e25a58.png"
            with urllib.request.urlopen(logo_url) as response:
                logo_data = response.read()
                logo_img = ImageReader(io.BytesIO(logo_data))
                c.drawImage(logo_img, 50, height - 100, width=50, height=50, mask='auto')
        except:
            pass  # Continue without logo if download fails

        # School title
        c.setFont("Helvetica-Bold", 18)
        school_name = school.school_name if school else "Dewra High School"
        c.drawString(110, height - 80, school_name)
        
        c.setFont("Helvetica", 10)
        school_address = school.school_address if school else "ভাংগা, ফরিদপুর"
        c.drawString(110, height - 100, school_address)
        
        # Report title
        c.setFont("Helvetica-Bold", 16)
        c.drawString(width/2 - 100, height - 140, "DAILY ATTENDANCE REPORT")
        
        # Draw line
        c.line(50, height - 150, width - 50, height - 150)

        # Details section
        y = height - 180
        c.setFont("Helvetica-Bold", 10)
        c.drawString(50, y, "Class & Section:")
        c.drawString(150, y, f"{attendance_session.class_name} - {attendance_session.section}")
        c.drawString(300, y, "Date:")
        c.drawString(350, y, attendance_session.date.strftime('%d/%m/%Y'))
        
        y -= 20
        c.drawString(50, y, "Subject:")
        c.drawString(150, y, subject.name if subject else "N/A")
        c.drawString(300, y, "Teacher:")
        c.drawString(350, y, teacher.username if teacher else "N/A")
        
        y -= 20
        c.drawString(50, y, "Head Teacher:")
        c.drawString(150, y, school.head_teacher_name if school else "Head Teacher")
        c.drawString(300, y, "Total Students:")
        c.drawString(400, y, str(len(students)))

        # Summary box
        y -= 40
        present_count = sum(1 for a in attendance_records if a.status == 'present')
        absent_count = len(students) - present_count
        attendance_rate = (present_count / len(students) * 100) if len(students) > 0 else 0
        
        c.setFillColorRGB(0.9, 0.95, 1)  # Light blue background
        c.rect(50, y - 10, width - 100, 50, fill=1, stroke=1)
        
        c.setFont("Helvetica-Bold", 12)
        c.setFillColorRGB(0, 0, 0)
        c.drawString(70, y + 20, f"Present: {present_count}")
        c.drawString(200, y + 20, f"Absent: {absent_count}")
        c.drawString(330, y + 20, f"Rate: {attendance_rate:.1f}%")
        
        # Table header
        y -= 70
        c.setFont("Helvetica-Bold", 9)
        c.drawString(50, y, "Roll No")
        c.drawString(100, y, "Name")
        c.drawString(250, y, "Status")
        c.drawString(300, y, "Contact")
        c.drawString(400, y, "Remarks")

        # Draw line
        c.line(50, y - 5, width - 50, y - 5)

        # Student rows
        y -= 20
        c.setFont("Helvetica", 8)
        row_height = 15
        
        for student in students:
            if y < 100:  # New page if running out of space
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 8)

            attendance = next((a for a in attendance_records if a.student_id == student.id), None)
            status = attendance.status if attendance else "Absent"
            
            # Color code status
            if status.lower() == 'present':
                c.setFillColorRGB(0.2, 0.6, 0.2)  # Green
            else:
                c.setFillColorRGB(0.8, 0.2, 0.2)  # Red

            c.drawString(50, y, str(student.roll_number))
            c.setFillColorRGB(0, 0, 0)  # Black for other text
            c.drawString(100, y, student.name[:25])  # Limit name length
            c.setFillColorRGB(0.2, 0.6, 0.2) if status.lower() == 'present' else c.setFillColorRGB(0.8, 0.2, 0.2)
            c.drawString(250, y, status.upper())
            c.setFillColorRGB(0, 0, 0)
            
            phone = format_phone_e164(student.father_phone or student.mother_phone or "")
            c.drawString(300, y, phone if phone else "N/A")
            
            remarks = attendance.notes[:20] + "..." if attendance and attendance.notes and len(attendance.notes) > 20 else (attendance.notes if attendance and attendance.notes else "")
            c.drawString(400, y, remarks)

            y -= row_height

        # Signatures
        y = 150
        c.setFont("Helvetica-Bold", 10)
        c.drawString(100, y, "Class Teacher")
        c.drawString(width - 200, y, "Head Teacher")
        
        y -= 5
        c.line(100, y, 250, y)
        c.line(width - 200, y, width - 50, y)
        
        y -= 20
        c.setFont("Helvetica", 9)
        c.drawString(100, y, teacher.username if teacher else "N/A")
        c.drawString(width - 200, y, school.head_teacher_name if school else "Head Teacher")

        # Footer
        c.setFont("Helvetica", 8)
        c.drawString(50, 50, f"Report generated: {datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M')}")
        c.drawString(50, 40, f"Report ID: ATT-{attendance_session.id}-{attendance_session.date.strftime('%Y%m%d')}")

        c.save()
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

        return buffer, f"/uploads/pdfs/{pdf_basename}"

    except Exception as e:
        app.logger.error(f"Simple PDF fallback error: {str(e)}")
        return None, None

# ============= FIXED: ATTENDANCE ROUTE =============
@app.route('/attendance/take', methods=['GET', 'POST'])
@login_required
@teacher_required
def take_attendance():
    """Take attendance for assigned classes and subjects"""

    if request.method == 'POST':
        try:
            data = request.get_json()
            class_name = data.get('class_name')
            section = data.get('section')
            subject_id = data.get('subject_id')
            attendance_data = data.get('attendance', [])
            date_str = data.get('date', datetime.now(timezone.utc).date().isoformat())

            if not current_user.is_assigned_to(class_name, section, subject_id):
                return jsonify({'success': False, 'error': 'You are not assigned to this class/subject'}), 403

            try:
                attendance_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            except:
                attendance_date = datetime.now(timezone.utc).date()

            subject = db.session.get(Subject, subject_id)
            if not subject:
                return jsonify({'success': False, 'error': 'Invalid subject'}), 400

            # FIXED: Proper student query
            students = Student.query.filter_by(
                class_name=class_name,
                section=section,
                is_active=True
            ).order_by(Student.roll_number).all()

            if not students:
                return jsonify({'success': False, 'error': 'No students found in this class'}), 400

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

            for student in students:
                student_attendance = next((item for item in attendance_data if str(item['student_id']) == str(student.id)), None)
                status = student_attendance['status'] if student_attendance else 'absent'
                notes = student_attendance.get('notes', '') if student_attendance else ''

                if status == 'present':
                    present_count += 1
                else:
                    absent_count += 1

                existing = existing_attendance.get(student.id)

                if existing:
                    existing.status = status
                    existing.notes = notes
                    existing.sms_status = 'pending'
                else:
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
                    db.session.flush()

                    if student.father_phone:
                        message = get_sms_message(
                            student, 
                            status, 
                            class_name, 
                            section, 
                            attendance_date
                        )
                        sms_tasks.append((student.father_phone, message, attendance.id))

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

            # Generate enhanced PDF
            try:
                pdf_buffer, pdf_url = generate_enhanced_pdf(attendance_session)

                if pdf_url:
                    pdf_download_url = url_for('download_attendance_pdf', 
                                              class_name=class_name, 
                                              section=section,
                                              date=attendance_date.strftime('%Y-%m-%d'),
                                              subject_id=subject_id)
                else:
                    pdf_download_url = None
                    flash('⚠️ PDF could not be generated, but attendance was saved', 'warning')

            except Exception as e:
                app.logger.error(f"Enhanced PDF generation error: {str(e)}")
                pdf_url = None
                pdf_download_url = None
                flash('⚠️ PDF generation failed, but attendance was saved', 'warning')

            # Send SMS with better error handling
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
            app.logger.error(f"Attendance save error: {str(e)}")
            return jsonify({'success': False, 'error': str(e)}), 500

    try:
        assigned_classes = current_user.get_assigned_classes_dict()

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
                             motivational_msg=motivational_msg)
    except Exception as e:
        flash(f'Error loading attendance form: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

# ============= FIXED: SMS PROCESSING =============
def process_attendance_sms_with_delay(attendance_session_id):
    """Process SMS for attendance session with 10 second delay"""
    with app.app_context():
        try:
            attendance_session = db.session.get(AttendanceSession, attendance_session_id)
            if not attendance_session:
                app.logger.error(f"Attendance session {attendance_session_id} not found")
                return

            # Get all students for attendance
            attendance_records = Attendance.query.filter_by(
                teacher_id=attendance_session.teacher_id,
                class_name=attendance_session.class_name,
                section=attendance_session.section,
                subject_id=attendance_session.subject_id,
                date=attendance_session.date
            ).all()

            sms_tasks = []
            for record in attendance_records:
                student = record.student
                if student and student.father_phone:
                    message = get_sms_message(
                        student, 
                        record.status, 
                        attendance_session.class_name, 
                        attendance_session.section, 
                        attendance_session.date
                    )
                    sms_tasks.append((student.father_phone, message, record.id))

            # Send SMS with 10 second delay between each
            if sms_tasks:
                app.logger.info(f"Starting SMS sending for {len(sms_tasks)} guardians")
                results = send_sms_bulk_with_delay(sms_tasks)
                app.logger.info(f"SMS sending results with delay: {results}")

                # Log completion
                log_activity(
                    'sms_sent', 
                    'attendance', 
                    f"Sent {results['success']} SMS, Failed {results['failed']} for class {attendance_session.class_name}-{attendance_session.section}"
                )
        except Exception as e:
            app.logger.error(f"Error processing attendance SMS with delay: {str(e)}")

# ============= FIXED: API ENDPOINTS =============
@app.route('/api/students/<class_name>/<section>')
@login_required
def get_students_by_class(class_name, section):
    """API to get students by class and section"""

    try:
        if current_user.role == 'teacher':
            if not current_user.is_assigned_to(class_name, section):
                return jsonify({'error': 'Not authorized for this class'}), 403

        students = Student.query.filter_by(
            class_name=class_name,
            section=section,
            is_active=True
        ).order_by(Student.roll_number).all()

        student_list = []
        for student in students:
            student_list.append({
                'id': student.id,
                'roll_number': student.roll_number,
                'name': student.name,
                'father_name': student.father_name or '',
                'father_phone': student.father_phone,
                'mother_name': student.mother_name or '',
                'mother_phone': student.mother_phone or '',
                'class_name': student.class_name,
                'section': student.section,
                'photo_url': url_for('static', filename=student.photo) if student.photo else None
            })

        return jsonify({'success': True, 'students': student_list})
    except Exception as e:
        app.logger.error(f"Error getting students: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-attendance/<class_name>/<section>/<subject_id>/<date>')
@login_required
def check_existing_attendance(class_name, section, subject_id, date):
    """Check existing attendance for a specific date"""
    try:
        if current_user.role == 'teacher':
            if not current_user.is_assigned_to(class_name, section, subject_id):
                return jsonify({'error': 'Not authorized'}), 403

        attendance_date = datetime.strptime(date, '%Y-%m-%d').date()
        
        # Get students
        students = Student.query.filter_by(
            class_name=class_name,
            section=section,
            is_active=True
        ).order_by(Student.roll_number).all()

        # Get existing attendance
        existing_records = Attendance.query.filter_by(
            teacher_id=current_user.id,
            class_name=class_name,
            section=section,
            subject_id=subject_id,
            date=attendance_date
        ).all()

        attendance_dict = {record.student_id: {'status': record.status, 'notes': record.notes or ''} 
                          for record in existing_records}

        attendance_list = []
        for student in students:
            existing = attendance_dict.get(student.id, {'status': 'absent', 'notes': ''})
            attendance_list.append({
                'student_id': student.id,
                'roll_number': student.roll_number,
                'name': student.name,
                'status': existing['status'],
                'notes': existing['notes']
            })

        return jsonify({
            'success': True,
            'exists': len(existing_records) > 0,
            'attendance': attendance_list,
            'total_students': len(students)
        })

    except Exception as e:
        app.logger.error(f"Error checking attendance: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ============= FIXED: PDF DOWNLOAD ROUTES =============
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

        pdf_filename = f"Enhanced_Attendance_{class_name}_{section}_{attendance_date.strftime('%Y%m%d')}.pdf"
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], 'pdfs', pdf_filename)

        if os.path.exists(pdf_path):
            return send_from_directory(
                os.path.join(app.config['UPLOAD_FOLDER'], 'pdfs'),
                pdf_filename,
                as_attachment=True,
                download_name=pdf_filename
            )

        # Generate PDF if not exists
        try:
            pdf_buffer, pdf_url = generate_enhanced_pdf(attendance_session)
            
            if pdf_buffer:
                return send_file(
                    pdf_buffer,
                    as_attachment=True,
                    download_name=pdf_filename,
                    mimetype='application/pdf'
                )
            else:
                flash('Error generating PDF', 'danger')
                return redirect(url_for('attendance_history'))
        except Exception as e:
            flash(f'Error generating enhanced PDF: {str(e)}', 'danger')
            return redirect(url_for('attendance_history'))
    except Exception as e:
        flash(f'Error downloading PDF: {str(e)}', 'danger')
        return redirect(url_for('attendance_history'))

# ============= OTHER NECESSARY MODEL CLASSES =============
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

class DailyQuote(db.Model):
    __tablename__ = 'daily_quote'
    id = db.Column(db.Integer, primary_key=True)
    quote = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(100))
    category = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class BackupLog(db.Model):
    __tablename__ = 'backup_log'
    id = db.Column(db.Integer, primary_key=True)
    backup_type = db.Column(db.String(20))
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)
    status = db.Column(db.String(20))
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class DropboxConfig(db.Model):
    __tablename__ = 'dropbox_config'
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String(200))
    refresh_token = db.Column(db.String(200))
    folder_path = db.Column(db.String(200), default='/attendance')
    enabled = db.Column(db.Boolean, default=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

# ============= TEMPLATE FILTERS =============
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
                db.session.add(settings)
                print("✅ Created system settings")

            db.session.commit()
            print("🎉 System initialization complete!")

        except Exception as e:
            db.session.rollback()
            print(f"❌ System initialization failed: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            raise

# ============= MAIN APPLICATION ROUTES =============
@app.route('/')
def index():
    """Homepage"""
    return render_template('index.html')

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
                flash(f'Welcome back, {user.username}!', 'success')
                
                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))
            else:
                flash('❌ Invalid email or password', 'danger')

        except Exception as e:
            flash('❌ Database error. Please try again.', 'danger')
            app.logger.error(f"Login error: {str(e)}")

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    today = datetime.now(timezone.utc).date()
    
    if current_user.role == 'super_admin':
        stats = {
            'total_students': Student.query.filter_by(is_active=True).count(),
            'total_teachers': User.query.filter_by(role='teacher', is_active=True).count(),
            'today_attendance': Attendance.query.filter_by(date=today).count(),
            'total_classes': Class.query.count(),
        }
        return render_template('admin/dashboard.html', stats=stats)
    else:
        assigned_classes = current_user.get_assigned_classes_dict()
        today_attendance = Attendance.query.filter_by(
            teacher_id=current_user.id,
            date=today
        ).count()
        
        recent_sessions = AttendanceSession.query.filter_by(
            teacher_id=current_user.id
        ).order_by(AttendanceSession.date.desc()).limit(5).all()
        
        return render_template('teacher/dashboard.html',
                             assigned_classes=assigned_classes,
                             today_attendance=today_attendance,
                             recent_sessions=recent_sessions)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# ============= RUN APPLICATION =============
if __name__ == '__main__':
    try:
        print("Starting Dewra High School Smart Attendance System...")
        print(f"Database path: {database_path}")
        
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
    print(f"📱 SMS Service: {'✅ SMSGate' if SMSGATE_USERNAME and SMSGATE_PASSWORD else '⚠️ Not configured'}")
    print("=" * 60)
    print("🌐 Starting server on http://localhost:5000")
    print("👑 Super Admin: admin@dewra.edu.bd")
    print("🔑 Password: Admin@2025")
    print("=" * 60)

    app.run(
        debug=os.getenv('FLASK_DEBUG', 'True').lower() == 'true',
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        threaded=True
    )