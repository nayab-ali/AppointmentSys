from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
import secrets
import string
from sqlalchemy.orm import aliased
from datetime import datetime, date, time
import os
import re


# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the-gift'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('MYSQL_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extension
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Setup logging
handler = ConcurrentRotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Add handler to logger of Flask app
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# To generate random password
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# To check current user is admin or not
def is_admin():
    if current_user.role != 'admin':
        flash('Unauthorized Access.', 'danger')
        return redirect(url_for('login'))
    
# To check current user is teacher or not
def is_teacher():
    if current_user.role != 'teacher':
        flash('Unauthorized Access.', 'danger')
        return redirect(url_for('login'))
    
# To check current user is studenet or not
def is_student():
    if current_user.role != 'student':
        flash('Unauthorized Access.', 'danger')
        return redirect(url_for('login'))

# Database Model
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False) # student/teacher/admin
    status = db.Column(db.String(20), default='pending') # For student approval

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)
    

class Teacher(db.Model):
    __tablename__ = 'teachers'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    department = db.Column(db.String(100))
    subject = db.Column(db.String(100))

    user = db.relationship('User', backref='teacher', uselist=False)


class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    teacher_slot_id = db.Column(db.Integer, db.ForeignKey('teacher_slots.id'), nullable=False)
    slot_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending') # pending/approved/canceled
    purpose = db.Column(db.Text)

    teacher_slot = db.relationship('TeacherSlot', backref=db.backref('appointments', lazy=True))
    student = db.relationship('User', backref=db.backref('appointments', lazy=True), foreign_keys=[student_id])

class TeacherSlot(db.Model):
    __tablename__ = 'teacher_slots'
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teachers.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='available') # available/booked

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

if not os.path.exists('messages.txt'):
    with open('messages.txt', 'w') as f:
        pass

# Routes
@app.route('/')
def home():
    app.logger.info('Home page accessed.')
    return render_template('home.html', title='Home')

@app.route('/about')
def about():
    app.logger.info('About page accessed.')
    return render_template('about.html', title='About')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    errors = []

    if request.method == 'POST':
        name = request.form.get('name').strip()
        email = request.form.get('email').strip()
        message = request.form.get('message').strip()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Validate 1: Check if field are empty
        if not name or not email or not message:
            errors.append("All field are required. ")

        # Validate 2: Name should only contain letters and spaces
        if name and not re.match(r"^[A-Za-z\s]+$", name):
            errors.append("Name should only contain letters and spaces. ")
        
        # Validate 3: Email format validation
        if email and not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
            errors.append("Please enter a valid email address. ")

        # Validate 4: Message lenght (10 to 200)
        if message and len(message) < 10 or len(message) > 200:
            errors.append("Message must be between 10 to 200 character. ")

        if errors:

            flash("".join(errors), 'danger')
            return render_template('contact.html', errors=errors)
        
        try:
            with open('messages.txt', 'a') as f:
                f.write(f"Timestamp: {timestamp}\nName: {name}\nEmail: {email}\nMessage: {message}\n{'-'*50}\n\n")
                app.logger.info(f'{name} message via contact page.')
                flash("Your message successfully sumbit. We'll contact you soon.", 'success')
        except Exception as e:
            app.logger.error(f"Error writting to file: {str(e)}")
            flash('An error occured while sending the message. Please try again later.', 'danger')
        
        return redirect(url_for('contact'))
        
    return render_template('contact.html')
            

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        app.logger.info(f"User {current_user.email} (Role: {current_user.role}) attempted to access login page while already logged in.")
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash('Email and password are required.', 'danger')
            app.logger.warning('Login attempt with missing email or password.')
            return redirect(url_for('login'))

        try:
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                if user.role == 'student' and user.status != 'approved':
                    flash('Awaiting admin approval.', 'danger')
                    app.logger.info(f"User {email} (Role: student) login failed: Awaiting admin approval.")
                    return redirect(url_for('login'))
                login_user(user)
                app.logger.info(f"User {email} (Role: {user.role}) logged in successfully.")
                flash('Logged in successfully', 'success')

                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user.role == 'teacher':
                    return redirect(url_for('teacher_dashboard'))
                else:
                    return redirect(url_for('student_dashboard'))
            else:
                flash('Invalid email or password.', 'danger')
                app.logger.warning(f"Login attempt failed for email: {email} - Invalid credentials.")
                return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f"Error during login for email {email}: {str(e)}")
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', title='Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    errors = []

    if request.method == 'POST':
        name = request.form.get('name').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password').strip()
        confirm_password = request.form.get('confirm_password').strip()

        # Validate 1: Check if field are empty
        if not name or not email or not password or not confirm_password:
            errors.append("All field are required. ")

        # Validate 2: Name should only contain letters and spaces
        if name and not re.match(r"^[A-Za-z\s]+$", name):
            errors.append("Name should only contain letters and spaces. ")
        
        # Validate 3: Email format validation
        if email and not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
            errors.append("Please enter a valid email address. ")

        # Validate 4: passwords must be same
        if password != confirm_password:
            errors.append("Both Passwords must be same. ")

        if errors:
            flash("".join(errors), 'danger')
            return render_template('register.html', errors=errors)
        
        try:
            user = User(name=name, email=email, role='student')
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            app.logger.info(f"Student {email} registered")
            flash('Registration successsful. Awaiting approval.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f"Error to register as a student {email}: {str(e)}")
            flash('An error occured while registration. Please try again later.', 'danger')
            return redirect(url_for('register'))
    return render_template('register.html', title='Register')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    app.logger.info(f"Admin {current_user.email} accessed dashboard")
    return render_template('admin_dashboard.html', title='Admin Dashboard')

@app.route('/admin/add_teacher', methods=['GET', 'POST'])
@login_required
def add_teacher():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result

    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        department = request.form.get('department')
        subject = request.form.get('subject')

        # Generate random password
        password = generate_random_password()

        # if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists.', 'danger')
            return redirect(url_for('add_teacher'))
        
        try:
            # create new User with role 'teacher'
            new_user = User(name=name, email=email, role='teacher', status='approved')
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            # create new teacher entry
            new_teacher = Teacher(user_id=new_user.id, department=department, subject=subject)
            db.session.add(new_teacher)
            db.session.commit()

            app.logger.info(f"Teacher: {email} added by {current_user.email}")
            flash(f'Teacher: {name} with email ID: {email} added successfully. Their temporary password is: {password}', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Failed to add teacher {email} by {current_user.email}: {str(e)}") # log the error
            flash('An error occured while adding the teacher. Please try again.', 'danger')
            return redirect(url_for('add_teacher'))
        
    return render_template('add_teacher.html', title='Add Teacher')

@app.route('/admin/update_delete_teacher', methods=['GET'])
@login_required
def update_delete_teacher():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    # Get all teachers with their user details
    teachers = Teacher.query.join(User).filter(User.role == 'teacher').all()
    return render_template('update_delete_teacher.html', teachers=teachers, title='Manage Teachers')

@app.route('/admin/update_teacher/<int:teacher_id>', methods=['GET', 'POST'])
@login_required
def update_teacher(teacher_id):
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    teacher = Teacher.query.get_or_404(teacher_id)
    user = User.query.get(teacher.user_id)

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        department = request.form.get('department')
        subject = request.form.get('subject')

        # check if the new email is aleready exists but exclude the current user
        existing_user = User.query.filter(User.email == email, User.id != user.id).first()
        if existing_user:
            flash('Email already exists', 'danger')
            return redirect(url_for('update_teacher', teacher_id=teacher.id))
        
        try:
            # update user details
            user.name = name
            user.email = email
            # update teacher details
            teacher.department = department
            teacher.subject = subject
            db.session.commit()
            app.logger.info(f"Teacher: {name}, email: {email} updated by: {current_user.email}")
            flash('Teacher updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating teacher: {str(e)}")
            flash('An error occurred while updating the teacher. Please try again.', 'danger')
            return redirect(url_for('update_teacher', teacher_id=teacher.id))
        
    return render_template('update_teacher.html', teacher=teacher, user=user, title='Update Teacher')


@app.route('/admin/delete_teacher/<int:teacher_id>', methods=['GET'])
@login_required
def delete_teacher(teacher_id):
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    teacher = Teacher.query.get_or_404(teacher_id)
    user = User.query.get(teacher.user_id)

    try:
        teacher_slots = TeacherSlot.query.filter_by(teacher_id=teacher.id).all()
        for slot in teacher_slots:
            appointments_for_slot = Appointment.query.filter_by(teacher_slot_id=slot.id)
            for appointment in appointments_for_slot:
                db.session.delete(appointment)
            db.session.delete(slot)

        # Delete related appointments (if any)
        appointments = Appointment.query.filter_by(teacher_id=teacher.id).all()
        for appointment in appointments:
            db.session.delete(appointment)

        # Delete the teacher and associated user
        db.session.delete(teacher)
        db.session.delete(user)
        db.session.commit()
        app.logger.info(f"Teacher: {user.name}, email: {user.email} deleted by: {current_user.email}")
        flash('Teacher deleted successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting teacher: {str(e)}")
        flash('An error occured while deleting the teacher. Please try again.', 'danger')
        return redirect(url_for('update_delete_teacher'))


# Listing pending students
@app.route('/admin/approve_students', methods=['GET'])
@login_required
def approve_students():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result

    # Get all pending students
    students = User.query.filter_by(role='student', status='pending').all()
    return render_template('approve_students.html', students=students, title='Approve Students')

# Approve student route
@app.route('/admin/approve_student/<int:student_id>', methods=['GET'])
@login_required
def approve_student(student_id):
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    student = User.query.get_or_404(student_id)
    if student.role != 'student' or student.status != 'pending':
        flash('Invalid student or status.', 'danger')
        return redirect(url_for('approve_students'))
    
    try:
        student.status = 'approved'
        db.session.commit()
        app.logger.info(f"Student: {student.name}, email: {student.email} approved by {current_user.email}")
        flash(f'Student {student.name} approved successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error approving student: {str(e)}")
        flash('An error occurred while approving the student. Please try again.', 'danger')

    return redirect(url_for('approve_students'))


@app.route('/admin/reject_student/<int:student_id>', methods=['GET'])
@login_required
def reject_student(student_id):
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result
    
    student = User.query.get_or_404(student_id)
    if student.role != 'student' or student.status != 'pending':
        flash('Invalid student or status.', 'danger')
        return redirect(url_for('approve_students'))
    
    try:
        # check appointment for defensive programming
        appointments = Appointment.query.filter_by(student_id=student.id).all()
        for appointment in appointments:
            db.session.delete(appointment)

        db.session.delete(student)
        db.session.commit()
        app.logger.info(f"Student: {student.name}, email: {student.email} rejected by {current_user.email}")
        flash(f'Student {student.name} rejected and removed successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger(f"Error rejecting student {str(e)}")
        flash(f'An error occured while rejecting the student. Please try again.', 'danger')
    
    return redirect(url_for('approve_students'))


@app.route('/admin/view_all_appointments', methods=['GET'])
@login_required
def view_all_appointments():
    is_admin_result = is_admin()
    if is_admin_result is not None:
        return is_admin_result

    try:
        # Create aliases for User table to distinguish between student and teacher users
        StudentUser = aliased(User, name='student_user')
        TeacherUser = aliased(User, name='teacher_user')
        
        
        # Fetch all appointments with related student and teacher data
        appointments = Appointment.query.join(StudentUser, StudentUser.id == Appointment.student_id)\
                                        .join(Teacher, Teacher.id == Appointment.teacher_id)\
                                        .join(TeacherUser, TeacherUser.id == Teacher.user_id)\
                                        .add_columns(
                                            StudentUser.name.label('student_name'),
                                            TeacherUser.name.label('teacher_name'),
                                            Appointment.slot_time,
                                            Appointment.status
                                        ).all()
        
        # Fetch teacher names separately based on teacher_user_id
        appointment_list = []
        for appt in appointments:

            # Extract date time from slot_time
            slot_time = appt.slot_time
            date_str = slot_time.strftime('%Y-%m-%d')
            time_str = slot_time.strftime('%H:%M')

            appointment_list.append({
                'student_name':appt.student_name if appt.student_name else 'Unknown',
                'teacher_name':appt.teacher_name if appt.teacher_name else 'Unknown',
                'date':date_str,
                'time_slot': time_str,
                'status':appt.status
            })
        
        app.logger.info(f"Admin: {current_user.email} view the appointment list.")
        return render_template('view_all_appointments.html', appointments=appointment_list, title='View All Appointments')
    except Exception as e:
        app.logger.error(f"Error fetching appointments: {str(e)}")
        flash('An error occured while fetching appointments. Please try again.', 'danger')
        return render_template('view_all_appointments.html', appointments=[], title='View All Appointments')

# change teacher temporary password
@app.route('/change_password', methods=['GET', 'POST'])
# @login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not all([current_password, new_password, confirm_password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('change_password'))

        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            app.logger.warning(f"User {current_user.email} provided incorrect current password during password change.")
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('change_password'))
        
        try:
            current_user.set_password(new_password)
            db.session.commit()
            app.logger.info(f"User {current_user.email} changed their password successfully.")
            flash('Password changed successfully.', 'success')

            if current_user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('home'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error changing password for user {current_user.email}: {str(e)}")
            flash(f'An Error Occured while changing the password. Please try again.', 'danger')
            return redirect(url_for('change_password'))

    return render_template('change_password.html')
    

@app.route('/teacher/dashboard')
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        flash('Unauthorized.', 'danger')
        return redirect(url_for('login'))
    app.logger.info(f"Teacher {current_user.email} accessed dashboard")
    return render_template('teacher_dashboard.html', title='Teacher Dashboard')

@app.route('/teacher/schedule_slot', methods=['GET', 'POST'])
@login_required
def schedule_slot():
    is_teacher_result = is_teacher()
    if is_teacher_result is not None:
        return is_teacher_result
    
    # Get teacher records
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    if not teacher:
        flash('Teacher profile not found.', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    if request.method == 'POST':
        date_str = request.form.get('date')
        time_slot = request.form.get('time_slot')

        if not date_str or not time_slot:
            flash('All fields are required.', 'danger')
            return render_template('schedule_slot.html', form_data=request.form, today=date.today().strftime('%Y-%m-%d'))
        
        try:
            slot_date = datetime.strptime(date_str, '%Y-%m-%d').date()

            # Check if date is in the past
            if slot_date < date.today():
                flash('Cannot schedule slots in the past.', 'danger')
                return render_template('schedule_slot.html', form_data=request.form, today=date.today().strftime('%Y-%m-%d'))

            # Check if slot already exists for this teacher on this date and time
            existing_slot = TeacherSlot.query.filter_by(
                teacher_id = teacher.id,
                date=slot_date,
                time=time_slot
            ).first()
            if existing_slot:
                flash('This slot is already scheduled.', 'danger')
                return render_template('schedule_slot.html', form_data=request.form, today=date.today().strftime('%Y-%m-%d'))
            
            new_slot = TeacherSlot(
                teacher_id = teacher.id,
                date = slot_date,
                time = time_slot,
                status = 'available'
            )
            db.session.add(new_slot)
            db.session.commit()

            app.logger.info(f"Slot scheduled by teacher {current_user.email}: {date_str} {time_slot}")
            flash('Slot scheduled successfully.', 'success')
            return redirect(url_for('teacher_dashboard'))
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return render_template('schedule_slot.html', form_data=request.form, today=date.today().strftime('%Y-%m-%d'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error scheduling slot for teacher {5}: {str(e)}")
            flash('An error occurred while scheduling the slot. Please try again.', 'danger')
            return render_template('schedule_slot.html', form_data=request.form, today=date.today().strftime('%Y-%m-%d'))

    return render_template('schedule_slot.html', form_data={}, today=date.today().strftime('%Y-%m-%d'))


@app.route('/teacher/manage_appointments', methods=['GET'])
@login_required
def manage_appointments():
    is_teacher_result = is_teacher()
    if is_teacher_result is not None:
        return is_teacher_result
    
    # Get Teacher's record
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    if not teacher:
        flash('Teacher profile not found.', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    # Get all appointments for this teacher's slots
    appointments = (
        db.session.query(Appointment, TeacherSlot, User)
        .join(TeacherSlot, Appointment.teacher_slot_id == TeacherSlot.id)
        .join(User, Appointment.student_id == User.id)
        .filter(TeacherSlot.teacher_id == teacher.id)
        .all()
    )
    
    return render_template('manage_appointments.html', appointments=appointments)


@app.route('/teacher/appointment/<int:appointment_id>/approve', methods=['POST'])
@login_required
def approve_appointment(appointment_id):
    is_teacher_result = is_teacher()
    if is_teacher_result is not None:
        return is_teacher_result
    
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    if not teacher:
        flash('Teacher profile not found.', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    # Get the Appointment
    appointment = Appointment.query.get_or_404(appointment_id)

    # Check if the appointment belongs to this teacher's slot
    teacher_slot = TeacherSlot.query.get(appointment.teacher_slot_id)
    if teacher_slot.teacher_id != teacher.id:
        flash('Unauthorized Access.', 'danger')
        return redirect(url_for('manage_appointments'))
    
    # update appointment status
    try:
        appointment.status = 'approved'
        db.session.commit()
        app.logger.info(f"Teacher: {current_user.email} approve student's appointment. appointment id: {appointment_id}")
        flash('Appointment approved successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error approving appointment {appointment_id}: {str(e)}")
        flash('An error occured while approving the appointment. Please try again.', 'danger')

    return redirect(url_for('manage_appointments'))

@app.route('/teacher/appointment/<int:appointment_id>/cancel', methods=['POST'])
@login_required
def cancel_appointment(appointment_id):
    is_teacher_result = is_teacher()
    if is_teacher_result is not None:
        return is_teacher_result
    
    # Get the teacher's record
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    if not teacher:
        flash('Teacher profile not found.', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    # Get the appointment
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Check if the appointment belongs to this teacher's slot
    teacher_slot = TeacherSlot.query.get(appointment.teacher_slot_id)
    if teacher_slot.teacher_id != teacher.id:
        flash('Unauthorized Access.', 'danger')
        return redirect(url_for('manage_appointments'))
    
    # Update appointment status
    try:
        appointment.status = 'canceled'
        teacher_slot.status = 'available'
        db.session.commit()
        app.logger.info(f"Teacher: {current_user.email} cancel student's appointment. appointment id: {appointment_id}")
        flash('Appointment cancelled successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error cancelling appointment {appointment_id}: {str(e)}")
        flash('An error occured while cancelling the appointment. Please try again.', 'danger')

    return redirect(url_for('manage_appointments'))


@app.route('/teacher/view_messages', methods=['GET'])
@login_required
def view_messages():
    is_teacher_result = is_teacher()
    if is_teacher_result is not None:
        return is_teacher_result
    
    # Get the teacher's record
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    if not teacher:
        flash('Teacher profile not found.', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    try:
        # Get all appointments for this teacher with purpose (message)
        appointments = (
            db.session.query(Appointment, TeacherSlot, User)
            .join(TeacherSlot, Appointment.teacher_slot_id == TeacherSlot.id)
            .join(User, Appointment.student_id == User.id)
            .filter(TeacherSlot.teacher_id == teacher.id)
            .filter(Appointment.purpose != None)
            .all()
        )
        app.logger.info(f"Teacher: {current_user.email} view student's messages")
    except Exception as e:
        app.logger.error(f"Failed to view student's messages by teacher: {current_user.email}. error: {str(e)}")
        flash("An error occured. Please try again later.", 'danger')
    return render_template('view_messages.html', appointments=appointments)

@app.route('/teacher/view_all_appointments_teacher', methods=['GET'])
@login_required
def view_all_appointments_teacher():
    is_teacher_result = is_teacher()
    if is_teacher_result is not None:
        return is_teacher_result
    
    teacher = Teacher.query.filter_by(user_id=current_user.id).first()
    if not teacher:
        flash('Teacher profile not found.', 'danger')
        return redirect(url_for('teacher_dashboard'))
    
    try:
        appointments = (
            db.session.query(Appointment, TeacherSlot, User)
            .join(TeacherSlot, Appointment.teacher_slot_id == TeacherSlot.id)
            .join(User, Appointment.student_id == User.id)
            .filter(TeacherSlot.teacher_id == teacher.id)
            .all()
        )
        app.logger.info(f"Teacher: {current_user.email} view the appointment list.")
    except Exception as e:
        app.logger.error(f"Failed to view the appointment list by teacher: {current_user.email}. error: {str(e)}")
        flash("An error occured to view appointment list. Please try again later.", 'danger')

    return render_template('view_all_appointments_teacher.html', appointments=appointments)

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student' or current_user.status != 'approved':
        flash('Unauthorized or unapproved.', 'danger')
        return redirect(url_for('login'))
    app.logger.info(f"Student {current_user.email} accessed dashboard")
    return render_template('student_dashboard.html', title='Student Dashboard')

@app.route('/student/search_teacher', methods=['GET', 'POST'])
@login_required
def search_teacher():
    is_student_result = is_student()
    if is_student_result is not None:
        return is_student_result
    
    teachers = []
    search_name = ''
    search_department = ''
    search_subject = ''

    if request.method == 'POST':
        search_name = request.form.get('name', '').strip()
        search_department = request.form.get('department', '').strip()
        search_subject = request.form.get('subject', '').strip()

        try:
            query = (
                db.session.query(Teacher, User)
                .join(User, Teacher.user_id == User.id)
                .filter(User.role == 'teacher', User.status == 'approved')
            )

            if search_name:
                query = query.filter(User.name.ilike(f'%{search_name}%'))
            if search_department:
                query = query.filter(Teacher.department.ilike(f'%{search_department}%'))
            if search_subject:
                query = query.filter(Teacher.subject.ilike(f'%{search_subject}%'))

            teachers = query.all()
            if teachers:
                flash('Teachers found successfully!', 'success')
            else:
                flash('No teachers found matching your criteria.', 'danger')
            app.logger.info(f"Student: {current_user.email} search for teachers.")
        except Exception as e:
            app.logger.error(f'Error during teacher search: {str(e)}')
            flash('An error occured while searching the teachers. Please try again later.', 'danger')
            teachers = []
        
    return render_template('search_teacher.html', teachers=teachers, search_name=search_name, search_department=search_department, search_subject=search_subject)

@app.route('/student/book_appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    is_student_result = is_student()
    if is_student_result is not None:
        return is_student_result
    
    teachers = (
        db.session.query(Teacher, User)
        .join(User, Teacher.user_id == User.id)
        .filter(User.role == 'teacher', User.status == 'approved')
        .all()
    )

    selected_teacher_id = None
    slots = []
    try:
        if request.method == 'POST':
            selected_teacher_id = request.form.get('teacher_id')
            if selected_teacher_id:
                # Fetch available slots for the selected teacher
                slots = (
                    db.session.query(TeacherSlot)
                    .filter(
                        TeacherSlot.teacher_id == selected_teacher_id,
                        TeacherSlot.status == 'available',
                        TeacherSlot.date >= date.today()
                    )
                    .all()
                )

                # Book appointment if a slot is selected
                selected_slot_id = request.form.get('slot_id')
                if selected_slot_id:
                    purpose = request.form.get('purpose', '').strip()
                    if not purpose:
                        flash('Purpose is required', 'danger')
                        return render_template('book_appointment.html', teachers=teachers, selected_teacher_id=selected_teacher_id, slots=slots)
                    
                    # Create the appointment
                    slot = TeacherSlot.query.get_or_404(selected_slot_id)
                    appointment = Appointment(
                        student_id = current_user.id,
                        teacher_id = slot.teacher_id,
                        teacher_slot_id = selected_slot_id,
                        slot_time = datetime.combine(slot.date, time.fromisoformat(slot.time.split('-')[0])),
                        status = 'pending',
                        purpose = purpose
                    )
                    # Update slot status to booked
                    slot.status = 'booked'

                    db.session.add(appointment)
                    db.session.commit()
                    app.logger.info(f"Student: {current_user.email} booked appointment successfully.")
                    flash('Appointment booked successfully! Waiting for teacher approval.', 'success')
                    return redirect(url_for('student_dashboard'))
    except Exception as e:
        app.logger.error(f'Error during booking appointment: {str(e)}')
        flash('An error occured while booking the appointment. Please try again later.', 'danger')
        slots = []

    return render_template('book_appointment.html', teachers=teachers, selected_teacher_id=selected_teacher_id, slots=slots)

@app.route('/student/view_my_appointments', methods=['GET'])
@login_required
def view_my_appointments():
    is_student_result = is_student()
    if is_student_result is not None:
        return is_student_result
    
    try:
        appointments = (
            db.session.query(Appointment, TeacherSlot, User)
            .join(TeacherSlot, Appointment.teacher_slot_id == TeacherSlot.id)
            .join(User, Appointment.teacher_id == User.id)
            .filter(Appointment.student_id == current_user.id)
            .all()
        )
        if appointments:
            app.logger.info(f"Student: {current_user.email} view the status of appointment")
    except Exception as e:
        app.logger.error(f"Failed to view the appointment status by student: {current_user.email}, error: {str(e)}")
        flash('An error occur to view the status of appointment. Please try again later.', 'danger')
    return render_template('view_my_appointments.html', appointments=appointments)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    try:
        user_email = current_user.email
        user_role = current_user.role
        logout_user()
        app.logger.info(f"User {user_email} (Role: {user_role}) logged out successfully.")
        flash('You have been logged out successfully.', 'success')
    except Exception as e:
        app.logger.error(f"Error logging out user {user_email}: {str(e)}")
        flash('An error occured while logging out. Please try again.', 'danger')
    
    return redirect(url_for('login'))

# Initialize database
with app.app_context():
    db.create_all()

