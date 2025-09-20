from flask import Flask, request, session, jsonify, redirect, url_for, render_template
from flask_bcrypt import Bcrypt
from flask import flash
from datetime import datetime
import os
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'my_secret_key')
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///arise.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///arise.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    program = db.Column(db.String(100), nullable=False)
    year = db.Column(db.String(50), nullable=False)
    interests = db.Column(db.Text, nullable=False)
    subscribed = db.Column(db.Boolean, default=False)
    has_paid = db.Column(db.Boolean, default=False)

class generalFeedback(db.Model):
    __tablename__ = 'general_feedback'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(150), nullable=True)
    category = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    message = db.Column(db.Text, nullable=False)

class eventFeedback(db.Model):
    __tablename__ = 'event_feedback'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(150), nullable=True)
    event_name = db.Column(db.String(200), nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    event_msg = db.Column(db.Text, nullable=False)
    interested_in_future_events = db.Column(db.Boolean, default=False)

class suggestions(db.Model):
    __tablename__ = 'suggestions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(150), nullable=True)
    type = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    interested_in_volunteering = db.Column(db.Boolean, default=False)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/resources')
def resources():
    if 'user_id' not in session:
        flash('Please log in to access member resources.')
        return redirect(url_for('login'))
    
    return render_template('resources.html', user_email=session.get('email'))
   
@app.route('/join')
def join():
    if 'user_id' in session:
        flash('You are already logged in.')
        return redirect(url_for('resources'))
    return render_template('join.html')

@app.route('/submit_membership', methods=['POST'])
def submit_membership():
    data = request.get_json()
    existing_user = User.query.filter_by(email=data.get('email')).first()
    if existing_user:
        return jsonify({'message': 'This email is already registered. Please log in or use a different email.'}), 400
    
    hashed_password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
    new_user = User(
        email=data.get('email'),
        first_name=data.get('firstName'),
        last_name=data.get('lastName'),
        password=hashed_password,
        phone=data.get('phone'),
        program=data.get('program'),
        year=data.get('year'),
        interests=data.get('interests'),
        subscribed=bool(data.get('newsletter'))
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Thank you for your application! We will review it and get back to you within 2-3 business days. Please proceed with payment to complete your membership.'})

@app.route('/events')
def events():
    return render_template('events.html')

@app.route('/feedback')
def feedback():
    return render_template('feedback.html')

@app.route('/submit_general_feedback', methods=['POST'])
def submit_general_feedback():
    data = request.get_json()
    gen_feedback = generalFeedback(
        name=data.get('name'),
        email=data.get('email'),
        category=data.get('category'),
        rating=data.get('rating'),
        message=data.get('feedback')
    )
    db.session.add(gen_feedback)
    db.session.commit()
    return jsonify({'message': 'Thank you for your feedback! We appreciate your input and will review it carefully.'})

@app.route('/submit_event_feedback', methods=['POST'])
def submit_event_feedback():
    data = request.get_json()
    event_date = datetime.strptime(data.get('event-date'), '%Y-%m-%d').date()
    evt_feedback = eventFeedback(
        name=data.get('name'),
        email=data.get('email'),
        event_name=data.get('event-name'),
        event_date=event_date,
        rating=data.get('event-rating'),
        event_msg=data.get('event-feedback'),
        interested_in_future_events=bool(data.get('future-events'))
    )
    db.session.add(evt_feedback)
    db.session.commit()
    return jsonify({'message': 'Thank you for your feedback! We appreciate your input and will review it carefully.'})

@app.route('/submit_suggestion', methods=['POST'])
def submit_suggestion():
    data = request.get_json()
    sugg = suggestions(
        name=data.get('name'),
        email=data.get('email'),
        type=data.get('suggestion-type'),
        title=data.get('suggestion-title'),
        description=data.get('suggestion-details'),
        interested_in_volunteering=bool(data.get('volunteer'))
    )
    db.session.add(sugg)
    db.session.commit()
    return jsonify({'message': 'Thank you for your suggestion! We appreciate your input and will review it carefully.'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if not user.has_paid:
                flash('Please complete your payment to access member resources.')
                return redirect(url_for('join'))
            session['user_id'] = user.id
            session['email'] = user.email
            flash('Login successful!')
            return redirect(url_for('resources'))
        else:
            flash('Invalid credentials')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been Logged out.')
    return redirect(url_for('login'))

@app.route('/init-db')
def init_db():
    db.create_all()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
