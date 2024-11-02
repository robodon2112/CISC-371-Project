from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'Gordon_Ramsey'  

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://robodonnell:Naruto2112@localhost/TrackitmasterDB'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model that maps to MySQL DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)

# Initialize the database and create tables
with app.app_context():
    db.create_all()

# Route to display login and sign-up page
@app.route('/')
def home():
    return render_template('login.html')

# Route to handle user sign-up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']  # Capture the role selected in the form

        # Hash the password before storing it
        hashed_password = generate_password_hash(password)

        # Create a new user instance with role
        new_user = User(username=username, password=hashed_password, role=role)

        try:
            # Add and commit the new user to the database
            db.session.add(new_user)
            db.session.commit()
            flash("Sign-up successful! Please log in.")
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash(f"Sign-up failed: {e}")
            return redirect(url_for('signup'))
    else:
        return render_template('signup.html')

# Route to handle user login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Query for the user by username
    user = User.query.filter_by(username=username).first()

    # Check if user exists and password matches
    if user and check_password_hash(user.password, password):
        session['username'] = username  # Set session variable
        return redirect(url_for('dashboard'))
    else:
        flash("Invalid username or password")
        return redirect(url_for('home'))

# Protected route for the dashboard
@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in
    if 'username' in session:
        return f"Welcome, {session['username']}! This is your dashboard."
    return redirect(url_for('home'))

# Route to handle user logout
@app.route('/logout')
def logout():
    session.pop('username', None)  # Clear the session
    flash("You have been logged out.")
    return redirect(url_for('home'))

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)

@app.route('/test_db')
def test_db():
    try:
        # Attempt to retrieve all users to see if the connection is successful
        users = User.query.all()
        return f"Users found: {len(users)}"
    except Exception as e:
        return f"Database connection error: {e}"
