from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'Gordon_Ramsey'  

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trackitmaster.db'
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
            flash(f"Sign-up failed: {e}", "danger")
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
        session['role'] = user.role

        # Redirect based on role
        if user.role == 'Helpdesk':
            return redirect(url_for('helpdesk_page'))
        elif user.role == 'SupportStaff':
            return redirect(url_for('support_staff_page'))
        elif user.role == 'Administrator':
            return redirect(url_for('administrator_page'))
        elif user.role == 'Manager':
            return redirect(url_for('manager_page'))
        else:
            flash("Unknown role. Please contact support.", "danger")
            return redirect(url_for('home'))
        
    else:
        flash("Invalid username or password")
        return redirect(url_for('home'))

# Protected route for the dashboard
@app.route('/helpdesk')
def helpdesk_page():
    return render_template('helpdesk.html')

@app.route('/support_staff')
def support_staff_page():
    return render_template('support_staff.html')

@app.route('/administrator')
def administrator_page():
    return render_template('administrator.html')

@app.route('/manager')
def manager_page():
    return render_template('manager.html')

# Route to handle user logout
@app.route('/logout')
def logout():
    session.pop('username', None)  # Clear the session
    flash("You have been logged out.")
    return redirect(url_for('home'))


# Ticket Creation / Ticket Closing


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Ticket Number
    title = db.Column(db.String(100), nullable=False)  # Title
    status = db.Column(db.String(20), default="Opened")  # Status: Opened/Closed
    created_by = db.Column(db.String(50), nullable=False)  # Request User
    assigned_to = db.Column(db.String(50), nullable=True)  # Assigned to (optional)
    created_at = db.Column(db.DateTime, default=db.func.now())  # Date

# Create Ticket Route
@app.route('/create_ticket', methods=['GET', 'POST'])
def create_ticket():
    if 'username' not in session:
        flash("You must log in to create a ticket.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']  # Capture ticket details
        created_by = session['username']  # Logged-in user

        new_ticket = Ticket(
            title=title,
            description=description,
            created_by=created_by
        )
        try:
            db.session.add(new_ticket)
            db.session.commit()
            flash("Ticket created successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to create ticket: {e}", "danger")

        # Redirect back to user's homepage
        role = session.get('role')
        if role == 'Helpdesk':
            return redirect(url_for('helpdesk_page'))
        elif role == 'SupportStaff':
            return redirect(url_for('support_staff_page'))
        elif role == 'Administrator':
            return redirect(url_for('administrator_page'))
        elif role == 'Manager':
            return redirect(url_for('manager_page'))
        return redirect(url_for('home'))

    return render_template('createticket.html')

# View Ticket Route
@app.route('/view_ticket/<int:ticket_id>', methods=['GET', 'POST'])
def view_ticket(ticket_id):
    if 'username' not in session:
        flash("You must log in to view tickets.", "danger")
        return redirect(url_for('home'))

    ticket = Ticket.query.get(ticket_id)
    if not ticket:
        flash("Ticket not found.", "danger")
        return redirect(url_for('home'))

    # Handle ticket closure
    if request.method == 'POST' and session.get('role') in ['Manager', 'Admin', 'Helpdesk']:
        ticket.status = "Closed"
        db.session.commit()
        flash(f"Ticket {ticket.id} closed successfully!", "success")
        return redirect(url_for('view_ticket', ticket_id=ticket_id))

    return render_template('viewticket.html', ticket=ticket, role=session.get('role'))

# Close Ticket Route

@app.route('/close_ticket/<int:ticket_id>', methods=['POST'])
def close_ticket(ticket_id):
    if 'username' not in session or session.get('role') not in ['Manager', 'Admin', 'Helpdesk']:
        flash("You do not have permission to close tickets.")
        return redirect(url_for('view_tickets'))

    ticket = Ticket.query.get(ticket_id)
    if ticket:
        ticket.status = "Closed"
        db.session.commit()
        flash("Ticket closed successfully!")
    else:
        flash("Ticket not found.")
    return redirect(url_for('view_tickets'))