""" URL is https://cisc-371-project.onrender.com  """

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'Gordon_Ramsey'  

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://trackitmasterdb_user:TAyVBZ1PtMRe3I4VMsMf0k9XfVDs5TGI@dpg-ct8ek9u8ii6s73c9is60-a.oregon-postgres.render.com/trackitmasterdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Initialize the database and create tables
with app.app_context():
    db.create_all()

# User model that maps user to POSTGRESQL 
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)

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
        role = request.form['role']  # Capture the role selected in form
        # Hash the password 
        hashed_password = generate_password_hash(password)
        # Create a new user instance with role
        new_user = User(username=username, password=hashed_password, role=role)
        try:
            # Add and commit the new user to database
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
    # Debugging
    print(f"Login attempt with username: {username}")
    # Query for the user by username (case-insensitive)
    user = User.query.filter_by(username=username).first()
    # Debugging:
    if user:
        print(f"User found: {user.username}, Role: {user.role}")
    else:
        print("No user found with that username.")
    # Check if user exists and password matches
    if user and check_password_hash(user.password, password):
        session['username'] = username  # Set session variable
        session['role'] = user.role
        print(f"Login successful. Session: {session}")

        # Redirect based on role
        if user.role == 'Helpdesk':
            return redirect(url_for('helpdesk_page'))
        elif user.role == 'Support Staff':
            return redirect(url_for('support_staff_page'))
        elif user.role == 'Administrator':
            return redirect(url_for('administrator_page'))
        elif user.role == 'Manager':
            return redirect(url_for('manager_page'))
        else:
            flash("Unknown role. Please contact support.", "danger")
            return redirect(url_for('home'))
        
    else:
        flash("Invalid username or password", "danger")
        print("Login failed: Invalid username or password")
        return redirect(url_for('home'))

# Protected route for respective dashboard
@app.route('/helpdesk')
def helpdesk_page():
    if 'username' not in session:
        flash("You must log in to view tickets.", "danger")
        return redirect(url_for('home')) 
    tickets = Ticket.query.order_by(Ticket.created_at.asc()).all()
    print(f"Tickets retrieved: {tickets}")
    return render_template('helpdesk.html', tickets=tickets, role=session.get('role'))

@app.route('/support_staff')
def support_staff_page():
    if 'username' not in session:
        flash("You must log in to view tickets.", "danger")
        return redirect(url_for('home'))
    tickets = Ticket.query.order_by(Ticket.created_at.asc()).all()
    print(f"Tickets retrieved: {tickets}")
    return render_template('supportstaff.html', tickets=tickets, role=session.get('role'))

@app.route('/administrator')
def administrator_page():
    if 'username' not in session:
        flash("You must log in to view tickets.", "danger")
        return redirect(url_for('home'))
    tickets = Ticket.query.order_by(Ticket.created_at.asc()).all()
    print(f"Tickets retrieved: {tickets}")
    return render_template('administrator.html', tickets=tickets, role=session.get('role'))

@app.route('/manager')
def manager_page():
    if 'username' not in session:
        flash("You must log in to view tickets.", "danger")
        return redirect(url_for('home'))
    tickets = Ticket.query.order_by(Ticket.created_at.asc()).all()
    print(f"Tickets retrieved: {tickets}")
    return render_template('manager.html', tickets=tickets, role=session.get('role'))

# Route to handle logout
@app.route('/logout')
def logout():
    session.pop('username', None)  # Clear the session
    flash("You have been logged out.")
    return redirect(url_for('home'))

# Ticket Creation / Ticket Closing

# User model that maps tickets to POSTGRESQL
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Ticket ID
    title = db.Column(db.String(100), nullable=False)  # Title
    description = db.Column(db.Text, nullable=False)  # Description
    status = db.Column(db.String(20), default="Opened")  # Status
    created_by = db.Column(db.String(50), nullable=False)  # Request User
    assigned_to = db.Column(db.String(50), nullable=True)  # Assigned to
    created_at = db.Column(db.DateTime, default=db.func.now())  # Timestamp

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

        # Redirect back to user's respective homepage
        role = session.get('role')
        if role == 'Helpdesk':
            return redirect(url_for('helpdesk_page'))
        elif role == 'Support Staff':
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
    if request.method == 'POST' and session.get('role') in ['Manager', 'Administrator', 'Helpdesk']:
        ticket.status = "Closed"
        db.session.commit()
        flash(f"Ticket {ticket.id} closed successfully!", "success")
        return redirect(url_for('view_ticket', ticket_id=ticket_id))

    return render_template('viewticket.html', ticket=ticket, role=session.get('role'))

# Assign ticket route 
@app.route('/assign_ticket/<int:ticket_id>', methods=['POST'])
def assign_ticket(ticket_id):
    if 'username' not in session or session.get('role') not in ['Manager', 'Admin', 'Helpdesk']:
        flash("You do not have permission to assign tickets.")
        return redirect(url_for('helpdesk_page'))

    assigned_user = request.form.get('username')  # Get assigned user from the form
    ticket = Ticket.query.get(ticket_id)

    if ticket:
        ticket.assigned_to = assigned_user
        db.session.commit()
        flash(f"Ticket {ticket.id} assigned to {assigned_user} successfully!")
    else:
        flash("Ticket not found.")

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

# Close Ticket Route
@app.route('/close_ticket/<int:ticket_id>', methods=['POST'])
def close_ticket(ticket_id):
    if 'username' not in session or session.get('role') not in ['Manager', 'Admin', 'Helpdesk']:
        flash("You do not have permission to close tickets.", "danger")
        return redirect(url_for('home'))
    ticket = Ticket.query.get(ticket_id)
    if ticket:
        try:
            ticket.status = "Closed"  # Update the status
            db.session.commit()  # Save the change
            flash(f"Ticket {ticket.id} closed successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to close ticket: {e}", "danger")
    else:
        flash("Ticket not found.", "danger")

    # Role-based redirection
    role = session.get('role')
    if role == 'Helpdesk':
        return redirect(url_for('helpdesk_page'))
    elif role == 'Support Staff':
        return redirect(url_for('support_staff_page'))
    elif role == 'Administrator':
        return redirect(url_for('administrator_page'))
    elif role == 'Manager':
        return redirect(url_for('manager_page'))

    # Fallback in case role is undefined
    return redirect(url_for('home'))

"""
# debugging to check tables are being created in database
with app.app_context():
    print("Creating tables...")
    db.create_all()
    print("Tables created successfully.")
"""
