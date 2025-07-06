from flask import Flask, render_template, redirect, url_for, session, request, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from functools import wraps
import os
import uuid

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure, unique key in production

# Configuration for file uploads
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create uploads folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for('login'))
        if session['user'] != 'admin':
            flash("You do not have permission to access the admin dashboard.", "error")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize database for users
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL)''')
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    if 'profile_photo' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN profile_photo TEXT DEFAULT 'default.jpg'")
    c.execute("SELECT * FROM users WHERE username = ?", ('admin',))
    if not c.fetchone():
        hashed_password = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                  ('admin', 'admin@example.com', hashed_password))
    conn.commit()
    conn.close()

# Initialize database for certificates
def init_certificates_db():
    if not os.path.exists("certificates.db"):
        conn = sqlite3.connect("certificates.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS certificates
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      title TEXT NOT NULL,
                      description TEXT NOT NULL,
                      image_url TEXT NOT NULL)''')
        sample_certificates = [
            ("Hackathon 2024 Winner", "Awarded for outstanding innovation in AI development.", "https://via.placeholder.com/300x150"),
            ("CodeFest 2023 Runner-Up", "Recognized for exceptional problem-solving skills.", "https://via.placeholder.com/300x150"),
            ("TechSprint 2022 Best Design", "Honored for creative UI/UX implementation.", "https://via.placeholder.com/300x150")
        ]
        c.executemany("INSERT INTO certificates (title, description, image_url) VALUES (?, ?, ?)", sample_certificates)
        conn.commit()
        conn.close()

# Initialize database for hackathons
def init_hackathons_db():
    if not os.path.exists("hackathons.db"):
        conn = sqlite3.connect("hackathons.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS hackathons
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      date TEXT NOT NULL,
                      location TEXT NOT NULL,
                      description TEXT NOT NULL,
                      image_url TEXT NOT NULL)''')
        sample_hackathons = [
            ("Hackathon 2024", "May 2024", "Online", "Participated in a global AI hackathon, won first place.", "https://via.placeholder.com/300x150"),
            ("CodeFest 2023", "August 2023", "Bangalore, India", "Competed with 50+ teams, secured second place.", "https://via.placeholder.com/300x150"),
            ("TechSprint 2022", "March 2022", "Mumbai, India", "Focused on UI/UX, won best design award.", "https://via.placeholder.com/300x150")
        ]
        c.executemany("INSERT INTO hackathons (name, date, location, description, image_url) VALUES (?, ?, ?, ?, ?)", sample_hackathons)
        conn.commit()
        conn.close()

# Initialize database for registrations
def init_registrations_db():
    if not os.path.exists("registrations.db"):
        conn = sqlite3.connect("registrations.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS registrations
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      name TEXT NOT NULL,
                      email TEXT NOT NULL UNIQUE,
                      contact_number TEXT NOT NULL,
                      interested_domain TEXT NOT NULL,
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
        conn.close()

# Initialize database for teams
def init_teams_db():
    conn = sqlite3.connect("teams.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS teams (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    hackathon_event TEXT NOT NULL,
                    leader_username TEXT NOT NULL,
                    join_code TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS team_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    team_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    name TEXT NOT NULL,
                    phone_number TEXT NOT NULL,
                    email TEXT NOT NULL,
                    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (team_id) REFERENCES teams(id))''')
    conn.commit()
    conn.close()

# Initialize all databases
init_db()
init_certificates_db()
init_hackathons_db()
init_registrations_db()
init_teams_db()

# Home (public) route
@app.route("/")
def main():
    return render_template("main.html")

# Protected home route
@app.route("/home")
@login_required
def home():
    team = [
        {"name": "Akshit Jaiswal", "role": "Founder", "desc": "Leads the team...", "image": "images/founder.jpg", "linkedin": "https://www.linkedin.com/in/akshit-jaiswal-60b150326/", "email": "mailto:akshit@example.com", "instagram": "https://www.instagram.com/akshitjaiswal"},
        {"name": "Ankit Saraswat", "role": "Co-founder", "desc": "Manages teams...", "image": "images/cofounder.jpg", "linkedin": "https://www.linkedin.com/in/ankit-saraswat-781550326/", "email": "mailto:ankit@example.com", "instagram": "https://www.instagram.com/_ankitsaraswat"},
        {"name": "Manish Chaudhary", "role": "Research & Development Head", "desc": "Manages research...", "image": "images/r&d.jpg", "linkedin": "https://www.linkedin.com/in/manish-chaudhary-4569bb276/", "email": "mailto:manish@example.com", "instagram": "https://www.instagram.com/manishchaudhary"}
    ]
    return render_template("index.html", team=team)

# Certificate page route (protected)
@app.route("/certificates")
@login_required
def certificates():
    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()
    c.execute("SELECT title, description, image_url FROM certificates")
    certificates = c.fetchall()
    conn.close()
    return render_template("certificates.html", certificates=certificates)

# API route to fetch certificates
@app.route("/api/certificates", methods=['GET'])
@login_required
def get_certificates():
    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()
    c.execute("SELECT title, description, image_url FROM certificates")
    certificates = c.fetchall()
    conn.close()
    certificates_list = [
        {"title": cert[0], "description": cert[1], "image_url": cert[2]}
        for cert in certificates
    ]
    return jsonify(certificates_list)

# Hackathons page route (protected)
@app.route("/hackathons")
@login_required
def hackathons():
    conn = sqlite3.connect("hackathons.db")
    c = conn.cursor()
    c.execute("SELECT name, date, location, description, image_url FROM hackathons")
    hackathons = c.fetchall()
    conn.close()
    return render_template("hackathons.html", hackathons=hackathons)

# API route to fetch hackathons
@app.route("/api/hackathons", methods=['GET'])
@login_required
def get_hackathons():
    conn = sqlite3.connect("hackathons.db")
    c = conn.cursor()
    c.execute("SELECT name, date, location, description, image_url FROM hackathons")
    hackathons = c.fetchall()
    conn.close()
    hackathons_list = [
        {"name": hack[0], "date": hack[1], "location": hack[2], "description": hack[3], "image_url": hack[4]}
        for hack in hackathons
    ]
    return jsonify(hackathons_list)

# Profile page route (protected)
@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT username, email, profile_photo FROM users WHERE username = ?", (session['user'],))
    user_data = c.fetchone()
    conn.close()

    if not user_data:
        flash("User not found.", "error")
        return redirect(url_for('home'))

    user = {'username': user_data[0], 'email': user_data[1], 'profile_photo': user_data[2] or 'default.jpg'}

    if request.method == 'POST':
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file.filename == '':
                flash("No file selected.", "error")
                return redirect(url_for('profile'))
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                conn = sqlite3.connect("users.db")
                c = conn.cursor()
                c.execute("UPDATE users SET profile_photo = ? WHERE username = ?", (filename, session['user']))
                conn.commit()
                conn.close()
                flash("Profile photo updated successfully.", "success")
                return redirect(url_for('profile'))
            else:
                flash("Invalid file type. Allowed types: png, jpg, jpeg, gif.", "error")
                return redirect(url_for('profile'))

    return render_template("profile_page.html", user=user)

# Update password route
@app.route("/update_password", methods=['POST'])
@login_required
def update_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not all([current_password, new_password, confirm_password]):
        flash("All fields are required.", "error")
        return redirect(url_for('profile'))

    if new_password != confirm_password:
        flash("New passwords do not match.", "error")
        return redirect(url_for('profile'))

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (session['user'],))
    user = c.fetchone()

    if not user or not check_password_hash(user[0], current_password):
        flash("Current password is incorrect.", "error")
        conn.close()
        return redirect(url_for('profile'))

    hashed_password = generate_password_hash(new_password)
    try:
        c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, session['user']))
        conn.commit()
        flash("Password updated successfully.", "success")
    except sqlite3.Error as e:
        flash(f"Error updating password: {str(e)}", "error")
    conn.close()
    return redirect(url_for('profile'))

# Admin page route
@app.route("/admin", methods=['GET'])
@login_required
@admin_required
def admin():
    search_query = request.args.get('search', '').strip()
    reg_search_query = request.args.get('reg_search', '').strip()
    team_search_query = request.args.get('team_search', '').strip()
    
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    try:
        if search_query:
            c.execute("SELECT username, email FROM users WHERE LOWER(username) LIKE ?", ('%' + search_query.lower() + '%',))
        else:
            c.execute("SELECT username, email FROM users")
        users = c.fetchall()
    except sqlite3.Error as e:
        flash(f"Error fetching users: {str(e)}", "error")
        users = []
    conn.close()
    
    conn = sqlite3.connect("registrations.db")
    c = conn.cursor()
    try:
        if reg_search_query:
            c.execute("SELECT name, email, contact_number, interested_domain FROM registrations WHERE LOWER(name) LIKE ?", 
                      ('%' + reg_search_query.lower() + '%',))
        else:
            c.execute("SELECT name, email, contact_number, interested_domain FROM registrations")
        registrations = c.fetchall()
    except sqlite3.Error as e:
        flash(f"Error fetching registrations: {str(e)}", "error")
        registrations = []
    conn.close()
    
    conn = sqlite3.connect("teams.db")
    c = conn.cursor()
    try:
        if team_search_query:
            c.execute("SELECT id, team_name, hackathon_event, leader_username FROM teams WHERE LOWER(team_name) LIKE ?",
                      ('%' + team_search_query.lower() + '%',))
        else:
            c.execute("SELECT id, team_name, hackathon_event, leader_username FROM teams")
        teams = c.fetchall()
        team_data = []
        for team in teams:
            team_id = team[0]
            c.execute("SELECT username, name, phone_number, email FROM team_members WHERE team_id = ?", (team_id,))
            members = c.fetchall()
            team_data.append({
                'id': team[0],
                'team_name': team[1],
                'hackathon_event': team[2],
                'leader_username': team[3],
                'members': members
            })
    except sqlite3.Error as e:
        flash(f"Error fetching teams: {str(e)}", "error")
        team_data = []
    conn.close()
    
    return render_template("admin.html", users=users, search_query=search_query, 
                         registrations=registrations, reg_search_query=reg_search_query,
                         teams=team_data, team_search_query=team_search_query)

# Route to delete a team
@app.route("/delete_team/<int:team_id>", methods=['POST'])
@login_required
@admin_required
def delete_team(team_id):
    conn = sqlite3.connect("teams.db")
    c = conn.cursor()
    try:
        c.execute("DELETE FROM team_members WHERE team_id = ?", (team_id,))
        c.execute("DELETE FROM teams WHERE id = ?", (team_id,))
        conn.commit()
        flash("Team deleted successfully.", "success")
    except sqlite3.Error as e:
        flash(f"Error deleting team: {str(e)}", "error")
    conn.close()
    return redirect(url_for('admin'))

# Route to handle admin password changes for other users
@app.route("/change_password", methods=['POST'])
@login_required
@admin_required
def change_password():
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    if not username or not new_password:
        flash("Username and new password are required.", "error")
        return redirect(url_for('admin'))
    
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        if not user:
            flash("User not found.", "error")
            conn.close()
            return redirect(url_for('admin'))
        
        hashed_password = generate_password_hash(new_password)
        c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
        conn.commit()
        flash(f"Password updated successfully for {username}.", "success")
    except sqlite3.Error as e:
        flash(f"Error updating password: {str(e)}", "error")
    conn.close()
    return redirect(url_for('admin'))

# Team registration route
@app.route("/register", methods=['GET', 'POST'])
@login_required
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        contact_number = request.form.get('contact_number')
        interested_domain = request.form.get('interested_domain')
        if not all([name, email, contact_number, interested_domain]):
            flash("All fields are required.", "error")
            return redirect(url_for('register'))
        try:
            conn = sqlite3.connect('registrations.db')
            c = conn.cursor()
            c.execute('INSERT INTO registrations (name, email, contact_number, interested_domain) VALUES (?, ?, ?, ?)',
                      (name, email, contact_number, interested_domain))
            conn.commit()
            flash("Registration successful.", "success")
        except sqlite3.IntegrityError:
            flash("Email already registered.", "error")
        except sqlite3.Error as e:
            flash(f"Error during registration: {str(e)}", "error")
        conn.close()
        return redirect(url_for('register'))
    return render_template('register.html')

# Team management route
@app.route("/team_management", methods=['GET', 'POST'])
@login_required
def team_management():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT username, email, profile_photo FROM users WHERE username = ?", (session['user'],))
    user_data = c.fetchone()
    conn.close()

    if not user_data:
        flash("User not found.", "error")
        return redirect(url_for('home'))

    user = {'username': user_data[0], 'email': user_data[1], 'profile_photo': user_data[2] or 'default.jpg'}

    conn = sqlite3.connect("hackathons.db")
    c = conn.cursor()
    c.execute("SELECT name FROM hackathons")
    hackathons = c.fetchall()
    conn.close()

    conn = sqlite3.connect("teams.db")
    c = conn.cursor()
    c.execute("SELECT team_id FROM team_members WHERE username = ?", (session['user'],))
    user_team = c.fetchone()

    team = None
    team_members = []
    if user_team:
        team_id = user_team[0]
        c.execute("SELECT * FROM teams WHERE id = ?", (team_id,))
        team = c.fetchone()
        if team:
            c.execute("SELECT username, name, phone_number, email FROM team_members WHERE team_id = ?", (team_id,))
            team_members = c.fetchall()
            team = {
                'id': team[0],
                'team_name': team[1],
                'description': team[2],
                'hackathon_event': team[3],
                'leader_username': team[4],
                'join_code': team[5]
            }
    conn.close()

    if request.method == 'POST':
        if user_team:
            flash("You are already part of a team.", "error")
            return redirect(url_for('team_management'))

        team_name = request.form.get('team_name')
        description = request.form.get('description')
        hackathon_event = request.form.get('hackathon_event')
        member_names = request.form.getlist('member_name[]')
        member_phones = request.form.getlist('member_phone[]')
        member_emails = request.form.getlist('member_email[]')

        if not team_name or not hackathon_event or len(member_names) != len(member_phones) or len(member_names) != len(member_emails):
            flash("Invalid team details.", "error")
            return redirect(url_for('team_management'))

        join_code = str(uuid.uuid4())[:8]
        conn = sqlite3.connect("teams.db")
        c = conn.cursor()
        try:
            c.execute("INSERT INTO teams (team_name, description, hackathon_event, leader_username, join_code) VALUES (?, ?, ?, ?, ?)",
                      (team_name, description, hackathon_event, session['user'], join_code))
            team_id = c.lastrowid
            c.execute("INSERT INTO team_members (team_id, username, name, phone_number, email) VALUES (?, ?, ?, ?, ?)",
                      (team_id, session['user'], session['user'], member_phones[0], member_emails[0]))
            for i in range(1, len(member_names)):
                if member_names[i] and member_phones[i] and member_emails[i]:
                    c.execute("INSERT INTO team_members (team_id, username, name, phone_number, email) VALUES (?, ?, ?, ?, ?)",
                              (team_id, member_names[i], member_names[i], member_phones[i], member_emails[i]))
            conn.commit()
            flash("Team created successfully.", "success")
        except sqlite3.IntegrityError:
            flash("Team name already exists.", "error")
        except sqlite3.Error as e:
            flash(f"Error creating team: {str(e)}", "error")
        conn.close()
        return redirect(url_for('team_management'))

    return render_template("team_management.html", user=user, hackathons=hackathons, team=team, team_members=team_members)

# Route to search for teams
@app.route("/search_team", methods=['GET', 'POST'])
@login_required
def search_team():
    conn = sqlite3.connect("teams.db")
    c = conn.cursor()
    c.execute("SELECT team_id FROM team_members WHERE username = ?", (session['user'],))
    user_team = c.fetchone()
    conn.close()

    if user_team:
        flash("You are already part of a team.", "error")
        return redirect(url_for('team_management'))

    search_query = ''
    teams = []
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        if search_query:
            conn = sqlite3.connect("teams.db")
            c = conn.cursor()
            c.execute("SELECT id, team_name, hackathon_event, leader_username FROM teams WHERE LOWER(team_name) LIKE ?",
                      ('%' + search_query.lower() + '%',))
            teams = c.fetchall()
            conn.close()

    return render_template("search_team.html", search_query=search_query, teams=teams)

# Route to join a team
@app.route("/join_team/<team_id>", methods=['GET'])
@login_required
def join_team(team_id):
    conn = sqlite3.connect("teams.db")
    c = conn.cursor()
    c.execute("SELECT team_id FROM team_members WHERE username = ?", (session['user'],))
    user_team = c.fetchone()

    if user_team:
        flash("You are already part of a team.", "error")
        return redirect(url_for('team_management'))

    c.execute("SELECT * FROM teams WHERE id = ?", (team_id,))
    team = c.fetchone()

    if not team:
        flash("Team not found.", "error")
        return redirect(url_for('home'))

    conn_users = sqlite3.connect("users.db")
    c_users = conn_users.cursor()
    c_users.execute("SELECT email FROM users WHERE username = ?", (session['user'],))
    user_data = c_users.fetchone()
    conn_users.close()

    if not user_data:
        flash("User not found.", "error")
        return redirect(url_for('home'))

    try:
        c.execute("INSERT INTO team_members (team_id, username, name, phone_number, email) VALUES (?, ?, ?, ?, ?)",
                  (team_id, session['user'], session['user'], "N/A", user_data[0]))
        conn.commit()
        flash("Successfully joined the team.", "success")
    except sqlite3.Error as e:
        flash(f"Error joining team: {str(e)}", "error")
    conn.close()

    return redirect(url_for('team_management'))

# Signup route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_username = c.fetchone()
        if existing_username:
            flash("Username already exists. Please choose a different username.", "error")
            conn.close()
            return redirect(url_for("signup"))
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_email = c.fetchone()
        if existing_email:
            flash("Email already exists. Try logging in.", "error")
            conn.close()
            return redirect(url_for("signup"))
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
            conn.commit()
            flash("Signup successful! Please login.", "success")
        except sqlite3.Error as e:
            flash(f"Error during signup: {str(e)}", "error")
        conn.close()
        return redirect(url_for("login"))
    return render_template("signup.html")

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user[3], password):
            session['user'] = username
            flash("Login successful.", "success")
            return redirect(url_for('home'))
        else:
            flash("Incorrect username or password.", "error")
            return redirect(url_for('login'))
    return render_template("login.html")

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    response = redirect(url_for('main'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Force no-cache headers globally
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == "__main__":
    app.run(debug=True)