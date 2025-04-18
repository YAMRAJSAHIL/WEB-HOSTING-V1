from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from datetime import datetime
import os
import json
import subprocess
import uuid
from werkzeug.utils import secure_filename
from functools import wraps
import requests # Added for telegram notification

app = Flask(__name__)
app.secret_key = 'YAMRAJ'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
if not os.path.exists('users.json'):
    with open('users.json', 'w') as f:
        json.dump({}, f)
if not os.path.exists('processes.json'):
    with open('processes.json', 'w') as f:
        json.dump({}, f)
if not os.path.exists('announcements.json'):
    with open('announcements.json', 'w') as f:
        json.dump([], f)

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin', False):
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with open('users.json', 'r') as f:
            users = json.load(f)

        if username in users:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        # First user is admin
        is_first_user = len(users) == 0

        users[username] = {
            'password': password,  # In production, use proper password hashing
            'is_admin': is_first_user
        }

        with open('users.json', 'w') as f:
            json.dump(users, f)

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with open('users.json', 'r') as f:
            users = json.load(f)

        if username not in users or users[username]['password'] != password:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

        session['username'] = username
        session['is_admin'] = users[username].get('is_admin', False)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
    files = []

    if os.path.exists(user_dir):
        files = [f for f in os.listdir(user_dir) if f.endswith('.py')]

    # Get process status
    with open('processes.json', 'r') as f:
        processes = json.load(f)

    user_processes = {k: v for k, v in processes.items() if v['username'] == username}

    # Track running files
    running_files = {}
    for pid, process in user_processes.items():
        if process['status'] == 'running':
            running_files[process['filename']] = pid

    # Get last 10 announcements
    with open('announcements.json', 'r') as f:
        announcements = json.load(f)[:10]

    return render_template('dashboard.html', 
                         username=username,
                         files=files,
                         processes=user_processes,
                         announcements=announcements,
                         is_admin=session.get('is_admin', False))

def send_telegram_notification(message):
    bot_token = "7542341973:AAE5MWBPQotu0qN3zJkEEuxvoxs4WhVbaQA"
    owner_chat_id = "YAMRAJSAHIL2"  # Replace with actual owner's chat ID
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = {
            "chat_id": owner_chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        requests.post(url, json=data)
    except Exception as e:
        print(f"Error sending Telegram notification: {e}")

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    if not file.filename.endswith('.py'):
        flash('Only Python (.py) files are allowed', 'danger')
        return redirect(url_for('dashboard'))

    if file:
        username = session['username']
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
        os.makedirs(user_dir, exist_ok=True)

        filename = secure_filename(file.filename)
        filepath = os.path.join(user_dir, filename)
        file.save(filepath)

        flash('File uploaded successfully', 'success')
    else:
        flash('Only Python files (.py) are allowed', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/delete/<filename>')
def delete_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
    filepath = os.path.join(user_dir, filename)

    if not os.path.exists(filepath):
        flash('File not found', 'danger')
        return redirect(url_for('dashboard'))

    # Stop any running processes for this file
    with open('processes.json', 'r') as f:
        processes = json.load(f)

    # Find and stop processes running this file
    processes_to_remove = []
    for pid, process in processes.items():
        if process['username'] == username and process['filename'] == filename:
            try:
                subprocess.run(['pkill', '-f', process['filepath']], check=False)
                processes_to_remove.append(pid)
            except:
                pass

    # Remove processes from json
    for pid in processes_to_remove:
        processes.pop(pid, None)

    with open('processes.json', 'w') as f:
        json.dump(processes, f)

    # Delete the file
    try:
        os.remove(filepath)
        flash('File deleted successfully', 'success')
    except:
        flash('Error deleting file', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/start/<filename>')
def start_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
    filepath = os.path.join(user_dir, filename)

    # Load processes
    with open('processes.json', 'r') as f:
        processes = json.load(f)

    # Check if script is already running
    for process in processes.values():
        if process['filename'] == filename and process['username'] == username:
            if process['status'] == 'running':
                flash('Script is already running!', 'warning')
                return redirect(url_for('dashboard'))
            # Reuse existing process ID instead of creating new one
            process_id = next(pid for pid, p in processes.items() if p['filename'] == filename and p['username'] == username)
            break
    else:
        process_id = str(uuid.uuid4())

    if not os.path.exists(filepath):
        flash('File not found', 'danger')
        return redirect(url_for('dashboard'))

    # Check if there's an existing process for this file
    existing_process = None
    for pid, proc in processes.items():
        if proc['filename'] == filename and proc['username'] == username:
            existing_process = pid
            break
    
    # Use existing process ID or generate new one
    process_id = existing_process if existing_process else str(uuid.uuid4())

    # Create log file
    log_file = os.path.join(user_dir, f"{filename}.log")
    with open(log_file, 'a') as f:
        f.write(f"=== Starting process for {filename} ===\n")

    # Start the process
    try:
        # Try different Python versions
        python_versions = ['python3', 'python3.11', 'python3.10', 'python3.9', 'python3.8', 'python']
        process = None

        for py_version in python_versions:
            try:
                process = subprocess.Popen(
                    [py_version, filepath],
                    stdout=open(log_file, 'a'),
                    stderr=subprocess.STDOUT,
                    text=True
                )
                break
            except FileNotFoundError:
                continue

        if not process:
            raise Exception("No compatible Python version found")

        # Save process info
        with open('processes.json', 'r') as f:
            processes = json.load(f)

        processes[process_id] = {
            'pid': process.pid,
            'username': username,
            'filename': filename,
            'filepath': filepath,
            'log_file': log_file,
            'status': 'running'
        }

        with open('processes.json', 'w') as f:
            json.dump(processes, f)

        flash('Process started successfully', 'success')
    except Exception as e:
        flash(f'Error starting process: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/stop/<process_id>')
def stop_file(process_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with open('processes.json', 'r') as f:
        processes = json.load(f)

    if process_id not in processes or processes[process_id]['username'] != session['username']:
        flash('Process not found or access denied', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Stop the process more forcefully
        try:
            subprocess.run(['pkill', '-f', processes[process_id]['filepath']], check=False)
        except:
            pass
        
        # Update status
        processes[process_id]['status'] = 'stopped'

        # Log the stop
        with open(processes[process_id]['log_file'], 'a') as f:
            f.write(f"\n=== Process stopped by user ===\n")

        with open('processes.json', 'w') as f:
            json.dump(processes, f)

        flash('Process stopped successfully', 'success')
    except Exception as e:
        flash(f'Error stopping process: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/restart/<process_id>')
def restart_file(process_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with open('processes.json', 'r') as f:
        processes = json.load(f)

    if process_id not in processes or processes[process_id]['username'] != session['username']:
        flash('Process not found or access denied', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Stop the existing process if running
        if processes[process_id]['status'] == 'running':
            try:
                subprocess.run(['pkill', '-f', processes[process_id]['filepath']], check=False)
            except:
                pass

        # Log the restart
        with open(processes[process_id]['log_file'], 'a') as f:
            f.write(f"\n=== Restarting process ===\n")

        # Start a new process
        # Try different Python versions
        python_versions = ['python3', 'python3.11', 'python3.10', 'python3.9', 'python3.8', 'python']
        process = None
        
        for py_version in python_versions:
            try:
                process = subprocess.Popen(
                    [py_version, processes[process_id]['filepath']],
                    stdout=open(processes[process_id]['log_file'], 'a'),
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=os.path.dirname(processes[process_id]['filepath'])
                )
                break
            except FileNotFoundError:
                continue
                
        if not process:
            raise Exception("No compatible Python version found")

        # Update process info
        processes[process_id]['pid'] = process.pid
        processes[process_id]['status'] = 'running'

        with open('processes.json', 'w') as f:
            json.dump(processes, f)

        flash('Process restarted successfully', 'success')
    except Exception as e:
        flash(f'Error restarting process: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/logs/<process_id>')
def view_logs(process_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    with open('processes.json', 'r') as f:
        processes = json.load(f)

    if process_id not in processes or processes[process_id]['username'] != session['username']:
        flash('Process not found or access denied', 'danger')
        return redirect(url_for('dashboard'))

    try:
        with open(processes[process_id]['log_file'], 'r') as f:
            logs = f.read()
    except FileNotFoundError:
        logs = "No log file found"

    return render_template('logs.html', 
                         logs=logs,
                         filename=processes[process_id]['filename'],
                         status=processes[process_id]['status'])

ADMIN_USERNAME = "YAMRAJSAHIL2"
ADMIN_PASSWORD = "SAHIL@123"

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['is_admin'] = True
            session['username'] = username
            return redirect(url_for('admin_panel'))
        flash('Invalid credentials', 'danger')
        return redirect(url_for('admin'))
    return render_template('admin_login.html')

from flask import send_from_directory

@app.route('/download_file/<username>/<filename>')
@admin_required
def download_file(username, filename):
    try:
        directory = os.path.join(app.config['UPLOAD_FOLDER'], username)
        return send_from_directory(
            directory,
            filename,
            as_attachment=True
        )
    except FileNotFoundError:
        flash('File not found', 'danger')
        return redirect(url_for('admin_panel'))
    except Exception as e:
        flash(f'Error downloading file: {str(e)}', 'danger')
        return redirect(url_for('admin_panel'))


@app.route('/admin/panel')
def admin_panel():
    if not session.get('is_admin'):
        return redirect(url_for('admin'))

    with open('announcements.json', 'r') as f:
        announcements = json.load(f)

    with open('users.json', 'r') as f:
        users = json.load(f)

    with open('processes.json', 'r') as f:
        processes = json.load(f)

    # Get user files
    user_files = {}
    for username in users:
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], username)
        if os.path.exists(user_dir):
            files = [{'name': f} for f in os.listdir(user_dir) if f.endswith('.py')]
            user_files[username] = files

    # Count total files
    total_files = sum(len(files) for files in user_files.values())

    return render_template('admin.html',
                         announcements=announcements,
                         users=users,
                         processes=processes,
                         user_files=user_files,
                         total_files=total_files)

@app.route('/admin/delete_announcement/<int:index>', methods=['POST'])
@admin_required
def delete_announcement(index):
    with open('announcements.json', 'r') as f:
        announcements = json.load(f)
    
    if 0 <= index < len(announcements):
        announcements.pop(index)
        with open('announcements.json', 'w') as f:
            json.dump(announcements, f)
        flash('Announcement deleted', 'success')
    
    return redirect(url_for('admin_panel'))

@app.route('/admin/announce', methods=['POST'])
@admin_required
def make_announcement():
    message = request.form.get('message')
    if not message:
        flash('Message cannot be empty', 'danger')
        return redirect(url_for('admin_panel')) # Redirect to admin panel

    with open('announcements.json', 'r') as f:
        announcements = json.load(f)

    from datetime import datetime
    import pytz
    
    def get_formatted_time():
        tz = pytz.timezone('Asia/Kolkata')
        now = datetime.now(tz)
        return {
            'time': now.strftime('%I:%M:%S %p').lstrip('0'),
            'date': now.strftime('%d-%m-%Y')
        }
    
    timestamp = get_formatted_time()
    announcements.insert(0, {
        'message': message,
        'author': session['username'],
        'timestamp': timestamp['time'],
        'date': timestamp['date']
    })

    # Keep only the last 10 announcements
    if len(announcements) > 10:
        announcements = announcements[:10]

    with open('announcements.json', 'w') as f:
        json.dump(announcements, f)

    flash('Announcement posted', 'success')
    return redirect(url_for('admin_panel')) # Redirect to admin panel

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)