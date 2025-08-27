from flask import Flask, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_cors import CORS
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from bcrypt import hashpw, checkpw, gensalt
import os

# Flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 1 day in seconds
app.config['SESSION_COOKIE_SAMESITE'] = 'None'  # Required for cross-origin cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Requires HTTPS in production

# CORS setup
CORS(app, supports_credentials=True, origins=['http://localhost:3000', 'https://frontend.com'])

# SQLAlchemy setup
engine = create_engine('sqlite:///users.db', echo=False)
Base = declarative_base()
Session = sessionmaker(bind=engine)

# User model
class User(UserMixin, Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password = Column(String(120), nullable=False)

# Create database tables
Base.metadata.create_all(engine)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# CSRF protection
csrf = CSRFProtect(app)

# Create uploads folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# User loader
@login_manager.user_loader
def load_user(user_id):
    session = Session()
    try:
        user = session.query(User).get(int(user_id))
        return user
    finally:
        session.close()

# CSRF token endpoint
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf()})

# Login API
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    session = Session()
    try:
        user = session.query(User).filter_by(username=username).first()
        if user and checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            login_user(user, remember=True)
            session.close()
            return jsonify({'message': 'Logged in successfully', 'username': user.username}), 200
        session.close()
        return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        session.close()
        return jsonify({'message': f'Error: {str(e)}'}), 500

# Logout API
@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

# Image upload API
@app.route('/api/upload', methods=['POST'])
@login_required
def upload_image():
    from flask_login import current_user
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    
    if file and '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']:
        filename = f"{current_user.username}_{file.filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'File uploaded successfully', 'filename': filename}), 200
    return jsonify({'message': 'Invalid file type'}), 400

# Protected API (for testing)
@app.route('/api/protected')
@login_required
def protected():
    return jsonify({'message': 'This is a protected route'})

# Initialize database with a test user
if __name__ == '__main__':
    session = Session()
    try:
        if not session.query(User).filter_by(username='testuser').first():
            hashed_password = hashpw('testpassword'.encode('utf-8'), gensalt()).decode('utf-8')
            user = User(username='testuser', password=hashed_password)
            session.add(user)
            session.commit()
    finally:
        session.close()
    
    app.run(debug=True, port=5000)
