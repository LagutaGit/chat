import os
from datetime import timedelta

class Config:
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    SECRET_KEY = 'supersecretkey'
    DB_PATH = os.path.join(BASEDIR, 'messenger.db')
    UPLOAD_FOLDER = os.path.join(BASEDIR, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max file size
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4', 'doc', 'docx'}
    OFFLINE_THRESHOLD = timedelta(minutes=2)
    ADMIN_USERNAME = 'Admin'
    FORBIDDEN_USERNAMES = {'owner', 'moderator', 'sysadmin', 'adm', 'admi', 'admn'}

# Create upload folder if it doesn't exist
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)