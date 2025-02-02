from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask import g

db = SQLAlchemy()

# Favorileme için ara tablo
favorites = db.Table('favorites',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('image_id', db.Integer, db.ForeignKey('image.id'), primary_key=True),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_premium = db.Column(db.Boolean, default=False)
    subscription_type = db.Column(db.String(20))
    daily_tokens = db.Column(db.Integer, default=5)
    daily_audio_seconds = db.Column(db.Integer, default=0)
    daily_text_tokens = db.Column(db.Integer, default=1000)
    last_token_reset = db.Column(db.DateTime, default=datetime.utcnow)
    
    # İlişkiler
    images = db.relationship('Image', backref='user', lazy=True)
    audios = db.relationship('Audio', backref='user', lazy=True)
    texts = db.relationship('Text', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_token(self, secret_key):
        return jwt.encode(
            {'user_id': self.id, 'exp': datetime.utcnow() + timedelta(days=1)},
            secret_key,
            algorithm='HS256'
        )
    
    @staticmethod
    def verify_token(token, secret_key):
        try:
            data = jwt.decode(token, secret_key, algorithms=['HS256'])
            return User.query.get(data['user_id'])
        except:
            return None

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prompt = db.Column(db.String(500), nullable=False)
    path = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.Column(db.Integer, default=0)
    
    # Favorileyen kullanıcılar
    favorited_by = db.relationship('User', secondary=favorites,
        backref=db.backref('favorite_images', lazy='dynamic'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'prompt': self.prompt,
            'path': self.path,
            'created_at': self.created_at.strftime('%d.%m.%Y %H:%M'),
            'likes': self.likes,
            'is_favorite': self.is_favorite(g.user) if hasattr(g, 'user') else False
        }
    
    def is_favorite(self, user):
        return user in self.favorited_by

class Audio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    path = db.Column(db.String(200), nullable=False)
    duration = db.Column(db.Float)
    voice_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Text(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topic = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    template = db.Column(db.String(50))
    length = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 