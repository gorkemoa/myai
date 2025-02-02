import os
import time
import requests
import json
import traceback
import logging
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from models import db, User, Image, Audio, Text, favorites
import uuid
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_dance.consumer import oauth_authorized
from sqlalchemy.orm.exc import NoResultFound
import base64
import random
from flask_caching import Cache

# .env dosyasını yükle
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myai.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Önbellekleme ayarları
app.config['CACHE_TYPE'] = 'filesystem'
app.config['CACHE_DIR'] = 'cache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300
cache = Cache(app)

# Statik dosyalar için önbellekleme
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 yıl

# OAuth yapılandırması
app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')
app.config['FACEBOOK_OAUTH_CLIENT_ID'] = os.environ.get('FACEBOOK_OAUTH_CLIENT_ID')
app.config['FACEBOOK_OAUTH_CLIENT_SECRET'] = os.environ.get('FACEBOOK_OAUTH_CLIENT_SECRET')

# Oturum ayarları
app.config['SESSION_COOKIE_SECURE'] = False  # Geliştirme ortamında False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_TYPE'] = 'filesystem'

db.init_app(app)

# Google OAuth blueprint
google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    scope=['profile', 'email'],
    redirect_to='index',
    offline=True,
    reprompt_consent=True
)

# Facebook OAuth blueprint
facebook_bp = make_facebook_blueprint(
    client_id=app.config['FACEBOOK_OAUTH_CLIENT_ID'],
    client_secret=app.config['FACEBOOK_OAUTH_CLIENT_SECRET'],
    scope=['email'],
    redirect_to='index'
)

app.register_blueprint(google_bp, url_prefix='/login')
app.register_blueprint(facebook_bp, url_prefix='/login')

# SSL ayarları için
if not app.debug:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '0'
    os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
    app.config['PREFERRED_URL_SCHEME'] = 'https'

# Ses dosyaları için önbellekleme
@app.after_request
def add_header(response):
    if 'audio' in response.mimetype:
        response.cache_control.max_age = 31536000  # 1 yıl
        response.cache_control.public = True
        response.headers['Accept-Ranges'] = 'bytes'
    return response

@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        return False

    resp = google.get('/oauth2/v2/userinfo')
    if not resp.ok:
        return False

    google_info = resp.json()
    google_user_id = str(google_info['id'])

    # Kullanıcıyı veritabanında ara veya oluştur
    try:
        user = User.query.filter_by(email=google_info['email']).first()
        if not user:
            user = User(
                username=google_info['name'],
                email=google_info['email']
            )
            db.session.add(user)
            db.session.commit()
        
        session['user_id'] = user.id
        return False  # Flask-Dance'in oturumu yönetmesini engelle
    
    except Exception as e:
        print(f"Google login hatası: {str(e)}")
        return False

@oauth_authorized.connect_via(facebook_bp)
def facebook_logged_in(blueprint, token):
    if not token:
        return False

    resp = facebook.get('/me?fields=id,name,email')
    if not resp.ok:
        return False

    facebook_info = resp.json()
    facebook_user_id = str(facebook_info['id'])

    # Kullanıcıyı veritabanında ara veya oluştur
    try:
        user = User.query.filter_by(email=facebook_info.get('email')).first()
        if not user:
            user = User(
                username=facebook_info['name'],
                email=facebook_info.get('email', f"{facebook_user_id}@facebook.com")
            )
            db.session.add(user)
            db.session.commit()
        
        session['user_id'] = user.id
        return False  # Flask-Dance'in oturumu yönetmesini engelle
    
    except Exception as e:
        print(f"Facebook login hatası: {str(e)}")
        return False

# Veritabanını oluştur
with app.app_context():
    # Gerekli klasörleri oluştur
    os.makedirs('static/uploads', exist_ok=True)
    os.makedirs('static/audios', exist_ok=True)
    
    db.create_all()

# HTTP istemcisi ayarları
http_session = requests.Session()
http_session.headers.update({
    'Content-Type': 'application/json; charset=utf-8',
    'Accept': 'application/json; charset=utf-8'
})

# API ayarları
API_TOKEN = os.environ.get('HF_API_TOKEN')
TRANSLATE_API_URL = "https://api-inference.huggingface.co/models/Helsinki-NLP/opus-mt-tr-en"
PROMPTER_API_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2"
IMAGE_API_URL = "https://api-inference.huggingface.co/models/stabilityai/stable-diffusion-xl-base-1.0"
AUDIO_API_URL = "https://api-inference.huggingface.co/models/facebook/mms-tts-tur"
TEXT_API_URL = "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2"

# Oturum ayarları
app.config['SESSION_COOKIE_SECURE'] = False  # Geliştirme ortamında False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_TYPE'] = 'filesystem'

# Rate limit ayarları
RATE_LIMIT_MINUTES = 1
usage_data = {
    'requests': 0,
    'last_request_time': None
}

def check_rate_limit(ip_address):
    now = datetime.now()
    user_data = usage_data[ip_address]
    
    # İlk kullanım ise
    if not user_data['reset_time']:
        user_data['reset_time'] = now + timedelta(days=1)
        user_data['count'] = 0
        user_data['last_request'] = None
    
    # Günlük limit sıfırlama kontrolü
    if now >= user_data['reset_time']:
        user_data['count'] = 0
        user_data['reset_time'] = now + timedelta(days=1)
    
    # Son istek kontrolü
    if user_data['last_request'] and (now - user_data['last_request']) < timedelta(minutes=RATE_LIMIT_MINUTES):
        remaining_time = (user_data['last_request'] + timedelta(minutes=RATE_LIMIT_MINUTES) - now).seconds
        return False, f"Lütfen {remaining_time} saniye bekleyin"
    
    # Günlük limit kontrolü
    if user_data['count'] >= DAILY_LIMIT:
        reset_time = user_data['reset_time'].strftime('%H:%M')
        return False, f"Günlük limitinize ulaştınız. Limit {reset_time}'de sıfırlanacak"
    
    return True, None

def update_usage(ip_address):
    now = datetime.now()
    usage_data[ip_address]['count'] += 1
    usage_data[ip_address]['last_request'] = now

def get_remaining_requests(ip_address):
    if ip_address not in usage_data:
        return DAILY_LIMIT
    return max(0, DAILY_LIMIT - usage_data[ip_address]['count'])

def convert_to_ascii(text):
    """Türkçe karakterleri ASCII karşılıklarına dönüştürür"""
    tr_map = str.maketrans('ıİğĞüÜşŞöÖçÇ', 'iIgGuUsSoOcC')
    return text.translate(tr_map)

def translate_text(text):
    try:
        # Türkçe karakterleri UTF-8 ile kodla
        encoded_text = text.encode('utf-8').decode('utf-8')
        
        payload = {
            "inputs": encoded_text,
            "parameters": {"src_lang": "tr", "tgt_lang": "en"}
        }
        
        headers = {
            'Authorization': f'Bearer {API_TOKEN}',
            'Content-Type': 'application/json; charset=utf-8',
            'Accept': 'application/json; charset=utf-8'
        }
        
        logging.debug(f"Çeviri API isteği - Payload: {payload}")
        
        response = http_session.post(
            TRANSLATE_API_URL, 
            headers=headers,
            data=json.dumps(payload).encode('utf-8'),
            timeout=30
        )
        
        if response.status_code == 200:
            try:
                result = response.json()
                logging.debug(f"Çeviri API yanıtı - JSON: {result}")
                return result[0]['translation_text']
            except Exception as e:
                logging.error(f"JSON ayrıştırma hatası: {str(e)}")
                return text
        else:
            logging.error(f"Çeviri API'si hata döndürdü: {response.status_code} - {response.text}")
            return text
            
    except Exception as e:
        logging.error(f"Çeviri hatası: {str(e)}\nHata detayı: {traceback.format_exc()}")
        return text

def enhance_prompt(prompt):
    try:
        # Türkçe metni İngilizce'ye çevir
        english_text = translate_text(prompt)
        logging.debug(f"Çevrilmiş metin: {english_text}")
        
        # Kalite terimlerini ekle
        enhanced_prompt = f"{english_text}, 8k ultra hd, highly detailed, professional photography, dramatic lighting, cinematic, masterpiece, sharp focus"
        
        return {
            'turkish': prompt,
            'english': enhanced_prompt
        }
            
    except Exception as e:
        logging.error(f"Prompt geliştirme hatası: {str(e)}\nHata detayı: {traceback.format_exc()}")
        return {
            'turkish': prompt,
            'english': prompt
        }

def generate_image(prompt):
    print(f"\n=== DEBUG: Görsel Oluşturma ===")
    print(f"Prompt: '{prompt}'")
    
    try:
        headers = {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "inputs": prompt,
            "parameters": {
                "negative_prompt": "ugly, text, watermark, logo, signature, bad quality, deformed, low quality, blurry",
                "num_inference_steps": 50,
                "guidance_scale": 8.5,
                "width": 1024,
                "height": 1024,
                "seed": random.randint(1, 999999999)
            }
        }

        print(f"API isteği gönderiliyor: {prompt}")
        response = requests.post(IMAGE_API_URL, headers=headers, json=payload)
        print(f"API yanıtı status: {response.status_code}")
        
        if response.status_code == 200:
            return response.content
        elif response.status_code == 503:
            print("Model yükleniyor... Tekrar deneniyor...")
            time.sleep(5)  # 5 saniye bekle
            return generate_image(prompt)  # Tekrar dene
        else:
            print(f"API Hatası: {response.text}")
            return None
            
    except Exception as e:
        print(f"Görsel oluşturma hatası: {str(e)}")
        print(f"Hata detayı:", traceback.format_exc())
        return None

def get_gallery_images():
    """Oluşturulan görselleri alır ve sıralar"""
    try:
        images = []
        static_dir = os.path.join(os.getcwd(), 'static')
        for file in os.listdir(static_dir):
            if file.startswith('output_') and file.endswith('.png'):
                file_path = os.path.join(static_dir, file)
                creation_time = os.path.getmtime(file_path)
                images.append({
                    'path': f'/static/{file}',
                    'created_at': datetime.fromtimestamp(creation_time).strftime('%d.%m.%Y %H:%M'),
                    'prompt': 'AI tarafından oluşturuldu'  # İleride veritabanından alınabilir
                })
        
        # En yeni görseller önce gelecek şekilde sırala
        images.sort(key=lambda x: x['created_at'], reverse=True)
        return images
    except Exception as e:
        print(f"Galeri görsellerini alma hatası: {str(e)}")
        return []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Lütfen önce giriş yapın', 'error')
            return redirect(url_for('giris'))
        return f(*args, **kwargs)
    return decorated_function

def check_token_limit():
    user = db.session.get(User, session['user_id'])
    if not user:
        return False
        
    # Premium kullanıcılar için sınırsız token
    if user.is_premium:
        return True
        
    # Token sıfırlama kontrolü (her gün)
    now = datetime.utcnow()
    if (now - user.last_token_reset).days >= 1:
        user.daily_tokens = 5 if not user.is_premium else 50
        user.last_token_reset = now
        db.session.commit()
    
    return user.daily_tokens > 0

def get_user(user_id):
    return db.session.get(User, user_id)

# Logging konfigürasyonu
def setup_logging():
    log_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] - %(message)s\n'
        'Dosya: %(pathname)s\n'
        'Fonksiyon: %(funcName)s\n'
        'Satır: %(lineno)d\n'
        'Detay: %(message)s\n'
        '------------------------'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    
    # Dosya handler
    file_handler = logging.FileHandler('debug.log', encoding='utf-8')
    file_handler.setFormatter(log_formatter)
    
    # Root logger ayarları
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    return root_logger

logger = setup_logging()

def log_request_details(request, user=None):
    """HTTP isteği detaylarını loglar"""
    logger.debug(
        f"\n=== İSTEK DETAYLARI ===\n"
        f"Zaman: {datetime.now()}\n"
        f"Endpoint: {request.endpoint}\n"
        f"Metod: {request.method}\n"
        f"URL: {request.url}\n"
        f"Headers: {dict(request.headers)}\n"
        f"Form Data: {request.form.to_dict() if request.form else None}\n"
        f"JSON Data: {request.get_json(silent=True)}\n"
        f"Kullanıcı: {user.username if user else 'Anonim'}\n"
        f"IP: {request.remote_addr}\n"
        f"User Agent: {request.user_agent}\n"
    )

def log_api_request(url, payload, headers):
    """API isteklerini loglar"""
    logger.debug(
        f"\n=== API İSTEĞİ ===\n"
        f"URL: {url}\n"
        f"Headers: {headers}\n"
        f"Payload: {json.dumps(payload, indent=2, ensure_ascii=False)}\n"
    )

def log_api_response(response):
    """API yanıtlarını loglar"""
    logger.debug(
        f"\n=== API YANITI ===\n"
        f"Status: {response.status_code}\n"
        f"Headers: {dict(response.headers)}\n"
        f"Content: {response.text[:1000]}{'...' if len(response.text) > 1000 else ''}\n"
    )

def log_error(e, context=""):
    """Hata detaylarını loglar"""
    logger.error(
        f"\n=== HATA DETAYI ===\n"
        f"Zaman: {datetime.now()}\n"
        f"Bağlam: {context}\n"
        f"Hata Tipi: {type(e).__name__}\n"
        f"Hata Mesajı: {str(e)}\n"
        f"Traceback:\n{traceback.format_exc()}\n"
    )

@app.before_request
def before_request():
    try:
        # Giriş sayfası ve statik dosyalar için kontrol yapma
        if request.endpoint in ['giris', 'kayit', 'static']:
            return
            
        user_id = session.get('user_id')
        if user_id:
            user = get_user(user_id)
            if user:
                g.user = user
                log_request_details(request, user)
            else:
                logger.warning("Geçersiz oturum tespit edildi")
                session.clear()
                flash('Oturumunuz sonlandırıldı. Lütfen tekrar giriş yapın.', 'warning')
                return redirect(url_for('giris'))
        else:
            log_request_details(request)
            return redirect(url_for('giris'))
    except Exception as e:
        logger.error(f"Before request hatası: {str(e)}\nTraceback: {traceback.format_exc()}")
        session.clear()
        return redirect(url_for('giris'))

@app.route('/')
@login_required
def index():
    try:
        user = get_user(session.get('user_id'))
        if not user:
            logger.warning("Oturum var ama kullanıcı bulunamadı")
            session.clear()
            flash('Oturum süresi doldu. Lütfen tekrar giriş yapın.', 'error')
            return redirect(url_for('giris'))
            
        logger.info(f"Anasayfaya erişim: {user.email}")
        return render_template('index.html', user=user)
        
    except Exception as e:
        logger.error(f"Anasayfa hatası: {str(e)}\nTraceback: {traceback.format_exc()}")
        session.clear()
        flash('Bir hata oluştu. Lütfen tekrar giriş yapın.', 'error')
        return redirect(url_for('giris'))

@app.route('/giris', methods=['GET', 'POST'])
def giris():
    logger.debug("Giriş sayfası erişildi")
    
    # Eğer kullanıcı zaten giriş yapmışsa anasayfaya yönlendir
    if 'user_id' in session:
        user = get_user(session['user_id'])
        if user:
            logger.debug(f"Aktif oturum bulundu: {session['user_id']}")
            return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        logger.debug(f"Giriş denemesi - Email: {email}")
        
        try:
            if not email or not password:
                logger.warning("Eksik form alanları")
                flash('Lütfen tüm alanları doldurun', 'error')
                return render_template('giris.html', error='Lütfen tüm alanları doldurun')
            
            user = User.query.filter_by(email=email).first()
            
            if user and check_password_hash(user.password_hash, password):
                # Önceki oturum verilerini temizle
                session.clear()
                
                # Yeni oturum oluştur
                session['user_id'] = user.id
                session.permanent = True
                
                if remember:
                    # 30 günlük oturum
                    app.permanent_session_lifetime = timedelta(days=30)
                else:
                    # 1 günlük oturum
                    app.permanent_session_lifetime = timedelta(days=1)
                
                logger.info(f"Başarılı giriş: {user.email}")
                
                # Güvenli bir şekilde son giriş zamanını güncelle
                try:
                    user.last_login = datetime.utcnow()
                    db.session.commit()
                except Exception as e:
                    logger.error(f"Son giriş zamanı güncellenirken hata: {str(e)}")
                    db.session.rollback()
                
                # Doğrudan anasayfaya yönlendir
                return redirect(url_for('index'))
            else:
                logger.warning(f"Başarısız giriş denemesi: {email}")
                flash('Geçersiz email veya şifre', 'error')
                return render_template('giris.html', error='Geçersiz email veya şifre')
                
        except Exception as e:
            logger.error(f"Giriş hatası: {str(e)}\nTraceback: {traceback.format_exc()}")
            flash('Giriş sırasında bir hata oluştu', 'error')
            return render_template('giris.html', error='Giriş sırasında bir hata oluştu')
    
    return render_template('giris.html')

@app.route('/kayit', methods=['GET', 'POST'])
def kayit():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            password_confirm = request.form.get('password_confirm')
            terms = request.form.get('terms') == 'on'
            
            # Form validasyonu
            if not all([username, email, password, password_confirm]):
                flash('Lütfen tüm alanları doldurun', 'error')
                return render_template('kayit.html', error='Lütfen tüm alanları doldurun')
            
            if not terms:
                flash('Kullanım şartlarını kabul etmelisiniz', 'error')
                return render_template('kayit.html', error='Kullanım şartlarını kabul etmelisiniz')
            
            if password != password_confirm:
                flash('Şifreler eşleşmiyor', 'error')
                return render_template('kayit.html', error='Şifreler eşleşmiyor')
            
            if len(password) < 6:
                flash('Şifre en az 6 karakter olmalıdır', 'error')
                return render_template('kayit.html', error='Şifre en az 6 karakter olmalıdır')
            
            # Email kontrolü
            if User.query.filter_by(email=email).first():
                flash('Bu email adresi zaten kullanımda', 'error')
                return render_template('kayit.html', error='Bu email adresi zaten kullanımda')
            
            # Yeni kullanıcı oluştur
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                created_at=datetime.utcnow(),
                last_token_reset=datetime.utcnow(),
                daily_tokens=5,
                is_premium=False
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            print(f"Yeni kullanıcı kaydedildi: {email}")
            flash('Kayıt başarılı! Şimdi giriş yapabilirsiniz.', 'success')
            return redirect(url_for('giris'))
            
        except Exception as e:
            print(f"Kayıt hatası: {str(e)}")
            db.session.rollback()
            flash('Kayıt sırasında bir hata oluştu', 'error')
            return render_template('kayit.html', error='Kayıt sırasında bir hata oluştu')
    
    return render_template('kayit.html')

@app.route('/cikis')
def cikis():
    session.pop('user_id', None)
    return redirect(url_for('giris'))

@app.route('/enhance-prompt', methods=['POST'])
def enhance_prompt_route():
    data = request.get_json()
    turkish_prompt = data.get('prompt', '')
    result = enhance_prompt(turkish_prompt)
    return jsonify(result)

@app.route('/generate', methods=['POST'])
@login_required
def generate():
    logger.info("\n=== GÖRSEL OLUŞTURMA BAŞLADI ===")
    
    if not check_token_limit():
        logger.warning("Token limiti aşıldı")
        return jsonify({
            'success': False,
            'error': 'Günlük token limitinize ulaştınız'
        })
    
    user = db.session.get(User, session['user_id'])
    prompt = request.form.get('prompt')
    
    try:
        logger.debug(f"Kullanıcı: {user.username}")
        logger.debug(f"Orijinal Prompt: {prompt}")
        
        # Prompt'u geliştir ve çevir
        enhanced_prompts = enhance_prompt(prompt)
        logger.debug(f"Geliştirilmiş promptlar: {enhanced_prompts}")
        
        # API isteği detayları
        headers = {
            'Authorization': f'Bearer {API_TOKEN}',
            'Content-Type': 'application/json; charset=utf-8',
            'Accept': 'application/json; charset=utf-8'
        }
        
        payload = {
            "inputs": enhanced_prompts['english'],
            "parameters": {
                "negative_prompt": "ugly, blurry, bad quality, error, deformed, low quality, bad anatomy, worst quality, low resolution, text, watermark, signature, deformed hands, deformed face, out of frame, extra limbs, disfigured, gross proportions, malformed limbs, missing arms, missing legs, extra arms, extra legs, mutated hands, fused fingers, too many fingers, long neck",
                "num_inference_steps": 50,
                "guidance_scale": 7.5,
                "width": 1024,
                "height": 1024,
                "seed": random.randint(1, 999999999)
            }
        }
        
        log_api_request(IMAGE_API_URL, payload, headers)
        
        # Görsel oluştur
        response = http_session.post(
            IMAGE_API_URL,
            headers=headers,
            data=json.dumps(payload).encode('utf-8'),
            timeout=30
        )
        log_api_response(response)
        
        if response.status_code != 200:
            logger.error(f"API Hatası: {response.text}")
            return jsonify({
                'success': False,
                'error': 'Görsel oluşturulamadı'
            })
        
        # Görsel kaydetme işlemleri
        image_filename = f"output_{uuid.uuid4()}.png"
        image_path = os.path.join('static', image_filename)
        
        logger.debug(f"Görsel kaydediliyor: {image_path}")
        
        with open(image_path, "wb") as f:
            f.write(response.content)
        
        # Veritabanı işlemleri
        logger.debug("Veritabanı kaydı oluşturuluyor")
        
        image = Image(
            user_id=user.id,
            prompt=enhanced_prompts['turkish'],
            path=image_path
        )
        db.session.add(image)
        
        if not user.is_premium:
            user.daily_tokens -= 1
            logger.debug(f"Kalan token: {user.daily_tokens}")
        
        db.session.commit()
        logger.info("Görsel oluşturma başarıyla tamamlandı")
        
        return jsonify({
            'success': True,
            'image_path': image_path,
            'remaining_tokens': user.daily_tokens,
            'enhanced_prompt': enhanced_prompts['english']
        })
        
    except Exception as e:
        log_error("Görsel oluşturma sırasında hata", e)
        return jsonify({'error': str(e)}), 500

@app.route('/toggle-favorite', methods=['POST'])
@login_required
def toggle_favorite():
    try:
        data = request.get_json()
        image_id = data.get('image_id')
        
        if not image_id:
            return jsonify({'success': False, 'error': 'Görsel ID gerekli'}), 400
            
        image = Image.query.get(image_id)
        if not image:
            return jsonify({'success': False, 'error': 'Görsel bulunamadı'}), 404
            
        user = get_user(session['user_id'])
        
        if image.is_favorite(user):
            # Favorilerden çıkar
            image.favorited_by.remove(user)
            is_favorite = False
        else:
            # Favorilere ekle
            image.favorited_by.append(user)
            is_favorite = True
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'is_favorite': is_favorite,
            'message': 'Favorilere eklendi' if is_favorite else 'Favorilerden çıkarıldı'
        })
        
    except Exception as e:
        log_error("Favori işlemi sırasında hata", e)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/galeri')
@login_required
def galeri():
    try:
        user = get_user(session['user_id'])
        page = request.args.get('page', 1, type=int)
        per_page = 12
        
        filter_type = request.args.get('filter', 'all')
        
        # Sorguları hazırla
        if filter_type == 'my':
            base_query = Image.query.filter_by(user_id=user.id)
        elif filter_type == 'favorites':
            base_query = user.favorite_images
        elif filter_type == 'popular':
            base_query = Image.query.order_by(Image.likes.desc())
        else:
            base_query = Image.query
        
        # Ana sorguyu oluştur
        images = base_query.order_by(Image.created_at.desc())
        
        # Sayfalama
        paginated_images = images.paginate(page=page, per_page=per_page)
        
        # Görsel verilerini hazırla
        for image in paginated_images.items:
            # Görsel yolunu düzelt
            if not image.path.startswith('/'):
                image.path = '/' + image.path
            
            # Tarihi formatla
            if isinstance(image.created_at, datetime):
                image.created_at = image.created_at.strftime('%d.%m.%Y %H:%M')
            
            # Favori durumunu kontrol et
            image.is_favorite = image.is_favorite(user) if hasattr(image, 'is_favorite') else False
        
        return render_template('galeri.html', 
            user=user, 
            images=paginated_images,
            filter_type=filter_type,
            active_page='galeri'
        )
        
    except Exception as e:
        log_error(e, "Galeri sayfası yüklenirken hata oluştu")
        flash('Galeri yüklenirken bir hata oluştu', 'error')
        return redirect(url_for('index'))

@app.route('/premium')
@login_required
def premium():
    user = get_user(session['user_id'])
    return render_template('premium.html', user=user)

@app.route('/hakkimizda')
def about():
    return render_template('hakkimizda.html')

@app.route('/iletisim')
def contact():
    return render_template('iletisim.html')

@app.route('/sss')
def faq():
    return render_template('sss.html')

@app.route('/profil')
@login_required
def profil():
    user = get_user(session['user_id'])
    return render_template('profil.html', user=user)

@app.route('/ses-studio')
@login_required
def ses_studio():
    user = get_user(session['user_id'])
    return render_template('ses-studio.html', user=user)

@app.route('/metin-studio')
@login_required
def metin_studio():
    user = get_user(session['user_id'])
    return render_template('metin-studio.html', user=user)

@app.route('/gorsel-studio')
@login_required
def gorsel_studio():
    user = get_user(session['user_id'])
    return render_template('gorsel-studio.html', user=user)

@app.route('/generate-audio', methods=['POST'])
@login_required
@cache.memoize(timeout=300)
def generate_audio():
    logger.info("\n=== SES OLUŞTURMA BAŞLADI ===")
    
    user = get_user(session['user_id'])
    logger.debug(f"Kullanıcı: {user.username}")
    
    if not user.is_premium and user.daily_audio_seconds >= 1800:
        logger.warning("Ses limiti aşıldı")
        return jsonify({
            'success': False,
            'error': 'Günlük ses oluşturma limitinize ulaştınız'
        })
    
    text = request.form.get('text')
    speed = float(request.form.get('speed', 1.0))
    
    logger.debug(f"Metin: {text}")
    logger.debug(f"Hız: {speed}")
    
    try:
        headers = {
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json; charset=utf-8"
        }
        
        payload = {
            "inputs": text,
            "parameters": {
                "speaker_embeddings": None,
                "speed_ratio": speed,
                "return_intermediate_steps": False
            }
        }
        
        log_api_request(AUDIO_API_URL, payload, headers)
        
        response = requests.post(AUDIO_API_URL, headers=headers, json=payload)
        log_api_response(response)
        
        if response.status_code == 200:
            audio_filename = f"audio_{uuid.uuid4()}.wav"
            audio_path = os.path.join('static', 'audios', audio_filename)
            
            logger.debug(f"Ses dosyası kaydediliyor: {audio_path}")
            
            with open(audio_path, 'wb') as f:
                f.write(response.content)
            
            duration = len(text.split()) * 0.5
            if not user.is_premium:
                user.daily_audio_seconds += int(duration)
                logger.debug(f"Kalan ses süresi: {1800 - user.daily_audio_seconds} saniye")
            
            audio = Audio(
                user_id=user.id,
                text=text,
                path=audio_path,
                duration=duration
            )
            db.session.add(audio)
            db.session.commit()
            
            logger.info("Ses oluşturma başarıyla tamamlandı")
            
            return jsonify({
                'success': True,
                'audio_path': f"/{audio_path}",
                'remaining_seconds': 'Sınırsız' if user.is_premium else (1800 - user.daily_audio_seconds)
            })
            
        else:
            logger.error(f"API Hatası: {response.text}")
            return jsonify({
                'success': False,
                'error': f"API Hatası: {response.text}"
            })
            
    except Exception as e:
        log_error(e, "Ses oluşturma sırasında hata")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/generate-text', methods=['POST'])
@login_required
def generate_text():
    print(f"\n=== DEBUG: Metin Oluşturma ===")
    
    user = db.session.get(User, session['user_id'])
    print(f"Kullanıcı: {user.username}")
    
    if not user.is_premium and user.daily_text_tokens <= 0:
        return jsonify({
            'success': False,
            'error': 'Günlük token limitinize ulaştınız'
        })
    
    template = request.form.get('template')
    topic = request.form.get('topic')
    keywords = request.form.get('keywords', '')
    tone = request.form.get('tone', 'professional')
    length = request.form.get('length', 'medium')
    
    print(f"Şablon: {template}")
    print(f"Konu: {topic}")
    print(f"Anahtar Kelimeler: {keywords}")
    print(f"Ton: {tone}")
    print(f"Uzunluk: {length}")
    
    # Uzunluk ayarları
    length_tokens = {
        'short': 300,
        'medium': 600,
        'long': 1000
    }
    
    # Ton ayarları
    tone_map = {
        'professional': 'profesyonel ve resmi',
        'casual': 'günlük ve samimi',
        'friendly': 'arkadaşça ve sıcak',
        'formal': 'resmi ve akademik'
    }
    
    # Template ayarları
    template_prompts = {
        'blog': f"""<s>[INST] Sen profesyonel bir Türkçe içerik yazarısın. Aşağıdaki konuda {tone_map[tone]} bir blog yazısı yaz.

Konu: {topic}
Anahtar Kelimeler: {keywords}
Uzunluk: {length_tokens[length]} kelime

Lütfen tamamen Türkçe olarak yaz. [/INST]""",
        'social': f"""<s>[INST] Sen profesyonel bir Türkçe sosyal medya yöneticisisin. Aşağıdaki konu için {tone_map[tone]} bir sosyal medya gönderisi yaz.

Konu: {topic}
Anahtar Kelimeler: {keywords}

Lütfen tamamen Türkçe olarak yaz. [/INST]""",
        'seo': f"""<s>[INST] Sen profesyonel bir Türkçe SEO içerik yazarısın. Aşağıdaki konu için SEO uyumlu ve {tone_map[tone]} bir metin yaz.

Konu: {topic}
Anahtar Kelimeler: {keywords}
Uzunluk: {length_tokens[length]} kelime

Lütfen tamamen Türkçe olarak yaz ve SEO kurallarına uygun olsun. [/INST]"""
    }
    
    try:
        # Hugging Face API'ye istek
        headers = {"Authorization": f"Bearer {API_TOKEN}"}
        
        payload = {
            "inputs": template_prompts[template],
            "parameters": {
                "max_new_tokens": length_tokens[length],
                "temperature": 0.7,
                "top_p": 0.9,
                "do_sample": True,
                "return_full_text": False
            }
        }
        
        print(f"API isteği gönderiliyor: {payload}")
        response = requests.post(TEXT_API_URL, headers=headers, json=payload)
        print(f"API yanıtı status: {response.status_code}")
        
        if response.status_code == 200:
            response_data = response.json()
            generated_text = response_data[0]['generated_text'].strip()
            
            # Token sayısını güncelle
            used_tokens = len(generated_text.split())
            if not user.is_premium:
                user.daily_text_tokens -= used_tokens
            
            # Veritabanına kaydet
            text = Text(
                user_id=user.id,
                topic=topic,
                content=generated_text,
                template=template,
                length=used_tokens,
                created_at=datetime.utcnow()
            )
            db.session.add(text)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'text': generated_text,
                'remaining_tokens': 'Sınırsız' if user.is_premium else user.daily_text_tokens
            })
            
        print(f"API Hatası: {response.text}")
        return jsonify({
            'success': False,
            'error': 'Metin oluşturulurken bir hata oluştu'
        })
        
    except Exception as e:
        print(f"Hata: {str(e)}")
        print(f"Hata detayı:", traceback.format_exc())
        return jsonify({
            'success': False,
            'error': 'Bir hata oluştu'
        })

@app.route('/upgrade-plan', methods=['POST'])
@login_required
def upgrade_plan():
    user = db.session.get(User, session['user_id'])
    plan = request.json.get('plan')
    
    # Ödeme işlemi burada yapılacak
    # Örnek olarak başarılı kabul ediyoruz
    try:
        user.is_premium = True
        user.subscription_type = plan
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Premium üyeliğiniz başarıyla aktifleştirildi'
        })
        
    except Exception as e:
        print(f"Hata: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Ödeme işlemi sırasında bir hata oluştu'
        })

# API fonksiyonları güncelleme
def make_api_request(url, data, is_file=False):
    if not API_TOKEN:
        return None, "API anahtarı bulunamadı"
        
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    
    try:
        if is_file:
            response = requests.post(url, headers=headers, data=data)
        else:
            response = requests.post(url, headers=headers, json=data)
            
        if response.status_code == 200:
            return response.content if is_file else response.json(), None
        elif response.status_code == 401:
            return None, "API yetkilendirme hatası"
        else:
            return None, f"API Hatası: {response.text}"
            
    except Exception as e:
        print(f"Hata: {str(e)}")
        return None, str(e)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3002))
    logger.info(f"Uygulama başlatılıyor - Port: {port}")
    app.run(host='0.0.0.0', port=port, debug=True) 