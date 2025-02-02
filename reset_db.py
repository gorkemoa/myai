from app import app, db
import os

def reset_database():
    # Veritabanı dosyasını sil
    db_path = os.path.join('instance', 'myai.db')
    if os.path.exists(db_path):
        os.remove(db_path)
        print("Eski veritabanı silindi.")
    
    # Yeni veritabanını oluştur
    with app.app_context():
        db.create_all()
        print("Veritabanı başarıyla yeniden oluşturuldu.")

if __name__ == "__main__":
    reset_database() 