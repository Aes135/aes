from flask import Flask, render_template, request

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib
import pypyodbc  # Microsoft SQL Server için pypyodbc kullanın



# RSA anahtarları oluştur
key = RSA.generate(2048)
public_key = key.publickey().export_key()
private_key = key.export_key()

# Microsoft SQL Server veritabanına bağlan
conn_str = (
    'Driver={SQL Server};'
    'Server=DESKTOP-AUOR546\SQLEXPRESS;'
    'Database=Verikayit;'
    'Trusted_Connection=True;'
)

mydb = pypyodbc.connect(conn_str)
cursor = mydb.cursor()

# Tabloyu oluştur, eğer tablo henüz yoksa
create_table_query = '''
    IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'users')
    BEGIN
        CREATE TABLE users (
            username NVARCHAR(255) PRIMARY KEY,
            password_hash NVARCHAR(255)
        )
    END
'''

cursor.execute(create_table_query)


app = Flask(__name__)

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    role = request.form['role']
    
    # RSA kullanarak parolayı şifrele
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_password = cipher_rsa.encrypt(password.encode())

    # SHA256 kullanarak şifrelenmiş parolayı hashle
    hashed_password = hashlib.sha256(encrypted_password).hexdigest()

    # Kullanıcının veritabanında varlığını kontrol et
    cursor.execute(f"SELECT * FROM users WHERE username=?", (username,))
    result = cursor.fetchone()

    if result:
        # Hashlenmiş parolanın saklanan hash ile eşleşip eşleşmediğini kontrol et
        if result[1] == hashed_password:
            return "Giriş başarılı!"
        else:
            return "Yanlış parola."
    else:
        return "Kullanıcı bulunamadı."

@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    # RSA kullanarak parolayı şifrele
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_password = cipher_rsa.encrypt(password.encode())

    # SHA256 kullanarak şifrelenmiş parolayı hashle
    hashed_password = hashlib.sha256(encrypted_password).hexdigest()

    # Yeni kullanıcıyı veritabanına ekleyin
    cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
    mydb.commit()

    return "Kayıt başarılı!"

if __name__ == "__main__":
    app.run(debug=True)