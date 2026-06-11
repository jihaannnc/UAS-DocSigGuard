from flask import Flask, render_template, request, redirect, url_for, send_file, session
import hashlib
import os
import sqlite3
import datetime
import qrcode
import random
import smtplib
from email.mime.text import MIMEText
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = os.urandom(24)

# --- PROTEKSI DATABASE: Persistent Volume di Cloud / Lokal ---
if os.path.exists('/data'):
    DB_NAME = "/data/doc_security.db"
else:
    DB_NAME = "doc_security.db"

# --- KREDENSIAL EMAIL PENGIRIM OTP (SUDAH DISESUAIKAN) ---
EMAIL_PENGIRIM = "cyberareajiji@gmail.com"  
EMAIL_PASSWORD = "fukoehqnfnoziiax" 

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Membuat tabel jika belum ada saat aplikasi pertama kali dijalankan"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            status TEXT NOT NULL,
            kode_verifikasi TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS berkas_autentikasi (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            judul TEXT NOT NULL,
            penulis TEXT NOT NULL,
            penerbit TEXT NOT NULL,
            hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

# Jalankan inisialisasi basis data
init_db()

# --- SOLUSI REGISTER STUCK: Menggunakan SMTP TLS Port 587 (Cloud Friendly) ---
def kirim_email_token(email_tujuan, username, kode):
    """Mengirimkan kode OTP 6-digit dengan penanganan error cloud yang lebih tangguh"""
    subjek = "Kode Verifikasi Pendaftaran Akun DocSigGuard"
    isi_surat = (
        f"Halo {username},\n\n"
        f"Terima kasih telah melakukan registrasi pada sistem DocSigGuard.\n\n"
        f"Berikut adalah kode keamanan untuk mengaktifkan akun Anda:\n"
        f"KODE VERIFIKASI: {kode}\n\n"
        f"Silakan masukkan kode di atas pada halaman verifikasi sistem."
    )
    
    msg = MIMEText(isi_surat)
    msg['Subject'] = subjek
    msg['From'] = EMAIL_PENGIRIM
    msg['To'] = email_tujuan

    try:
        # Konfigurasi koneksi SMTP yang stabil untuk lingkungan server cloud
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=15)
        server.set_debuglevel(1) 
        server.ehlo()
        server.starttls() 
        server.ehlo()
        server.login(EMAIL_PENGIRIM, EMAIL_PASSWORD)
        server.sendmail(EMAIL_PENGIRIM, email_tujuan, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"CRITICAL SMTP ERROR LOG: {str(e)}") 
        return False


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not username or not email or not password:
            error = "Semua bidang formulir wajib diisi!"
            return render_template('register.html', error=error)

        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        kode_token = str(random.randint(100000, 999999))
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, email, password, status, kode_verifikasi) 
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, hashed_password, 'PENDING', kode_token))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            # Kirim email token secara aman via Port 587 TLS
            email_terkirim = kirim_email_token(email, username, kode_token)
            if email_terkirim:
                return redirect(url_for('verify_account', user_id=user_id))
            else:
                # Rollback jika email gagal terkirim agar user bisa mendaftar ulang
                conn = get_db_connection()
                conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
                conn.commit()
                conn.close()
                error = "Sistem gagal mengirimkan kode verifikasi ke email Anda. Coba lagi nanti."
        except sqlite3.IntegrityError:
            error = "Username atau Alamat Email sudah terdaftar dalam sistem DocSigGuard."
            try: conn.close()
            except: pass
            
    return render_template('register.html', error=error)

@app.route('/verify-account/<int:user_id>', methods=['GET', 'POST'])
def verify_account(user_id):
    error = None
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        conn.close()
        return "Pengguna tidak ditemukan dalam sistem.", 404
        
    if request.method == 'POST':
        input_kode = request.form.get('kode', '').strip()
        if input_kode == user['kode_verifikasi']:
            conn.execute('UPDATE users SET status = ?, kode_verifikasi = NULL WHERE id = ?', ('ACTIVE', user_id))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        else:
            error = "Kode keamanan yang Anda masukkan keliru. Periksa kotak masuk/spam email Anda."
            
    conn.close()
    return render_template('verify_account.html', user=user, error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
        
    error = None
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '')
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE (username = ? OR email = ?) AND password = ? AND status = ?', 
                            (username_or_email, username_or_email, hashed_password, 'ACTIVE')).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            error = "Kredensial salah atau akun Anda belum diverifikasi via OTP Email."
            
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# --- PROTEKSI MULTI-USER: Menjamin data histori tidak bocor ke orang asing ---
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    cursor = conn.cursor()

    current_user = cursor.execute('SELECT * FROM users WHERE id = ? AND status = ?', (session['user_id'], 'ACTIVE')).fetchone()
    if not current_user:
        conn.close()
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST' and 'pdf' in request.files:
        file = request.files['pdf']
        if file and file.filename.endswith('.pdf'):
            filename = file.filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            judul = request.form.get('judul', 'Tidak Diketahui').strip()
            penulis = request.form.get('penulis', 'Tidak Diketahui').strip()
            penerbit = request.form.get('penerbit', 'Tidak Diketahui').strip()

            with open(filepath, 'rb') as f:
                file_bytes = f.read()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            cursor.execute('''
                INSERT INTO berkas_autentikasi (user_id, filename, judul, penulis, penerbit, hash, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (session['user_id'], filename, judul, penulis, penerbit, sha256_hash, timestamp))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

    # Hanya mengambil histori milik user yang login aktif
    history = cursor.execute('SELECT * FROM berkas_autentikasi WHERE user_id = ? ORDER BY id DESC', 
                             (session['user_id'],)).fetchall()
    conn.close()
    return render_template('response.html', history=history)

# --- VALIDASI KEAMANAN TINGGI: Menghapus berkas wajib mencocokkan user_id ---
@app.route('/delete/<int:item_id>')
def delete_item(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    conn.execute('DELETE FROM berkas_autentikasi WHERE id = ? AND user_id = ?', (item_id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

# --- VALIDASI KEAMANAN TINGGI: Ekspor Sertifikat PDF mencocokkan user_id pemilik asli ---
@app.route('/export-pdf/<int:item_id>')
def export_pdf(item_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    target_item = conn.execute('SELECT * FROM berkas_autentikasi WHERE id = ? AND user_id = ?', (item_id, session['user_id'])).fetchone()
    conn.close()
    
    if not target_item:
        return "Akses Ditolak: Anda tidak berwenang melihat atau mengunduh sertifikat dokumen ini.", 403

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54)
    story = []
    
    styles = getSampleStyleSheet()
    main_title = ParagraphStyle('MainTitle', fontName='Helvetica-Bold', fontSize=24, leading=28, textColor=colors.HexColor('#9D174D'), spaceAfter=4)
    subtitle = ParagraphStyle('SubTitle', fontName='Helvetica', fontSize=10, leading=14, textColor=colors.HexColor('#666666'), spaceAfter=15)
    section_title = ParagraphStyle('SecTitle', fontName='Helvetica-Bold', fontSize=12, textColor=colors.HexColor('#9D174D'), spaceBefore=12, spaceAfter=6)
    body_text = ParagraphStyle('BodyText', fontName='Helvetica', fontSize=10, leading=15, textColor=colors.HexColor('#333333'))
    code_text = ParagraphStyle('CodeText', fontName='Courier-Bold', fontSize=9, leading=12, textColor=colors.HexColor('#9D174D'))
    cert_text = ParagraphStyle('CertText', fontName='Helvetica-Oblique', fontSize=9, leading=14, textColor=colors.HexColor('#444444'), alignment=1)

    story.append(Paragraph("DocSigGuard", main_title))
    story.append(Paragraph("Sertifikat Autentikasi & Verifikasi Integritas Berkas Digital", subtitle))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#9D174D'), spaceAfter=15))

    deklarasi_isi = f"Melalui pengujian integritas sistem, dokumen digital dengan nama berkas <b>{target_item['filename']}</b> telah berhasil terdaftar dan terautentikasi menggunakan algoritma kriptografi SHA-256."
    story.append(Paragraph(deklarasi_isi, body_text))
    story.append(Spacer(1, 10))

    metadata_table_data = [
        [Paragraph("<b>Judul Dokumen / Buku</b>", body_text), Paragraph(target_item['judul'], body_text)],
        [Paragraph("<b>Penulis / Penyusun</b>", body_text), Paragraph(target_item['penulis'], body_text)],
        [Paragraph("<b>Penerbit / Institusi</b>", body_text), Paragraph(target_item['penerbit'], body_text)]
    ]
    meta_table = Table(metadata_table_data, colWidths=[150, 350])
    meta_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LINEBELOW', (0,0), (-1,-2), 0.5, colors.HexColor('#E5E7EB')),
        ('LINEBELOW', (0,-1), (-1,-1), 1, colors.HexColor('#9D174D'))
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))

    story.append(Paragraph("Kode Proteksi Kriptografi:", section_title))
    hash_box_data = [[Paragraph(target_item['hash'], code_text)]]
    hash_table = Table(hash_box_data, colWidths=[500])
    hash_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor('#FFF5F5')),
        ('BOX', (0,0), (0,0), 1, colors.HexColor('#FBCFE8')),
        ('PADDING', (0,0), (0,0), 10),
    ]))
    story.append(hash_table)
    story.append(Spacer(1, 20))

    qr_isi_scan = (
        f"[ VERIFIKASI DOCSIGGUARD ]\n"
        f"Status: VALID & TERAUTENTIKASI\n"
        f"Berkas: {target_item['filename']}\n"
        f"Hash SHA-256: {target_item['hash']}\n"
        f"Sistem Pengembang: Jihan Fitria Nur Anisa"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=1)
    qr.add_data(qr_isi_scan)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    qr_buffer = BytesIO()
    qr_img.save(qr_buffer, format='PNG')
    qr_buffer.seek(0)
    qr_reportlab_img = Image(qr_buffer, width=95, height=95)

    ttd_html_text = f"""<br/>
    Dokumen ini telah dinyatakan sah, aman, dan terautentikasi secara digital oleh sistem:<br/>
    <font color="#9D174D" size="11"><b>DocSigGuard System Validation</b></font><br/>
    <font color="#777777" size="8.5">Sistem Validasi Keamanan Kriptografi</font><br/>
    <font color="#555555" size="8">Dikembangkan oleh: <b>JIHAN FITRIA NUR ANISA</b></font>
    """
    ttd_paragraph = Paragraph(ttd_html_text, cert_text)

    bottom_grid_data = [[qr_reportlab_img, ttd_paragraph]]
    bottom_table = Table(bottom_grid_data, colWidths=[120, 380])
    bottom_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ALIGN', (1,0), (1,0), 'CENTER'),
        ('PADDING', (0,0), (-1,-1), 0),
    ]))
    story.append(bottom_table)

    story.append(Spacer(1, 35))
    footer_p = Paragraph(f"Sertifikat Digital Otomatis • Dibuat pada: {target_item['timestamp']}", ParagraphStyle('Foot', fontName='Helvetica', fontSize=8, textColor=colors.gray, alignment=1))
    story.append(footer_p)

    doc.build(story)
    buffer.seek(0)
    
    nama_unduhan = f"signed_{os.path.splitext(target_item['filename'])[0]}.pdf"
    return send_file(buffer, as_attachment=True, download_name=nama_unduhan, mimetype='application/pdf')

if __name__ == '__main__':
    app.run(debug=True)