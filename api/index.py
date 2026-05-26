import os
import io
import json
import datetime
import hmac
import hashlib
import base64
import time
from flask import Flask, request, jsonify, send_from_directory

# Import shared modules
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from lib.services import get_drive_service, get_firestore
from lib.utils import add_watermark

app = Flask(__name__, static_folder='../public', static_url_path='')

# ================= CONFIG =================
FOLDER_ID = os.getenv("FOLDER_ID", "")
TOKEN_SECRET = os.getenv("TOKEN_SECRET_KEY", os.urandom(32).hex())

# ================= TOKEN UTILS =================
def generate_token(username):
    payload = f"{username}:{int(time.time()) + 86400}"  # 24 jam expiry
    signature = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}.{signature}".encode()).decode()

def verify_token(token):
    try:
        decoded = base64.urlsafe_b64decode(token).decode()
        payload, sig = decoded.rsplit('.', 1)
        expected_sig = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        username, expires_at = payload.split(':')
        if int(time.time()) > int(expires_at):
            return None
        return {"username": username}
    except:
        return None

# ================= CORS DECORATOR =================
def cors_headers():
    origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
    origin = request.headers.get("Origin", "")
    allow = origin if origin in origins or origins == ["*"] else (origins[0] if origins else "*")
    return {
        'Access-Control-Allow-Origin': allow,
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    }

@app.after_request
def after_request(response):
    headers = cors_headers()
    for k, v in headers.items():
        response.headers[k] = v
    return response

# ================= ROUTES: UPLOAD SITE =================
@app.route('/api/upload-site', methods=['POST', 'OPTIONS'])
def upload_site():
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        note = request.form.get('note', '')
        
        try:
            latitude = float(request.form.get('latitude', 0))
            longitude = float(request.form.get('longitude', 0))
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid coordinates'}), 400
        
        if not file.content_type or not file.content_type.startswith('image/'):
            return jsonify({'error': 'Only images allowed'}), 400
        
        content = file.read()
        if len(content) > 4 * 1024 * 1024:
            return jsonify({'error': 'File too large (max 4MB)'}), 413
        
        # Watermark
        img = add_watermark(io.BytesIO(content), f"{latitude:.6f}, {longitude:.6f}", note)
        if img is None:
            return jsonify({'error': 'Failed to process image'}), 500
        
        # Upload to Google Drive
        drive = get_drive_service()
        filename = f"Site_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
        from googleapiclient.http import MediaIoBaseUpload
        media = MediaIoBaseUpload(img, mimetype='image/jpeg')
        fr = drive.files().create(
            body={'name': filename, 'parents': [FOLDER_ID]},
            media_body=media,
            fields='id, webViewLink'
        ).execute()
        
        # Save to Firestore
        db = get_firestore()
        db.collection('laporan').add({
            'timestamp': datetime.datetime.now().isoformat(),
            'type': 'site',
            'location': f"{latitude},{longitude}",
            'latitude': latitude,
            'longitude': longitude,
            'note': note,
            'drive_id': fr.get('id'),
            'drive_link': fr.get('webViewLink'),
            'filename': filename
        })
        
        return jsonify({
            'success': True,
            'message': 'Laporan Site berhasil dikirim!',
            'drive_link': fr.get('webViewLink')
        }), 200
        
    except Exception as e:
        print(f"Upload site error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ================= ROUTES: UPLOAD DOC =================
@app.route('/api/upload-doc', methods=['POST', 'OPTIONS'])
def upload_doc():
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        files = request.files.getlist('files')
        if not files:
            return jsonify({'error': 'No files provided'}), 400
        
        note = request.form.get('note', '')
        nominal = request.form.get('nominal', '')
        
        # Upload each file to Drive (simplified: upload first file only for demo)
        file = files[0]
        content = file.read()
        if len(content) > 4 * 1024 * 1024:
            return jsonify({'error': 'File too large (max 4MB)'}), 413
        
        drive = get_drive_service()
        filename = f"Doc_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{os.path.splitext(file.filename)[1]}"
        from googleapiclient.http import MediaIoBaseUpload
        media = MediaIoBaseUpload(io.BytesIO(content), mimetype=file.content_type or 'application/octet-stream')
        fr = drive.files().create(
            body={'name': filename, 'parents': [FOLDER_ID], 'description': f"{note} - {nominal}"},
            media_body=media,
            fields='id, webViewLink'
        ).execute()
        
        # Save to Firestore
        db = get_firestore()
        db.collection('laporan').add({
            'timestamp': datetime.datetime.now().isoformat(),
            'type': 'doc',
            'note': note,
            'nominal': nominal,
            'jumlah_file': len(files),
            'drive_id': fr.get('id'),
            'drive_link': fr.get('webViewLink'),
            'filename': filename
        })
        
        return jsonify({
            'success': True,
            'message': 'Dokumen berhasil dikirim!',
            'drive_link': fr.get('webViewLink')
        }), 200
        
    except Exception as e:
        print(f"Upload doc error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ================= ROUTES: ADMIN AUTH =================
@app.route('/api/admin-login', methods=['POST', 'OPTIONS'])
def admin_login():
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json() or {}
        action = data.get('type', 'login').lower()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username & password required'}), 400
        
        db = get_firestore()
        doc_ref = db.collection('admin_users').document(username)
        doc = doc_ref.get()
        
        if action == 'register':
            if doc.exists:
                return jsonify({'error': 'Username already taken'}), 409
            salt = os.urandom(16).hex()
            pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
            doc_ref.set({
                'username': username,
                'password_hash': pw_hash,
                'salt': salt,
                'failed_attempts': 0,
                'created_at': datetime.datetime.now().isoformat()
            })
            return jsonify({'success': True, 'message': 'Account created'}), 201
        
        elif action == 'login':
            if not doc.exists:
                return jsonify({'error': 'Invalid credentials'}), 401
            ud = doc.to_dict()
            if ud.get('failed_attempts', 0) >= 5:
                doc_ref.delete()
                return jsonify({'error': 'Account deleted. Please register again.'}), 403
            ch = hashlib.pbkdf2_hmac('sha256', password.encode(), ud['salt'].encode(), 100000).hex()
            if ch != ud['password_hash']:
                na = ud.get('failed_attempts', 0) + 1
                if na >= 5:
                    doc_ref.delete()
                    return jsonify({'error': 'Account deleted. Please register again.'}), 403
                doc_ref.update({'failed_attempts': na})
                return jsonify({'error': 'Invalid credentials'}), 401
            doc_ref.update({'failed_attempts': 0})
            token = generate_token(username)
            return jsonify({'success': True, 'token': token, 'username': username}), 200
        
        return jsonify({'error': 'Invalid action'}), 400
        
    except Exception as e:
        print(f"Admin login error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# ================= ROUTES: ADMIN REPORTS =================
@app.route('/api/admin-reports', methods=['GET', 'OPTIONS'])
def admin_reports():
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '') if auth else ''
        if not verify_token(token):
            return jsonify({'error': 'Unauthorized'}), 401
        
        db = get_firestore()
        docs = db.collection('laporan').order_by('timestamp', direction='DESCENDING').limit(100).stream()
        reports = [{'id': d.id, **d.to_dict()} for d in docs]
        return jsonify({'success': True, 'reports': reports, 'count': len(reports)}), 200
        
    except Exception as e:
        print(f"Admin reports error: {e}")
        return jsonify({'error': 'Failed to load reports'}), 500

# ================= ROUTES: ADMIN DELETE =================
@app.route('/api/admin-delete', methods=['DELETE', 'OPTIONS'])
def admin_delete():
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '') if auth else ''
        if not verify_token(token):
            return jsonify({'error': 'Unauthorized'}), 401
        
        report_id = request.args.get('id') or request.path.split('/')[-1]
        if not report_id:
            return jsonify({'error': 'Report ID required'}), 400
        
        db = get_firestore()
        doc_ref = db.collection('laporan').document(report_id)
        doc = doc_ref.get()
        if not doc.exists:
            return jsonify({'error': 'Report not found'}), 404
        
        data = doc.to_dict()
        drive_id = data.get('drive_id')
        
        # Delete from Google Drive (if exists)
        if drive_id:
            try:
                drive = get_drive_service()
                drive.files().delete(fileId=drive_id).execute()
            except Exception as e:
                print(f"Drive delete warning: {e}")
        
        doc_ref.delete()
        return jsonify({'success': True, 'message': 'Deleted'}), 200
        
    except Exception as e:
        print(f"Admin delete error: {e}")
        return jsonify({'error': 'Failed to delete'}), 500

# ================= ROUTES: CLEANUP (CRON) =================
@app.route('/api/cleanup')
def cleanup():
    try:
        # Add cleanup logic here if needed
        return jsonify({'success': True, 'message': 'Cleanup done'}), 200
    except Exception as e:
        print(f"Cleanup error: {e}")
        return jsonify({'error': str(e)}), 500

# ================= SERVE STATIC FILES =================
@app.route('/')
def index():
    return send_from_directory('../public', 'index.html')

@app.route('/admin')
def admin():
    return send_from_directory('../public', 'admin.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('../public', path)

# ================= ENTRY POINT FOR RAILWAY =================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
