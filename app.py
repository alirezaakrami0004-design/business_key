import os, json, time, sqlite3, csv, io, secrets
from dotenv import load_dotenv
load_dotenv()
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import requests
import feedparser
from flask import Flask, jsonify, request, send_from_directory, session, redirect, make_response

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv('DATABASE_PATH', os.path.join(BASE, 'business_key.db'))
app = Flask(__name__, static_folder=os.path.join(BASE, 'templates'), static_url_path='')
app.secret_key = os.getenv('SECRET_KEY') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE','0') == '1', PERMANENT_SESSION_LIFETIME=timedelta(days=14))

OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '').strip()
OPENAI_BASE_URL = os.getenv('OPENAI_BASE_URL', 'https://api.openai.com/v1').rstrip('/')
OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
NEWS_FEEDS = [x.strip() for x in os.getenv('NEWS_FEEDS', '').split(',') if x.strip()]
ECONOMIC_DATA_URL = os.getenv('ECONOMIC_DATA_URL', '').strip()
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '20'))



def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    from werkzeug.security import generate_password_hash
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', plan TEXT NOT NULL DEFAULT 'free', status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, expires_at TEXT);
        CREATE TABLE IF NOT EXISTS business_data (user_id INTEGER PRIMARY KEY, payload TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS usage_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL);
        """)
        email=os.getenv('ADMIN_EMAIL','').strip().lower(); password=os.getenv('ADMIN_PASSWORD','').strip()
        if email and password and not con.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone():
            con.execute('INSERT INTO users(email,name,password_hash,role,plan,status,created_at) VALUES(?,?,?,?,?,?,?)',(email,'مدیر سیستم',generate_password_hash(password),'admin','enterprise','active',datetime.now(timezone.utc).isoformat()))

def current_user():
    uid=session.get('user_id')
    if not uid: return None
    with db() as con: row=con.execute('SELECT id,email,name,role,plan,status,created_at,expires_at FROM users WHERE id=?',(uid,)).fetchone()
    return dict(row) if row else None

def require_login():
    user=current_user()
    if not user: return None, (jsonify({'error':'برای ادامه وارد حساب کاربری شوید.'}),401)
    if user['status'] != 'active': return None, (jsonify({'error':'حساب کاربری غیرفعال است.'}),403)
    return user, None

def require_admin():
    user,err=require_login()
    if err: return None,err
    if user['role']!='admin': return None,(jsonify({'error':'دسترسی مدیر سیستم لازم است.'}),403)
    return user,None

@app.post('/api/auth/register')
def register():
    from werkzeug.security import generate_password_hash
    data=request.get_json(silent=True) or {}; name=str(data.get('name','')).strip(); email=str(data.get('email','')).strip().lower(); password=str(data.get('password',''))
    if len(name)<2 or '@' not in email or len(password)<8: return jsonify({'error':'نام، ایمیل معتبر و گذرواژه حداقل ۸ کاراکتری لازم است.'}),400
    try:
        with db() as con:
            cur=con.execute('INSERT INTO users(email,name,password_hash,created_at) VALUES(?,?,?,?)',(email,name,generate_password_hash(password),datetime.now(timezone.utc).isoformat()))
            uid=cur.lastrowid; con.execute('INSERT INTO business_data(user_id,payload,updated_at) VALUES(?,?,?)',(uid,'{}',datetime.now(timezone.utc).isoformat()))
        session.clear(); session['user_id']=uid; session.permanent=True
        return jsonify({'user':current_user()})
    except sqlite3.IntegrityError: return jsonify({'error':'این ایمیل قبلاً ثبت شده است.'}),409

@app.post('/api/auth/login')
def login():
    from werkzeug.security import check_password_hash
    data=request.get_json(silent=True) or {}; email=str(data.get('email','')).strip().lower(); password=str(data.get('password',''))
    with db() as con: row=con.execute('SELECT id,password_hash,status FROM users WHERE email=?',(email,)).fetchone()
    if not row or not check_password_hash(row['password_hash'],password): return jsonify({'error':'ایمیل یا گذرواژه نادرست است.'}),401
    if row['status']!='active': return jsonify({'error':'حساب کاربری غیرفعال است.'}),403
    session.clear(); session['user_id']=row['id']; session.permanent=True
    return jsonify({'user':current_user()})

@app.post('/api/auth/logout')
def logout():
    session.clear(); return jsonify({'ok':True})

@app.get('/api/auth/me')
def me():
    user=current_user()
    return jsonify({'authenticated':bool(user),'user':user})

@app.route('/api/account/data',methods=['GET','PUT'])
def account_data():
    user,err=require_login()
    if err:return err
    if request.method=='GET':
        with db() as con: row=con.execute('SELECT payload,updated_at FROM business_data WHERE user_id=?',(user['id'],)).fetchone()
        return jsonify({'data':json.loads(row['payload']) if row else {},'updated_at':row['updated_at'] if row else None})
    payload=request.get_json(silent=True) or {}
    raw=json.dumps(payload,ensure_ascii=False)
    if len(raw)>1_000_000:return jsonify({'error':'حجم اطلاعات بیش از حد مجاز است.'}),413
    now=datetime.now(timezone.utc).isoformat()
    with db() as con: con.execute('INSERT INTO business_data(user_id,payload,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at',(user['id'],raw,now))
    return jsonify({'ok':True,'updated_at':now})

@app.get('/api/account/report.csv')
def account_report():
    user,err=require_login()
    if err:return err
    with db() as con: row=con.execute('SELECT payload FROM business_data WHERE user_id=?',(user['id'],)).fetchone()
    payload=json.loads(row['payload']) if row else {}; profile=payload.get('profile') or {}; goals=payload.get('goals') or []; comps=payload.get('competitors') or []
    output=io.StringIO(); w=csv.writer(output); w.writerow(['section','field','value']);
    for k,v in profile.items(): w.writerow(['business_profile',k,v])
    for g in goals: w.writerow(['goal',g.get('t',''),f"KR={g.get('k','')} | days={g.get('d','')} | done={g.get('done',False)}"])
    for c in comps: w.writerow(['competitor',c.get('n',''),f"strength={c.get('s','')} | weakness={c.get('w','')} | price={c.get('p','')}"])
    resp=make_response('\ufeff'+output.getvalue()); resp.headers['Content-Type']='text/csv; charset=utf-8'; resp.headers['Content-Disposition']='attachment; filename=business-key-report.csv'; return resp

@app.get('/api/admin/users')
def admin_users():
    admin,err=require_admin()
    if err:return err
    with db() as con: rows=con.execute('SELECT id,email,name,role,plan,status,created_at,expires_at FROM users ORDER BY id DESC').fetchall()
    return jsonify({'users':[dict(r) for r in rows]})

@app.patch('/api/admin/users/<int:uid>')
def admin_update_user(uid):
    admin,err=require_admin()
    if err:return err
    data=request.get_json(silent=True) or {}; allowed={'plan':{'free','pro','enterprise'},'status':{'active','suspended'},'role':{'user','admin'}}
    updates=[]
    for key,values in allowed.items():
        if key in data and data[key] in values: updates.append((key,data[key]))
    if not updates:return jsonify({'error':'تغییر معتبری ارسال نشده است.'}),400
    with db() as con:
        if uid==admin['id'] and any(k=='role' and v!='admin' for k,v in updates):return jsonify({'error':'نمی‌توانید دسترسی مدیر خودتان را حذف کنید.'}),400
        for key,val in updates: con.execute(f'UPDATE users SET {key}=? WHERE id=?',(val,uid))
    return jsonify({'ok':True})

@app.get('/api/admin/summary')
def admin_summary():
    admin,err=require_admin()
    if err:return err
    with db() as con:
        total=con.execute('SELECT COUNT(*) n FROM users').fetchone()['n']; active=con.execute("SELECT COUNT(*) n FROM users WHERE status='active'").fetchone()['n']; pro=con.execute("SELECT COUNT(*) n FROM users WHERE plan IN ('pro','enterprise')").fetchone()['n']
    return jsonify({'total_users':total,'active_users':active,'paid_plan_users':pro})

init_db()

SYSTEM_PROMPT = '''تو کوچ و مشاور مدیریتی BUSINESS KEY برای صاحبان کسب‌وکار در ایران هستی. فارسی روان و دقیق پاسخ بده. پاسخ را عملیاتی، مرحله‌بندی‌شده و متناسب با نوع فعالیت، شهر، اندازه و اعداد کسب‌وکار ارائه کن. هرجا داده کافی نیست سؤال روشن بپرس و عدد یا خبر نساز. بین واقعیت تأییدشده، فرض، تحلیل و پیش‌بینی تفاوت بگذار. برای تحلیل تورم و بازار، تاریخ و منبع داده را ذکر کن و اگر داده زنده در دسترس نیست صریح بگو. توصیه مالیاتی/حقوقی را قطعی جلوه نده و لزوم بررسی متخصص را یادآوری کن. در پایان پاسخ‌های مدیریتی، 1 تا 3 اقدام قابل اندازه‌گیری پیشنهاد بده.'''

@app.get('/')
def home():
    return send_from_directory(app.static_folder, 'index.html')

@app.get('/api/health')
def health():
    return jsonify({
        'status': 'ok',
        'accounts_enabled': True,
        'coach_connected': bool(OPENAI_API_KEY),
        'news_feeds_configured': len(NEWS_FEEDS),
        'economic_data_configured': bool(ECONOMIC_DATA_URL),
        'model': OPENAI_MODEL if OPENAI_API_KEY else None,
        'server_time': datetime.now(timezone.utc).isoformat()
    })

@app.post('/api/coach')
def coach():
    user,err=require_login()
    if err:return err
    if not OPENAI_API_KEY:
        return jsonify({'error': 'موتور هوش مصنوعی هنوز پیکربندی نشده است. OPENAI_API_KEY را در فایل .env تنظیم کنید.'}), 503
    payload = request.get_json(silent=True) or {}
    question = str(payload.get('question', '')).strip()
    profile = payload.get('profile') or {}
    history = payload.get('history') or []
    if not question:
        return jsonify({'error': 'متن سؤال خالی است.'}), 400
    context = 'اطلاعات کسب‌وکار کاربر (ممکن است ناقص باشد):\n' + json.dumps(profile, ensure_ascii=False)
    messages = [{'role': 'system', 'content': SYSTEM_PROMPT + '\n\n' + context}]
    for item in history[-8:]:
        role = item.get('role')
        content = str(item.get('content', ''))[:4000]
        if role in ('user', 'assistant') and content:
            messages.append({'role': role, 'content': content})
    messages.append({'role': 'user', 'content': question})
    with db() as con: con.execute('INSERT INTO usage_log(user_id,action,created_at) VALUES(?,?,?)',(user['id'],'coach',datetime.now(timezone.utc).isoformat()))
    try:
        response = requests.post(
            OPENAI_BASE_URL + '/chat/completions',
            headers={'Authorization': 'Bearer ' + OPENAI_API_KEY, 'Content-Type': 'application/json'},
            json={'model': OPENAI_MODEL, 'messages': messages, 'temperature': 0.35},
            timeout=REQUEST_TIMEOUT
        )
        if response.status_code >= 400:
            return jsonify({'error': 'خطا از سرویس هوش مصنوعی', 'detail': response.text[:1000]}), 502
        result = response.json()['choices'][0]['message']['content']
        return jsonify({'answer': result, 'model': OPENAI_MODEL, 'generated_at': datetime.now(timezone.utc).isoformat()})
    except requests.RequestException as exc:
        return jsonify({'error': 'ارتباط با سرویس هوش مصنوعی برقرار نشد.', 'detail': str(exc)}), 502
    except (KeyError, IndexError, ValueError):
        return jsonify({'error': 'پاسخ سرویس هوش مصنوعی قابل پردازش نبود.'}), 502

@app.get('/api/news')
def news():
    items = []
    errors = []
    for feed_url in NEWS_FEEDS[:15]:
        try:
            parsed = feedparser.parse(feed_url)
            if parsed.bozo and not parsed.entries:
                errors.append('یک خوراک خبری قابل خواندن نبود.')
            for entry in parsed.entries[:12]:
                published = entry.get('published') or entry.get('updated') or ''
                items.append({
                    'title': entry.get('title', 'بدون عنوان'),
                    'summary': entry.get('summary', '')[:600],
                    'url': entry.get('link', ''),
                    'source': parsed.feed.get('title', urlparse(feed_url).netloc),
                    'published': published
                })
        except Exception:
            errors.append('دریافت یکی از منابع خبری ناموفق بود.')
    # Keep only unique articles and newest first when a parseable date exists.
    seen, unique = set(), []
    for item in items:
        key = item['url'] or item['title']
        if key and key not in seen:
            seen.add(key); unique.append(item)
    unique.sort(key=lambda x: x.get('published', ''), reverse=True)
    return jsonify({'items': unique[:40], 'updated_at': datetime.now(timezone.utc).isoformat(), 'configured_sources': len(NEWS_FEEDS), 'errors': errors})

@app.get('/api/economic-indicators')
def economic_indicators():
    if not ECONOMIC_DATA_URL:
        return jsonify({'available': False, 'message': 'منبع داده شاخص‌های اقتصادی تنظیم نشده است؛ برای جلوگیری از نمایش اعداد ساختگی، شاخصی نمایش داده نمی‌شود.'})
    try:
        r = requests.get(ECONOMIC_DATA_URL, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        return jsonify({'available': True, 'source_url': ECONOMIC_DATA_URL, 'fetched_at': datetime.now(timezone.utc).isoformat(), 'data': data})
    except Exception as exc:
        return jsonify({'available': False, 'message': 'دریافت داده شاخص‌های اقتصادی ناموفق بود.', 'detail': str(exc)}), 502

if __name__ == '__main__':
    app.run(host=os.getenv('HOST', '127.0.0.1'), port=int(os.getenv('PORT', '8000')), debug=False)
