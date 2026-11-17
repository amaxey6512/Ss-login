import os, sqlite3, time, secrets, hmac
from flask import Flask, request, session, redirect, render_template_string, abort
from werkzeug.security import generate_password_hash, check_password_hash
app=Flask(__name__)
app.secret_key=os.environ['SESSION_SECRET']
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE='Strict')
DB=os.getenv('DB_PATH','accounts.db')
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
with db() as c:
    c.execute('CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password TEXT NOT NULL, expires INTEGER, active INTEGER NOT NULL)')
def csrf():
    if 'csrf' not in session: session['csrf']=secrets.token_hex(32)
    return session['csrf']
@app.before_request
def protect():
    if request.method=='POST' and not hmac.compare_digest(session.get('csrf','!'),request.form.get('csrf','')): abort(403)
STYLE='''<meta name="viewport" content="width=device-width,initial-scale=1"><style>body{background:#080b08;color:#e6f1e4;font:16px system-ui;max-width:540px;margin:40px auto;padding:20px}h1,h2{color:#65ff32}input,select,button{box-sizing:border-box;width:100%;padding:13px;margin:8px 0;border:1px solid #527047;border-radius:8px;background:#111b11;color:white;font:inherit}button{background:#65ff32;color:#080b08;font-weight:bold}article{border:1px solid #395333;padding:14px;margin:12px 0;border-radius:10px}a{color:#65ff32}</style>'''
def page(body,**kw): return render_template_string(STYLE+body,csrf=csrf(),**kw)
@app.route('/',methods=['GET','POST'])
def login():
    message=''
    if request.method=='POST':
        with db() as c: u=c.execute('SELECT * FROM users WHERE name=?',(request.form.get('name','').lower(),)).fetchone()
        if u and check_password_hash(u['password'],request.form.get('password','')) and u['active'] and (u['expires'] is None or u['expires']>time.time()):
            session.clear(); session['user']=u['name']; return redirect('/access')
        message='Invalid credentials or access expired/revoked.'
    return page('''<h1>SS LOGIN</h1><p>Authorized users only</p><form method=post><input type=hidden name=csrf value="{{csrf}}"><input name=name placeholder=Username required maxlength=64><input name=password type=password placeholder=Password required maxlength=256><button>Login</button></form><p>{{message}}</p>''',message=message)
@app.get('/access')
def access():
    with db() as c: u=c.execute('SELECT * FROM users WHERE name=?',(session.get('user',''),)).fetchone()
    if not u or not u['active'] or (u['expires'] is not None and u['expires']<=time.time()): session.clear(); return redirect('/')
    return page('<h1>Access granted</h1><p>Welcome {{name}}. This is a standalone authentication test.</p><form method=post action=/logout><input type=hidden name=csrf value="{{csrf}}"><button>Logout</button></form>',name=u['name'])
@app.post('/logout')
def logout(): session.clear(); return redirect('/')
@app.route('/admin',methods=['GET','POST'])
def admin():
    if request.method=='POST' and not session.get('admin'):
        if hmac.compare_digest(request.form.get('password',''),os.environ['ADMIN_PASSWORD']): session.clear(); session['admin']=True; return redirect('/admin')
    if not session.get('admin'): return page('<h1>SS ADMIN</h1><form method=post><input type=hidden name=csrf value="{{csrf}}"><input type=password name=password placeholder="Owner password" required><button>Sign in</button></form>')
    message=''
    if request.method=='POST':
        name=request.form.get('name','').strip().lower(); action=request.form.get('action')
        with db() as c:
            if action=='create':
                password=request.form.get('password',''); days=request.form.get('days')
                if not name or len(name)>64 or len(password)<12 or len(password)>256 or days not in ['1','7','30','365','life']: message='Invalid input; password needs 12+ characters.'
                else:
                    try: c.execute('INSERT INTO users VALUES (?,?,?,1)',(name,generate_password_hash(password),None if days=='life' else int(time.time())+int(days)*86400))
                    except sqlite3.IntegrityError: message='Username already exists.'
            elif action in ('revoke','restore'): c.execute('UPDATE users SET active=? WHERE name=?',(int(action=='restore'),name))
    with db() as c: users=c.execute('SELECT name,expires,active FROM users ORDER BY name').fetchall()
    return page('''<h1>SS ADMIN</h1><h2>Grant access</h2><form method=post><input type=hidden name=csrf value="{{csrf}}"><input type=hidden name=action value=create><input name=name required placeholder=Username maxlength=64><input name=password type=password required minlength=12 placeholder="Temporary password"><select name=days><option>1</option><option>7</option><option selected>30</option><option>365</option><option value=life>Lifetime</option></select><button>Create account</button></form><p>{{message}}</p><h2>Accounts</h2>{% for u in users %}<article><b>{{u.name}}</b><p>{{'Revoked' if not u.active else 'Expired' if u.expires and u.expires<=now else 'Active'}} · {{fmt(u.expires)}}</p><form method=post><input type=hidden name=csrf value="{{csrf}}"><input type=hidden name=name value="{{u.name}}"><button name=action value="{{'revoke' if u.active else 'restore'}}">{{'Revoke' if u.active else 'Restore'}}</button></form></article>{% endfor %}<form method=post action=/logout><input type=hidden name=csrf value="{{csrf}}"><button>Sign out</button></form>''',users=users,now=time.time(),fmt=lambda t: time.strftime('%Y-%m-%d %H:%M UTC',time.gmtime(t)) if t else 'Lifetime',message=message)
