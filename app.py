from flask import Flask, request, jsonify, render_template, g, session, redirect, url_for
import sqlite3, os, hashlib, secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
DB_PATH = os.path.join(os.path.dirname(__file__), 'timeblock.db')

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                date        TEXT    NOT NULL,
                start_slot  INTEGER NOT NULL,
                span        INTEGER NOT NULL DEFAULT 1,
                title       TEXT    NOT NULL DEFAULT '',
                note        TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_date ON events(date);

            CREATE TABLE IF NOT EXISTS auth (
                id          INTEGER PRIMARY KEY CHECK (id = 1),
                salt        TEXT    NOT NULL,
                hash        TEXT    NOT NULL
            );
        """)

def is_authenticated():
    return session.get('authed') is True

def password_is_set():
    row = get_db().execute('SELECT id FROM auth WHERE id=1').fetchone()
    return row is not None

# ── Auth routes ────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        password = data.get('password', '')
        db = get_db()

        if not password_is_set():
            # First run: set the password
            salt = secrets.token_hex(16)
            h = hash_password(password, salt)
            db.execute('INSERT INTO auth(id, salt, hash) VALUES(1,?,?)', (salt, h))
            db.commit()
            session['authed'] = True
            return jsonify({'ok': True, 'setup': True})

        row = db.execute('SELECT salt, hash FROM auth WHERE id=1').fetchone()
        if hash_password(password, row['salt']) == row['hash']:
            session['authed'] = True
            return jsonify({'ok': True})
        return jsonify({'ok': False, 'error': 'Wrong password'}), 401

    return render_template('index.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/auth/change-password', methods=['POST'])
def change_password():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    current = data.get('current', '')
    new_pw  = data.get('new', '')
    if not new_pw:
        return jsonify({'error': 'New password required'}), 400
    db = get_db()
    row = db.execute('SELECT salt, hash FROM auth WHERE id=1').fetchone()
    if row and hash_password(current, row['salt']) != row['hash']:
        return jsonify({'error': 'Wrong current password'}), 401
    salt = secrets.token_hex(16)
    h = hash_password(new_pw, salt)
    db.execute('UPDATE auth SET salt=?, hash=? WHERE id=1', (salt, h))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/auth/status')
def auth_status():
    return jsonify({
        'authed': is_authenticated(),
        'setup': password_is_set()
    })

# ── App routes ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

def require_auth():
    if not is_authenticated():
        return jsonify({'error': 'Unauthorized'}), 401
    return None

@app.route('/api/day/<date>')
def get_day(date):
    err = require_auth()
    if err: return err
    rows = get_db().execute(
        'SELECT id, start_slot, span, title, note FROM events WHERE date=? ORDER BY start_slot',
        (date,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/event', methods=['POST'])
def create_event():
    err = require_auth()
    if err: return err
    d = request.get_json()
    db = get_db()
    cur = db.execute(
        'INSERT INTO events(date,start_slot,span,title,note) VALUES(?,?,?,?,?)',
        (d['date'], int(d['start_slot']), int(d.get('span',1)),
         d.get('title','').strip(), d.get('note','').strip())
    )
    db.commit()
    return jsonify({'ok': True, 'id': cur.lastrowid})

@app.route('/api/event/<int:eid>', methods=['PUT'])
def update_event(eid):
    err = require_auth()
    if err: return err
    d = request.get_json()
    db = get_db()
    fields, vals = [], []
    for col in ('title', 'note', 'span', 'start_slot'):
        if col in d:
            fields.append(f'{col}=?')
            vals.append(d[col])
    vals.append(eid)
    db.execute(f'UPDATE events SET {", ".join(fields)} WHERE id=?', vals)
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/event/<int:eid>', methods=['DELETE'])
def delete_event(eid):
    err = require_auth()
    if err: return err
    get_db().execute('DELETE FROM events WHERE id=?', (eid,))
    get_db().commit()
    return jsonify({'ok': True})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5050)