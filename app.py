from flask import Flask, request, jsonify, render_template, g
import sqlite3, os

app = Flask(__name__)
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
        """)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/day/<date>')
def get_day(date):
    rows = get_db().execute(
        'SELECT id, start_slot, span, title, note FROM events WHERE date=? ORDER BY start_slot',
        (date,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/event', methods=['POST'])
def create_event():
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
    get_db().execute('DELETE FROM events WHERE id=?', (eid,))
    get_db().commit()
    return jsonify({'ok': True})

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5050)
