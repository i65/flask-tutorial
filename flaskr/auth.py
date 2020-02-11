import functools

from flask import (
  Blueprint, g, redirect, flash, render_template, url_for, session, request
)

from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

# 注册视图
@bp.route('/register', methods=['GET', 'POST'])
def register():
  if request.method == 'POST':
    username = request.form['username']
    password = request.form['password']
    db = get_db()
    error = None

    if not username:
      error = 'Username is required!'
    elif not password:
      error = 'Password is required!'
    elif db.execute(
      'SELECT id FROM user WHERE username = ?', (username, )
    ).fetchone() is not None:
      error = 'User {} is already registed!'.format(username)

    if error is None:
      db.execute(
        'INSERT INTO user (username, password) VALUES (?, ?)', (username, generate_password_hash(password))
      )
      db.commit()
      return redirect(url_for('auth.login'))
    flash(error)
  return render_template('auth/register.html')


# 登录视图
@bp.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    username = request.form['username']
    password = request.form['password']
    db = get_db()
    error = None
    user = db.execute(
      'SELECT * FROM user WHERE username = ?', (username,)
    ).fetchone()

    if user is None:
      error = 'Incorrect username!'
    elif not check_password_hash(user['password'], password):
      error = 'Incorrect password!'
    
    if error is None:
      session.clear()
      session['user_id'] = user['id']

      return redirect(url_for('index'))

    flash(error)
  return render_template('auth/login.html')

# 注册一个 在视图函数之前运行的函数，不论其 URL 是什么
@bp.before_app_request
def load_logged_in_user():
  user_id = session.get('user_id')

  if user_id is None:
    g.user = None
  else:
    g.user = get_db().execute(
      'SELECT * FROM user WHERE id = ?', (user_id, )
    ).fetchone()

# 退出登录
@bp.route('/logout')
def logout():
  session.clear()
  return redirect(url_for('index'))

# 登录验证
def login_required(view):
  @functools.wraps(view)
  def wrapped_view(**kwargs):
    if g.user is None:
      return redirect(url_for('auth.login'))
    
    return view(**kwargs)
  
  return wrapped_view


  
