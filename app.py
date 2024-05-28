from flask import Flask, request, jsonify, render_template, send_from_directory, redirect, session, url_for
from flask_socketio import join_room, leave_room, send, SocketIO
import mysql.connector
import os
import random
import logging
from string import ascii_uppercase
from sm2 import *
from sm2_k import *
import time

app = Flask(__name__)
app.logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
app.logger.addHandler(handler)

# SM4加密
def sm4_encode(key, data):
    sm4Alg = CryptSM4()  # 实例化sm4
    sm4Alg.set_key(key.encode(), SM4_ENCRYPT)  # 设置密钥
    dateStr = str(data)
    app.logger.info("明文:%s", dateStr)
    enRes = sm4Alg.crypt_ecb(dateStr.encode())  # 开始加密,bytes类型，ecb模式
    enHexStr = enRes.hex()
    app.logger.info("密文:%s", enHexStr)
    return enHexStr  # 返回十六进制值

# SM4解密
def sm4_decode(key, data):
    sm4Alg = CryptSM4()  # 实例化sm4
    sm4Alg.set_key(key.encode(), SM4_DECRYPT)  # 设置密钥
    deRes = sm4Alg.crypt_ecb(bytes.fromhex(data))  # 开始解密。十六进制类型,ecb模式
    deHexStr = deRes.decode()
    app.logger.info("解密后明文:%s", deRes)
    app.logger.info("解密后明文hex:%s", deHexStr)
    return deHexStr

# 设置密钥用于 session
app.secret_key = 'lan1oc'

# 将套接字与flask应用关联
socketio = SocketIO(app)

# 存储聊天室信息的字典，包括聊天室成员数量和消息列表
rooms = {}

# 存储协商的密钥
key = None

# 生成指定长度的房间码
def generate_unique_code(length):
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)

        if code not in rooms:
            break

    return code

# 获取MySQL数据库连接
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', 'root'),
        database=os.getenv('DB_DATABASE', 'test')
    )

# 创建数据库和表结构
def create_database_and_tables():
    while True:
        try:
            db = get_db_connection()
            app.logger.info("Database connection successful!")
            break  # 如果连接成功，跳出循环
        except mysql.connector.Error as err:
            app.logger.info("Error connecting to MySQL: %s", err)
            app.logger.info("Waiting for 1 second before trying again.")
            time.sleep(7)  # 如果连接失败，等待1秒后再次尝试

    cursor = db.cursor()

    # 检查是否存在 test 数据库，如果不存在则创建
    cursor.execute("SHOW DATABASES")
    databases = cursor.fetchall()
    databases = [db[0] for db in databases]

    if 'test' not in databases:
        cursor.execute("CREATE DATABASE test")

    # 切换到 test 数据库
    cursor.execute("USE test")

    # 检查是否存在 users 表，如果不存在则创建
    cursor.execute("SHOW TABLES LIKE 'users'")
    tables = cursor.fetchall()
    if not tables:
        cursor.execute(
            "CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255))")
        db.commit()

    cursor.close()
    db.close()

# 初始化数据库和表结构
create_database_and_tables()

# 配置静态文件夹
app.static_folder = 'static'

# 提供静态文件的路由
@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

# 根路由，返回 index.html 页面
@app.route('/')
def index():
    return render_template('index.html')

# 注册路由，返回注册页面
@app.route('/register', methods=['GET'])
def show_register_form():
    return render_template('register.html')

# 处理注册请求
@app.route('/register', methods=['POST'])
def register():
    data = request.form
    username = data.get('username')
    password = data.get('password')

    try:
        db = get_db_connection()
        cursor = db.cursor()

        # 检查用户名是否已存在
        check_query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(check_query, (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return render_template("register.html", error="用户名已存在.")
        
        # 在数据库中插入新用户信息
        insert_query = "INSERT INTO users (username, password) VALUES (%s, %s)"
        cursor.execute(insert_query, (username, password))
        db.commit()

        # 自动登录并跳转到 chat 路由
        session['username'] = username
        return redirect('/chat')
    
    except mysql.connector.Error as err:
        app.logger.error("Database error: %s", err)
        return render_template("register.html", error="注册失败，请稍后再试。")
    
    finally:
        cursor.close()
        db.close()

# 登录路由，返回登录页面
@app.route('/login', methods=['GET'])
def show_login_form():
    return render_template('login.html')

# 处理登录请求
@app.route('/login', methods=['POST'])
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')

    try:
        db = get_db_connection()
        cursor = db.cursor()

        # 查询数据库验证用户信息
        select_query = "SELECT * FROM users WHERE username = %s AND password = %s"
        cursor.execute(select_query, (username, password))
        user = cursor.fetchone()

        if user:
            # 登录成功，设置会话并跳转到 chat 路由
            session['username'] = username
            return redirect('/chat')
        else:
            return render_template("login.html", error="账户不存在。")
    
    except mysql.connector.Error as err:
        app.logger.error("Database error: %s", err)
        return render_template("login.html", error="登录失败，请稍后再试。")
    
    finally:
        cursor.close()
        db.close()

# 聊天室主页
@app.route("/chat", methods=["POST", "GET"])
def home():
    # 获取会话中的用户名
    name = session.get("username")
    # 如果没有登录，重定向到主页
    if 'username' not in session:
        return redirect('/')
    if request.method == "GET":
        return render_template('home.html', name=name)

    if request.method == "POST":
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if not name:
            return redirect('/')

        if join and not code:
            return render_template("home.html", error="请输入房号。", code=code, name=name)

        room = code
        if create:
            room = generate_unique_code(4)
            rooms[room] = {"members": 0, "messages": [], "members_name": []}
        elif code not in rooms:
            return render_template("home.html", error="聊天室不存在。", code=code, name=name)

        session["room"] = room
        return redirect('/room')

    return render_template("home.html")

# 聊天室
@app.route("/room")
def room():
    name = session.get("username")
    room = session.get("room")
    if room is None or name is None or room not in rooms:
        return redirect(url_for("home"))
    return render_template("room.html", code=room, messages=rooms[room]["messages"], count=rooms[room]["members"], list=rooms[room]["members_name"])

@socketio.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return
    if rooms[room]["members"] > 1:
        # 协商的密钥（sm4）
        global key

    # 单人时的测试密钥
    key = "cb851b18e4b6b239414f5a7c24a72536"

    # sm2
    SM2_PRIVATE_KEY1, SM2_PUBLIC_KEY1 = create_key_pair()
    sm2_crypt1 = CryptSM2(public_key=SM2_PUBLIC_KEY1, private_key=SM2_PRIVATE_KEY1)

    content = {
        "name": session.get("username"),
        "message": data["data"]
    }

    # SM4加密消息
    enHexRes = sm4_encode(key, str(data["data"]))
    sm4_decode(key, enHexRes)
    content["message"] = enHexRes

    # SM2签名
    random_hex_str = random_hex(sm2_crypt1.para_len)
    sign = sm2_crypt1.sign(enHexRes, random_hex_str)
    app.logger.info("sign:%s", sign)
    content["sign"] = sign

    send(content, to=room)
    rooms[room]["messages"].append(content)

@socketio.on("connect")
def connect(auth):
    username = session.get("username")
    room = session.get("room")

    if not username or not room:
        return

    if room not in rooms:
        leave_room(room)
        return

    join_room(room)
    send({"name": username, "message": "进入了聊天室"}, to=room)
    rooms[room]["members"] += 1
    rooms[room]["members_name"].append(username)

    update_user_list(room)
    app.logger.info("%s joined room %s", username, room)

@socketio.on("disconnect")
def disconnect():
    username = session.get("username")
    room = session.get("room")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        rooms[room]["members_name"].remove(username)
        if rooms[room]["members"] <= 0:
            del rooms[room]

    send({"name": username, "message": "离开了聊天室"}, to=room)
    update_user_list(room)
    app.logger.info("%s disconnected from room %s", username, room)

# 更新在线用户列表
def update_user_list(room):
    if room in rooms:
        users_list = rooms[room]["members_name"]
        users_count = rooms[room]["members"]
        send({"count": users_count, "list": users_list}, to=room)
        app.logger.info("Online users in room %s: %s", room, users_list)

if __name__ == "__main__":
    socketio.run(app, port=404, debug=True)
