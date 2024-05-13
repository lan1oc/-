from flask import Flask, request, jsonify, render_template, send_from_directory, redirect, session, url_for
from flask_socketio import join_room, leave_room, send, SocketIO
import mysql.connector
import random
from string import ascii_uppercase
from sm2 import *
from sm2_k import *

# SM4加密
def sm4_encode(key, data):
    sm4Alg = CryptSM4()  # 实例化sm4
    sm4Alg.set_key(key.encode(), SM4_ENCRYPT)  # 设置密钥
    dateStr = str(data)
    print("明文:", dateStr);
    enRes = sm4Alg.crypt_ecb(dateStr.encode())  # 开始加密,bytes类型，ecb模式
    enHexStr = enRes.hex()
    print("密文:", enHexStr);
    return enHexStr # 返回十六进制值

#SM4解密
def sm4_decode(key, data):
    sm4Alg = CryptSM4()  # 实例化sm4
    sm4Alg.set_key(key.encode(), SM4_DECRYPT)  # 设置密钥
    deRes = sm4Alg.crypt_ecb(bytes.fromhex(data))  # 开始解密。十六进制类型,ecb模式
    deHexStr = deRes.decode()
    print("解密后明文:", deRes);
    print("解密后明文hex:", deHexStr);
    return deHexStr

app = Flask(__name__)

# 设置密钥用于 session
app.secret_key = 'lan1oc'

#将套接字与flask应用关联
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

# 连接MySQL数据库
db = mysql.connector.connect(
    host="localhost",
    port="3306",
    user="root",
    password="Joker1412"
)

# 创建数据库和表结构
def create_database_and_tables():
    global db  # 引用全局变量 db

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
    global db  # 引用全局变量 db
    if db is None:
        create_database_and_tables()  # 如果数据库未连接，再次尝试创建数据库和表

    cursor = db.cursor()

    data = request.form
    username = data.get('username')
    password = data.get('password')

    # 检查用户名是否已存在
    check_query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(check_query, (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        jsonify({"message": "注册失败"}), 401
        return render_template("register.html", error="用户名已存在.")
    # 在数据库中插入新用户信息
    insert_query = "INSERT INTO users (username, password) VALUES (%s, %s)"
    cursor = db.cursor()
    cursor.execute(insert_query, (username, password))
    db.commit()

    # 自动登录并跳转到 chat 路由
    session['username'] = username
    jsonify({"message": "注册成功", "redirect": "/chat"})
    return redirect('/chat')

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

    # 查询数据库验证用户信息
    select_query = "SELECT * FROM users WHERE username = %s AND password = %s"
    cursor = db.cursor()
    cursor.execute(select_query, (username, password))
    user = cursor.fetchone()

    if user:
        # 登录成功，设置会话并跳转到 chat 路由
        session['username'] = username


        jsonify({"message": "登录成功", "redirect": "/chat"})
        return redirect('/chat')

    else:
        # 登录失败，返回失败消息
        jsonify({"message": "登录失败"}), 401
        return render_template("login.html", error="账户不存在.")


#聊天室主页
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
            jsonify({"message": "阿巴阿巴"}), 401
            return redirect('/')

        if join != False and not code:
            return render_template("home.html", error="请输入房号.", code=code, name=name)

        room = code
        if create != False:
            room = generate_unique_code(4)
            rooms[room] = {"members": 0, "messages": [], "members_name": []}
        elif code not in rooms:
            return render_template("home.html", error="聊天室不存在.", code=code, name=name)

        session["room"] = room
        return redirect('/room')

    return render_template("home.html")

#聊天室
@app.route("/room")
def room():
    name = session.get("username")
    room = session.get("room")
    if room is None or name is None or room not in rooms:
        return redirect(url_for("home"))
    return render_template("room.html", code=room, messages=rooms[room]["messages"], count=rooms[room]["members"],list=rooms[room]["members_name"])


@socketio.on("message")
def message(data):
    room = session.get("room")
    if room not in rooms:
        return
    if rooms[room]["members"] > 1:
    # 协商的密钥（sm4）
        global key

    #单人时的测试密钥
    key="cb851b18e4b6b239414f5a7c24a72536"

    #sm2
    SM2_PRIVATE_KEY1, SM2_PUBLIC_KEY1 = create_key_pair()
    sm2_crypt1 = CryptSM2(public_key=SM2_PUBLIC_KEY1, private_key=SM2_PRIVATE_KEY1)

    content = {
        "name": session.get("username"),
        "message": data["data"]
    }

    # SM4加密消息
    enHexRes = sm4_encode(key,str(data["data"]));
    sm4_decode(key, enHexRes);

    #sm2 签名
    a = data["data"].encode('utf-8')
    b = sm2_crypt1.sign_with_sm3(a)
    print("签名：", b)
    print("验证结果：", sm2_crypt1.verify_with_sm3(b, data["data"].encode('utf-8')))

    send(content, to=room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('username')} said: {data['data']}")

@socketio.on("connect")
def connect(auth):
    global key
    room = session.get("room")
    name = session.get("username")
    rooms[room]["members_name"].append(name)
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return

    join_room(room)
    send({"name": name, "message": "已加入聊天室"}, to=room)
    rooms[room]["members"] += 1
    print(f"{name} 已加入聊天室 {room}")
    # 当房间内人数大于1时，开始进行密钥协商
    if rooms[room]["members"] > 1:
        members_name = rooms[room]["members_name"]
        if rooms[room]["members"] == 2:
            print("双人协商")
            a = SM2(ID=members_name[0])
            b = SM2(ID=members_name[1])
            key=test_SM2_agreement(a, b, True)
        elif rooms[room]["members"] > 2:
            print("双人以上的协商\n")
            n = rooms[room]["members"] // 2
            # 取前 n 个成员名连接成字符串
            a_part = ''.join(members_name[:n])
            # 取从第 n 个成员名到最后一个成员名连接成字符串
            b_part = ''.join(members_name[n:])
            a = SM2(ID=a_part)
            b = SM2(ID=b_part)
            key = test_SM2_agreement(a, b, True)

    # 更新在线人数列表并发送给前端
    update_user_list(room)

def update_user_list(room):
    members_count = rooms[room]["members"]
    members_name = rooms[room]["members_name"]
    socketio.emit("Count", members_count, room=room)
    socketio.emit("List", members_name, room=room)

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("username")
    leave_room(room)

    if room in rooms:
        # 如果用户在房间中，将其从 members_name 列表中删除
        if name in rooms[room]["members_name"]:
            rooms[room]["members_name"].remove(name)
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
        print()

    send({"name": name, "message": "已离开房间"}, to=room)
    update_user_list(room)
    print(f"{name} 已离开房间 {room}")


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000,debug=True, allow_unsafe_werkzeug=True)
