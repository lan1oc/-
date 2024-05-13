# 使用官方 Python 运行时作为父镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 将当前目录中的文件复制到工作目录中
COPY . .

#设置一个等待服务
COPY wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh


# 安装依赖包
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 暴露端口
EXPOSE 5000

# 启动应用

CMD ["/wait-for-it.sh", "db:3306", "--", "bash", "-c", "python3 -u app.py"]