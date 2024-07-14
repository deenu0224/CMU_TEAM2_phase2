from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/send', methods=['POST'])
def send():
    # 파이썬 스크립트를 실행합니다.
    subprocess.Popen(['python', 'vpn.py'])
    return 'Packets sent successfully!'

if __name__ == '__main__':
    # '0.0.0.0'을 사용하면 서버가 모든 IP 주소에서 접근 가능하게 됩니다.
    # 원하는 IP와 포트로 변경할 수 있습니다.
    app.run(host='192.168.0.127', port=5000, debug=True)
