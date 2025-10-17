# FastMCP & FastAgent 설치 및 실행 가이드

## 📋 시스템 구성

```
[Suricata IDS] → [FastMCP] → [FastAgent] → [iptables 차단]
     (탐지)       (통신)       (분석/대응)     (실행)
```

## 🔧 사전 요구사항

```bash
# Python 3.7 이상 필요
python3 --version

# Suricata가 이미 설치되어 있어야 함
suricata --version

# sudo 권한 필요 (iptables 사용)
```

## 📦 설치

### 1. 파일 저장

```bash
# 작업 디렉토리 생성
mkdir -p ~/suricata-automation
cd ~/suricata-automation

# FastMCP 저장
nano fastmcp.py
# (첫 번째 artifact 내용 복사)

# FastAgent 저장
nano fastagent.py
# (두 번째 artifact 내용 복사)

# 실행 권한 부여
chmod +x fastmcp.py fastagent.py
```

### 2. 로그 디렉토리 확인

```bash
# Suricata 로그 경로 확인
ls -l /var/log/suricata/eve.json

# 권한이 없다면 조정
sudo chmod 644 /var/log/suricata/eve.json
```

### 3. FastAgent 로그 디렉토리 준비

```bash
# 차단 로그 파일 생성
sudo touch /var/log/fastagent_blocks.log
sudo chmod 666 /var/log/fastagent_blocks.log
```

## 🚀 실행

### 터미널 1: FastMCP 서버 실행

```bash
cd ~/suricata-automation
python3 fastmcp.py
```

**출력 예시:**
```
[FastMCP] Starting...
[FastMCP] Monitoring: /var/log/suricata/eve.json
[FastMCP] Server started on ('0.0.0.0', 9000)
```

### 터미널 2: FastAgent 실행

```bash
cd ~/suricata-automation
python3 fastagent.py
```

**출력 예시:**
```
[FastAgent] Starting...
[FastAgent] Auto-block mode: ENABLED
[FastAgent] Connecting to FastMCP at localhost:9000
[FastAgent] Connected to FastMCP
```

## 🧪 테스트

### 1. Suricata 룰 테스트

```bash
# 테스트 룰 추가 (ICMP 탐지)
sudo nano /etc/suricata/rules/test.rules

# 다음 내용 추가:
alert icmp any any -> any any (msg:"ICMP Test Alert"; sid:1000001; rev:1;)

# Suricata 재시작
sudo systemctl restart suricata
```

### 2. 알림 생성

```bash
# 다른 터미널에서 ping 실행
ping -c 5 localhost
```

### 3. 결과 확인

**FastMCP 출력:**
```
[FastMCP] Alert detected: ICMP Test Alert
```

**FastAgent 출력:**
```
[FastAgent] ⚠️  Alert #1
  Severity: LOW
  Source: 127.0.0.1:0
  Dest: 127.0.0.1:0
  Signature: ICMP Test Alert
  Category: unknown
  Total alerts: 1 | Blocked IPs: 0
```

## ⚙️ 설정 조정

### FastMCP 설정 (fastmcp.py)

```python
mcp = FastMCP(
    eve_log_path="/var/log/suricata/eve.json",  # 로그 경로
    host="0.0.0.0",                              # 서버 IP
    port=9000                                    # 포트 번호
)
```

### FastAgent 설정 (fastagent.py)

```python
agent = FastAgent(
    mcp_host="localhost",    # FastMCP 서버 주소
    mcp_port=9000,          # FastMCP 포트
    auto_block=False        # ⚠️ 테스트시 False 권장!
)

# 차단 임계값 조정
self.block_threshold = 5     # N번 탐지시 차단
self.time_window = 300       # 시간 윈도우 (초)
```

## ⚠️ 중요 주의사항

### 자동 차단 기능

**`auto_block=True`로 설정하면 실제로 IP가 차단됩니다!**

- **테스트 환경**에서는 반드시 `auto_block=False`로 설정
- **프로덕션 환경**에서는 신중하게 활성화
- 차단된 IP는 수동으로 해제해야 함:

```bash
# 차단된 IP 확인
sudo iptables -L INPUT -n --line-numbers

# 특정 IP 차단 해제
sudo iptables -D INPUT <line_number>

# 모든 차단 규칙 초기화 (주의!)
sudo iptables -F INPUT
```

### 차단 로그 확인

```bash
# 차단된 IP 목록 확인
cat /var/log/fastagent_blocks.log

# 실시간 모니터링
tail -f /var/log/fastagent_blocks.log
```

## 🔍 모니터링

### 시스템 상태 확인

```bash
# FastMCP 프로세스 확인
ps aux | grep fastmcp

# FastAgent 프로세스 확인
ps aux | grep fastagent

# 네트워크 연결 확인
netstat -tlnp | grep 9000
```

### Suricata 로그 실시간 확인

```bash
# eve.json 모니터링
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

## 🔄 서비스로 등록 (선택사항)

### FastMCP Systemd 서비스

```bash
sudo nano /etc/systemd/system/fastmcp.service
```

```ini
[Unit]
Description=FastMCP - Suricata MCP Server
After=network.target suricata.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/youruser/suricata-automation
ExecStart=/usr/bin/python3 /home/youruser/suricata-automation/fastmcp.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### FastAgent Systemd 서비스

```bash
sudo nano /etc/systemd/system/fastagent.service
```

```ini
[Unit]
Description=FastAgent - Security Response Agent
After=network.target fastmcp.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/youruser/suricata-automation
ExecStart=/usr/bin/python3 /home/youruser/suricata-automation/fastagent.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### 서비스 활성화

```bash
# 서비스 등록
sudo systemctl daemon-reload

# 자동 시작 설정
sudo systemctl enable fastmcp
sudo systemctl enable fastagent

# 서비스 시작
sudo systemctl start fastmcp
sudo systemctl start fastagent

# 상태 확인
sudo systemctl status fastmcp
sudo systemctl status fastagent
```

## 🐛 문제 해결

### "Permission denied" 오류

```bash
# Suricata 로그 읽기 권한 부여
sudo chmod 644 /var/log/suricata/eve.json

# 또는 그룹에 사용자 추가
sudo usermod -a -G adm $USER
```

### "Connection refused" 오류

```bash
# FastMCP가 실행 중인지 확인
ps aux | grep fastmcp

# 방화벽 확인
sudo ufw status
sudo ufw allow 9000/tcp
```

### iptables 명령 실패

```bash
# sudo 권한 확인
sudo -v

# iptables 설치 확인
sudo apt install iptables
```

## 📚 다음 단계

1. **기능 확장**: 이메일 알림, Slack 연동 등
2. **ML 통합**: 이상 탐지 모델 추가
3. **대시보드**: 웹 UI로 시각화
4. **데이터베이스**: 이벤트 히스토리 저장

## 📖 참고 문서

- Suricata 공식 문서: https://suricata.io/
- Python asyncio: https://docs.python.org/3/library/asyncio.html
- iptables 가이드: https://www.netfilter.org/