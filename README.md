# MCP 표준 Suricata 서버 설치 가이드

## 🏗️ 아키텍처

```
[Suricata IDS] → [MCP Server] → [Claude AI / MCP Client] → [자동 대응]
                   (표준 프로토콜)
```

## 📦 1단계: 환경 설정

### uv 설치

```bash
# uv 설치
curl -LsSf https://astral.sh/uv/install.sh | sh

# 쉘 재시작 또는 환경변수 로드
source ~/.bashrc
# 또는
source ~/.zshrc

# 설치 확인
uv --version
```

### 프로젝트 설정

```bash
# 프로젝트 디렉토리
cd ~/suricata-automation

# Python 가상환경 생성
uv venv

# 가상환경 활성화
source .venv/bin/activate

# MCP SDK 설치
uv pip install mcp

# 필요한 다른 패키지
uv pip install asyncio
```

## 📝 2단계: 서버 파일 저장

```bash
# MCP 서버 저장
nano mcp_suricata_server.py
# (위의 코드 붙여넣기)

# 실행 권한
chmod +x mcp_suricata_server.py
```

## 🚀 3단계: 서버 실행

### 방법 1: 직접 실행

```bash
# 가상환경 활성화된 상태에서
python3 mcp_suricata_server.py
```

### 방법 2: uv로 실행

```bash
uv run mcp_suricata_server.py
```

## 🔌 4단계: MCP 클라이언트 연결

### Claude Desktop 설정

Claude Desktop에서 사용하려면:

**`~/Library/Application Support/Claude/claude_desktop_config.json`** (macOS)  
또는  
**`%APPDATA%\Claude\claude_desktop_config.json`** (Windows)

```json
{
  "mcpServers": {
    "suricata": {
      "command": "python3",
      "args": [
        "/home/youruser/suricata-automation/mcp_suricata_server.py"
      ],
      "env": {
        "PYTHONPATH": "/home/youruser/suricata-automation/.venv/lib/python3.x/site-packages"
      }
    }
  }
}
```

### Python MCP 클라이언트 예제

```python
#!/usr/bin/env python3
"""
MCP 클라이언트 - Suricata 서버와 통신
"""

import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(
        command="python3",
        args=["mcp_suricata_server.py"],
        env=None
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # 도구 목록 가져오기
            tools = await session.list_tools()
            print("Available tools:")
            for tool in tools.tools:
                print(f"  - {tool.name}: {tool.description}")
            
            # 최근 알림 가져오기
            result = await session.call_tool(
                "get_recent_alerts",
                arguments={"count": 5}
            )
            print("\nRecent alerts:")
            print(result.content[0].text)
            
            # 통계 가져오기
            result = await session.call_tool(
                "get_alert_stats",
                arguments={}
            )
            print("\nStatistics:")
            print(result.content[0].text)

if __name__ == "__main__":
    asyncio.run(main())
```

저장 후 실행:
```bash
python3 mcp_client_example.py
```

## 🛠️ MCP 서버가 제공하는 기능

### 리소스 (Resources)

1. **`suricata://alerts`**: 최근 보안 알림
2. **`suricata://blocked_ips`**: 차단된 IP 목록

### 도구 (Tools)

1. **`get_recent_alerts`**: 최근 알림 조회
   ```json
   {
     "count": 10,
     "severity": 1
   }
   ```

2. **`block_ip`**: IP 차단
   ```json
   {
     "ip": "192.168.1.100",
     "reason": "Malicious activity"
   }
   ```

3. **`get_alert_stats`**: 통계 조회
   ```json
   {}
   ```

4. **`search_alerts`**: 알림 검색
   ```json
   {
     "query": "192.168.1.100"
   }
   ```

## 🧪 테스트

### 서버 시작
```bash
cd ~/suricata-automation
source .venv/bin/activate
python3 mcp_suricata_server.py
```

### 다른 터미널에서 트래픽 생성
```bash
# ICMP 테스트
ping -c 5 8.8.8.8

# HTTP 테스트
curl http://testmynids.org/uid/index.html
```

### 로그 확인
```bash
# Suricata 로그
sudo tail -f /var/log/suricata/eve.json

# MCP 서버 출력 확인
# (서버 실행 중인 터미널에서)
```

## 📊 MCP Inspector로 테스트

MCP Inspector는 MCP 서버를 테스트하는 공식 도구예요:

```bash
# MCP Inspector 설치
npm install -g @modelcontextprotocol/inspector

# 서버 테스트
mcp-inspector python3 mcp_suricata_server.py
```

브라우저가 열리면서 GUI에서 도구를 테스트할 수 있어요.

## 🔧 문제 해결

### "Module 'mcp' not found"
```bash
# 가상환경 활성화 확인
source .venv/bin/activate

# MCP 재설치
uv pip install --force-reinstall mcp
```

### "Permission denied" (iptables)
```bash
# sudoers 파일에 추가 (조심해서!)
sudo visudo

# 다음 줄 추가:
youruser ALL=(ALL) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables
```

### Suricata 로그 권한
```bash
# 로그 읽기 권한
sudo chmod 644 /var/log/suricata/eve.json

# 또는 사용자 추가
sudo usermod -a -G adm $USER
```

## 🔄 Systemd 서비스 등록

```bash
sudo nano /etc/systemd/system/suricata-mcp.service
```

```ini
[Unit]
Description=Suricata MCP Server
After=network.target suricata.service

[Service]
Type=simple
User=root
WorkingDirectory=/home/youruser/suricata-automation
Environment="PATH=/home/youruser/suricata-automation/.venv/bin:/usr/bin"
ExecStart=/home/youruser/suricata-automation/.venv/bin/python3 /home/youruser/suricata-automation/mcp_suricata_server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# 서비스 등록
sudo systemctl daemon-reload
sudo systemctl enable suricata-mcp
sudo systemctl start suricata-mcp

# 상태 확인
sudo systemctl status suricata-mcp

# 로그 확인
sudo journalctl -u suricata-mcp -f
```

## 📚 MCP 표준 vs 커스텀 방식

### MCP 표준 방식 (지금)
- ✅ AI와 표준화된 통신
- ✅ Claude, 다른 AI 에이전트 연동 가능
- ✅ 도구/리소스 표준 인터페이스
- ❌ 설정이 복잡함

### 커스텀 방식 (이전)
- ✅ 간단한 구현
- ✅ 빠른 프로토타이핑
- ❌ AI 연동 어려움
- ❌ 표준화 안됨

## 🎯 다음 단계

1. **AI 연동**: Claude Desktop에서 Suricata 알림 조회
2. **자동화**: AI가 자동으로 위협 분석하고 차단 결정
3. **확장**: 더 많은 도구 추가 (unblock_ip, add_rule 등)
4. **대시보드**: 웹 UI 추가

## 📖 참고 자료

- MCP 공식 문서: https://modelcontextprotocol.io/
- MCP Python SDK: https://github.com/modelcontextprotocol/python-sdk
- Suricata 문서: https://suricata.io/