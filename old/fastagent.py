#!/usr/bin/env python3
"""
FastAgent - Suricata 탐지 이벤트를 분석하고 자동 대응하는 Agent
FastMCP로부터 이벤트를 받아 위협을 분석하고 필요시 차단
"""

import json
import asyncio
import subprocess
from datetime import datetime
from typing import Dict, List, Set
from collections import defaultdict
import re

class FastAgent:
    def __init__(self, 
                 mcp_host: str = "localhost",
                 mcp_port: int = 9000,
                 auto_block: bool = False):
        self.mcp_host = mcp_host
        self.mcp_port = mcp_port
        self.auto_block = auto_block
        
        # 통계 및 상태
        self.alert_count = 0
        self.blocked_ips: Set[str] = set()
        self.ip_alert_history = defaultdict(list)
        
        # 차단 임계값
        self.block_threshold = 5  # 5번 이상 탐지시 차단
        self.time_window = 300  # 5분 이내
        
    async def connect_to_mcp(self):
        """FastMCP 서버에 연결"""
        while True:
            try:
                print(f"[FastAgent] Connecting to FastMCP at {self.mcp_host}:{self.mcp_port}")
                reader, writer = await asyncio.open_connection(
                    self.mcp_host, self.mcp_port
                )
                print("[FastAgent] Connected to FastMCP")
                return reader, writer
            except Exception as e:
                print(f"[FastAgent] Connection failed: {e}")
                print("[FastAgent] Retrying in 5 seconds...")
                await asyncio.sleep(5)
    
    def analyze_severity(self, alert: Dict) -> str:
        """알림 심각도 분석"""
        severity = alert.get('severity', 3)
        category = alert.get('category', '').lower()
        signature = alert.get('signature', '').lower()
        
        # 심각도 레벨 결정
        if severity == 1:
            return 'CRITICAL'
        elif severity == 2:
            return 'HIGH'
        elif 'exploit' in signature or 'attack' in signature:
            return 'HIGH'
        elif 'scan' in signature or 'probe' in signature:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def should_block_ip(self, source_ip: str, alert: Dict) -> bool:
        """IP 차단 여부 결정"""
        if not self.auto_block:
            return False
        
        # 현재 시간
        current_time = datetime.now().timestamp()
        
        # 히스토리에 추가
        self.ip_alert_history[source_ip].append({
            'timestamp': current_time,
            'alert': alert
        })
        
        # 시간 윈도우 내의 알림만 필터링
        recent_alerts = [
            a for a in self.ip_alert_history[source_ip]
            if current_time - a['timestamp'] < self.time_window
        ]
        self.ip_alert_history[source_ip] = recent_alerts
        
        # 임계값 초과 확인
        if len(recent_alerts) >= self.block_threshold:
            return True
        
        # Critical 알림은 즉시 차단
        severity = self.analyze_severity(alert)
        if severity == 'CRITICAL':
            return True
        
        return False
    
    def is_ipv6(self, ip: str) -> bool:
        """IPv6 주소인지 확인"""
        return ':' in ip
    
    async def block_ip(self, ip: str, reason: str):
        """IP 주소 차단 (iptables/ip6tables 사용)"""
        if ip in self.blocked_ips:
            print(f"[FastAgent] IP {ip} already blocked")
            return
        
        try:
            # IPv6인지 IPv4인지 확인
            if self.is_ipv6(ip):
                # IPv6는 ip6tables 사용
                cmd = ['sudo', 'ip6tables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
            else:
                # IPv4는 iptables 사용
                cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                ip_type = "IPv6" if self.is_ipv6(ip) else "IPv4"
                print(f"[FastAgent] 🚫 BLOCKED ({ip_type}): {ip} - Reason: {reason}")
                
                # 로그 파일에 기록
                with open('/var/log/fastagent_blocks.log', 'a') as f:
                    f.write(f"{datetime.now().isoformat()} | BLOCKED | {ip_type} | {ip} | {reason}\n")
            else:
                print(f"[FastAgent] Failed to block {ip}: {result.stderr}")
                
        except Exception as e:
            print(f"[FastAgent] Error blocking IP {ip}: {e}")
    
    async def process_alert(self, alert_data: Dict):
        """알림 처리 및 대응"""
        self.alert_count += 1
        
        source_ip = alert_data.get('source_ip', 'unknown')
        dest_ip = alert_data.get('dest_ip', 'unknown')
        signature = alert_data.get('signature', 'unknown')
        severity = self.analyze_severity(alert_data)
        
        # 알림 출력
        print(f"\n[FastAgent] ⚠️  Alert #{self.alert_count}")
        print(f"  Severity: {severity}")
        print(f"  Source: {source_ip}:{alert_data.get('source_port', '?')}")
        print(f"  Dest: {dest_ip}:{alert_data.get('dest_port', '?')}")
        print(f"  Signature: {signature}")
        print(f"  Category: {alert_data.get('category', 'unknown')}")
        
        # 차단 결정
        if self.should_block_ip(source_ip, alert_data):
            await self.block_ip(source_ip, signature)
        
        # 통계 출력
        print(f"  Total alerts: {self.alert_count} | Blocked IPs: {len(self.blocked_ips)}")
    
    async def send_heartbeat(self, writer):
        """주기적으로 heartbeat 전송"""
        while True:
            try:
                message = json.dumps({'type': 'ping'}) + '\n'
                writer.write(message.encode())
                await writer.drain()
                await asyncio.sleep(30)
            except Exception as e:
                print(f"[FastAgent] Heartbeat failed: {e}")
                break
    
    async def run(self):
        """FastAgent 실행"""
        print("[FastAgent] Starting...")
        print(f"[FastAgent] Auto-block mode: {'ENABLED' if self.auto_block else 'DISABLED'}")
        
        while True:
            try:
                reader, writer = await self.connect_to_mcp()
                
                # Heartbeat 태스크 시작
                heartbeat_task = asyncio.create_task(self.send_heartbeat(writer))
                
                # 메시지 수신
                while True:
                    data = await reader.readline()
                    if not data:
                        print("[FastAgent] Connection closed by server")
                        break
                    
                    try:
                        message = json.loads(data.decode())
                        
                        if message.get('type') == 'alert':
                            alert_data = message.get('data', {})
                            await self.process_alert(alert_data)
                            
                    except json.JSONDecodeError:
                        print(f"[FastAgent] Invalid message: {data[:50]}")
                    except Exception as e:
                        print(f"[FastAgent] Error processing message: {e}")
                
                heartbeat_task.cancel()
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                print(f"[FastAgent] Connection error: {e}")
            
            print("[FastAgent] Reconnecting in 5 seconds...")
            await asyncio.sleep(5)


async def main():
    """메인 함수"""
    # Agent 생성
    agent = FastAgent(
        mcp_host="localhost",  # FastMCP 서버 주소
        mcp_port=9000,         # FastMCP 서버 포트
        auto_block=True        # 자동 차단 활성화 (테스트시 False 권장)
    )
    
    try:
        await agent.run()
    except KeyboardInterrupt:
        print("\n[FastAgent] Shutting down...")


if __name__ == "__main__":
    asyncio.run(main())