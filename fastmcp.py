#!/usr/bin/env python3
"""
FastMCP - Suricata와 AI Agent를 연결하는 MCP 서버
Suricata의 eve.json 로그를 실시간으로 모니터링하고 이벤트를 전달
"""

import json
import time
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import socket

class FastMCP:
    def __init__(self, 
                 eve_log_path: str = "/var/log/suricata/eve.json",
                 host: str = "localhost",
                 port: int = 9000):
        self.eve_log_path = Path(eve_log_path)
        self.host = host
        self.port = port
        self.clients = []
        self.running = False
        
    async def tail_eve_log(self):
        """Suricata eve.json 로그를 실시간으로 읽기"""
        print(f"[FastMCP] Monitoring: {self.eve_log_path}")
        
        # 파일이 없으면 생성 대기
        while not self.eve_log_path.exists():
            print(f"[FastMCP] Waiting for {self.eve_log_path}...")
            await asyncio.sleep(1)
        
        with open(self.eve_log_path, 'r') as f:
            # 파일 끝으로 이동
            f.seek(0, 2)
            
            while self.running:
                line = f.readline()
                if line:
                    try:
                        event = json.loads(line.strip())
                        await self.process_event(event)
                    except json.JSONDecodeError:
                        print(f"[FastMCP] Invalid JSON: {line[:50]}...")
                else:
                    await asyncio.sleep(0.1)
    
    async def process_event(self, event: Dict):
        """이벤트 처리 및 필터링"""
        event_type = event.get('event_type', '')
        
        # alert 이벤트만 처리
        if event_type == 'alert':
            alert_data = self.extract_alert_info(event)
            print(f"[FastMCP] Alert detected: {alert_data['signature']}")
            await self.broadcast_to_agents(alert_data)
    
    def extract_alert_info(self, event: Dict) -> Dict:
        """Alert 정보 추출"""
        return {
            'timestamp': event.get('timestamp', ''),
            'source_ip': event.get('src_ip', ''),
            'dest_ip': event.get('dest_ip', ''),
            'source_port': event.get('src_port', 0),
            'dest_port': event.get('dest_port', 0),
            'protocol': event.get('proto', ''),
            'signature': event.get('alert', {}).get('signature', ''),
            'category': event.get('alert', {}).get('category', ''),
            'severity': event.get('alert', {}).get('severity', 3),
            'signature_id': event.get('alert', {}).get('signature_id', 0),
            'raw_event': event
        }
    
    async def broadcast_to_agents(self, alert_data: Dict):
        """연결된 모든 Agent에게 알림 전송"""
        message = json.dumps({
            'type': 'alert',
            'data': alert_data
        }) + '\n'
        
        disconnected = []
        for writer in self.clients:
            try:
                writer.write(message.encode())
                await writer.drain()
            except Exception as e:
                print(f"[FastMCP] Client disconnected: {e}")
                disconnected.append(writer)
        
        # 연결 끊긴 클라이언트 제거
        for writer in disconnected:
            self.clients.remove(writer)
    
    async def handle_client(self, reader, writer):
        """Agent 연결 처리"""
        addr = writer.get_extra_info('peername')
        print(f"[FastMCP] New agent connected: {addr}")
        
        self.clients.append(writer)
        
        try:
            # 연결 유지
            while self.running:
                data = await reader.read(1024)
                if not data:
                    break
                
                # Agent로부터 메시지 수신 (예: 상태 확인)
                try:
                    message = json.loads(data.decode())
                    if message.get('type') == 'ping':
                        response = json.dumps({'type': 'pong'}) + '\n'
                        writer.write(response.encode())
                        await writer.drain()
                except:
                    pass
                    
        except Exception as e:
            print(f"[FastMCP] Error with client {addr}: {e}")
        finally:
            if writer in self.clients:
                self.clients.remove(writer)
            writer.close()
            await writer.wait_closed()
            print(f"[FastMCP] Agent disconnected: {addr}")
    
    async def start_server(self):
        """MCP 서버 시작"""
        server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        
        addr = server.sockets[0].getsockname()
        print(f"[FastMCP] Server started on {addr}")
        
        async with server:
            await server.serve_forever()
    
    async def run(self):
        """FastMCP 실행"""
        self.running = True
        print("[FastMCP] Starting...")
        
        # 로그 모니터링과 서버를 동시에 실행
        await asyncio.gather(
            self.tail_eve_log(),
            self.start_server()
        )
    
    def stop(self):
        """FastMCP 중지"""
        self.running = False
        print("[FastMCP] Stopping...")


async def main():
    """메인 함수"""
    # 설정
    mcp = FastMCP(
        eve_log_path="/var/log/suricata/eve.json",  # Suricata 로그 경로
        host="0.0.0.0",  # 모든 인터페이스에서 수신
        port=9000  # MCP 서버 포트
    )
    
    try:
        await mcp.run()
    except KeyboardInterrupt:
        print("\n[FastMCP] Shutting down...")
        mcp.stop()


if __name__ == "__main__":
    asyncio.run(main())