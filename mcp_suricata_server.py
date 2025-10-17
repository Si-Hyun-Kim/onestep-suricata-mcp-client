#!/usr/bin/env python3
"""
Suricata MCP Server - MCP 표준 프로토콜 사용
Suricata 이벤트를 MCP 도구로 제공
"""

import asyncio
import json
from pathlib import Path
from typing import Any
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)

# 전역 변수
alert_history = []
blocked_ips = set()

class SuricataMonitor:
    """Suricata 로그 모니터링"""
    
    def __init__(self, eve_log_path: str = "/var/log/suricata/eve.json"):
        self.eve_log_path = Path(eve_log_path)
        self.file_position = 0
        self.running = False
        
    async def start(self):
        """모니터링 시작"""
        self.running = True
        
        # 파일이 없으면 대기
        while not self.eve_log_path.exists():
            print(f"Waiting for {self.eve_log_path}...")
            await asyncio.sleep(1)
        
        # 파일 끝으로 이동
        with open(self.eve_log_path, 'r') as f:
            f.seek(0, 2)
            self.file_position = f.tell()
        
        print(f"Monitoring: {self.eve_log_path}")
        
        # 모니터링 루프
        while self.running:
            await self.check_new_events()
            await asyncio.sleep(0.01)
    
    async def check_new_events(self):
        """새 이벤트 확인"""
        try:
            current_size = self.eve_log_path.stat().st_size
            
            if current_size > self.file_position:
                with open(self.eve_log_path, 'r') as f:
                    f.seek(self.file_position)
                    new_lines = f.readlines()
                    self.file_position = f.tell()
                    
                    for line in new_lines:
                        if line.strip():
                            try:
                                event = json.loads(line.strip())
                                if event.get('event_type') == 'alert':
                                    self.process_alert(event)
                            except json.JSONDecodeError:
                                pass
        except Exception as e:
            print(f"Error checking events: {e}")
    
    def process_alert(self, event: dict):
        """Alert 처리"""
        alert_info = {
            'timestamp': event.get('timestamp', ''),
            'source_ip': event.get('src_ip', ''),
            'dest_ip': event.get('dest_ip', ''),
            'source_port': event.get('src_port', 0),
            'dest_port': event.get('dest_port', 0),
            'protocol': event.get('proto', ''),
            'signature': event.get('alert', {}).get('signature', ''),
            'category': event.get('alert', {}).get('category', ''),
            'severity': event.get('alert', {}).get('severity', 3),
        }
        
        alert_history.append(alert_info)
        
        # 최근 100개만 유지
        if len(alert_history) > 100:
            alert_history.pop(0)
        
        print(f"Alert: {alert_info['signature']} from {alert_info['source_ip']}")
    
    def stop(self):
        """모니터링 중지"""
        self.running = False


# MCP 서버 초기화
server = Server("suricata-mcp-server")
monitor = SuricataMonitor()


@server.list_resources()
async def handle_list_resources() -> list[Resource]:
    """사용 가능한 리소스 목록"""
    return [
        Resource(
            uri="suricata://alerts",
            name="Suricata Alerts",
            description="Recent security alerts from Suricata IDS",
            mimeType="application/json",
        ),
        Resource(
            uri="suricata://blocked_ips",
            name="Blocked IPs",
            description="List of blocked IP addresses",
            mimeType="application/json",
        ),
    ]


@server.read_resource()
async def handle_read_resource(uri: str) -> str:
    """리소스 읽기"""
    if uri == "suricata://alerts":
        return json.dumps({
            "total": len(alert_history),
            "alerts": alert_history[-10:]  # 최근 10개
        }, indent=2)
    
    elif uri == "suricata://blocked_ips":
        return json.dumps({
            "total": len(blocked_ips),
            "ips": list(blocked_ips)
        }, indent=2)
    
    else:
        raise ValueError(f"Unknown resource: {uri}")


@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """사용 가능한 도구 목록"""
    return [
        Tool(
            name="get_recent_alerts",
            description="Get recent security alerts from Suricata",
            inputSchema={
                "type": "object",
                "properties": {
                    "count": {
                        "type": "number",
                        "description": "Number of recent alerts to retrieve (default: 10)",
                        "default": 10
                    },
                    "severity": {
                        "type": "number",
                        "description": "Filter by severity level (1-3)",
                        "minimum": 1,
                        "maximum": 3
                    }
                }
            }
        ),
        Tool(
            name="block_ip",
            description="Block an IP address using iptables",
            inputSchema={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "IP address to block"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for blocking"
                    }
                },
                "required": ["ip"]
            }
        ),
        Tool(
            name="get_alert_stats",
            description="Get statistics about security alerts",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="search_alerts",
            description="Search alerts by IP address or signature",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (IP or keyword)"
                    }
                },
                "required": ["query"]
            }
        )
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[TextContent | ImageContent | EmbeddedResource]:
    """도구 실행"""
    
    if name == "get_recent_alerts":
        count = arguments.get("count", 10) if arguments else 10
        severity = arguments.get("severity") if arguments else None
        
        alerts = alert_history[-count:]
        
        if severity:
            alerts = [a for a in alerts if a.get('severity') == severity]
        
        return [
            TextContent(
                type="text",
                text=json.dumps({
                    "count": len(alerts),
                    "alerts": alerts
                }, indent=2)
            )
        ]
    
    elif name == "block_ip":
        if not arguments:
            raise ValueError("IP address required")
        
        ip = arguments["ip"]
        reason = arguments.get("reason", "Security threat")
        
        # IPv6 체크
        is_ipv6 = ':' in ip
        cmd = ['sudo', 'ip6tables' if is_ipv6 else 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
        
        try:
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                blocked_ips.add(ip)
                return [
                    TextContent(
                        type="text",
                        text=f"Successfully blocked {ip}. Reason: {reason}"
                    )
                ]
            else:
                return [
                    TextContent(
                        type="text",
                        text=f"Failed to block {ip}: {result.stderr}"
                    )
                ]
        except Exception as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error blocking {ip}: {str(e)}"
                )
            ]
    
    elif name == "get_alert_stats":
        # 통계 계산
        total = len(alert_history)
        by_severity = {}
        by_category = {}
        top_sources = {}
        
        for alert in alert_history:
            # 심각도별
            sev = alert.get('severity', 3)
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            # 카테고리별
            cat = alert.get('category', 'unknown')
            by_category[cat] = by_category.get(cat, 0) + 1
            
            # Source IP별
            src = alert.get('source_ip', 'unknown')
            top_sources[src] = top_sources.get(src, 0) + 1
        
        # Top 5 sources
        top_5 = sorted(top_sources.items(), key=lambda x: x[1], reverse=True)[:5]
        
        stats = {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_category": by_category,
            "top_sources": dict(top_5),
            "blocked_ips": len(blocked_ips)
        }
        
        return [
            TextContent(
                type="text",
                text=json.dumps(stats, indent=2)
            )
        ]
    
    elif name == "search_alerts":
        if not arguments or "query" not in arguments:
            raise ValueError("Query required")
        
        query = arguments["query"].lower()
        results = []
        
        for alert in alert_history:
            # IP 검색
            if query in alert.get('source_ip', '').lower():
                results.append(alert)
            elif query in alert.get('dest_ip', '').lower():
                results.append(alert)
            # 시그니처 검색
            elif query in alert.get('signature', '').lower():
                results.append(alert)
        
        return [
            TextContent(
                type="text",
                text=json.dumps({
                    "query": query,
                    "results": len(results),
                    "alerts": results[-20:]  # 최근 20개
                }, indent=2)
            )
        ]
    
    else:
        raise ValueError(f"Unknown tool: {name}")


async def main():
    """메인 함수"""
    # Suricata 모니터링 시작
    monitor_task = asyncio.create_task(monitor.start())
    
    # MCP 서버 실행
    async with stdio_server() as (read_stream, write_stream):
        print("Suricata MCP Server started")
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="suricata-mcp-server",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())