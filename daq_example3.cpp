#include <stdio.h>
#include <string.h>
#include <cstdlib>
// 외부의 C 함수를 C++에 사용하기 위한 설정
extern "C" {
  #include <daq.h>
  #include <daq_api.h>
}

// 애플리케이션 프로토콜 식별 함수
void print_application_protocol(uint16_t port) 
{
    switch(port) {
        case 20: case 21: printf(" (FTP)\n"); break;
        case 22: printf(" (SSH)\n"); break;
        case 23: printf(" (Telnet)\n"); break;
        case 25: printf(" (SMTP)\n"); break;
        case 53: printf(" (DNS)\n"); break;
        case 67: case 68: printf(" (DHCP)\n"); break;
        case 69: printf(" (TFTP)\n"); break;
        case 80: printf(" (HTTP)\n"); break;
        case 110: printf(" (POP3)\n"); break;
        case 119: printf(" (NNTP)\n"); break;
        case 123: printf(" (NTP)\n"); break;
        case 143: printf(" (IMAP)\n"); break;
        case 161: case 162: printf(" (SNMP)\n"); break;
        case 179: printf(" (BGP)\n"); break;
        case 194: printf(" (IRC)\n"); break;
        case 389: printf(" (LDAP)\n"); break;
        case 443: printf(" (HTTPS)\n"); break;
        case 465: printf(" (SMTPS)\n"); break;
        case 514: printf(" (Syslog)\n"); break;
        case 515: printf(" (LPD)\n"); break;
        case 587: printf(" (SMTP Submission)\n"); break;
        case 631: printf(" (IPP)\n"); break;
        case 636: printf(" (LDAPS)\n"); break;
        case 993: printf(" (IMAPS)\n"); break;
        case 995: printf(" (POP3S)\n"); break;
        case 1433: printf(" (MSSQL)\n"); break;
        case 1521: printf(" (Oracle SQL)\n"); break;
        case 1723: printf(" (PPTP)\n"); break;
        case 3306: printf(" (MySQL)\n"); break;
        case 3389: printf(" (RDP)\n"); break;
        case 5432: printf(" (PostgreSQL)\n"); break;
        case 8080: printf(" (HTTP Proxy)\n"); break;
        default: printf("\n"); break;
    }
}

// TCP 헤더 분석 함수
void analyze_tcp_header(const uint8_t *tcp_data, uint32_t tcp_len) {
    printf("TCP 헤더:\n");

    // 출발지 및 목적지 포트
    uint16_t src_port = (tcp_data[0] << 8) | tcp_data[1];
    uint16_t dst_port = (tcp_data[2] << 8) | tcp_data[3];

    printf("  출발지 포트: %u", src_port);
    print_application_protocol(src_port);

    printf("  목적지 포트: %u", dst_port);
    print_application_protocol(dst_port);

    // 시퀀스 번호 및 ACK 번호
    uint32_t seq_num = (tcp_data[4] << 24) | (tcp_data[5] << 16) | (tcp_data[6] << 8) | tcp_data[7];
    uint32_t ack_num = (tcp_data[8] << 24) | (tcp_data[9] << 16) | (tcp_data[10] << 8) | tcp_data[11];

    printf("  시퀀스 번호: %u\n", seq_num);
    printf("  확인 응답 번호: %u\n", ack_num);

    // 데이터 오프셋 및 플래그
    uint8_t data_offset = (tcp_data[12] >> 4) * 4;  // 32비트 워드 단위
    uint8_t flags = tcp_data[13];

    printf("  데이터 오프셋: %u bytes\n", data_offset);
    printf("  플래그: 0x%02x", flags);

    // TCP 플래그 해석
    if (flags & 0x01) printf(" FIN");
    if (flags & 0x02) printf(" SYN");
    if (flags & 0x04) printf(" RST");
    if (flags & 0x08) printf(" PSH");
    if (flags & 0x10) printf(" ACK");
    if (flags & 0x20) printf(" URG");
    if (flags & 0x40) printf(" ECE");
    if (flags & 0x80) printf(" CWR");
    printf("\n");

    // 윈도우 크기
    uint16_t window = (tcp_data[14] << 8) | tcp_data[15];
    printf("  윈도우 크기: %u\n", window);
}

// UDP 헤더 분석 함수
void analyze_udp_header(const uint8_t *udp_data, uint32_t udp_len) {
    printf("UDP 헤더:\n");

    // 출발지 및 목적지 포트
    uint16_t src_port = (udp_data[0] << 8) | udp_data[1];
    uint16_t dst_port = (udp_data[2] << 8) | udp_data[3];

    printf("  출발지 포트: %u", src_port);
    print_application_protocol(src_port);

    printf("  목적지 포트: %u", dst_port);
    print_application_protocol(dst_port);

    // 길이 및 체크섬
    uint16_t length = (udp_data[4] << 8) | udp_data[5];
    uint16_t checksum = (udp_data[6] << 8) | udp_data[7];

    printf("  길이: %u\n", length);
    printf("  체크섬: 0x%04x\n", checksum);
}

// 패킷 처리 콜백 함수 (DAQ_Analysis_Func_t 형식)
static DAQ_Verdict packet_callback(void *user, const DAQ_PktHdr_t *hdr, const uint8_t *data) 
{
    int *packet_count = (int *)user;
    (*packet_count)++;
    printf("Packet #%d: 패킷 수신: 길이=%u captured=%d\n", 
		    *packet_count, hdr->pktlen, hdr->caplen);
    
    // Ethernet 헤더 분석
    if (hdr->caplen >= 14) {
        printf("Ethernet 헤더:\n");
        printf("  목적지 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               data[0], data[1], data[2], data[3], data[4], data[5]);
        printf("  출발지 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               data[6], data[7], data[8], data[9], data[10], data[11]);
        
        uint16_t eth_type = (data[12] << 8) | data[13];
        printf("  EtherType: 0x%04x", eth_type);
        
        // 일반적인 EtherType 값 해석
        switch(eth_type) {
            case 0x0800: printf(" (IPv4)\n"); break;
            case 0x0806: printf(" (ARP)\n"); break;
            case 0x86DD: printf(" (IPv6)\n"); break;
            default: printf(" (기타)\n"); break;
        }
    }
    
    // IP 헤더 분석 (Ethernet 다음)
    if (hdr->caplen >= 34 && ((data[12] << 8) | data[13]) == 0x0800) {
        printf("IP 헤더:\n");
        uint8_t ip_header_len = (data[14] & 0x0F) * 4;
        printf("  IP 헤더 길이: %u bytes\n", ip_header_len);
        printf("  프로토콜: %u", data[23]);
        
        // 일반적인 프로토콜 값 해석
        switch(data[23]) {
            case 1: printf(" (ICMP)\n"); break;
            case 6: printf(" (TCP)\n"); break;
            case 17: printf(" (UDP)\n"); break;
            default: printf(" (기타)\n"); break;
        }
        
        printf("  출발지 IP: %u.%u.%u.%u\n", 
               data[26], data[27], data[28], data[29]);
        printf("  목적지 IP: %u.%u.%u.%u\n", 
               data[30], data[31], data[32], data[33]);
    }

    // 전송 계층 프로토콜 확인
    uint8_t ip_header_len = (data[14] & 0x0F) * 4;  // IP 헤더 길이 (32비트 워드 단위)
    uint8_t ip_protocol = data[23];  // 프로토콜 필드
    switch(ip_protocol) {
        case 6:  // TCP
            printf(" (TCP)\n");
            if (hdr->caplen >= 14 + ip_header_len + 20) {  // Ethernet + IP + TCP 헤더 최소 길이
                analyze_tcp_header(data + 14 + ip_header_len, hdr->caplen - 14 - ip_header_len);
            } else {
                printf("  패킷이 너무 짧아 TCP 헤더를 분석할 수 없습니다.\n");
            }
            break;
            
        case 17:  // UDP
            printf(" (UDP)\n");
            if (hdr->caplen >= 14 + ip_header_len + 8) {  // Ethernet + IP + UDP 헤더 최소 길이
                analyze_udp_header(data + 14 + ip_header_len, hdr->caplen - 14 - ip_header_len);
            } else {
                printf("  패킷이 너무 짧아 UDP 헤더를 분석할 수 없습니다.\n");
            }
            break;
            
        default:
            printf(" (기타 프로토콜)\n");
            break;
    }
    
    // 전체 패킷 데이터를 16진수로 출력
    printf("\n전체 패킷 데이터 (16진수):\n");
    for (unsigned int i = 0; i < hdr->caplen; i++) {
        if (i % 16 == 0) {
            if (i != 0) printf("\n");
            printf("%04x: ", i);
        }
        printf("%02x ", data[i]);
        if (i % 8 == 7) printf(" ");
    }
    printf("\n");
    
    // ASCII 표현도 함께 출력 (옵션)
    printf("ASCII 표현:\n");
    for (unsigned int i = 0; i < hdr->caplen; i++) {
        if (i % 16 == 0) {
            if (i != 0) printf("\n");
            printf("%04x: ", i);
        }
        
        // 출력 가능한 ASCII 문자는 그대로, 아니면 점으로 출력
        if (data[i] >= 32 && data[i] <= 126) {
            printf("%c", data[i]);
        } else {
            printf(".");
        }
        
        if (i % 8 == 7) printf(" ");
    }
    printf("\n\n");    

    return DAQ_VERDICT_PASS;
}

int main(int argc, char *argv[]) 
{
    const DAQ_Module_t *module = NULL;
    void *handle = NULL;
    const char *filter_string = "tcp port 80";
    char errbuf[DAQ_ERRBUF_SIZE];
    int ret;

    // DAQ 모듈 디렉토리 설정
    const char *module_dirs[] = {"/usr/local/lib/daq", NULL};
    ret = daq_load_modules(module_dirs);
    if (ret != DAQ_SUCCESS) {
        fprintf(stderr, "DAQ 모듈 로드 실패: %s\n", daq_get_error(NULL, NULL));
        return 1;
    }

    // 모듈 찾기
    module = daq_find_module("pcap");
    if (module == NULL) {
        fprintf(stderr, "DAQ 모듈 찾기 실패: %s\n", errbuf);
        daq_unload_modules();
        return 1;
    }

    // 설정 추가
    DAQ_Config_t config;
    memset(&config, 0, sizeof(config));
    config.mode = DAQ_MODE_PASSIVE;  // 패시브 모드
    config.snaplen = 1518;           // 최대 패킷 길이
    config.timeout = 1000;           // 타임아웃 (ms)
    char iface[] = "eth0";
    config.name = iface;             // 문자 배열 사용

    // 설정 초기화(initialize)
    ret = module->initialize(&config, &handle, errbuf, sizeof(errbuf));
    if (ret != DAQ_SUCCESS) {
        fprintf(stderr, "DAQ 초기화 실패: %s\n", errbuf);
        daq_unload_modules();
        return 1;
    }

    // 필터 설정
    ret = daq_set_filter(module, handle, filter_string);
    if (ret != DAQ_SUCCESS) {
        fprintf(stderr, "필터 설정 실패: %s\n", daq_get_error(module, handle));
        module->shutdown(handle);
        daq_unload_modules();
        return 1;
    }

    printf("BPF 필터 설정 성공: %s\n", filter_string);

    // 패킷 캡처 시작
    ret = daq_start(module, handle);
    if (ret != DAQ_SUCCESS) {
        fprintf(stderr, "패킷 캡처 시작 실패: %s\n", daq_get_error(module, handle));
        module->shutdown(handle);
        daq_unload_modules();
        return 1;
    }

    printf("패킷 캡처 시작 (필터: %s)\n", filter_string);
    // 패킷 처리 루프 (예: 100개 패킷 획득)
    const unsigned int max_packets = 100;
    unsigned int packet_count = 0;
    DAQ_PktHdr_t pkt_hdr;
    const uint8_t *pkt_data;

    while (packet_count < max_packets) {
        // 패킷 획득 (타임아웃 1000ms)
	ret = daq_acquire(module, handle, 1000, packet_callback, &packet_count);
	if (ret == DAQ_SUCCESS) {
            // 패킷 데이터 처리
            printf("패킷 #%u: 길이=%u\n", packet_count, pkt_hdr.pktlen); 
            packet_count++;
        } else if (ret == DAQ_ERROR_AGAIN) { 
            printf("타임아웃, 재시도...\n");
            continue;
        } else {
            fprintf(stderr, "패킷 획득 실패: %d\n", ret);
            break;
        }
    }

    // 패킷 캡처 중지
    ret = daq_stop(module, handle);
    if (ret != DAQ_SUCCESS) {
        fprintf(stderr, "패킷 캡처 중지 실패: %s\n", daq_get_error(module, handle));
    }

    // 정리
    module->shutdown(handle);
    daq_unload_modules();

    return 0;
}
