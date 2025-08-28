#include <stdio.h>
#include <string.h>
#include <cstdlib>
// 외부의 C 함수를 C++에 사용하기 위한 설정
extern "C" {
  #include <daq.h>
  #include <daq_api.h>
}

// 패킷 처리 콜백 함수 (DAQ_Analysis_Func_t 형식)
static DAQ_Verdict packet_callback(void *user, const DAQ_PktHdr_t *hdr, const uint8_t *data) 
{
    printf("패킷 수신: 길이=%u\n", hdr->pktlen);
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
    module = daq_find_module("pcap"); // errbuf, sizeof(errbuf));
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
    config.name = iface;                 // 문자 배열 사용

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
	ret = daq_acquire(module, handle, 1000, packet_callback, NULL);
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

        // 여기에 패킷 분석 로직 추가 (예: 페이로드 검사)
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