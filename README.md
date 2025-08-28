# daq_example
Snort 2.9.20에서 daq_set_filter 사용 예제입니다.

Snort 2.9에서는 DAQ(Data Acquisition) 라이브러리를 사용하여 패킷 I/O를 처리합니다. 
DAQ는 다양한 하드웨어 및 소프트웨어 인터페이스에서 작동할 수 있도록 추상화 계층을 제공하며, daq_set_filter 함수는 특정 DAQ 모듈에 BPF 필터를 적용하는 데 사용됩니다. 

- DAQ 모듈 초기화: daq_load_modules( ) 함수를 사용하여 DAQ 모듈들을 로드합니다.
- 모듈 이름 정확성: daq_find_module("pcap")에서 모듈 이름이 정확한지 확인합니다.
- 필터 문자열: filter_string 변수에 BPF 구문을 지정합니다. 예제에서는 tcp port 80(HTTP 트래픽)을 사용했습니다.
- 오류 처리: 모든 DAQ 함수 호출 후 반환 값을 확인하여 오류를 처리합니다.

컴파일 및 실행
실행시 루트 권한이 필요합니다.
- $ g++ -g -ggdb -o daq_example1  daq_example.cpp1 -I/usr/local/include -L/usr/local/lib -ldaq
- $ sudo ./daq_example1
