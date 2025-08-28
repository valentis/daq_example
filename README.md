# daq_example
Snort 2.9.20에서 daq_set_filter 사용 예제입니다.

스노트(Snort)는 오픈소스 기반의 네트워크 침입 탐지 및 방지 시스템(IDPS)으로, 네트워크 트래픽을 실시간으로 분석하여 악의적인 활동을 감지하고 차단하는 역할을 합니다. 
규칙(rule)을 사용하여 정의된 패턴과 일치하는 네트워크 활동을 찾아내며, 이를 통해 네트워크 보안을 강화할 수 있습니다. 

Snort 2.9에서는 DAQ(Data Acquisition) 라이브러리를 사용하여 패킷 I/O를 처리합니다. 
DAQ는 다양한 하드웨어 및 소프트웨어 인터페이스에서 작동할 수 있도록 추상화 계층을 제공하며, daq_set_filter 함수는 특정 DAQ 모듈에 BPF 필터를 적용하는 데 사용됩니다. 

- DAQ 모듈 초기화: daq_load_modules( ) 함수를 사용하여 DAQ 모듈들을 로드합니다.
- 모듈 이름 정확성: daq_find_module("pcap")에서 모듈 이름이 정확한지 확인합니다.
- 필터 문자열: filter_string 변수에 BPF 구문을 지정합니다. 예제에서는 tcp port 80(HTTP 트래픽)을 사용했습니다.
- 오류 처리: 모든 DAQ 함수 호출 후 반환 값을 확인하여 오류를 처리합니다.

스노트 설치
snort-2.9.20 설치하실 때 "sudo apt install libtirpc-dev" 설치
1. DAQ 설치
- $ wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz
- $ tar zxvf daq-2.0.7.tar.gz
- $ cd daq-2.0.7
- $ ./configure
- $ make && sudo make install
2. SNORT 설치
- $ wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
- $ tar zxvf snort-2.9.20.tar.gz
- $ cd snort-2.9.20
src/detection-plugins/Makefile
src/preprocessors/Makefile
src/reload-adjust/Makefile
src/Makefile
파일에서 CFLAGS 옵션에 -I/usr/include/tirpc 추가
CFLAGS = -g -O0 -DSF_VISIBILITY -fvisibility=hidden -g -ggdb -Wall -I/usr/include/tirpc
- $ ./configure
- $ make && sudo make install

컴파일 및 실행
실행시 루트 권한이 필요합니다.
- $ g++ -g -ggdb -o daq_example1  daq_example.cpp1 -I/usr/local/include -L/usr/local/lib -ldaq
- $ sudo ./daq_example1
