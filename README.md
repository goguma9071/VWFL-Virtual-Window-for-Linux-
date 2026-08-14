**VWFL**

**NOTE: IT'S CURRENTLY ON VERY EXPERIMENTAL STAGE**

이 프로젝트는 리눅스에서 윈도우 프로그램을 완벽히 네이티브로 구동시키고자 합니다.
따라서 프로젝트에서는 윈도우 커널을 최소한으로 부팅시켜 리눅스에 별도의 프로세스로서 동작하게 하고, 윈도우 프로그램의 동작을 커널이 보조하도록 해 더욱 뛰어나고 완전무결토록 프로그램이 작동하도록 하고자 합니다.
또한, 최대한 네이티브에 근접하기 위해 하이퍼바이저임을 은폐하여 스텔스하는것도 기본 목표입니다. 이를 통해 커널 수준의 안티치트같은 프로그램도 실행 가능토록 합니다.
KVM을 활용하여 윈도우를 가상화 시킵니다.

작업 디렉토리에 KrnlFile이라 이름붙혀 폴더를 생성하십시오.
그곳에 다음의 파일을 집어넣어야 합니다.
```
Window 10 Build 19041을 기준으로 합니다.
ntoskrnl.exe
hal.dll
ci.dll
BOOTVID.DLL
PSHED.DLL
kd.dll
kdcom.dll
HalExtIntcLpioDMA.dll
HalExtPL080.dll
msasn1.dll
msisadrv.sys
acpi.sys
clfs.sys
pci.sys
pciidex.sys
C_437.NLS
C_1252.NLS
l_intl.nls
(이 외에 더 추가 될 수 있음)
/config/
```
위의 모든 파일과 폴더는 윈도우 10 설치 미디어(ISO)에 있습니다.
iso 파일을 압축관리자로 여시고, 검색에서 install.wim이라는 파일만을 따로 추출하십시오.
이후 install.wim 압축관리자오 여신 뒤, 위의 파일 및 폴더를 추출하십시오.
주의: Microsoft사의 약관과 정책을 준수하십시오. 정품인증을 받은 ISO를 사용하는것을 권장합니다.



