# VirusTotal URL 스캐너

이 프로젝트는 사용자가 입력한 URL의 악성 여부를 [VirusTotal API](https://www.virustotal.com/)와 [Google Safe Browsing API](https://developers.google.com/safe-browsing)를 사용하여 교차 확인하는 웹 애플리케이션입니다.
학생들의 포트폴리오용으로 제작되었으며, Flask 프레임워크와 Python을 기반으로 합니다.

## 주요 기능

-   VirusTotal과 Google Safe Browsing API를 이용한 URL 다중 분석
-   두 엔진의 분석 결과를 좌우로 비교하여 직관적인 UI 제공
-   종합적인 분석 결과를 통해 최종 안전도 요약
-   안전한 API 키 관리를 위한 환경 변수 사용
-   폴링(Polling)을 이용한 비동기 실시간 결과 업데이트

## API 키 발급받기

이 애플리케이션을 사용하려면 **두 종류의 API 키**가 모두 필요합니다.

### 1. VirusTotal API 키

1.  **VirusTotal 가입**: [VirusTotal 웹사이트](https://www.virustotal.com/gui/join-us)를 방문하여 계정을 생성합니다.
2.  **로그인**: 가입한 계정으로 로그인합니다.
3.  **API 키 확인**: 로그인 후, 우측 상단의 프로필 아이콘을 클릭하고 **[API Key]** 메뉴로 이동하면 본인의 API 키를 확인할 수 있습니다. 이 키를 복사해두세요.

### 2. Google Safe Browsing API 키

1.  **Google Cloud Console 접속**: [Google Cloud Console](https://console.cloud.google.com/)에 접속하여 Google 계정으로 로그인합니다.
2.  **새 프로젝트 생성**: 상단의 프로젝트 선택 메뉴에서 '새 프로젝트'를 클릭하여 프로젝트를 하나 생성합니다. (기존 프로젝트 사용 가능)
3.  **API 라이브러리로 이동**: 좌측 메뉴에서 **[API 및 서비스] > [라이브러리]**로 이동합니다.
4.  **Safe Browsing API 검색 및 활성화**: 검색창에 "Safe Browsing API"를 검색하고, 검색된 API를 선택한 후 **[사용]** 버튼을 클릭하여 활성화합니다.
5.  **API 키 생성**: 
    - 좌측 메뉴에서 **[API 및 서비스] > [사용자 인증 정보]**로 이동합니다.
    - 상단의 **[+ 사용자 인증 정보 만들기] > [API 키]**를 클릭합니다.
    - 생성된 API 키를 복사해둡니다. (보안을 위해 API 키를 특정 IP 주소나 웹사이트로 제한하는 것이 좋지만, 로컬 테스트 환경에서는 일단 그대로 사용해도 됩니다.)

## 환경 변수 설정

API 키와 같은 민감한 정보는 코드에 직접 작성하는 대신, 환경 변수를 통해 안전하게 관리해야 합니다.

1.  **`.env` 파일 생성**: 이 프로젝트의 루트 디렉토리(`flask-virustotal-checker/`)에 `.env` 라는 이름의 파일을 생성합니다.

2.  **API 키 저장**: 생성한 `.env` 파일 안에 아래와 같은 형식으로 **두 개의 API 키**를 모두 입력하고 저장합니다.

    ```
    VIRUSTOTAL_API_KEY='여기에_VirusTotal_API_키_입력'
    GOOGLE_SAFE_BROWSING_API_KEY='여기에_Google_API_키_입력'
    ```

## 설치 방법

1.  **프로젝트 복제(Clone)** 또는 다운로드합니다.

2.  **가상 환경 생성 및 활성화 (권장)**:

    ```bash
    python -m venv venv
    source venv/bin/activate  # macOS/Linux
    .\venv\Scripts\activate    # Windows
    ```

3.  **필요한 라이브러리 설치**:
    프로젝트 폴더로 이동하여 아래 명령어를 실행합니다.

    ```bash
    pip install -r requirements.txt
    ```

## 실행 방법

프로젝트 폴더에서 아래 명령어를 실행하여 Flask 개발 서버를 시작합니다.

```bash
python app.py
```

서버가 실행되면 웹 브라우저에서 `http://127.0.0.1:5000` 또는 `http://localhost:5000` 주소로 접속하여 애플리케이션을 사용할 수 있습니다.

## 프로그램 동작 원리

이 애플리케이션은 두 개의 다른 API를 효율적으로 사용하여 신속하고 정확한 분석 결과를 제공합니다.

1.  **사용자 입력**: 사용자가 웹 페이지에 URL을 입력하고 '확인' 버튼을 클릭합니다.

2.  **서버 동시 요청**: Flask 서버는 `/check` 엔드포인트에서 URL을 받아, 두 개의 API에 **동시에** 분석을 요청합니다.
    *   **Google Safe Browsing (즉시 응답)**: Google의 API에는 즉시 URL의 악성 여부를 조회합니다. 이 API는 보통 수 초 내에 결과를 반환합니다.
    *   **VirusTotal (비동기 분석)**: VirusTotal의 API에는 URL 분석을 '의뢰'하고, 즉시 고유한 **`analysis_id`** (분석 ID)를 받습니다. 실제 분석은 VirusTotal의 서버에서 시간이 걸리는 작업입니다.

3.  **초기 결과 표시 및 폴링 시작**:
    *   서버는 Google의 즉각적인 결과와 VirusTotal의 `analysis_id`를 브라우저에 전달합니다.
    *   브라우저는 우선 Google Safe Browsing의 결과를 화면 왼쪽에 표시합니다.
    *   동시에, 브라우저는 **폴링(Polling)**을 시작합니다. 즉, 몇 초 간격으로 `/result/{analysis_id}` 엔드포인트에 VirusTotal의 분석이 완료되었는지 자동으로 계속 확인합니다.

4.  **최종 결과 업데이트 및 종합**:
    *   VirusTotal의 분석이 완료되면, 폴링이 중단되고 그 결과가 화면 오른쪽에 업데이트됩니다.
    *   두 개의 분석 결과가 모두 준비되면, 하단에 이 둘을 종합한 최종적인 안전도 요약이 표시됩니다. 이 과정을 통해 사용자는 빠르고 정확한 다각적인 분석을 한눈에 볼 수 있습니다.
