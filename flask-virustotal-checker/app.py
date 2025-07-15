
import os
import requests
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

# .env 파일에서 환경 변수를 로드합니다.
# 이 방식을 사용하면 API 키와 같은 민감한 정보를 코드에 직접 하드코딩하지 않고 안전하게 관리할 수 있습니다.
load_dotenv()

# Flask 애플리케이션 인스턴스를 생성합니다.
app = Flask(__name__)

# VirusTotal API 키를 환경 변수에서 가져옵니다.
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
# Google Safe Browsing API 키를 환경 변수에서 가져옵니다.
GSB_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')

# API 기본 URL을 상수로 정의합니다.
VT_BASE_URL = 'https://www.virustotal.com/api/v3'
GSB_BASE_URL = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}'


@app.route('/')
def index():
    """
    메인 페이지를 렌더링합니다.
    사용자가 URL을 입력할 수 있는 폼을 포함한 HTML 페이지를 반환합니다.
    """
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check():
    """
    사용자가 제출한 URL을 각 API에 스캔 요청하고 초기 결과를 반환합니다.
    """
    # API 키들이 설정되었는지 확인합니다.
    if not VT_API_KEY or not GSB_API_KEY:
        return jsonify({'error': '환경 변수에 API 키가 올바르게 설정되지 않았습니다. (VIRUSTOTAL_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY)'}), 500

    url_to_check = request.form.get('url')
    if not url_to_check:
        return jsonify({'error': 'URL을 입력해주세요.'}), 400

    # --- Google Safe Browsing API 요청 ---
    gsb_payload = {
        'client': {'clientId': 'my-flask-app', 'clientVersion': '1.0.0'},
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url_to_check}]
        }
    }
    try:
        gsb_response = requests.post(GSB_BASE_URL, json=gsb_payload)
        gsb_response.raise_for_status()
        gsb_data = gsb_response.json()
    except requests.exceptions.RequestException as e:
        gsb_data = {'error': f'Google Safe Browsing API 요청 실패: {e}'}


    # --- VirusTotal API 요청 ---
    vt_headers = {'x-apikey': VT_API_KEY}
    try:
        vt_scan_response = requests.post(f'{VT_BASE_URL}/urls', headers=vt_headers, data={'url': url_to_check})
        vt_scan_response.raise_for_status()
        vt_scan_data = vt_scan_response.json()
        analysis_id = vt_scan_data.get('data', {}).get('id')
        if not analysis_id:
            vt_data = {'error': 'VirusTotal 분석 ID를 가져오지 못했습니다.'}
        else:
            vt_data = {'analysis_id': analysis_id}

    except requests.exceptions.RequestException as e:
        vt_data = {'error': f'VirusTotal API 요청 실패: {e}'}

    # 두 API의 초기 결과를 함께 반환합니다.
    return jsonify({
        'google_safe_browsing': gsb_data,
        'virus_total': vt_data
    })


@app.route('/result/<analysis_id>')
def get_vt_result(analysis_id):
    """
    제공된 분석 ID를 사용하여 VirusTotal에서 분석 결과를 가져옵니다.
    """
    if not VT_API_KEY:
        return jsonify({'error': 'VIRUSTOTAL_API_KEY 환경 변수가 설정되지 않았습니다.'}), 500

    headers = {'x-apikey': VT_API_KEY}

    try:
        response = requests.get(f'{VT_BASE_URL}/analyses/{analysis_id}', headers=headers)
        response.raise_for_status()
        return jsonify(response.json())

    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'VirusTotal 분석 결과 조회 실패: {e}'}), 500


if __name__ == '__main__':
    # 디버그 모드로 애플리케이션을 실행합니다.
    # host='0.0.0.0'으로 설정하여 외부에서도 접속할 수 있도록 합니다.
    app.run(debug=True, host='0.0.0.0', port=5000)
