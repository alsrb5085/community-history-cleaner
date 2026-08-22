"""dcinside 모바일 앱 API 클라이언트

갤로그는 요청이 잦으면 HTTP 200 + 빈 본문으로 막아버림
목록은 갤로그 말고 얻을 방법이 없지만 삭제는 앱 API로 보낼 수 있어서,
호스트를 갈라 갤로그 쪽 요청량을 줄이는 것이 목적

  기존: 글 1개당 갤로그 GET 1회(service_code) + 갤로그 POST 1회
  변경: 글 1개당 app.dcinside.com POST 1회

인증은 안드로이드 앱과 같은 순서를 따름

  구글 checkin(protobuf) -> android_id / security_token
    -> Firebase Installations -> fid / authToken
      -> c2dm/register3 -> FCM 토큰(= client_token)
        -> dcinside mobile_app_verification -> app_id

protobuf는 checkin 응답에서 varint 필드 두 개만 읽으면 되므로
라이브러리 없이 아래 최소 구현으로 처리함
"""
from typing import Optional, Tuple
from urllib.parse import quote
import hashlib
import json
import os
import time

import requests

# 앱 5.0.9 기준 값. vCode를 올리지 않아도 서버가 받아줌 (2026-08 확인)
# vName은 app_check가 준 값을 되돌려주는 것이라 고정하지 않음
# signature는 APK 서명 해시라 앱 버전이 올라가도 그대로임
APP_PACKAGE = 'com.dcinside.app.android'
APP_VERSION_CODE = '100115'
APP_VERSION_NAME = '5.0.9'
APP_SIGNATURE = '5rJxRKJ2YLHgBgj6RdMZBl2X0KcftUuMoXVug0bsKd0='
ANDROID_OS_VERSION = '35'
ANDROID_TARGET_VERSION = '35'

FIREBASE_SENDER = '477369754343'
FIREBASE_APP_ID = f'1:{FIREBASE_SENDER}:android:d2ffdd960120a207727842'
FIREBASE_CLIENT = 'H4sIAAAAAAAAAKtWykhNLCpJSk0sKVayio7VUSpLLSrOzM9TslIyUqoFAFyivEQfAAAA'
FIREBASE_CERT = '43bd70dfc365ec1749f0424d28174da44ee7659d'
FIREBASE_APP_NAME_HASH = 'R1dAH9Ui7M-ynoznwBdw01tLxhI'
FIREBASE_PROJECT = 'dcinside-b3f40'
GOOGLE_API_KEY = 'AIzaSyDcbVof_4Bi2GwJ1H8NjSwSTaMPPZeCE38'
GCM_VERSION = '240514032'
GCM_INFO = 'Q2U3ar09NyAToOhBO1boBVw1nzmBjxg'
FCM_CLIENT_VERSION = 'fcm-24.0.3'

APP_USER_AGENT = 'dcinside.app'
MOBILE_APP_USER_AGENT = 'com.dcinside.mobileapp'

CHECKIN_URL = 'https://android.clients.google.com/checkin'
INSTALLATIONS_URL = f'https://firebaseinstallations.googleapis.com/v1/projects/{FIREBASE_PROJECT}/installations'
REGISTER_URL = 'https://android.clients.google.com/c2dm/register3'
APP_CHECK_URL = 'https://json2.dcinside.com/json0/app_check_A_rina_one_new.php'
APP_VERIFICATION_URL = 'https://msign.dcinside.com/auth/mobile_app_verification'
LOGIN_URL = 'https://msign.dcinside.com/api/login'
ARTICLE_DELETE_URL = 'https://app.dcinside.com/api/gall_del.php'
COMMENT_DELETE_URL = 'https://app.dcinside.com/api/comment_del.php'
# 쓰기. 글만 호스트가 다르다 (tui-inside src/api/endpoints.ts 참조)
ARTICLE_WRITE_URL = 'https://upload.dcinside.com/_app_write_api.php'
COMMENT_WRITE_URL = 'https://app.dcinside.com/api/comment_ok.php'

TIMEOUT = 20

# 기기 자격증명 저장 위치. 매 실행마다 새 기기를 등록하면 dcinside가
# "방금 생긴 기기가 곧바로 글을 지운다"고 보고 쓰기 요청을 거절함
# 한 번 만든 기기를 계속 재사용해야 함
DEVICE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'dcinside-app-device.json')

# 갓 발급된 자격증명은 거절당함. 이만큼 지난 뒤에 써야 함
FRESH_CREDENTIAL_DELAY = 30.0

# 일시적 거절에 대한 재시도. 1초, 2초 간격으로 최대 3회 시도함
TRANSIENT_RETRIES = 3
TRANSIENT_RETRY_DELAY = 1.0


def encodeDcField(value: str) -> str:
    """앱이 글 제목·본문을 싣는 형태

    JS encodeURIComponent와 같게 만들고 공백만 +로 바꾼다
    파이썬 quote는 영숫자와 `_.-~`를 이미 안 건드리므로 나머지만 지정한다
    """
    return quote(str(value), safe="!*'()").replace('%20', '+')


def isTruthyDcResult(value) -> bool:
    """앱 API의 성공 표기를 판정

    엔드포인트마다 true/"true"/"ok"/"success"/1/"1"을 섞어 쓴다
    좁게 잡으면 실제로 처리된 요청이 실패로 집계된다
    """
    return value in (True, 'true', 'ok', 'success', 1, '1')


def isTransientCause(cause: str) -> bool:
    """"잠시 후 다시 이용해 주세요" 계열인지 확인

    같은 뜻인데 응답마다 띄어쓰기가 달라서 공백을 걷어내고 비교한다
    """
    return '잠시후다시이용해주세요' in cause.replace(' ', '')


def isWriteCaptchaCause(cause: str) -> bool:
    """쓰기에 보안코드를 요구하는 응답인지

    이건 갤로그 봇체크와 다른, 앱 쪽 캡차다 (code.php / code_reple.php)
    자동으로 풀지 않으므로 사용자에게 그대로 알린다
    """
    squeezed = cause.replace(' ', '')
    return any(word in squeezed for word in ('보안코드', '자동입력방지', '코드를입력'))


class AppApiError(Exception):
    """앱 API 호출이 실패했을 때 발생함"""


class AppAuthExpiredError(AppApiError):
    """app_id 또는 로그인 세션이 만료됐을 때 발생함

    kind가 'app_id'면 재발급으로 자동 복구할 수 있고,
    'login_session'이면 사용자가 다시 로그인해야 함
    """

    def __init__(self, kind: str, cause: str):
        super().__init__(f'{kind}: {cause}')
        self.kind = kind
        self.cause = cause


def authExpiredKind(cause: str) -> Optional[str]:
    if cause == 'certification':
        return 'app_id'
    if cause == 'certification_login':
        return 'login_session'
    return None


# --- protobuf 최소 구현 (varint만) ---

def _encodeVarint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _fieldVarint(field: int, value: int) -> bytes:
    return _encodeVarint(field << 3) + _encodeVarint(value)


def _fieldBytes(field: int, payload: bytes) -> bytes:
    return _encodeVarint((field << 3) | 2) + _encodeVarint(len(payload)) + payload


def _readVarint(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise AppApiError('checkin 응답이 중간에서 끊겼습니다.')
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7


def buildCheckinRequest() -> bytes:
    """checkin 요청 본문. field4{ field1{ field10 = SDK 버전 } } + 상수 두 개"""
    build = _fieldVarint(10, int(ANDROID_OS_VERSION))
    checkin = _fieldBytes(1, build)
    return _fieldBytes(4, checkin) + _fieldVarint(14, 3) + _fieldVarint(20, 0)


def parseCheckinResponse(payload: bytes) -> Tuple[int, int]:
    """checkin 응답에서 field 7(android_id)과 8(security_token)만 뽑음"""
    android_id = None
    security_token = None
    pos = 0
    while pos < len(payload):
        key, pos = _readVarint(payload, pos)
        field, wire = key >> 3, key & 7
        value = None
        if wire == 0:
            value, pos = _readVarint(payload, pos)
        elif wire == 1:
            value = int.from_bytes(payload[pos:pos + 8], 'little')
            pos += 8
        elif wire == 2:
            length, pos = _readVarint(payload, pos)
            pos += length
        elif wire == 5:
            value = int.from_bytes(payload[pos:pos + 4], 'little')
            pos += 4
        else:
            raise AppApiError(f'checkin 응답에 알 수 없는 wire type {wire}이 있습니다.')

        if value is None:
            continue
        if field == 7:
            android_id = value
        elif field == 8:
            security_token = value

    if android_id is None or security_token is None:
        raise AppApiError('checkin 응답에 android_id/security_token이 없습니다.')
    return android_id, security_token


class AppApi:
    """앱 자격증명 발급과 삭제 API 호출을 담당함"""

    def __init__(self, session: requests.Session = None, device_path: str = DEVICE_PATH):
        # 갤로그용 쿠키 세션과 섞이면 안 되므로 별도 세션을 씀
        self.session = session or requests.Session()
        self.session.verify = False
        self.app_id = ''
        self.client_token = ''
        self.account = {}
        self.device_path = device_path
        # 자격증명을 이번 실행에서 새로 만들었는지, 만들었다면 언제인지
        # 갓 만든 자격증명은 잠시 뒤에야 삭제에 쓸 수 있음
        self.credentials_issued_at = 0.0
        self.credentials_are_new = False

    # --- 기기 자격증명 저장/재사용 ---

    def _readDeviceFile(self) -> dict:
        try:
            with open(self.device_path, encoding='utf-8') as f:
                device = json.load(f)
        except (OSError, ValueError):
            return {}
        return device if isinstance(device, dict) else {}

    def loadDevice(self) -> bool:
        """저장된 기기 자격증명을 불러온다. 없거나 깨졌으면 False"""
        device = self._readDeviceFile()
        client_token = device.get('client_token') or ''
        app_id = device.get('app_id') or ''
        if not client_token or not app_id:
            return False

        self.client_token = client_token
        self.app_id = app_id
        self.credentials_issued_at = float(device.get('issued_at') or 0)
        self.credentials_are_new = False
        return True

    def saveDevice(self) -> None:
        device = self._readDeviceFile()
        device.update({
            'client_token': self.client_token,
            'app_id': self.app_id,
            'issued_at': self.credentials_issued_at,
        })
        try:
            with open(self.device_path, 'w', encoding='utf-8') as f:
                json.dump(device, f)
            os.chmod(self.device_path, 0o600)
        except OSError:
            # 저장에 실패해도 이번 실행은 계속할 수 있음
            pass

    def loadAccount(self, login_id: str) -> bool:
        """저장된 로그인 결과를 복원

        실행할 때마다 로그인하면 dcinside가 캡차를 걸어버린다
        한 번 얻은 user_id를 저장해 두고 재사용해야 한다
        """
        accounts = self._readDeviceFile().get('accounts')
        if not isinstance(accounts, dict):
            return False
        saved = accounts.get(login_id)
        if not isinstance(saved, dict) or not saved.get('user_id'):
            return False

        self.setAccount(login_id, saved['user_id'],
                        saved.get('user_no', ''), saved.get('name', ''))
        return True

    def saveAccount(self) -> None:
        if not self.account.get('login_id'):
            return
        device = self._readDeviceFile()
        accounts = device.get('accounts')
        if not isinstance(accounts, dict):
            accounts = {}
        accounts[self.account['login_id']] = {
            'user_id': self.account.get('user_id', ''),
            'user_no': self.account.get('user_no', ''),
            'name': self.account.get('name', ''),
        }
        device['accounts'] = accounts
        try:
            with open(self.device_path, 'w', encoding='utf-8') as f:
                json.dump(device, f)
            os.chmod(self.device_path, 0o600)
        except OSError:
            pass

    def forgetAccount(self, login_id: str) -> None:
        device = self._readDeviceFile()
        accounts = device.get('accounts')
        if not isinstance(accounts, dict) or login_id not in accounts:
            return
        del accounts[login_id]
        device['accounts'] = accounts
        try:
            with open(self.device_path, 'w', encoding='utf-8') as f:
                json.dump(device, f)
        except OSError:
            pass

    def loginOrRestore(self, login_id: str, password: str) -> dict:
        """저장된 로그인 정보가 있으면 그걸 쓰고, 없을 때만 실제로 로그인함"""
        self.ensureCredentials()
        if self.loadAccount(login_id):
            return self.account
        account = self.login(login_id, password)
        self.saveAccount()
        return account

    def ensureCredentials(self) -> None:
        """자격증명 준비. 저장된 게 있으면 그대로 재사용"""
        if self.hasCredentials():
            return
        if self.loadDevice():
            return
        self.refreshCredentials()

    def waitUntilUsable(self, notify=None) -> None:
        """갓 발급된 자격증명이면 쓸 수 있을 때까지 대기

        방금 등록한 기기로 곧바로 삭제를 걸면 거절당한다
        """
        if not self.credentials_are_new:
            return
        remaining = FRESH_CREDENTIAL_DELAY - (time.time() - self.credentials_issued_at)
        if remaining <= 0:
            self.credentials_are_new = False
            return
        if notify:
            notify(remaining)
        time.sleep(remaining)
        self.credentials_are_new = False

    # --- 자격증명 ---

    def fetchClientToken(self) -> str:
        """FCM 토큰 발급. 앱 API의 client_token으로 쓰인다"""
        res = self.session.post(
            CHECKIN_URL,
            data=buildCheckinRequest(),
            headers={
                'Content-Type': 'application/x-protobuffer',
                'User-Agent': 'Android-Checkin/3.0',
            },
            timeout=TIMEOUT)
        res.raise_for_status()
        android_id, security_token = parseCheckinResponse(res.content)

        res = self.session.post(
            INSTALLATIONS_URL,
            json={
                'appId': FIREBASE_APP_ID,
                'authVersion': 'FIS_v2',
                'sdkVersion': 'a:17.1.0',
            },
            headers={
                'x-goog-api-key': GOOGLE_API_KEY,
                'X-firebase-client': FIREBASE_CLIENT,
            },
            timeout=TIMEOUT)
        res.raise_for_status()
        installation = res.json()
        try:
            fid = installation['fid']
            auth_token = installation['authToken']['token']
        except (KeyError, TypeError):
            raise AppApiError(f'Firebase 설치 응답 형식이 다릅니다: {installation}')

        res = self.session.post(
            REGISTER_URL,
            data={
                'X-subtype': FIREBASE_SENDER,
                'sender': FIREBASE_SENDER,
                'X-app_ver': APP_VERSION_CODE,
                'X-osv': ANDROID_OS_VERSION,
                'X-cliv': FCM_CLIENT_VERSION,
                'X-gmsv': GCM_VERSION,
                'X-appid': fid,
                'X-scope': '*',
                'X-Goog-Firebase-Installations-Auth': auth_token,
                'X-gmp_app_id': FIREBASE_APP_ID,
                'X-firebase-app-name-hash': FIREBASE_APP_NAME_HASH,
                'X-app_ver_name': APP_VERSION_NAME,
                'app': APP_PACKAGE,
                'device': str(android_id),
                'app_ver': APP_VERSION_CODE,
                'info': GCM_INFO,
                'plat': '0',
                'gcm_ver': GCM_VERSION,
                'cert': FIREBASE_CERT,
                'target_ver': ANDROID_TARGET_VERSION,
            },
            headers={'Authorization': f'AidLogin {android_id}:{security_token}'},
            timeout=TIMEOUT)
        res.raise_for_status()
        text = res.text.strip()
        if not text.startswith('token='):
            raise AppApiError(f'FCM 등록 응답 형식이 다릅니다: {text[:200]}')
        return text[len('token='):]

    def fetchAppId(self, client_token: str) -> str:
        """app_id 발급. value_token은 서버가 준 날짜로 매번 새로 해싱한다"""
        res = self.session.post(APP_CHECK_URL, timeout=TIMEOUT)
        res.raise_for_status()
        try:
            check = res.json()[0]
            date, version_name = check['date'], check['ver']
        except (ValueError, KeyError, IndexError, TypeError):
            raise AppApiError(f'app_check 응답 형식이 다릅니다: {res.text[:200]}')

        res = self.session.post(
            APP_VERIFICATION_URL,
            data={
                'value_token': hashlib.sha256(f'dcArdchk_{date}'.encode('ascii')).hexdigest(),
                'pkg': APP_PACKAGE,
                'vCode': APP_VERSION_CODE,
                'vName': version_name,
                'signature': APP_SIGNATURE,
                'client_token': client_token,
            },
            timeout=TIMEOUT)
        res.raise_for_status()
        try:
            app_id = res.json()['app_id']
        except (ValueError, KeyError, TypeError):
            raise AppApiError(f'app_id 발급 응답 형식이 다릅니다: {res.text[:200]}')
        if not app_id:
            raise AppApiError('app_id가 비어 있습니다.')
        return app_id

    def refreshCredentials(self) -> None:
        """자격증명을 새로 발급

        기기는 되도록 유지하고 app_id만 새로 받는다
        기기를 새로 등록하면 그때부터 대기 시간이 다시 붙기 때문
        """
        if self.client_token or self.loadDevice():
            self.app_id = self.fetchAppId(self.client_token)
            self.saveDevice()
            return

        self.client_token = self.fetchClientToken()
        self.app_id = self.fetchAppId(self.client_token)
        self.credentials_issued_at = time.time()
        self.credentials_are_new = True
        self.saveDevice()

    def hasCredentials(self) -> bool:
        return bool(self.app_id and self.client_token)

    def isReady(self) -> bool:
        """삭제를 보낼 수 있는 상태인지. 자격증명과 로그인 계정이 모두 필요함"""
        return self.hasCredentials() and bool(self.account.get('user_id'))

    # --- 로그인 ---

    def login(self, user_id: str, user_pw: str, mode: str = 'login_quick') -> dict:
        """앱 로그인. 삭제에 필요한 board_id/user_id/confirm_id를 확보

        갤로그용 웹 쿠키는 여기서 나오지 않는다
        그쪽은 Cleaner.login()이나 저장된 쿠키를 써야 한다
        """
        self.ensureCredentials()

        res = self.session.post(
            LOGIN_URL,
            files={
                'client_token': (None, self.client_token),
                'user_id': (None, user_id),
                'user_pw': (None, user_pw),
                'mode': (None, mode),
            },
            headers={
                'User-Agent': MOBILE_APP_USER_AGENT,
                'Referer': 'https://www.dcinside.com',
            },
            timeout=TIMEOUT)
        res.raise_for_status()
        try:
            raw = res.json()
        except ValueError:
            raise AppApiError(f'로그인 응답이 JSON이 아닙니다: {res.text[:200]}')

        value = raw[0] if isinstance(raw, list) and raw else raw
        if not isinstance(value, dict):
            raise AppApiError(f'로그인 응답 형식이 다릅니다: {str(raw)[:200]}')

        if value.get('result') in (True, 'true'):
            self.account = {
                'login_id': user_id,
                'user_id': str(value.get('user_id', '')),
                'user_no': str(value.get('user_no', '')),
                'name': str(value.get('name', '')),
            }
            return self.account

        cause = str(value.get('cause', '') or '로그인에 실패했습니다.')
        # 간편 로그인이 거부되면 일반 로그인으로 한 번만 더 시도함
        if mode == 'login_quick' and ('간편 아이디 삭제' in cause or '다시 로그인' in cause):
            return self.login(user_id, user_pw, 'login_normal')

        kind = authExpiredKind(cause)
        if kind:
            raise AppAuthExpiredError(kind, cause)
        raise AppApiError(cause)

    def setAccount(self, login_id: str, user_id: str, user_no: str = '', name: str = '') -> None:
        """저장된 계정 정보를 다시 주입 (로그인 없이)"""
        self.account = {
            'login_id': login_id,
            'user_id': user_id,
            'user_no': user_no,
            'name': name,
        }

    # --- 삭제 ---

    def deleteArticle(self, gallery_id: str, post_no: str) -> dict:
        """글 삭제. 일시적 거절은 몇 번 다시 시도한다"""
        result = None
        for attempt in range(1, TRANSIENT_RETRIES + 1):
            result = self._deleteArticleOnce(gallery_id, post_no)
            if result['ok'] or not result.get('transient'):
                return result
            if attempt < TRANSIENT_RETRIES:
                time.sleep(TRANSIENT_RETRY_DELAY * attempt)
        return result

    def _deleteArticleOnce(self, gallery_id: str, post_no: str) -> dict:
        body = {
            'id': (None, gallery_id),
            'no': (None, str(post_no)),
            'mode': (None, 'board_del'),
            'app_id': (None, self.app_id),
            'client_token': (None, self.client_token),
            'confirm_id': (None, self.account['user_id']),
            'user_id': (None, self.account['user_id']),
            'board_id': (None, self.account['login_id']),
        }
        res = self.session.post(
            ARTICLE_DELETE_URL,
            files=body,
            headers={
                'User-Agent': APP_USER_AGENT,
                'Referer': 'https://www.dcinside.com',
                'Connection': 'Keep-Alive',
            },
            timeout=TIMEOUT)
        return self._parseDeleteResult(res)

    def deleteComment(self, gallery_id: str, post_no: str, comment_no: str) -> dict:
        """댓글 삭제. 글과 같은 재시도 정책"""
        result = None
        for attempt in range(1, TRANSIENT_RETRIES + 1):
            result = self._deleteCommentOnce(gallery_id, post_no, comment_no)
            if result['ok'] or not result.get('transient'):
                return result
            if attempt < TRANSIENT_RETRIES:
                time.sleep(TRANSIENT_RETRY_DELAY * attempt)
        return result

    def _deleteCommentOnce(self, gallery_id: str, post_no: str, comment_no: str) -> dict:
        res = self.session.post(
            COMMENT_DELETE_URL,
            data={
                'id': gallery_id,
                'no': str(post_no),
                'comment_no': str(comment_no),
                'mode': 'comment_del',
                'app_id': self.app_id,
                'client_token': self.client_token,
                'board_id': self.account['login_id'],
                'user_id': self.account['user_id'],
            },
            headers={'User-Agent': APP_USER_AGENT},
            timeout=TIMEOUT)
        return self._parseDeleteResult(res)

    def _parseDeleteResult(self, res) -> dict:
        """삭제 응답을 {'ok', 'cause', 'transient'} 형태로 정규화

        속도 제한에 걸리면 여기도 빈 본문이 오므로 JSON 파싱을 감싼다
        """
        if not res.text.strip():
            return {'ok': False, 'cause': 'BLOCKED', 'transient': True}
        try:
            raw = res.json()
        except ValueError:
            return {'ok': False, 'cause': 'BLOCKED', 'transient': True}

        value = raw[0] if isinstance(raw, list) and raw else raw
        if not isinstance(value, dict):
            return {'ok': False, 'cause': f'알 수 없는 응답: {str(raw)[:120]}', 'transient': False}

        cause = str(value.get('cause', '') or value.get('message', '') or '')
        if isTruthyDcResult(value.get('result')):
            return {'ok': True, 'cause': cause, 'transient': False}

        kind = authExpiredKind(cause)
        if kind:
            raise AppAuthExpiredError(kind, cause)
        # 사유가 비면 원본을 조금 실어 보낸다
        # 그것 없이는 응답 형식이 바뀌었을 때 원인을 좁힐 수 없다
        return {
            'ok': False,
            'cause': cause or f'삭제에 실패했습니다. (응답: {str(raw)[:160]})',
            'transient': isTransientCause(cause),
        }

    # --- 쓰기 ---

    def writeArticle(self, gallery_id: str, subject: str, content: str) -> dict:
        """글 작성. {'ok', 'cause', 'no', 'captcha'} 형태로 돌려준다

        본문은 memo_block[0] 하나만 쓴다. 이미지·디시콘 블록은 다루지 않는다
        """
        res = self.session.post(
            ARTICLE_WRITE_URL,
            files={
                'id': (None, gallery_id),
                'app_id': (None, self.app_id),
                'mode': (None, 'write'),
                'client_token': (None, self.client_token),
                'subject': (None, encodeDcField(subject)),
                'fix': (None, ''),
                'secret_use': (None, '0'),
                'user_id': (None, self.account['user_id']),
                'memo_block[0]': (None, encodeDcField(content)),
            },
            headers={
                'User-Agent': APP_USER_AGENT,
                'Referer': 'https://www.dcinside.com',
            },
            timeout=TIMEOUT)
        return self._parseWriteResult(res)

    def writeComment(self, gallery_id: str, post_no: str, content: str) -> dict:
        """댓글 작성. 본문은 인코딩하지 않고 그대로 싣는다"""
        res = self.session.post(
            COMMENT_WRITE_URL,
            data={
                'comment_memo': content,
                'mode': 'com_write',
                'reple_id': '',
                'app_id': self.app_id,
                'client_token': self.client_token,
                'id': gallery_id,
                'no': str(post_no),
                'best_chk': 'N',
                'best_comno': '0',
                'board_id': self.account['login_id'],
                'user_id': self.account['user_id'],
            },
            headers={'User-Agent': APP_USER_AGENT},
            timeout=TIMEOUT)
        return self._parseWriteResult(res)

    def _parseWriteResult(self, res) -> dict:
        """쓰기 응답을 정규화

        성공하면 cause 자리에 글번호/댓글번호가 실려 온다
        쓰기에는 별도 캡차가 걸릴 수 있어 따로 표시한다 (app.dcinside.com/code.php)
        """
        text = res.text.strip()
        if not text:
            return {'ok': False, 'cause': 'BLOCKED', 'no': '', 'captcha': False,
                    'transient': True}
        try:
            raw = res.json()
        except ValueError:
            return {'ok': False, 'cause': f'JSON이 아닌 응답: {text[:160]}', 'no': '',
                    'captcha': False, 'transient': False}

        value = raw[0] if isinstance(raw, list) and raw else raw
        if not isinstance(value, dict):
            return {'ok': False, 'cause': f'알 수 없는 응답: {str(raw)[:160]}', 'no': '',
                    'captcha': False, 'transient': False}

        cause = str(value.get('cause', '') or value.get('message', '') or '')
        if isTruthyDcResult(value.get('result')):
            # 응답마다 번호를 싣는 자리가 다르다
            no = str(value.get('comment_no') or value.get('no')
                     or value.get('data') or cause or '')
            return {'ok': True, 'cause': '', 'no': no, 'captcha': False,
                    'transient': False}

        kind = authExpiredKind(cause)
        if kind:
            raise AppAuthExpiredError(kind, cause)
        return {
            'ok': False,
            'cause': cause or f'작성에 실패했습니다. (응답: {str(raw)[:160]})',
            'no': '',
            'captcha': isWriteCaptchaCause(cause),
            'transient': isTransientCause(cause),
        }

    def deleteWithAuthRefresh(self, delete_fn):
        """app_id가 만료되면 한 번 재발급하고 같은 작업을 다시 시도함"""
        try:
            return delete_fn()
        except AppAuthExpiredError as e:
            if e.kind != 'app_id':
                raise
            self.refreshCredentials()
            return delete_fn()
