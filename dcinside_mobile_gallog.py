"""m.dcinside.com 갤로그 목록/삭제

데스크톱 갤로그보다 가볍고(JSON 30건 vs HTML 20건) 글·댓글을
로그 번호 하나로 함께 지운다. 앱 갤로그 웹뷰가 쓰는 경로

  목록  POST /ajax/response-galloglist
  삭제  POST /ajax/access -> Block_key, POST /gallog/log-del

모든 호출에 갤로그 페이지의 csrf 토큰이 필요함
"""
from typing import Optional
import hashlib
import re
import time

import requests
from bs4 import BeautifulSoup

BASE = 'https://m.dcinside.com'
USER_AGENT = ('Mozilla/5.0 (Linux; Android 14; SM-S911N) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 dcinside_app')
TIMEOUT = 20

# 목록 메뉴 코드
MENU = {'posting': 'G_all', 'comment': 'R_all'}

# 봇체크 캡차. 검증 경로와 폼 구성은 m.dcinside.com/js/middle.min.js의
# captcha_action()에서 확인함 (#captcha_form serialize -> POST /gallog/codecheck)
CODECHECK_PATH = '/gallog/codecheck'
CAPTCHA_IMAGE_FALLBACK = '/captcha/code?id=log_del_botchk'

# ddddocr 출력이 이 모양일 때만 제출한다
# 이 캡차는 한글이 섞여 나오는데 ddddocr charset엔 한글이 사실상 없어서
# 한글 이미지는 한자로 뭉개진다. 그 성질을 거꾸로 써서 판별에 쓴다
# (출력에 CJK가 섞였다 = 읽을 수 없는 이미지다 -> 새로 뽑는다)
ALNUM_ONLY = re.compile(r'^[a-z0-9]{4,8}$')

# 같은 이미지가 이만큼 연속으로 오면 새로고침해도 코드가 재발급되지 않는 것
STATIC_IMAGE_LIMIT = 4


class MobileGallog:
    """모바일 갤로그 목록/삭제. 로그인 쿠키가 있는 세션을 그대로 씀"""

    def __init__(self, cookies: dict = None):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': USER_AGENT})
        self.csrf = ''
        self.user_id = ''
        self.extra_auth = {}    # 갤로그 페이지에 숨어 있는 삭제용 인증 값
        self.gallery_ids = {}   # gall_code -> 갤러리 문자열 ID
        if cookies:
            self.setCookies(cookies)

    def setCookies(self, cookies: dict) -> None:
        for name, value in cookies.items():
            self.session.cookies.set(name, value, domain='.dcinside.com')
        # 쿠키가 바뀌면 토큰도 새로 받아야 함
        self.csrf = ''
        self.extra_auth = {}

    def ensureToken(self, user_id: str, force: bool = False) -> bool:
        """갤로그 페이지에서 csrf 토큰과 숨은 인증 값을 받아 둔다

        속도 제한이나 캡차를 겪으면 토큰이 무효해진다. 그때는 force로 다시 받는다
        """
        if self.csrf and self.user_id == user_id and not force:
            return True

        res = self.session.get(f'{BASE}/gallog/{user_id}', timeout=TIMEOUT)
        if not res.text.strip():
            return False

        soup = BeautifulSoup(res.text, 'html.parser')
        meta = soup.select_one('meta[name="csrf-token"]')
        if not meta or not meta.get('content'):
            return False

        # 갤로그 JS가 삭제 요청에 함께 싣는 값들. 빠지면 서버가 거부함
        self.extra_auth = {}
        for field in ('confirm_id', 'app_id'):
            node = soup.select_one(f'#{field}')
            if node and node.get('value'):
                self.extra_auth[field] = node['value']

        self.csrf = meta['content']
        self.user_id = user_id
        self.session.headers.update({
            'X-CSRF-TOKEN': self.csrf,
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': f'{BASE}/gallog/{user_id}',
        })
        return True

    def _postJson(self, user_id: str, path: str, data: dict) -> Optional[dict]:
        """JSON을 받는 POST. 빈 응답이면 토큰을 갱신해 한 번 더 시도한다

        빈 응답이 속도 제한인지 토큰 만료인지 구분할 수 없어 확인해 보는 것
        두 번째도 비면 차단으로 보고 None
        """
        for attempt in range(2):
            if not self.ensureToken(user_id, force=attempt > 0):
                return None
            try:
                res = self.session.post(f'{BASE}{path}', data=data, timeout=TIMEOUT)
            except requests.RequestException:
                return None
            # 429는 토큰을 새로 받아도 같은 답이 온다. 재시도하면 요청만 는다
            if res.status_code == 429:
                return None
            if res.text.strip():
                try:
                    return res.json()
                except ValueError:
                    return None
            self.csrf = ''
        return None

    def fetchPage(self, user_id: str, post_type: str, page: int) -> Optional[dict]:
        """목록 한 페이지. 차단되면 None"""
        payload = self._postJson(user_id, '/ajax/response-galloglist', {
            'g_id': user_id,
            'menu': MENU.get(post_type, 'G_all'),
            'page': page,
            'list_more': 1,
        })
        if not isinstance(payload, dict):
            return None

        listing = payload.get('gallog_list')
        if not isinstance(listing, dict):
            return None

        rows = listing.get('data') or []
        return {
            'total': _toInt(listing.get('total')),
            'last_page': max(1, _toInt(listing.get('last_page'), 1)),
            'entries': [self._toEntry(row) for row in rows if isinstance(row, dict)],
        }

    @staticmethod
    def _toEntry(row: dict) -> dict:
        """목록 한 줄에서 쓸 값을 뽑는다

        log_no는 갤로그 삭제용, no와 cno는 앱 API 삭제용, gall_code는 필터용

        나머지(wdate/memo/subject/...)는 거르는 데 쓴다. 목록 응답에 이미
        들어 있으므로 이걸 쓰는 필터는 요청을 한 번도 더 보내지 않는다
        필드 이름은 m.dcinside.com/js/gallog.min.js의 목록 렌더링에서 확인함
        """
        return {
            'log_no': str(row.get('no') or ''),
            'no': str(row.get('pno') or ''),
            'cno': str(row.get('cno') or '0'),
            'gall_code': str(row.get('gall_code') or row.get('cid') or ''),
            'gall_name': str(row.get('name') or ''),
            'gall_type': str(row.get('type') or ''),
            # 모바일 목록엔 문자열 갤러리 ID가 없다. resolveGalleryId로 채운다
            'gallery': '',
            # --- 거르는 데 쓰는 값 ---
            'wdate': str(row.get('wdate') or ''),
            'memo': str(row.get('memo') or ''),
            'subject': str(row.get('subject') or ''),
            'total_comment': _toInt(row.get('total_comment')),
            # 갤로그 JS도 null인지만 본다. 값 자체는 쓰지 않는다
            'is_reply': row.get('re_comment') is not None,
            'secret': bool(row.get('secret')),
        }

    def resolveGalleryId(self, gall_code: str, gall_type: str) -> str:
        """숫자 갤러리 코드 -> 앱 API가 쓰는 문자열 갤러리 ID

        갤로그가 글 링크를 만들 때 쓰는 경로. 갤러리당 한 번만 조회한다
        """
        if not gall_code or not self.user_id:
            return ''
        if gall_code in self.gallery_ids:
            return self.gallery_ids[gall_code]

        payload = self._postJson(self.user_id, '/gallog/list-direct',
                                 {'gall_code': gall_code, 'gall_type': gall_type})
        gallery = str(payload.get('gall_id') or '') if isinstance(payload, dict) else ''

        # 실패는 캐시하지 않는다. 캐시하면 그 갤러리는 재시작 전까지 앱 API를 못 씀
        if gallery:
            self.gallery_ids[gall_code] = gallery
        return gallery

    def delete(self, user_id: str, log_no: str) -> dict:
        """글이든 댓글이든 로그 번호 하나로 지움"""
        access = self._postJson(user_id, '/ajax/access', {'token_verify': 'gallogDel'})
        if not isinstance(access, dict):
            return {'ok': False, 'cause': 'BLOCKED', 'transient': True}
        block_key = access.get('Block_key')
        if not block_key:
            return {'ok': False, 'cause': '삭제 토큰을 받지 못했습니다.', 'transient': False}

        form = {'no': log_no, 'g_id': user_id, 'con_key': block_key}
        form.update(self.extra_auth)
        res = self.session.post(f'{BASE}/gallog/log-del', data=form, timeout=TIMEOUT)

        # 상태 코드를 먼저 본다. 429는 {"message":"Too Many Attempts."}라는
        # JSON을 돌려주는데, result 키가 없어 아래 성공 판정을 그냥 통과한다
        # 그러면 지워지지도 않은 항목이 성공으로 집계되어 목록에서 빠진다
        if res.status_code == 429:
            return {'ok': False, 'cause': 'THROTTLED', 'transient': True}
        if res.status_code != 200:
            return {'ok': False, 'cause': f'HTTP {res.status_code}', 'transient': True}

        if not res.text.strip():
            return {'ok': False, 'cause': 'BLOCKED', 'transient': True}
        try:
            payload = res.json()
        except ValueError:
            return {'ok': False, 'cause': 'BLOCKED', 'transient': True}

        # 갤로그가 돌려주는 형태가 아니다. 성공으로 읽을 근거가 없다
        if not isinstance(payload, dict) or 'result' not in payload:
            return {'ok': False, 'cause': f'알 수 없는 응답: {str(payload)[:100]}',
                    'transient': True}

        # 갤로그 JS의 판정은 `0 == result면 실패` 하나뿐이다. 성공 값을 좁게
        # 잡으면 실제로 지워진 글이 실패로 집계됨
        if not _isFailureResult(payload.get('result')):
            return {'ok': True, 'cause': '', 'transient': False}

        cause = str(payload.get('cause') or '삭제에 실패했습니다.')
        # 이 문구는 기다린다고 풀리지 않는다. 봇 확인이 걸린 것이라
        # 갤로그에서 캡차를 풀어야 다시 지울 수 있다 (180초·360초 대기 실패 확인)
        if _isBotGate(cause):
            return {'ok': False, 'cause': cause, 'transient': False, 'captcha': True}
        return {'ok': False, 'cause': cause, 'transient': _isTransient(cause)}

    def hasCaptcha(self, user_id: str) -> Optional[bool]:
        """갤로그 페이지에 봇 확인 레이어가 붙었는지. 확인 자체가 실패하면 None

        갤로그 JS도 삭제 버튼을 누르기 전에 이 요소부터 본다
        """
        try:
            res = self.session.get(f'{BASE}/gallog/{user_id}?menu=R_all', timeout=TIMEOUT)
        except requests.RequestException:
            return None
        if res.status_code != 200 or not res.text.strip():
            return None
        # 문자열로 찾으면 인라인 스크립트에 적힌 captcha_div까지 걸린다
        # 이 판정에 삭제 흐름이 걸려 있으므로 요소로 확인한다
        soup = BeautifulSoup(res.text, 'html.parser')
        return soup.select_one('#captcha_div') is not None

    def readCaptchaForm(self, user_id: str) -> Optional[dict]:
        """봇체크 레이어에서 제출에 필요한 값을 읽는다

        게이트가 걸렸을 때만 서버가 #captcha_div를 심는다 (gallog.min.js의
        `$("#captcha_div").length>0` 판정과 같은 근거). 안 걸렸으면 None
        """
        try:
            res = self.session.get(f'{BASE}/gallog/{user_id}?menu=R_all', timeout=TIMEOUT)
        except requests.RequestException:
            return None
        if res.status_code != 200 or not res.text.strip():
            return None

        soup = BeautifulSoup(res.text, 'html.parser')
        if soup.select_one('#captcha_div') is None:
            return None
        scope = soup.select_one('#captcha_form') or soup.select_one('#captcha_div')

        fields = {}
        for node in scope.select('input'):
            name = node.get('name')
            if name:
                fields[name] = node.get('value') or ''
        # 삭제 요청에 싣는 값과 같은 것들. 폼에 이미 있으면 건드리지 않는다
        for name, value in self.extra_auth.items():
            fields.setdefault(name, value)

        img = scope.select_one('img')
        src = (img.get('src') or '') if img else ''
        if not src:
            src = CAPTCHA_IMAGE_FALLBACK
        if src.startswith('//'):
            src = 'https:' + src
        elif src.startswith('/'):
            src = BASE + src

        # 코드가 들어갈 칸. JS는 #captcha_code를 읽는다
        code_field = 'captcha_code'
        node = scope.select_one('#captcha_code')
        if node is not None and node.get('name'):
            code_field = node['name']

        return {'fields': fields, 'image_url': src, 'code_field': code_field}

    def fetchCaptchaImage(self, image_url: str, nonce: int) -> Optional[bytes]:
        """캡차 이미지를 새로 받는다. 캐시를 타면 같은 그림이 온다"""
        joiner = '&' if '?' in image_url else '?'
        try:
            res = self.session.get(f'{image_url}{joiner}_={nonce}',
                                   headers={'Referer': f'{BASE}/gallog/{self.user_id}'},
                                   timeout=TIMEOUT)
        except requests.RequestException:
            return None
        if res.status_code != 200 or not res.content:
            return None
        return res.content

    def submitCaptcha(self, form: dict, code: str) -> dict:
        """코드를 제출한다

        middle.min.js의 captcha_action()과 같다
        판정도 그대로 옮겼다 -- `0 == result`면 실패
        """
        data = dict(form['fields'])
        data[form['code_field']] = code
        try:
            res = self.session.post(f'{BASE}{CODECHECK_PATH}', data=data, timeout=TIMEOUT)
        except requests.RequestException as e:
            return {'ok': False, 'cause': f'{type(e).__name__}: {e}'}
        if res.status_code != 200:
            return {'ok': False, 'cause': f'HTTP {res.status_code}'}
        try:
            payload = res.json()
        except ValueError:
            return {'ok': False, 'cause': f'JSON이 아닌 응답: {res.text[:120]}'}
        if not isinstance(payload, dict):
            return {'ok': False, 'cause': f'알 수 없는 응답: {str(payload)[:120]}'}
        if _isFailureResult(payload.get('result')):
            return {'ok': False, 'cause': str(payload.get('cause') or '코드가 틀렸습니다.')}
        return {'ok': True, 'cause': ''}

    def solveCaptcha(self, user_id: str, ocr, tries: int = 40,
                     interval: float = 0.4, notify=None, dump=None) -> dict:
        """봇체크 캡차를 자동으로 푼다

        이 캡차는 한글·영문·숫자가 섞여 나오고 한글은 ddddocr로 못 읽는다
        그래서 푸는 게 아니라 고른다 -- 영문·숫자만 나올 때까지 새로 뽑고
        그때만 제출한다. 한글이 섞이면 ddddocr 출력에 한자가 끼므로 걸러진다

        돌려주는 값의 reason
          'solved'        풀렸음
          'no_captcha'    게이트가 없음
          'static_image'  새로고침해도 같은 이미지. 코드가 재발급되지 않는다
          'exhausted'     tries 안에 영문·숫자 이미지를 못 뽑았음
          그 외            서버 거절 사유
        """
        # 이미지 요청의 Referer에 쓴다. 목록을 안 거치고 바로 올 수도 있다
        if not self.user_id:
            self.user_id = user_id

        form = self.readCaptchaForm(user_id)
        if form is None:
            return {'solved': False, 'reason': 'no_captcha', 'attempts': 0, 'readable': 0}

        seen = []
        readable = 0
        for attempt in range(1, tries + 1):
            image = self.fetchCaptchaImage(form['image_url'], attempt)
            if image is None:
                return {'solved': False, 'reason': '캡차 이미지를 받지 못했습니다.',
                        'attempts': attempt, 'readable': readable}

            digest = hashlib.md5(image).hexdigest()
            seen.append(digest)
            # 새로고침이 코드를 다시 뽑지 않는다면 몇 번을 돌려도 같은 그림만 온다
            # 그때는 이 방법 자체가 성립하지 않으므로 사람에게 넘긴다
            if len(seen) >= STATIC_IMAGE_LIMIT and len(set(seen[-STATIC_IMAGE_LIMIT:])) == 1:
                return {'solved': False, 'reason': 'static_image',
                        'attempts': attempt, 'readable': readable}

            try:
                text = ocr.classification(image).strip().lower()
            except Exception as e:
                return {'solved': False, 'reason': f'OCR 실패: {type(e).__name__}: {e}',
                        'attempts': attempt, 'readable': readable}

            if dump:
                dump(attempt, image, text)
            if notify:
                notify(attempt, tries, text)

            # 한글 이미지는 한자로 뭉개져 여기서 걸린다. 다시 뽑는다
            if not ALNUM_ONLY.match(text):
                time.sleep(interval)
                continue

            readable += 1
            result = self.submitCaptcha(form, text)
            if result['ok']:
                # 게이트가 풀리면 토큰도 다시 받아야 한다
                self.csrf = ''
                return {'solved': True, 'reason': 'solved', 'attempts': attempt,
                        'readable': readable, 'code': text}

            # 틀렸으면 서버가 코드를 새로 잡는다. 폼도 다시 읽어야 한다
            refreshed = self.readCaptchaForm(user_id)
            if refreshed is None:
                # 게이트가 사라졌다. 어떤 이유로든 통과한 것이다
                self.csrf = ''
                return {'solved': True, 'reason': 'solved', 'attempts': attempt,
                        'readable': readable, 'code': text}
            form = refreshed
            time.sleep(interval)

        return {'solved': False, 'reason': 'exhausted', 'attempts': tries, 'readable': readable}


def _isFailureResult(result) -> bool:
    """갤로그 JS의 `0 == result`를 그대로 옮긴 것

    undefined/null은 0과 같지 않아 성공, false/""/"0"/0은 실패
    """
    if result is None:
        return False
    if isinstance(result, bool):
        return result is False
    if isinstance(result, (int, float)):
        return result == 0
    if isinstance(result, str):
        stripped = result.strip()
        if stripped == '':
            return True
        try:
            return float(stripped) == 0
        except ValueError:
            return False
    return False


def _isTransient(cause: str) -> bool:
    squeezed = cause.replace(' ', '')
    return '잠시후다시' in squeezed or '다시시도' in squeezed


def _isBotGate(cause: str) -> bool:
    """캡차를 풀어야만 풀리는 거절인지

    문구는 일시적인 것처럼 보이지만 기다려서는 풀리지 않는다
    """
    return '잠시후다시이용' in cause.replace(' ', '')


def _toInt(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
