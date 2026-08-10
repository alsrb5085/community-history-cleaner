"""m.dcinside.com 갤로그 목록/삭제

데스크톱 갤로그보다 가볍고(JSON 30건 vs HTML 20건) 글·댓글을
로그 번호 하나로 함께 지운다. 앱 갤로그 웹뷰가 쓰는 경로

  목록  POST /ajax/response-galloglist
  삭제  POST /ajax/access -> Block_key, POST /gallog/log-del

모든 호출에 갤로그 페이지의 csrf 토큰이 필요함
"""
from typing import Optional

import requests
from bs4 import BeautifulSoup

BASE = 'https://m.dcinside.com'
USER_AGENT = ('Mozilla/5.0 (Linux; Android 14; SM-S911N) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 dcinside_app')
TIMEOUT = 20

# 목록 메뉴 코드
MENU = {'posting': 'G_all', 'comment': 'R_all'}


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
        """목록 한 줄에서 삭제에 필요한 값만 남긴다

        log_no는 갤로그 삭제용, no와 cno는 앱 API 삭제용, gall_code는 필터용
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
        if not res.text.strip():
            return {'ok': False, 'cause': 'BLOCKED', 'transient': True}
        try:
            payload = res.json()
        except ValueError:
            return {'ok': False, 'cause': 'BLOCKED', 'transient': True}

        if not isinstance(payload, dict):
            return {'ok': True, 'cause': '', 'transient': False}

        # 갤로그 JS의 판정은 `0 == result면 실패` 하나뿐이다. 성공 값을 좁게
        # 잡으면 실제로 지워진 글이 실패로 집계됨
        if not _isFailureResult(payload.get('result')):
            return {'ok': True, 'cause': '', 'transient': False}

        cause = str(payload.get('cause') or '삭제에 실패했습니다.')
        return {'ok': False, 'cause': cause, 'transient': _isTransient(cause)}


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


def _toInt(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
