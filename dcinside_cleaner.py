from requests.exceptions import ConnectTimeout
from requests.exceptions import ProxyError
from twocaptcha import TwoCaptcha
from bs4 import BeautifulSoup
from typing import Union
from urllib.parse import parse_qs, urlparse
import requests
import urllib3
import time

from dcinside_app_api import AppApi, AppApiError, AppAuthExpiredError
from dcinside_mobile_gallog import MobileGallog

MAX_DELAY = 0.9

# 서버가 잠깐 거부했을 때 쓰는 문구들. 버리지 말고 뒤로 미뤄 다시 시도한다
# '삭제할 수 없습니다'는 여기 없다. 원글이 삭제된 댓글이라 영구 실패이고,
# 재시도가 아니라 갤로그 log-del로 넘겨야 한다
RETRYABLE_CAUSES = ('잠시후', '다시시도', '다시이용', '일시적')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _isRetryableCause(cause: str) -> bool:
    squeezed = str(cause).replace(' ', '')
    return any(pattern in squeezed for pattern in RETRYABLE_CAUSES)

class Cleaner:
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'
    login_headers = {
        "Referer": "https://sign.dcinside.com/login",
        'User-Agent': user_agent,
        'Sec-CH-UA': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        'Sec-CH-UA-Mobile': '?0',
        'Sec-CH-UA-Platform': '"Windows"',
    }

    delete_headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'ko-KR,ko;q=0.9',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Host': 'gallog.dcinside.com',
        'Origin': 'https://gallog.dcinside.com',
        'Referer': '',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': user_agent
    }

    dcinside_site_key = '6LcJyr4UAAAAAOy9Q_e9sDWPSHJ_aXus4UnYLfgL'

    # 로그인에 성공해야만 발급되는 쿠키. base64로 "아이디^번호"가 들어 있다
    # sso_* 는 로그인 실패 때도, ci_c/PHPSESSID 등은 비로그인에도 발급되므로
    # 로그인 판정에 쓰면 안 된다
    auth_cookies = ('unicro_id',)

    # 앱 API가 이만큼 연속으로 실패하면 접고 갤로그 경로로 돌아간다
    app_api_failure_limit = 3

    # 일시적으로 보이는 실패를 목록 끝으로 돌려보내 다시 시도하는 횟수
    retry_attempt_limit = 3

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Sec-CH-UA': '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Platform': '"Windows"',
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
        })
        self.post_list = []
        self.proxy_list = []
        self.twocaptcha_key = ''
        self.solver : TwoCaptcha
        self.delay = MAX_DELAY
        self.user_id = ''
        self.blocked = False
        self.last_login_error = ''
        # 앱 API. 삭제를 갤로그 대신 app.dcinside.com으로 보낸다
        # 준비되지 않으면 기존 갤로그 경로로 그대로 동작한다
        self.app_api = None
        self.last_app_api_error = ''
        self._app_api_failures = 0
        self._app_login = None
        # 모바일 갤로그. 목록·삭제 모두 데스크톱보다 가볍다
        # (JSON 11KB / 30건 vs HTML 43KB / 20건)
        self.mobile = MobileGallog()
        self.use_mobile = True

    def updateDelay(self):
        self.delay = round(MAX_DELAY / (len(self.proxy_list) or 1), 1)

    def _handleProxyError(func):
        def wrapper(self, *args):
            result = None
            while True:
                try:
                    result = func(self, *args)
                except (ProxyError, ConnectTimeout):
                    # 프록시를 안 쓰는데 타임아웃이 나면 뺄 프록시가 없다
                    # 빈 리스트에 pop을 걸면 죽으므로 차단으로 넘긴다
                    if not self.proxy_list:
                        return 'BLOCKED'
                    self.proxy_list.pop()
                    self.updateDelay()
                else:
                    return result

        return wrapper

    def serializeForm(self, input_elements):
        form = {}
        for element in input_elements:
            form[element['name']] = element['value']
        return form

    def getUserId(self) -> str:
        return self.user_id

    def setUserId(self, user_id: str) -> None:
        self.user_id = user_id

    def setProxyList(self, proxy_list: list) -> None:
        self.proxy_list = proxy_list
        self.updateDelay()

    def set2CaptchaKey(self, key) -> bool:
        twocaptcha_url = f'https://2captcha.com/in.php?key={key}'

        res = requests.get(twocaptcha_url)

        if res.text in ('ERROR_KEY_DOES_NOT_EXIST', 'ERROR_WRONG_USER_KEY'):
            return False
        
        self.twocaptcha_key = key

        self.solver = TwoCaptcha(key)
        
        return True

    def getCookies(self) -> dict:
        return self.session.cookies.get_dict()

    def _propagateCookies(self, cookies: dict) -> None:
        """쿠키를 관련 도메인 전체에 전파한다"""
        for k, v in cookies.items():
            self.session.cookies.set(k, v, domain='.dcinside.com')
        # 모바일 갤로그도 같은 인증 쿠키를 쓴다
        self.mobile.setCookies(cookies)

    def loginFromCookies(self, cookies: dict) -> bool:
        self._propagateCookies(cookies)
            
        if 'unicro_id' in cookies or 'unicro_id' in self.session.cookies.get_dict():
            import base64
            try:
                unicro_val = cookies.get('unicro_id') or self.session.cookies.get('unicro_id')
                decoded = base64.b64decode(unicro_val).decode('utf-8')
                self.user_id = decoded.split('^')[0]
            except:
                pass
            return True
        return False

    def gallogGet(self, url: str, proxies: dict = None, retries: int = 2):
        """갤로그 GET. 빈 본문이면 한 번만 더 시도한다

        갤로그는 요청이 잦으면 HTTP 200에 빈 본문을 돌려준다. 재 보면 두 가지다
          - 산발적인 단발: 잠깐 뒤 다시 하면 대부분 통과
          - 속도 제한: 수 분간 모든 요청이 계속 빈다
        후자에서 재시도를 늘리면 요청만 배로 늘어 제한이 길어진다
        그래서 1회만 더 해 보고, 그래도 비면 호출부가 차단으로 처리한다
        """
        res = None
        for attempt in range(retries):
            self.session.headers.update({'User-Agent': self.user_agent})
            res = self.session.get(url, proxies=proxies or {})
            if res.text.strip():
                return res
            if attempt < retries - 1:
                time.sleep(2.0)
        return res

    def hasAuthCookies(self) -> bool:
        """세션에 로그인 전용 쿠키가 있는지"""
        cookies = self.session.cookies.get_dict()
        return any(name in cookies for name in self.auth_cookies)

    def verifyLogin(self) -> bool:
        """갤로그 페이지로 실제 로그인 상태를 확인한다

        차단 상태에서는 빈 본문이 와서 페이지로 판단할 수 없다
        로그아웃으로 오판하면 멀쩡한 세션을 버리므로, 그때는 쿠키로 판정하고
        blocked 플래그를 세운다
        """
        self.blocked = False
        try:
            res = self.gallogGet(f'https://gallog.dcinside.com/{self.user_id}')
            soup = BeautifulSoup(res.text, 'html.parser')

            # 빈 본문은 로그아웃이 아니라 차단 신호다
            if not res.text.strip() or not soup.select_one('body'):
                self.blocked = True
                return self.hasAuthCookies()

            # 상단 로그인/로그아웃 버튼으로 판단
            login_btn = soup.select_one('.btn_top_loginout')
            if login_btn and login_btn.text.strip() == '로그인':
                return False

            # 갤로그 메뉴가 있고, 갤러리 드롭다운이 정상적이면 로그인 상태
            if soup.select('.gallog_menu li'):
                return True

            # 사이트 개편으로 위 선택자가 사라져도 쿠키로 판정한다
            return self.hasAuthCookies()
        except Exception:
            # 네트워크 오류로 확인하지 못한 것뿐이니 세션은 버리지 않는다
            self.blocked = True
            return self.hasAuthCookies()

    def login(self, user_id: str, user_pw: str) -> bool:
        """ID/PW 로그인

        Playwright로 실제 브라우저에서 진행한다. 캡차는 ddddocr로 풀어 보고,
        캠페인 리다이렉트로 쿠키가 깨지는 것도 막는다

        성공 판정은 발급된 인증 쿠키로 한다. 갤로그 DOM으로 판정하면
        사이트 개편이나 차단 때 성공한 로그인을 실패로 오판한다
        """
        self.user_id = user_id
        self.last_login_error = ''

        ocr = None
        try:
            import ddddocr
            ocr = ddddocr.DdddOcr(show_ad=False)
        except ImportError:
            pass
            
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            print("[Error] Playwright가 설치되지 않았습니다. 'pip install playwright' 및 'playwright install chromium'을 실행해주세요.")
            return False

        print("가상 브라우저를 통해 로그인을 진행합니다...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(user_agent=self.user_agent)
            
            # 캠페인 페이지 접근 차단 (쿠키 파괴 방지)
            context.route("**/*campaign/password_change*", lambda route: route.abort())
            
            page = context.new_page()

            # 로그인 실패 사유는 alert로 오는데 Playwright가 조용히 닫아버린다
            # 직접 받아서 사유를 남긴다
            dialog_messages = []

            def _on_dialog(dialog):
                dialog_messages.append(dialog.message.strip())
                dialog.accept()

            page.on('dialog', _on_dialog)

            try:
                page.goto("https://sign.dcinside.com/login", timeout=15000)

                page.fill("#id", user_id)
                page.fill("#pw", user_pw)

                # 캡차 확인
                if page.is_visible("#kcaptcha_code"):
                    if not ocr:
                        self.last_login_error = '캡차가 발견되었으나 ddddocr이 없어 풀 수 없습니다.'
                        print(self.last_login_error)
                        browser.close()
                        return False
                    page.wait_for_timeout(500)
                    captcha_img = page.locator("#kcaptcha").screenshot()
                    captcha_text = ocr.classification(captcha_img).lower()
                    print(f"캡차 자동 인식 중... ({captcha_text})")
                    page.fill("#kcaptcha_code", captcha_text)
                
                # 로그인 시도
                try:
                    with page.expect_navigation(timeout=5000):
                        page.click(".btn_blue.small.btn_wfull")
                except Exception:
                    pass
                
                page.wait_for_timeout(2000)

                # 인증 쿠키 발급 여부로 판정한다
                # 컨텍스트가 매번 새로 생기므로 이전 쿠키가 남아 오판할 일은 없다
                cookies = context.cookies()
                if any(c['name'] in self.auth_cookies for c in cookies):
                    # 로그인 성공, 쿠키 추출하여 requests 세션에 복사
                    self.session.cookies.clear()
                    for c in cookies:
                        self.session.cookies.set(c['name'], c['value'], domain=c['domain'], path=c['path'])

                    self._propagateCookies(self.session.cookies.get_dict())
                    browser.close()
                    return True

                self.last_login_error = dialog_messages[-1] if dialog_messages else ''

            except Exception as e:
                self.last_login_error = f'{type(e).__name__}: {e}'

            browser.close()
            return False

    def getLastLoginError(self) -> str:
        return self.last_login_error

    def enableAppApi(self, user_id: str, user_pw: str, notify=None) -> bool:
        """앱 API 자격증명을 받아 삭제 경로를 갤로그에서 옮긴다

        갤로그는 글 하나마다 요청을 두 번 받아 속도 제한에 쉽게 걸린다
        앱 API는 호스트가 달라 그 부하를 덜어낼 수 있다

        실패해도 예외를 올리지 않는다. 앱 API가 없어도 갤로그 경로로
        삭제는 진행되므로 여기서 죽으면 손해만 본다
        """
        self.last_app_api_error = ''
        try:
            api = AppApi()
            # 매 실행마다 로그인하면 캡차가 걸린다. 저장된 게 있으면 재사용한다
            api.loginOrRestore(user_id, user_pw)
            # 기기를 새로 등록했다면 곧바로 삭제를 걸 수 없다
            # 저장된 기기를 재사용했다면 그냥 지나간다
            api.waitUntilUsable(notify=notify)
            self.app_api = api
            self._app_login = (user_id, user_pw)
            self._app_api_failures = 0
            return True
        except (AppApiError, requests.RequestException) as e:
            self.last_app_api_error = f'{type(e).__name__}: {e}'
            self.app_api = None
            return False

    def getLastAppApiError(self) -> str:
        return self.last_app_api_error

    def isAppApiReady(self) -> bool:
        return bool(self.app_api and self.app_api.isReady())

    def getUserInfo(self) -> dict:
        self.session.headers.update(self.login_headers)
        res = self.session.get(f'https://gallog.dcinside.com/{self.user_id}')
        soup = BeautifulSoup(res.text, 'html.parser')
        nickname = soup.select_one('#top_bg > div.galler_info > strong').get_text()
        article_num = soup.select_one('#container > article > div > div.wrap_right > section > section:nth-child(2) > div > header > div > h2 > span').get_text()
        comment_num = soup.select_one('#container > article > div > div.wrap_right > section > section:nth-child(3) > div > header > div > h2 > span').get_text()

        remove_bracket = lambda x: x[1:-1]

        return {
            'nickname': nickname,
            'article_num': remove_bracket(article_num),
            'comment_num': remove_bracket(comment_num)
        }

    def deletePost(self, post, post_type: str, solve_captcha: bool) -> Union[dict, bool]:
        """글/댓글 하나를 삭제한다

        앱 API -> 모바일 갤로그 -> 데스크톱 갤로그 순으로 시도한다
        앱 API는 갤로그를 건드리지 않아 속도 제한에 걸리지 않는다
        """
        entry = post if isinstance(post, dict) else {'log_no': post, 'gallery': '', 'no': ''}

        # 앱 API는 문자열 갤러리 ID를 요구한다. 모바일 목록엔 숫자 코드뿐이라 변환한다
        if (not entry.get('gallery') and entry.get('gall_code')
                and self.isAppApiReady()):
            entry['gallery'] = self.mobile.resolveGalleryId(
                entry['gall_code'], entry.get('gall_type') or 'G')

        # 1) 앱 API. 모바일 목록이 글번호·댓글번호를 다 주므로 댓글도 여기서 지운다
        if not solve_captcha and self.isAppApiReady() and self._canUseAppApi(entry, post_type):
            result = self._deleteViaAppApi(entry, post_type)

            # 막힌 거라면 갤로그로 넘기지 않는다. 피하려던 부하가 그대로 돌아온다
            if not result or result == 'BLOCKED':
                return result

            # 앱 API가 이 항목을 거부했다
            # 원글이 삭제된 댓글이 대표적이다. 앱 API는 원글 번호로 대상을 찾는다
            # 갤로그 log-del은 로그 항목을 지우므로 원글이 없어도 된다
            if self.use_mobile and entry.get('log_no'):
                fallback = self._deleteViaMobileGallog(entry['log_no'])
                if fallback is not None:
                    return fallback
            return result

        # 2) 모바일 갤로그. log_no 하나로 글·댓글을 모두 처리한다
        if self.use_mobile and not solve_captcha and entry.get('log_no'):
            result = self._deleteViaMobileGallog(entry['log_no'])
            if result is not None:
                return result

        # 3) 데스크톱 갤로그. 캡차를 처리할 수 있는 유일한 경로다
        return self._deleteViaGallog(entry.get('log_no', ''), post_type, solve_captcha)

    @staticmethod
    def _canUseAppApi(entry: dict, post_type: str) -> bool:
        """앱 API로 지울 수 있는 항목인지"""
        if not entry.get('gallery') or not entry.get('no'):
            return False
        if post_type == 'comment':
            # 댓글번호가 0이면 어느 댓글인지 특정할 수 없다
            return entry.get('cno', '0') not in ('', '0')
        return True

    def _deleteViaAppApi(self, entry: dict, post_type: str):
        """앱 API로 글/댓글을 삭제한다

        쓸 수 없으면 None을 돌려주어 호출부가 갤로그로 넘기게 한다
        그 외에는 갤로그 경로와 같은 형태로 맞춰 돌려준다
        """
        if post_type == 'comment':
            def call():
                return self.app_api.deleteComment(
                    entry['gallery'], entry['no'], entry['cno'])
        else:
            def call():
                return self.app_api.deleteArticle(entry['gallery'], entry['no'])

        try:
            result = self.app_api.deleteWithAuthRefresh(call)
        except AppAuthExpiredError as e:
            # 저장된 로그인이 만료됐다. 한 번 다시 해 보고 안 되면 포기한다
            self.app_api.forgetAccount(self.app_api.account.get('login_id', ''))
            if self._app_login and self._relogin():
                try:
                    return self._appApiResult(call())
                except (AppApiError, requests.RequestException) as retry_error:
                    e = retry_error
            self.last_app_api_error = f'앱 로그인 세션 만료: {e}'
            self.app_api = None
            return None
        except (AppApiError, requests.RequestException) as e:
            # 이번 건만 갤로그로 넘긴다
            # 계속 실패하는데도 매번 넘기면 갤로그 부하가 조용히 원래대로 돌아온다
            self._app_api_failures += 1
            self.last_app_api_error = f'{type(e).__name__}: {e}'
            if self._app_api_failures >= self.app_api_failure_limit:
                self.last_app_api_error = (
                    f'앱 API 연속 실패 {self._app_api_failures}회로 사용을 중단합니다. '
                    f'({type(e).__name__}: {e})')
                self.app_api = None
            return None

        self._app_api_failures = 0
        return self._appApiResult(result)

    def _appApiResult(self, result: dict):
        """앱 API 응답을 갤로그 경로와 같은 형태로 맞춘다"""
        if result['ok']:
            return {}

        # 재시도를 다 쓰고도 거절이면 더 해 봐야 소용없다. 목록에 남긴 채 멈춘다
        if result['cause'] == 'BLOCKED' or result.get('transient'):
            self.last_app_api_error = result['cause']
            return 'BLOCKED'

        return {'result': 'fail', 'msg': result['cause']}

    def _relogin(self) -> bool:
        """만료된 앱 로그인을 한 번만 다시 시도한다"""
        try:
            self.app_api.login(*self._app_login)
            self.app_api.saveAccount()
            return True
        except (AppApiError, requests.RequestException) as e:
            self.last_app_api_error = f'재로그인 실패: {e}'
            return False

    def _deleteViaMobileGallog(self, log_no: str):
        """모바일 갤로그로 글/댓글을 삭제한다

        실패하면 토큰을 갱신해 한 번 더 해 보고, 그래도 안 되면 None
        """
        try:
            result = self.mobile.delete(self.user_id, log_no)
        except Exception:
            return None

        if result['ok']:
            return {}
        if result['cause'] == 'BLOCKED' or result.get('transient'):
            return 'BLOCKED'

        # 토큰 만료일 수 있으니 갱신 후 한 번 더
        self.mobile.csrf = ''
        try:
            result = self.mobile.delete(self.user_id, log_no)
        except Exception:
            return None

        if result['ok']:
            return {}
        if result['cause'] == 'BLOCKED' or result.get('transient'):
            return 'BLOCKED'
        return {'result': 'fail', 'msg': result['cause']}

    @_handleProxyError
    def _deleteViaGallog(self, post_no: str, post_type: str, solve_captcha: bool) -> Union[dict, bool]:
        gallog_url = f'https://gallog.dcinside.com/{self.user_id}/{post_type}'

        proxy = self.getProxy()

        res = self.gallogGet(gallog_url, proxies=proxy)

        soup = BeautifulSoup(res.text, 'html.parser')
        if not soup.select_one('body'):
            return 'BLOCKED'

        # service_code를 페이지에서 동적으로 추출
        service_code_el = soup.select_one('input[name="service_code"]')
        service_code = service_code_el['value'] if service_code_el else 'undefined'
        
        captcha = { 'g-recaptcha-response': self.solveCaptcha(gallog_url) if solve_captcha else 'undefined' }

        ci_c = self.session.cookies.get_dict().get('ci_c')
        if not ci_c:
            return 'BLOCKED'

        form_data = {
            'ci_t': ci_c,
            'no': post_no,
            'service_code': service_code,
            **(captcha if solve_captcha else {})
        }

        self.delete_headers['Referer'] = gallog_url
        self.session.headers.update(self.delete_headers)
        res = self.session.post(
            f'https://gallog.dcinside.com/{self.user_id}/ajax/log_list_ajax/delete', data=form_data, proxies=proxy)

        # 속도 제한에 걸리면 삭제 API도 JSON 대신 빈 본문을 돌려준다
        # 그대로 res.json()을 부르면 JSONDecodeError로 죽는다
        try:
            data = res.json()
        except ValueError:
            return 'BLOCKED'

        if res.status_code == 200 and data['result'] == 'success':
            return {}
        return data

    def deletePosts(self, post_type: str) -> Union[str, list]:
        solve_captcha = False

        while self.post_list:
            entry = self.post_list[0]
            post_no = entry.get('log_no') or entry.get('no') if isinstance(entry, dict) else entry

            a = time.time()
            time.sleep(self.delay)
            data = self.deletePost(entry, post_type, solve_captcha)
            delay = time.time() - a

            if data == 'BLOCKED':
                # 속도 제한. 기다렸다가 다시 시도한다
                # 목록 조회의 waitAndRetry와 같은 타이밍 (30초 -> 60초 -> 최대 120초)
                recovered = False
                for retry in range(5):
                    wait = min(30 * (retry + 1), 120)
                    yield {
                        'status': False,
                        'data': 'rate_limited',
                        'wait': wait,
                        'attempt': retry + 1,
                        'max_attempts': 5,
                    }
                    time.sleep(wait)
                    data = self.deletePost(entry, post_type, solve_captcha)
                    if data != 'BLOCKED':
                        recovered = True
                        yield {
                            'status': False,
                            'data': 'rate_cleared',
                        }
                        break

                if not recovered:
                    yield {
                        'status': False,
                        'data': 'ipblocked',
                        'reason': self.last_app_api_error or ''
                    }
                    return
                # 재시도 성공. data를 가지고 아래 처리로 넘어간다

            if data and ('captcha' in data['result'] or ('fail' in data['result'] and 'g-recaptcha error!' in data['msg'])):
                if self.twocaptcha_key: 
                    solve_captcha = True
                    continue

                # 캡차를 직접 풀 때까지 기다렸다가 같은 글을 다시 시도한다
                # 그냥 넘어가면 삭제되지 않은 글이 목록에서 빠진다
                yield {
                    'status': False,
                    'data': 'captcha'
                }
                continue

            if data:
                # 캡차가 아닌 실패를 걸러내지 않으면 지워지지도 않은 글이
                # 성공으로 집계된다
                reason = data.get('msg') or data.get('result') or '알 수 없는 사유'
                solve_captcha = False
                self.post_list.pop(0)

                # 서버가 잠깐 거부할 때가 있다. 몇 건씩 몰렸다가 저절로 풀린다
                # 여기서 버리면 다시 했으면 지워졌을 항목이 사라진다
                # 목록 끝으로 돌려보내고, 정해진 횟수를 넘기면 실패로 확정한다
                if isinstance(entry, dict) and _isRetryableCause(reason):
                    entry['_attempts'] = entry.get('_attempts', 0) + 1
                    if entry['_attempts'] < self.retry_attempt_limit:
                        self.post_list.append(entry)
                        yield {
                            'status': False,
                            'data': 'requeued',
                            'del_no': post_no,
                            'attempt': entry['_attempts'],
                            'max_attempts': self.retry_attempt_limit,
                            'reason': reason,
                        }
                        continue

                yield {
                    'status': False,
                    'data': 'failed',
                    'del_no': post_no,
                    'reason': reason
                }
                continue

            captcha_solved = solve_captcha

            solve_captcha = False
            self.post_list.pop(0)

            yield {
                'status': True,
                'data': {
                    'proxy': self.proxy_list and self.proxy_list[-1] or '',
                    'del_no': post_no,
                    'delay': round(delay, 1),
                    'captcha_solved': captcha_solved
                }
            }

    @_handleProxyError
    def getPageCount(self, gno: str, post_type: str) -> Union[int, str]:
        gallog_url = f'https://gallog.dcinside.com/{self.user_id}/{post_type}/index?{ "cno=" + str(gno) + "&" if gno else "" }p=%s'

        res = self.gallogGet(gallog_url % 1, proxies=self.getProxy())
        soup = BeautifulSoup(res.text, 'html.parser')
        if not soup.select_one('body'):
            return 'BLOCKED'
        pages = 1
        paging_elements = soup.select('.bottom_paging_box > a')

        try:
            if paging_elements:
                if paging_elements[-1].text == '끝':
                    pages = paging_elements[-1]['href'].split('&p=')[-1]
                else:
                    pages = int(paging_elements[-1].text)
            elif soup.select_one('.bottom_paging_box > em').text == '1':
                pass
        except:
            return 0

        return int(pages)

    @_handleProxyError
    def getPostList(self, gno: str, post_type: str, idx: int) -> Union[list, str]:
        gallog_url = f'https://gallog.dcinside.com/{self.user_id}/{post_type}/index?{ "cno=" + str(gno) + "&" if gno else "" }p=%s'

        res = self.gallogGet(gallog_url % idx, proxies=self.getProxy())

        soup = BeautifulSoup(res.text, 'html.parser')
        if not soup.select_one('body'):
            return 'BLOCKED'
        post_list_elements = soup.select('.cont_listbox > li')

        if len(post_list_elements) < 1:
            return []

        l = []
        for post_list_element in reversed(post_list_elements):
            l.append(self._parsePostEntry(post_list_element))

        return l

    @staticmethod
    def _parsePostEntry(element) -> dict:
        """갤로그 목록의 li 하나에서 삭제에 필요한 값을 뽑는다

        log_no는 갤로그 삭제용, gallery와 no는 앱 API 삭제용이다
        gallery/no는 항목 링크(board/view?id=&no=)에서 읽는다

        마크업이 바뀌어 링크를 못 읽으면 빈 값으로 두고 갤로그 경로로 돌아간다
        """
        entry = {'log_no': element.get('data-no', ''), 'gallery': '', 'no': ''}

        link = element.select_one('a[href*="/board/view"]') or element.select_one('a[href]')
        if not link:
            return entry

        try:
            query = parse_qs(urlparse(link['href']).query)
        except ValueError:
            return entry

        entry['gallery'] = (query.get('id') or [''])[0]
        entry['no'] = (query.get('no') or [''])[0]
        return entry

    def aggregatePosts(self, gno: str, post_type: str) -> None:
        # 모바일 API로 수집하고, 실패하면 데스크톱으로 돌아간다
        if self.use_mobile:
            result = self._aggregateViaMobile(gno, post_type)
            if result != 'FALLBACK':
                yield from result
                return

        yield from self._aggregateViaDesktop(gno, post_type)

    def _aggregateViaMobile(self, gno: str, post_type: str):
        """모바일 API로 목록을 수집한다

        첫 응답에 total/last_page가 같이 오므로 페이지 수를 따로 묻지 않아도 된다
        갤러리 필터는 전체를 받은 뒤 gall_code로 걸러낸다
        """
        self.post_list = []
        events = []

        # 첫 페이지로 총 페이지 수를 파악한다
        a = time.time()
        page_data = self.mobile.fetchPage(self.user_id, post_type, 1)
        delay = time.time() - a

        if page_data is None:
            return 'FALLBACK'

        last_page = page_data['last_page']
        self._appendFiltered(page_data['entries'], gno)
        events.append({'status': True, 'data': {'index': 1, 'proxy': '', 'delay': round(delay, 1)}})

        # 나머지 페이지
        for page in range(2, last_page + 1):
            a = time.time()
            time.sleep(self.delay)
            page_data = self.mobile.fetchPage(self.user_id, post_type, page)
            delay = time.time() - a

            if page_data is None:
                events.append({'status': False, 'data': 'ipblocked'})
                return events

            self._appendFiltered(page_data['entries'], gno)
            events.append({'status': True, 'data': {'index': page, 'proxy': '', 'delay': round(delay, 1)}})

        return events

    def _appendFiltered(self, entries: list, gno: str) -> None:
        """갤러리 필터를 적용해 post_list에 넣는다

        gno가 비어 있으면 전체, 아니면 gall_code가 같은 것만
        """
        for entry in reversed(entries):
            if not gno or entry.get('gall_code') == gno:
                self.post_list.append(entry)

    def _aggregateViaDesktop(self, gno: str, post_type: str):
        """데스크톱 갤로그로 목록 수집 (기존 로직)"""
        pages = self.getPageCount(gno, post_type)
        self.post_list = []

        if pages == 'BLOCKED':
            yield {
                'status': False,
                'data': 'ipblocked'
            }
            return

        for idx in range(pages, 0, -1):
            a = time.time()
            time.sleep(self.delay)
            res = self.getPostList(gno, post_type, idx)
            delay = time.time() - a

            if res == 'BLOCKED':
                yield {
                    'status': False,
                    'data': 'ipblocked'
                }
                return

            self.post_list += res

            yield {
                'status': True,
                'data': {
                    'index': idx,
                    'proxy': self.proxy_list and self.proxy_list[-1] or '',
                    'delay': round(delay, 1)
                }
            }

    def getGallList(self, post_type: str) -> Union[dict, str]:
        """갤러리 목록을 가져온다

        모바일 API에는 갤러리 드롭다운이 없어 목록 데이터에서 이름을 뽑는다
        실패하면 데스크톱 갤로그로 돌아간다
        """
        if self.use_mobile:
            result = self._getGallListViaMobile(post_type)
            if result is not None:
                return result

        return self._getGallListViaDesktop(post_type)

    def _getGallListViaMobile(self, post_type: str):
        """모바일 목록을 훑어 갤러리 이름을 모은다

        드롭다운이 없어 전 페이지를 돌며 gall_code -> 이름 매핑을 만든다
        글이 많으면 그만큼 요청이 늘지만, 빠지는 갤러리는 없다
        """
        page_data = self.mobile.fetchPage(self.user_id, post_type, 1)
        if page_data is None:
            return None

        # 갤러리가 하나도 없으면 빈 dict
        if not page_data['entries']:
            return {}

        # 전체 항목("모든 갤러리")은 gno=''로 잡힌다
        gall_list = {}
        seen = set()
        # 남은 페이지까지 훑어 빠지는 갤러리가 없게 한다
        last_page = page_data['last_page']
        for entry in page_data['entries']:
            code = entry.get('gall_code', '')
            name = entry.get('gall_name', '')
            if code and code not in seen:
                seen.add(code)
                gall_list[code] = name or code

        for page in range(2, last_page + 1):
            time.sleep(self.delay)
            pd = self.mobile.fetchPage(self.user_id, post_type, page)
            if pd is None:
                break
            for entry in pd['entries']:
                code = entry.get('gall_code', '')
                name = entry.get('gall_name', '')
                if code and code not in seen:
                    seen.add(code)
                    gall_list[code] = name or code

        return gall_list

    @_handleProxyError
    def _getGallListViaDesktop(self, post_type: str) -> Union[dict, str]:
        """데스크톱 갤로그의 갤러리 드롭다운을 파싱 (기존 로직)"""
        res = self.gallogGet(
            f'https://gallog.dcinside.com/{self.user_id}/{post_type}', proxies=self.getProxy())

        soup = BeautifulSoup(res.text, 'html.parser')

        if not soup.select_one('body'):
            return 'BLOCKED'

        gall_list_elements = soup.select(
            'div.option_sort.gallog > div > ul > li')

        if len(gall_list_elements) <= 1:
            return {}

        gall_list = {}

        for gall_list_element in gall_list_elements[1:]:
            gno = gall_list_element['data-value']
            gname = gall_list_element.text
            gall_list[gno] = gname
        return gall_list

    def getProxy(self) -> dict:
        if self.proxy_list:
            proxy = self.proxy_list.pop(0)
            self.proxy_list.append(proxy)
            return {
                'http': proxy,
                'https': proxy
            }

        return {}
    
    def solveCaptcha(self, page_url) -> str:
        result = self.solver.recaptcha(sitekey=self.dcinside_site_key, url=page_url)

        return result['code']