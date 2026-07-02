from requests.exceptions import ConnectTimeout
from requests.exceptions import ProxyError
from twocaptcha import TwoCaptcha
from bs4 import BeautifulSoup
from typing import Union
import requests
import urllib3
import time

MAX_DELAY = 0.9

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

    def updateDelay(self):
        self.delay = round(MAX_DELAY / (len(self.proxy_list) or 1), 1)

    def _handleProxyError(func):
        def wrapper(self, *args):
            result = None
            while True:
                try:
                    result = func(self, *args)
                except (ProxyError, ConnectTimeout):
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
        """쿠키를 모든 관련 도메인에 전파합니다."""
        for k, v in cookies.items():
            self.session.cookies.set(k, v, domain='.dcinside.com')

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

    def verifyLogin(self) -> bool:
        """gallog 페이지 접근으로 실제 로그인 상태를 확인합니다.
        갤로그에서 로그인/로그아웃 버튼 텍스트를 확인하여 판단합니다."""
        try:
            self.session.headers.update({'User-Agent': self.user_agent})
            res = self.session.get(f'https://gallog.dcinside.com/{self.user_id}')
            soup = BeautifulSoup(res.text, 'html.parser')
            
            if not soup.select_one('body'):
                return False
            
            # 상단 로그인/로그아웃 버튼으로 판단
            login_btn = soup.select_one('.btn_top_loginout')
            if login_btn and login_btn.text.strip() == '로그인':
                return False
            
            # 갤로그 메뉴가 있고, 갤러리 드롭다운이 정상적이면 로그인 상태
            gallog_menu = soup.select('.gallog_menu li')
            if gallog_menu:
                return True
            
            # 최소한 인증 쿠키가 있으면 통과
            cookies = self.session.cookies.get_dict()
            return 'unicro_id' in cookies or 'ci_c' in cookies
        except:
            return False

    def login(self, user_id: str, user_pw: str) -> bool:
        """ID/PW로 로그인을 시도합니다.
        
        Playwright(가상 브라우저)를 통해 실제 브라우저 환경에서 로그인을 진행합니다.
        캡차가 있으면 ddddocr로 자동 풀기를 시도합니다.
        캠페인 리다이렉트 등으로 인한 쿠키 파괴를 방어합니다.
        """
        self.user_id = user_id
        
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
            
            try:
                page.goto("https://sign.dcinside.com/login", timeout=15000)
                
                page.fill("#id", user_id)
                page.fill("#pw", user_pw)
                
                # 캡차 확인
                if page.is_visible("#kcaptcha_code"):
                    if not ocr:
                        print("캡차가 발견되었으나 ddddocr이 없어 풀 수 없습니다.")
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
                
                # 갤로그 접근으로 로그인 여부 확인
                page.goto(f"https://gallog.dcinside.com/{user_id}/posting", timeout=15000)
                login_btn = page.query_selector(".btn_top_loginout")
                btn_text = login_btn.inner_text() if login_btn else "없음"
                
                if btn_text.strip() == "로그아웃":
                    # 로그인 성공, 쿠키 추출하여 requests 세션에 복사
                    self.session.cookies.clear()
                    cookies = context.cookies()
                    for c in cookies:
                        self.session.cookies.set(c['name'], c['value'], domain=c['domain'], path=c['path'])
                    
                    self._propagateCookies(self.session.cookies.get_dict())
                    browser.close()
                    return True
                    
            except Exception as e:
                pass
            
            browser.close()
            return False

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

    @_handleProxyError
    def deletePost(self, post_no: str, post_type: str, solve_captcha: bool) -> Union[dict, bool]:
        gallog_url = f'https://gallog.dcinside.com/{self.user_id}/{post_type}'

        proxy = self.getProxy()

        self.session.headers.update({'User-Agent': self.user_agent})
        res = self.session.get(gallog_url, proxies=proxy)

        soup = BeautifulSoup(res.text, 'html.parser')
        if not soup.select_one('body'):
            return False
        
        # service_code를 페이지에서 동적으로 추출
        service_code_el = soup.select_one('input[name="service_code"]')
        service_code = service_code_el['value'] if service_code_el else 'undefined'
        
        captcha = { 'g-recaptcha-response': self.solveCaptcha(gallog_url) if solve_captcha else 'undefined' }

        form_data = {
            'ci_t': self.session.cookies.get_dict()['ci_c'],
            'no': post_no,
            'service_code': service_code,
            **(captcha if solve_captcha else {})
        }

        self.delete_headers['Referer'] = gallog_url
        self.session.headers.update(self.delete_headers)
        res = self.session.post(
            f'https://gallog.dcinside.com/{self.user_id}/ajax/log_list_ajax/delete', data=form_data, proxies=proxy)

        data = res.json()

        if res.status_code == 200 and data['result'] == 'success':
            return {}
        return data

    def deletePosts(self, post_type: str) -> Union[str, list]:
        solve_captcha = False

        while self.post_list:
            post_no = self.post_list[0]

            a = time.time()
            time.sleep(self.delay)
            data = self.deletePost(post_no, post_type, solve_captcha)
            delay = time.time() - a

            if data == 'BLOCKED':
                yield {
                    'status': False,
                    'data': 'ipblocked'
                }

            if data and ('captcha' in data['result'] or ('fail' in data['result'] and 'g-recaptcha error!' in data['msg'])):
                if self.twocaptcha_key: 
                    solve_captcha = True
                    continue

                yield {
                    'status': False,
                    'data': 'captcha'
                }

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
    def getPageCount(self, gno: str, post_type: str) -> int:
        gallog_url = f'https://gallog.dcinside.com/{self.user_id}/{post_type}/index?{ "cno=" + str(gno) + "&" if gno else "" }p=%s'
        self.session.headers.update({'User-Agent': self.user_agent})

        res = self.session.get(gallog_url % 1, proxies=self.getProxy())
        soup = BeautifulSoup(res.text, 'html.parser')
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
        self.session.headers.update({'User-Agent': self.user_agent})

        res = self.session.get(gallog_url % idx, proxies=self.getProxy())

        soup = BeautifulSoup(res.text, 'html.parser')
        if not soup.select_one('body'):
            return 'BLOCKED'
        post_list_elements = soup.select('.cont_listbox > li')

        if len(post_list_elements) < 1:
            return []

        l = []
        for post_list_element in reversed(post_list_elements):
            post_no = post_list_element['data-no']
            l.append(post_no)

        return l

    def aggregatePosts(self, gno: str, post_type: str) -> None:
        pages = self.getPageCount(gno, post_type)
        self.post_list = []

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

            self.post_list += res

            yield {
                'status': True,
                'data': {
                    'index': idx,
                    'proxy': self.proxy_list and self.proxy_list[-1] or '',
                    'delay': round(delay, 1)
                }
            }

    @_handleProxyError
    def getGallList(self, post_type: str) -> Union[dict, str]:
        res = self.session.get(
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