from dcinside_cleaner import Cleaner
from getpass import getpass
from tqdm import tqdm
import traceback
import json
import time
import re
import os
import sys

class Console:
    p_type = {'-p': 'posting', '-c': 'comment'}
    ACCOUNTS_FILE = 'dcinside-cleaner-accounts.json'

    def __init__(self):
        self.cleaner = Cleaner()
        self.login_flag = False
        self.g_list = {'type':  None}
        self.user_id = ''
        self.user_pw = ''
        
        if not self.login_flag:
            self.show_account_list()
            print('* ID/PW로 로그인이 안될 땐 "cookie" 명령어를 사용해 주세요.\n')
            
        self.getCommand()

    def show_account_list(self):
        if os.path.exists(self.ACCOUNTS_FILE):
            with open(self.ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                accounts = json.load(f)
                if accounts:
                    print('\n[저장된 계정 목록]')
                    for slot in sorted(accounts.keys(), key=lambda x: int(x) if x.isdigit() else x):
                        print(f'{slot}: {accounts[slot]["user_id"]}')
                    
                    if getattr(self, 'login_flag', False):
                        print('* 현재 로그인된 상태라면 "login 번호"로 계정을 전환해 주세요. (예: login 1)')
                    else:
                        print('* 저장된 번호를 입력하여 바로 로그인할 수 있습니다.')
    
    def save_account(self, slot=None):
        accounts = {}
        if os.path.exists(self.ACCOUNTS_FILE):
            try:
                with open(self.ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                    accounts = json.load(f)
            except Exception: pass
            
        current_user_id = self.cleaner.getUserId()
            
        if slot is None:
            # 이미 저장된 아이디면 그 슬롯을 찾아 덮어쓴다
            for k, v in accounts.items():
                if v.get('user_id') == current_user_id:
                    slot = str(k)
                    break
                    
            if slot is None:
                # 비어 있는 가장 작은 번호를 쓴다
                # 최대값+1로 하면 1번을 지웠을 때 1이 비어 있는데도 4번으로 들어간다
                used = {int(k) for k in accounts.keys() if k.isdigit()}
                number = 1
                while number in used:
                    number += 1
                slot = str(number)
        else:
            slot = str(slot)
            
        accounts[slot] = {
            'user_id': self.cleaner.getUserId(),
            'user_pw': self.user_pw,
            'cookies': self.cleaner.getCookies()
        }
        with open(self.ACCOUNTS_FILE, 'wt', encoding='utf-8') as f:
            f.write(json.dumps(accounts, indent=4))
        print(f'[{slot}번 계정] 저장되었습니다.')
        
    def load_and_login(self, slot):
        if not os.path.exists(self.ACCOUNTS_FILE):
            print('저장된 계정 파일이 없습니다.')
            return False
        with open(self.ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
            accounts = json.load(f)
            
        if slot not in accounts:
            print(f'{slot}번 계정 정보가 없습니다.')
            return False
            
        data = accounts[slot]
        print(f'[{slot}번: {data["user_id"]}] 로그인을 시도합니다...')
        
        self.cleaner.setUserId(data['user_id'])
        
        if 'cookies' in data:
            print('쿠키로 로그인을 시도합니다...')
            if self.cleaner.loginFromCookies(data['cookies']):
                if self.cleaner.verifyLogin():
                    self.user_pw = data.get('user_pw', '')
                    self.user_id = data['user_id']
                    print('쿠키 로그인에 성공했습니다.')
                    if self.cleaner.blocked:
                        print('* 갤로그가 계속 빈 응답을 보내고 있어 세션 확인은 쿠키로 대체했습니다.')
                        print('* 목록이 비어 보이면 잠시 후 다시 시도하거나 "proxy load"를 사용해 주세요.')
                    return True
                else:
                    self.cleaner.session.cookies.clear()
                    print('쿠키가 만료되어 ID/PW로 재로그인을 시도합니다...')
            else:
                print('쿠키 로그인에 실패하여 ID/PW로 로그인을 시도합니다...')
                
        if not data.get('user_pw'):
            print('비밀번호가 없어 수동 로그인이 필요합니다.')
            return False
            
        res = self.cleaner.login(data['user_id'], data['user_pw'])
        if res:
            self.user_pw = data['user_pw']
            self.user_id = data['user_id']
            self.save_account(slot)
            print('ID/PW로 로그인되었습니다.')
            return True
            
        reason = self.cleaner.getLastLoginError()
        print(f'로그인에 실패했습니다. ({reason})' if reason else '로그인에 실패했습니다. 비밀번호를 확인해 주세요.')
        return False

    def waitAndRetry(self, fetch, tries=5):
        """속도 제한에 걸리면 기다렸다가 다시 시도한다

        30초 간격으로 재 보면 빈 응답은 대개 단발이고 다음 번엔 통과한다
        반대로 몇 초 간격으로 몰아치면 수 분짜리 차단으로 굳는다
        그래서 처음엔 30초만 쉬고, 그래도 안 되면 대기를 늘린다 (최대 2분)
        """
        for i in range(tries):
            wait = min(30 * (i + 1), 120)
            print(f'속도 제한 상태입니다. {wait}초 기다렸다가 재시도합니다... ({i + 1}/{tries}, 취소: Ctrl+C)')
            try:
                time.sleep(wait)
            except KeyboardInterrupt:
                print('\n대기를 취소했습니다.')
                return 'BLOCKED'

            result = fetch()
            if result != 'BLOCKED':
                print('응답이 정상으로 돌아왔습니다.')
                return result
        return 'BLOCKED'

    def _retryAggregate(self, gno, post_type):
        """waitAndRetry용 콜백. aggregatePosts를 다시 돌려본다

        성공하면 'OK', 첫 이벤트가 차단이면 'BLOCKED'
        """
        for i in self.cleaner.aggregatePosts(gno, post_type):
            if not i['status'] and i['data'] == 'ipblocked':
                return 'BLOCKED'
        return 'OK' if self.cleaner.post_list else 'BLOCKED'

    def parseAndExecute(self, cmd_input : str) -> int:
        cmd = cmd_input.split()
        if not cmd: return 0

        if cmd[0] == 'help':
            print('1, 2... - 지정한 번호로 로그인합니다.')
            print('login - 수동으로 로그인합니다.')
            print('cookie - 쿠키를 직접 입력하여 로그인합니다.')
            print('export [번호] - 로그인 정보를 특정 번호에 수동으로 저장합니다.')
            print('remove [번호] - 저장된 계정을 삭제합니다. (예: remove 1)')
            print('list - 저장된 계정 목록을 확인합니다.')
            print('p - 작성한 글 리스트를 가져옵니다.')
            print('c - 작성한 댓글 리스트를 가져옵니다.')
            print('getglist -p, -c로도 사용 가능합니다.')
            print('del all | 1 2 3... | 1 ~ 4 - 선택한 갤러리의 글/댓글을 삭제합니다.')
            print('proxy load [파일명] - 프록시 리스트를 불러옵니다.')
            print('proxy off - 프록시 사용을 중지합니다.')
            print('2captcha [api_key] - 2captcha API 키를 설정합니다.')
            print('logout - 로그아웃합니다.')
            print('help - 도움말을 봅니다.')
            print('exit - 종료합니다.')
            return 0
        if cmd[0] == 'exit': return 0

        if cmd[0] == 'proxy':
            if len(cmd) > 1 and cmd[1] == 'load':
                filename = cmd[2] if len(cmd) > 2 else 'proxies.txt'
                if os.path.exists(filename):
                    with open(filename, 'r', encoding='utf-8') as f:
                        raw_proxies = [line.strip() for line in f if line.strip()]
                    
                    print(f'[{filename}]에서 {len(raw_proxies)}개의 프록시를 읽었습니다.')
                    print('현재 작동하는 프록시를 검사 중입니다... (최대 3초 소요)')
                    
                    import concurrent.futures
                    import requests
                    
                    valid_proxies = []
                    
                    def check_proxy(p):
                        try:
                            # proxy format handling
                            proxy_dict = {'http': p, 'https': p} if '://' in p else {'http': f'http://{p}', 'https': f'http://{p}'}
                            # check connection to dcinside with a strict 2-second timeout
                            requests.get('https://www.dcinside.com/', proxies=proxy_dict, timeout=2)
                            return p
                        except:
                            return None

                    # Use multithreading to check dozens of proxies simultaneously
                    from tqdm import tqdm
                    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                        results = list(tqdm(executor.map(check_proxy, raw_proxies), total=len(raw_proxies), desc="프록시 테스트"))
                        
                    valid_proxies = [r for r in results if r]
                    
                    self.cleaner.setProxyList(valid_proxies)
                    if valid_proxies:
                        print(f'검사 완료! 정상 작동하는 프록시 {len(valid_proxies)}개를 추려내어 적용했습니다.')
                    else:
                        print('검사 완료. 작동하는 프록시가 하나도 없습니다. 다른 프록시 목록을 구해보세요.')
                else:
                    print(f'{filename} 파일을 찾을 수 없습니다.')
            elif len(cmd) > 1 and cmd[1] == 'off':
                self.cleaner.setProxyList([])
                print('프록시 사용이 중지되었습니다.')
            else:
                print('사용법: proxy load [파일명] | proxy off')
            return 0

        if cmd[0] == '2captcha':
            if len(cmd) > 1:
                if self.cleaner.set2CaptchaKey(cmd[1]):
                    print('2captcha API 키가 정상적으로 설정되었습니다.')
                else:
                    print('2captcha API 키가 올바르지 않거나 잔액이 부족합니다.')
            else:
                print('사용법: 2captcha [api_key]')
            return 0

        if not self.login_flag and cmd[0].isdigit():
            if self.load_and_login(cmd[0]):
                self.login_flag = True
            return 0

        if self.login_flag and cmd[0].isdigit() and len(cmd) == 1:
            if self.g_list.get('type'):
                type_kor = '글' if self.g_list['type'] == 'posting' else '댓글'
                print(f'{cmd[0]}번 갤러리 {type_kor} 삭제를 시도합니다...')
                self.delete(self.g_list[int(cmd[0])], self.g_list['type'])
            else:
                print('먼저 리스트를 불러와주세요. (p 또는 c)')
            return 0

        elif cmd[0] == 'login':
            if len(cmd) > 1 and cmd[1].isdigit():
                self.login_flag = False
                if self.load_and_login(cmd[1]):
                    self.login_flag = True
                return 0

            if self.login_flag:
                print('기존 세션을 종료하고 새 로그인을 진행합니다.')
                self.login_flag = False
                self.cleaner.session.cookies.clear()
            
            self.user_id = input('ID >> ')
            self.user_pw = getpass('PW >> ')
            res = self.cleaner.login(self.user_id, self.user_pw)
            if res:
                print('로그인 성공! (캡차 자동 처리)')
                print('* 글 목록이 안 보이면 "cookie" 명령어를 사용해 주세요.')
                self.login_flag = True
                self.save_account()
            else:
                reason = self.cleaner.getLastLoginError()
                print(f'로그인에 실패했습니다. ({reason})' if reason else '로그인에 실패했습니다.')
                print('원인: 캡차 실패, 계정 정보 오류, 또는 차단됨')
                print('* ID/PW로 로그인이 안될 땐 "cookie" 명령어를 사용해 주세요.')
                return 0

        elif cmd[0] == 'cookie':
            if self.login_flag:
                print('기존 세션을 종료하고 새 쿠키 로그인을 진행합니다.')
                self.login_flag = False
                self.cleaner.session.cookies.clear()
            
            self.user_id = input('갤로그 ID (비워두면 자동 추출) >> ').strip()
            print('F12 -> Network -> Cookie 문자열을 붙여넣어 주세요.')
            raw_cookie = input('Cookie >> ')
            
            if not raw_cookie.strip():
                print('쿠키가 입력되지 않았습니다.')
                return 0
            
            import http.cookies
            parsed_cookies = {}
            try:
                simple_cookie = http.cookies.SimpleCookie()
                simple_cookie.load(raw_cookie)
                for key, morsel in simple_cookie.items():
                    parsed_cookies[key] = morsel.value
                
                if not parsed_cookies:
                    print('잘못된 쿠키 형식입니다.')
                    return 0
            except Exception as e:
                print(f'쿠키를 처리하지 못했습니다: {e}')
                return 0
                
            res = self.cleaner.loginFromCookies(parsed_cookies)
            if self.user_id:
                self.cleaner.user_id = self.user_id
            else:
                self.user_id = self.cleaner.user_id
                
            if res or self.cleaner.verifyLogin():
                print(f'쿠키 로그인 성공! (ID: {self.user_id})')
                self.login_flag = True
                self.save_account()
                print('쿠키가 저장되어 이후 번호로 로그인할 수 있습니다.')
            else:
                print('유효하지 않은 쿠키입니다.')
                return 0

        elif cmd[0] == 'remove':
            if len(cmd) < 2:
                print('삭제할 번호를 입력해 주세요. (예: remove 1)')
                return 0
            slot = cmd[1]
            if os.path.exists(self.ACCOUNTS_FILE):
                with open(self.ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                    accounts = json.load(f)
                if slot in accounts:
                    del accounts[slot]
                    with open(self.ACCOUNTS_FILE, 'wt', encoding='utf-8') as f:
                        f.write(json.dumps(accounts, indent=4))
                    print(f'[{slot}번 계정] 삭제되었습니다.')
                else:
                    print(f'[{slot}번 계정] 존재하지 않습니다.')
            else:
                print('저장된 계정 파일이 없습니다.')
            return 0

        elif cmd[0] == 'export':
            if not self.login_flag:
                print('먼저 로그인해 주세요.')
                return 0
            slot = cmd[1] if len(cmd) > 1 else '1'
            self.save_account(slot)

        elif cmd[0] == 'list':
            self.show_account_list()
            return 0

        elif not self.login_flag: 
            print('먼저 로그인해 주세요. (번호 또는 login 입력)')
            return 0

        elif cmd[0] in ['p', 'c', 'getglist']:
            if not self.cleaner.verifyLogin():
                print('\n로그인 세션이 만료되었습니다.')
                if self.user_id and self.user_pw:
                    print('저장된 정보로 재로그인을 시도합니다...')
                    if self.cleaner.login(self.user_id, self.user_pw):
                        print('재로그인 성공!')
                        self.save_account()
                    else:
                        print('재로그인에 실패했습니다. 수동으로 다시 로그인해 주세요.')
                        self.login_flag = False
                        return 0
                else:
                    print('다시 로그인해 주세요.')
                    self.login_flag = False
                    return 0

            if cmd[0] == 'p': 
                post_type = 'posting'
            elif cmd[0] == 'c': 
                post_type = 'comment'
            else:
                if len(cmd) < 2 or cmd[1] not in self.p_type:
                    print('옵션을 입력해 주세요. (p: 글, c: 댓글)')
                    return 0
                post_type = self.p_type[cmd[1]]

            g_list = self.cleaner.getGallList(post_type)

            if g_list == 'BLOCKED':
                print('갤로그가 빈 응답을 돌려주고 있습니다. (요청 속도 제한)')
                g_list = self.waitAndRetry(lambda: self.cleaner.getGallList(post_type))

            if g_list == 'BLOCKED':
                print('계속 빈 응답입니다. 로그인은 유지되니 나중에 다시 시도하거나 "proxy load"를 사용해 주세요.')
                return 0
            if not g_list:
                print('갤러리 리스트가 없습니다.')
                return 0

            self.g_list = {'type': post_type}
            idx = 1
            for k, v in g_list.items():
                self.g_list[idx] = k
                print(f'{idx}. {v}')
                idx += 1

        elif cmd[0] == 'del':
            if self.g_list.get('type') == None:
                print('갤러리 리스트를 선택해 주세요.')
                return 0
            del_list = []
            if len(cmd) < 2:
                print('삭제할 번호를 입력해 주세요.')
                return 0
            if cmd[1] == 'all':
                del_list = [str(k) for k in self.g_list.keys() if isinstance(k, int)]
            elif '~' in cmd_input:
                regex = re.compile(r'(\d+)~(\d+)')
                numbers = regex.findall(cmd_input)
                for number in numbers:
                    a, b = map(int, number)
                    del_list += [str(i) for i in range(a, b+1)]
            else:
                del_list = cmd[1:]
            
            del_list = sorted(list(set(del_list)))
            for del_no in del_list:
                if del_no.isdigit() and int(del_no) in self.g_list:
                    type_kor = '글' if self.g_list['type'] == 'posting' else '댓글'
                    print(f'{del_no}번 갤러리 {type_kor} 삭제를 시도합니다...')
                    self.delete(self.g_list[int(del_no)], self.g_list['type'])

        elif cmd[0] == 'logout':
            self.login_flag = False
            self.user_id = ''
            self.user_pw = ''
            print('로그아웃되었습니다.')
            self.show_account_list()

    def delete(self, gno, post_type):
        if not self.cleaner.verifyLogin():
            print('\n로그인 세션이 만료되었습니다.')
            if self.user_id and self.user_pw:
                print('저장된 정보로 재로그인을 시도합니다...')
                if self.cleaner.login(self.user_id, self.user_pw):
                    print('재로그인 성공!')
                    self.save_account()
                else:
                    print('재로그인에 실패했습니다. 수동으로 다시 로그인해 주세요.')
                    self.login_flag = False
                    return
            else:
                print('다시 로그인해 주세요.')
                self.login_flag = False
                return

        type_kor = '글' if post_type == 'posting' else '댓글'

        # 앱 API로 보내면 갤로그 요청이 건당 2회에서 0회가 된다
        # 모바일 목록이 댓글번호를 주므로 댓글도 같은 경로를 쓴다
        # 비밀번호가 필요하고, 실패해도 갤로그 경로로 그대로 진행한다
        if not self.cleaner.isAppApiReady() and self.user_id and self.user_pw:
            print('앱 API 준비 중... (실패해도 기존 방식으로 진행됩니다)')
            notify = lambda sec: print(
                f'기기를 새로 등록했습니다. dcinside가 받아줄 때까지 {sec:.0f}초 기다립니다... (최초 1회만)')
            if self.cleaner.enableAppApi(self.user_id, self.user_pw, notify=notify):
                print('앱 API 사용: 갤로그를 거치지 않고 삭제합니다.')
            else:
                error = self.cleaner.getLastAppApiError()
                print(f'앱 API를 쓸 수 없어 갤로그로 삭제합니다. ({error})')
                if '자동 입력 방지' in error or '보안코드' in error:
                    print('* 앱 로그인이 너무 잦아 캡차가 걸렸습니다. 잠시 후 다시 시도하면 풀립니다.')

        print(f'{type_kor} 목록 가져오는 중... (취소: Ctrl+C)')
        try:
            pbar = None
            blocked_on_first = False
            for i in self.cleaner.aggregatePosts(gno, post_type):
                if not i['status'] and i['data'] == 'ipblocked':
                    if pbar is None:
                        # 첫 요청부터 차단. 다시 시도한다
                        blocked_on_first = True
                        break
                    print('IP 차단이 감지되었습니다.')
                    pbar.close()
                    return
                if pbar is None:
                    # 첫 이벤트가 성공이면 진행률 표시를 시작한다
                    pbar = tqdm(total=None)
                pbar.update(1)

            if blocked_on_first:
                print('갤로그가 빈 응답을 돌려주고 있습니다. (요청 속도 제한)')
                result = self.waitAndRetry(lambda: self._retryAggregate(gno, post_type))
                if result == 'BLOCKED':
                    print('계속 빈 응답입니다. 나중에 다시 시도하거나 "proxy load"를 사용해 주세요.')
                    return

            if pbar is not None:
                pbar.close()
            if not self.cleaner.post_list:
                print('삭제할 항목이 없습니다.')
                return
        except KeyboardInterrupt:
            print('\n작업이 취소되었습니다.')
            return

        print('삭제 중... (일시정지: Ctrl+C)')
        total = len(self.cleaner.post_list)
        deleted = 0
        failed = 0
        requeued = 0
        try:
            with tqdm(total=total) as pbar:
                generator = self.cleaner.deletePosts(post_type)
                while True:
                    try:
                        i = next(generator)
                        if not i['status']:
                            if i['data'] == 'ipblocked':
                                reason = i.get('reason') or '요청이 계속 거절되고 있습니다.'
                                print(f'\n중단: {reason}')
                                print(f'남은 {len(self.cleaner.post_list)}건은 그대로 있습니다. '
                                      f'잠시 후 다시 시도해 주세요.')
                                return
                            if i['data'] == 'rate_limited':
                                tqdm.write(
                                    f"속도 제한. {i['wait']}초 대기 "
                                    f"({i['attempt']}/{i['max_attempts']}, 취소: Ctrl+C)")
                                continue
                            if i['data'] == 'rate_cleared':
                                tqdm.write('응답이 정상으로 돌아왔습니다.')
                                continue
                            if i['data'] == 'captcha':
                                print('캡차가 감지되었습니다!')
                                if i.get('where'):
                                    print(f"  {i['where']} 에서 삭제를 눌러 코드를 입력해 주세요.")
                                input('캡차 해제 후 엔터를 눌러주세요 >> ')
                                continue
                            if i['data'] == 'requeued':
                                # 목록 끝으로 밀려 나중에 다시 시도한다
                                # 아직 안 끝났으므로 진행률은 올리지 않는다
                                requeued += 1
                                tqdm.write(
                                    f"나중에 다시 시도 ({i.get('del_no')}): {i.get('reason')} "
                                    f"[{i.get('attempt')}/{i.get('max_attempts')}]")
                                continue
                            if i['data'] == 'failed':
                                # 지워지진 않았지만 목록에서 빠졌으니 진행률은 올린다
                                failed += 1
                                tqdm.write(f"삭제 실패 ({i.get('del_no')}): {i.get('reason')}")
                                pbar.update(1)
                            continue
                        deleted += 1
                        pbar.update(1)
                    except StopIteration:
                        break
                    except KeyboardInterrupt:
                        print('\n[일시정지] 계속할까요? (y/n)')
                        ans = input('>> ').strip().lower()
                        if ans != 'y':
                            print('삭제가 취소되었습니다.')
                            return
                        print('삭제를 재개합니다...')
                        generator = self.cleaner.deletePosts(post_type)
        except KeyboardInterrupt:
            print('\n삭제가 취소되었습니다.')
            return

        if requeued:
            print(f'\n(일시적 거부로 {requeued}회 다시 시도했습니다)')

        # 실패만 잔뜩 났는데 "완료"라고 하면 지워진 줄 안다
        if deleted and failed:
            print(f'\n{deleted}건 삭제, {failed}건 실패했습니다.')
        elif deleted:
            print(f'\n{deleted}건을 삭제했습니다.')
        elif failed:
            print(f'\n{failed}건 모두 실패했습니다. 삭제된 글이 없습니다.')
        else:
            print('\n삭제할 항목이 없었습니다.')

    def getCommand(self):
        print('dcinside cleaner')
        print('사용법이 필요하면 help를 입력해 주세요.')
        while True:
            try:
                prompt_text = f'[{self.user_id}] >> ' if self.login_flag and self.user_id else '>> '
                cmd = input(prompt_text).strip()
                if not cmd:
                    continue
                if cmd == 'exit':
                    break
                self.parseAndExecute(cmd)
            except KeyboardInterrupt:
                break
            except Exception:
                traceback.print_exc()
                print('오류가 발생했습니다.')
