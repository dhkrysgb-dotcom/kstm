from flask import Flask, request, jsonify
import requests, random, re, secrets, time

app = Flask(__name__)

class EmailChecker:
    def __init__(self):
        self.supported_domains = {
            'gmail.com': self.check_gmail,
            'googlemail.com': self.check_gmail,
            'hotmail.com': self.check_microsoft,
            'outlook.com': self.check_microsoft,
            'live.com': self.check_microsoft,
            'hi2.in': self.check_hi2,
            'aol.com': self.check_aol
        }
    
    def extract_username(self, email):
        if '@' in email:
            return email.split('@')[0]
        return email
    
    def check_gmail(self, email):
        try:
            username = self.extract_username(email)
            
            headers = {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
                'google-accounts-xsrf': '1',
            }
            
            __Host_GAPS = ''.join(secrets.choice("qwertyuiopasdfghjklzxcvbnm") for _ in range(20))
            cookies = {'__Host-GAPS': __Host_GAPS}
            
            url = 'https://accounts.google.com/_/signup/validatepersonaldetails'
            params = {'hl': "ar", '_reqid': "74404", 'rt': "j"}
            payload = {
                'f.req': '["AEThLlymT9V_0eW9Zw42mUXBqA3s9U9ljzwK7Jia8M4qy_5H3vwDL4GhSJXkUXTnPL_roS69KYSkaVJLdkmOC6bPDO0jy5qaBZR0nGnsWOb1bhxEY_YOrhedYnF3CldZzhireOeUd-vT8WbFd7SXxfhuWiGNtuPBrMKSLuMomStQkZieaIHlfdka8G45OmseoCfbsvWmoc7U","L7N","ToPython","L7N","ToPython",0,0,null,null,null,0,null,1,[],1]',
                'deviceinfo': '[null,null,null,null,null,"IQ",null,null,null,"GlifWebSignIn",null,[],null,null,null,null,1,null,0,1,"",null,null,1,1,2]',
            }
            
            response = requests.post(url, cookies=cookies, params=params, data=payload, headers=headers, timeout=15)
            
            if response.status_code != 200:
                return {"available": None, "error": "initial_request_failed"}
            
            if '",null,"' not in response.text:
                return {"available": None, "error": "token_not_found"}
            
            TL = str(response.text).split('",null,"')[1].split('"')[0]
            __Host_GAPS = response.cookies.get_dict().get('__Host-GAPS', __Host_GAPS)
            
            url = 'https://accounts.google.com/_/signup/usernameavailability'
            cookies = {'__Host-GAPS': __Host_GAPS}
            params = {'TL': TL}
            data = {
                'f.req': f'["TL:{TL}","{username}",0,0,1,null,0,5167]',
                'deviceinfo': '[null,null,null,null,null,"NL",null,null,null,"GlifWebSignIn",null,[],null,null,null,null,2,null,0,1,"",null,null,2,2]',
            }
            
            response = requests.post(url, params=params, cookies=cookies, headers=headers, data=data, timeout=15)
            
            if response.status_code == 200:
                if '"gf.uar",1' in response.text:
                    return {"available": True, "username": username, "domain": "gmail.com"}
                else:
                    return {"available": False, "username": username, "domain": "gmail.com"}
            else:
                return {"available": None, "error": "availability_check_failed"}
                
        except Exception as e:
            return {"available": None, "error": f"gmail_error: {str(e)}"}
    
    def check_microsoft(self, email):
        try:
            time.sleep(random.uniform(1, 2))
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ]
            user_agent = random.choice(user_agents)
            
            response = requests.post('https://signup.live.com', 
                                   headers={'user-agent': user_agent},
                                   timeout=15)
            
            cookies = response.cookies.get_dict()
            amsc = cookies.get('amsc')
            if not amsc:
                return {"available": None, "error": "cookie_not_found"}
            
            match = re.search(r'"apiCanary":"(.*?)"', response.text)
            if not match:
                return {"available": None, "error": "canary_not_found"}
            
            api_canary = match.group(1)
            canary = api_canary.encode().decode('unicode_escape')
            
            response = requests.post(
                'https://signup.live.com/API/CheckAvailableSigninNames',
                cookies={'amsc': amsc},
                headers={
                    'authority': 'signup.live.com',
                    'accept': 'application/json',
                    'accept-language': 'en-US,en;q=0.9',
                    'canary': canary,
                    'user-agent': user_agent
                },
                json={'signInName': email},
                timeout=15
            )
            
            if response.status_code == 200:
                if '"isAvailable":true' in response.text:
                    return {"available": True, "email": email, "domain": "microsoft"}
                else:
                    return {"available": False, "email": email, "domain": "microsoft"}
            else:
                return {"available": None, "error": f"api_error_{response.status_code}"}
                
        except Exception as e:
            return {"available": None, "error": f"microsoft_error: {str(e)}"}
    
    def check_aol(self, email):
        try:
            s = requests.Session()
            r = s.get("https://login.aol.com/account/create", timeout=15, 
                     headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
            
            if r.status_code != 200:
                return {"available": None, "error": "page_load_failed"}
            
            specData = re.search(r'name="specData" value="([^"]+)"', r.text)
            specId = re.search(r'name="specId" value="([^"]+)"', r.text)
            crumb = re.search(r'name="crumb" value="([^"]+)"', r.text)
            sessionIndex = re.search(r'name="sessionIndex" value="([^"]+)"', r.text)
            acrumb = re.search(r'name="acrumb" value="([^"]+)"', r.text)
            
            if not all([specData, specId, crumb, sessionIndex, acrumb]):
                return {"available": None, "error": "tokens_not_found"}
            
            specData = specData.group(1)
            specId = specId.group(1)
            crumb = crumb.group(1)
            sessionIndex = sessionIndex.group(1)
            acrumb = acrumb.group(1)
            
            data = f"browser-fp-data=&specId={specId}&cacheStored=&crumb={crumb}&acrumb={acrumb}&sessionIndex={sessionIndex}&done=https%3A%2F%2Fwww.aol.com&attrSetIndex=0&specData={specData}&userId={email}&signup="
            
            p = s.post("https://login.aol.com/account/module/create", 
                      params={"validateField": "userId"},
                      headers={
                          "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                          "x-requested-with": "XMLHttpRequest"
                      }, 
                      data=data,
                      timeout=15)
            
            if p.status_code != 200:
                return {"available": None, "error": "validation_failed"}
            
            if 'USERNAME_UNAVAILABLE' in p.text or 'taken' in p.text.lower():
                return {"available": False, "email": email, "domain": "aol.com"}
            else:
                return {"available": True, "email": email, "domain": "aol.com"}
                
        except Exception as e:
            return {"available": None, "error": f"aol_error: {str(e)}"}
    
    def check_hi2(self, email):
        try:
            username = self.extract_username(email)
            
            headers = {
                'User-Agent': "Mozilla/5.0",
                'Accept': "application/json, text/plain, */*",
                'authorization': "Basic bnVsbA==",
            }
            
            data = {
                'domain': "@hi2.in",
                'prefix': username,
                'recaptcha': "",
            }
            
            response = requests.post("https://hi2.in/api/custom", 
                                   data=data, 
                                   headers=headers, 
                                   timeout=15)
            
            if response.status_code == 200:
                response_data = response.json()
                if response_data.get('success'):
                    return {"available": True, "email": f"{username}@hi2.in", "domain": "hi2.in"}
                else:
                    return {"available": False, "email": f"{username}@hi2.in", "domain": "hi2.in"}
            else:
                return {"available": None, "error": f"api_error_{response.status_code}"}
                
        except Exception as e:
            return {"available": None, "error": f"hi2_error: {str(e)}"}
    
    def check_email(self, email):
        if '@' not in email:
            return {
                "success": False,
                "error": "invalid_email_format",
                "message": "البريد الإلكتروني غير صالح"
            }
        
        domain = email.split('@')[-1].lower()
        
        if domain not in self.supported_domains:
            return {
                "success": False,
                "error": "unsupported_domain",
                "domain": domain,
                "message": f"النطاق غير مدعوم: {domain}",
                "supported_domains": list(self.supported_domains.keys())
            }
        
        checker_function = self.supported_domains[domain]
        result = checker_function(email)
        
        result["success"] = result.get("available") is not None
        result["domain"] = domain
        result["input_email"] = email
        
        return result

email_checker = EmailChecker()

@app.route('/api/love-Mohsen', methods=['GET'])
def api_check_email():
    email = request.args.get('email')
    
    if not email:
        return jsonify({
            "success": False,
            "error": "missing_email",
            "message": "معامل email مطلوب"
        }), 400
    
    result = email_checker.check_email(email)
    
    if not result.get("success", False):
        return jsonify(result), 400
    
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "service": "email-checker-api",
        "timestamp": time.time()
    })

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "name": "Email Checker API",
        "version": "1.0",
        "endpoint": "/api/love-Mohsen?email=test@example.com",
        "supported_domains": list(email_checker.supported_domains.keys())
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))        
        if not email:
            return json_response({"error": "Email parameter is required"}, 400)
        
        url = "https://api32-normal-alisg.tiktokv.com/passport/account_lookup/email/"
        params = {"request_tag_from": "h5", "fixed_mix_mode": "1", "mix_mode": "1", "account_param": xor(email), "scene": "1", "device_platform": "android", "os": "android", "ssmix": "a", "_rticket": "1755466425423", "cdid": "cefe6f9c-d9d9-4107-9543-f5226d5b3ccd", "channel": "googleplay", "aid": "1233", "app_name": "musical_ly", "version_code": "370805", "version_name": "37.8.5", "manifest_version_code": "2023708050", "update_version_code": "2023708050", "ab_version": "37.8.5", "resolution": "1600*900", "dpi": "240", "device_type": "SM-S908E", "device_brand": "samsung", "language": "en", "os_api": "28", "os_version": "9", "ac": "wifi", "is_pad": "0", "current_region": "DE", "app_type": "normal", "sys_region": "US", "last_install_time": "1754825061", "mcc_mnc": "26202", "timezone_name": "Asia/Baghdad", "carrier_region_v2": "262", "residence": "DE", "app_language": "en", "carrier_region": "DE", "timezone_offset": "10800", "host_abi": "arm64-v8a", "locale": "en", "content_language": "en,", "ac2": "wifi", "uoo": "1", "op_region": "DE", "build_number": "37.8.5", "region": "US", "ts": "1755466424", "iid": "7536212628504381192", "device_id": "7536211658156213782", "openudid": "4196494d5939fa86", "support_webview": "1", "okhttp_version": "4.2.210.6-tiktok", "use_store_region_cookie": "1", "type":"3736", "app_version":"37.8.5"}
        cookies = {"passport_csrf_token": "d52c500f67607c862972a043a4662972", "passport_csrf_token_default": "d52c500f67607c862972a043a4662972", "install_id": "7536212628504381192"}
        m=SignerPy.sign(params=params,cookie=cookies)
        headers = {'User-Agent': "com.zhiliaoapp.musically/2023708050 (Linux; U; Android 9; en; SM-S908E; Build/TP1A.220624.014;tt-ok/3.12.13.16)", 'Accept': "application/json, text/plain, */*", 'Accept-Encoding': "gzip", 'rpc-persist-pyxis-policy-v-tnc': "1", 'x-ss-stub': m['x-ss-stub'], 'x-tt-referer': "https://inapp.tiktokv.com/ucenter_web/account_lookup_tool", 'x-tt-pba-enable': "1", 'x-bd-kmsv': "0", 'x-tt-dm-status': "login=1;ct=1;rt=1", 'x-ss-req-ticket':m['x-ss-req-ticket'], 'x-bd-client-key': "#LFLluN0wIdQaDxIXUUvEDzSMeYqmuwelaqRmzYJxN3Sl5PDfyg0ZQMCLkYm+QRisqBm2hpAXzDekRo0e", 'x-tt-passport-csrf-token': "d52c500f67607c862972a043a4662972", 'sdk-version': "2", 'tt-ticket-guard-iteration-version': "0", 'tt-ticket-guard-version': "3", 'passport-sdk-settings': "x-tt-token", 'passport-sdk-sign': "x-tt-token", 'passport-sdk-version': "6031990", 'oec-vc-sdk-version': "3.0.5.i18n", 'x-vc-bdturing-sdk-version': "2.3.8.i18n", 'x-tt-request-tag': "n=0;nr=011;bg=0", 'x-tt-pba-enable': "1", 'x-ladon':m['x-ladon'], 'x-khronos':m['x-khronos'], 'x-argus': m['x-argus'], 'x-gorgon':m['x-gorgon'], 'content-type': "application/x-www-form-urlencoded"}
        response = requests.post(url, headers=headers,params=params,cookies=cookies)
        passport_ticket=response.json()["data"]["accounts"][0]["passport_ticket"]
        email_temp = requests.post("https://api.internal.temp-mail.io/api/v3/email/new").json()["email"]
        params.update({"email":xor(email_temp),"not_login_ticket":passport_ticket}); url = "https://api16-normal-c-alisg.tiktokv.com/passport/email/send_code/"
        m=SignerPy.sign(params=params,cookie=cookies)
        headers = {'User-Agent': "com.zhiliaoapp.musically/2023708050 (Linux; U; Android 9; en; SM-S908E; Build/TP1A.220624.014;tt-ok/3.12.13.16)", 'Accept-Encoding': "gzip", 'x-ss-stub':m['x-ss-stub'], 'x-tt-pba-enable': "1", 'x-tt-multi-sids': "6639559680287080453%3Af67dac7231a906f233a957f8965344ba", 'x-bd-kmsv': "0", 'x-tt-dm-status': "login=1;ct=1;rt=1", 'x-ss-req-ticket': m['x-ss-req-ticket'], 'x-bd-client-key': "#LFLluN0wIdQaDxIXUUvEDzSMeYqmuwelaqRmzYJxN3Sl5PDfyg0ZQMCLkYm+QRisqBm2hpAXzDekRo0e", 'x-tt-passport-csrf-token': "d52c500f67607c862972a043a4662972", 'sdk-version': "2", 'tt-ticket-guard-iteration-version': "0", 'tt-ticket-guard-version': "3", 'passport-sdk-settings': "x-tt-token", 'passport-sdk-sign': "x-tt-token", 'passport-sdk-version': "6031990", 'x-tt-bypass-dp': "1", 'oec-vc-sdk-version': "3.0.5.i18n", 'x-vc-bdturing-sdk-version': "2.3.8.i18n", 'x-tt-request-tag': "n=0;nr=011;bg=0", 'x-tt-pba-enable': "1", 'x-ladon':m['x-ladon'], 'x-khronos':m['x-khronos'], 'x-argus': m['x-argus'], 'x-gorgon':m['x-gorgon']}
        response = requests.post(url,params=params, headers=headers,cookies=cookies);time.sleep(4.5)
        message = requests.get("https://api.internal.temp-mail.io/api/v3/email/{}/messages".format(email_temp))
        username = message.json()[0]["body_text"].split('This email was generated for')[1].split("\n")[0].strip().rstrip(".")
        try:
            headers = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Android 10; Pixel 3 Build/QKQ1.200308.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.6394.70 Mobile Safari/537.36 trill_350402 JsSdk/1.0 NetType/MOBILE Channel/googleplay AppName/trill app_version/35.3.1 ByteLocale/en ByteFullLocale/en Region/IN AppId/1180 Spark/1.5.9.1 AppVersion/35.3.1 BytedanceWebview/d8a21c6"}
            tikinfo = requests.get(f'https://www.tiktok.com/@{username}', headers=headers, timeout=10).text
            if 'webapp.user-detail"' in tikinfo:
                getting = str(tikinfo.split('webapp.user-detail"')[1]).split('"RecommendUserList"')[0]
                id = str(getting.split('id":"')[1]).split('",')[0]
                Name = str(getting.split('nickname":"')[1]).split('",')[0]
                bio = str(getting.split('signature":"')[1]).split('",')[0]
                country = str(getting.split('region":"')[1]).split('",')[0]
                private = str(getting.split('privateAccount":')[1]).split(',"')[0]
                Followers = str(getting.split('followerCount":')[1]).split(',"')[0]
                following = str(getting.split('followingCount":')[1]).split(',"')[0]
                like = str(getting.split('heart":')[1]).split(',"')[0]
                video = str(getting.split('videoCount":')[1]).split(',"')[0]
                UserName = username
                Level = level(id)
                secret = secrets.token_hex(16)
                url = "https://api16-normal-c-alisg.tiktokv.com/passport/find_account/tiktok_username/"
                params = {'request_tag_from': "h5", 'iid': str(random.randint(1, 10**19)), 'device_id': str(random.randint(1, 10**19)), 'ac': "WIFI", 'channel': "googleplay", 'aid': "567753", 'app_name': "tiktok_studio", 'version_code': "370301", 'version_name': "37.3.1", 'device_platform': "android", 'os': "android", 'ab_version': "37.3.1", 'ssmix': "a", 'device_type': "RMX3269", 'device_brand': "realme", 'language': "en", 'os_api': "28", 'os_version': "10", 'openudid': binascii.hexlify(os.urandom(8)).decode(), 'manifest_version_code': "370301", 'resolution': "720*1448", 'dpi': "420", 'update_version_code': "370301", '_rticket': str(round(random.uniform(1.2, 1.6)*100000000)*-1)+"4632", 'is_pad': "0", 'current_region': "en", 'app_type': "normal", 'sys_region': "en", 'last_install_time': "1650243523", 'mcc_mnc': "41840", 'timezone_name': "Asia/Baghdad", 'carrier_region_v2': "418", 'residence': "ُen", 'app_language': "en", 'carrier_region': "IQ", 'ac2': "wifi", 'uoo': "0", 'op_region': "IQ", 'timezone_offset': "10800", 'build_number': "37.3.1", 'host_abi': "arm64-v8a", 'locale': "en", 'region': "IQ", 'ts': str(round(random.uniform(1.2, 1.6)*100000000)*-1), 'cdid': str(uuid.uuid4()), 'support_webview': "1", 'cronet_version': "f6248591_2024-09-11", 'ttnet_version': "4.2.195.9-tiktok", 'use_store_region_cookie': "1", 'app_version': "37.3.1"}
                cookies = {"passport_csrf_token": secret, "passport_csrf_token_default": secret}
                payload = {'mix_mode': "1", 'username': username}        
                for version in [4404, 8404]:
                    try:
                        m = SignerPy.sign(params=params, cookie=cookies, payload=payload, version=version)
                        headers = {'User-Agent': 'com.zhiliaoapp.musically/2023105030 (Linux; U; Android 11; ar; RMX3269; Build/RP1A.201005.001; Cronet/TTNetVersion:2fdb62f9 2023-09-06 QuicVersion:bb24d47c 2023-07-19)', 'x-tt-passport-csrf-token': cookies['passport_csrf_token'], 'x-ss-req-ticket': m['x-ss-req-ticket'], 'x-ss-stub': m['x-ss-stub'], 'x-gorgon': m["x-gorgon"], 'x-khronos': m["x-khronos"], 'content-type': "application/x-www-form-urlencoded"}
                        response = requests.post(url, params=params, data=payload, headers=headers, cookies=cookies, timeout=10)
                        if response.text.strip() and "token" in response.text:
                            token = response.json()["data"]["token"]
                            params['not_login_ticket'] = token
                            params['_rticket'] = str(round(random.uniform(1.2, 1.6)*100000000)*-1)+"4632"
                            params['ts'] = str(round(random.uniform(1.2, 1.6)*100000000)*-1)
                            m = SignerPy.sign(params=params, cookie=cookies, version=version)
                            headers.update({'x-ss-req-ticket': m['x-ss-req-ticket'], 'x-ss-stub': m['x-ss-stub'], 'x-gorgon': m["x-gorgon"], 'x-khronos': m["x-khronos"]})
                            available_ways = requests.post("https://api16-normal-c-alisg.tiktokv.com/passport/auth/available_ways/", params=params, headers=headers, cookies=cookies, timeout=10)
                            if 'success' in available_ways.text:
                                ways_data = available_ways.json()["data"]
                                passkey = "Yes" if ways_data.get('has_passkey') else "No"
                                out_passkey = "Yes" if ways_data.get('has_oauth') else "No"
                            else:
                                passkey = "No"
                                out_passkey = "No"
                            break
                    except:
                        continue        
                result = {
                    "Name": Name,
                    "UserName": UserName,
                    "Followers": Followers,
                    "following": following,
                    "bio": bio,
                    "country": country,
                    "private": private,
                    "like": like,
                    "video": video,
                    "passkey": passkey,
                    "out_passkey": out_passkey,
                    "Level": Level
                }
                return json_response(result)
            else:
                return json_response({"error": "user not found"}, 404)
        except:
            secret = secrets.token_hex(16)
            url = "https://api16-normal-c-alisg.tiktokv.com/passport/find_account/tiktok_username/"
            params = {'request_tag_from': "h5", 'iid': str(random.randint(1, 10**19)), 'device_id': str(random.randint(1, 10**19)), 'ac': "WIFI", 'channel': "googleplay", 'aid': "567753", 'app_name': "tiktok_studio", 'version_code': "370301", 'version_name': "37.3.1", 'device_platform': "android", 'os': "android", 'ab_version': "37.3.1", 'ssmix': "a", 'device_type': "RMX3269", 'device_brand': "realme", 'language': "en", 'os_api': "28", 'os_version': "10", 'openudid': binascii.hexlify(os.urandom(8)).decode(), 'manifest_version_code': "370301", 'resolution': "720*1448", 'dpi': "420", 'update_version_code': "370301", '_rticket': str(round(random.uniform(1.2, 1.6)*100000000)*-1)+"4632", 'is_pad': "0", 'current_region': "en", 'app_type': "normal", 'sys_region': "en", 'last_install_time': "1650243523", 'mcc_mnc': "41840", 'timezone_name': "Asia/Baghdad", 'carrier_region_v2': "418", 'residence': "ُen", 'app_language': "en", 'carrier_region': "IQ", 'ac2': "wifi", 'uoo': "0", 'op_region': "IQ", 'timezone_offset': "10800", 'build_number': "37.3.1", 'host_abi': "arm64-v8a", 'locale': "en", 'region': "IQ", 'ts': str(round(random.uniform(1.2, 1.6)*100000000)*-1), 'cdid': str(uuid.uuid4()), 'support_webview': "1", 'cronet_version': "f6248591_2024-09-11", 'ttnet_version': "4.2.195.9-tiktok", 'use_store_region_cookie': "1", 'app_version': "37.3.1"}
            cookies = {"passport_csrf_token": secret, "passport_csrf_token_default": secret}
            payload = {'mix_mode': "1", 'username': username}    
            for version in [4404, 8404]:
                try:
                    m = SignerPy.sign(params=params, cookie=cookies, payload=payload, version=version)
                    headers = {'User-Agent': 'com.zhiliaoapp.musically/2023105030 (Linux; U; Android 11; ar; RMX3269; Build/RP1A.201005.001; Cronet/TTNetVersion:2fdb62f9 2023-09-06 QuicVersion:bb24d47c 2023-07-19)', 'x-tt-passport-csrf-token': cookies['passport_csrf_token'], 'x-ss-req-ticket': m['x-ss-req-ticket'], 'x-ss-stub': m['x-ss-stub'], 'x-gorgon': m["x-gorgon"], 'x-khronos': m["x-khronos"], 'content-type': "application/x-www-form-urlencoded"}
                    response = requests.post(url, params=params, data=payload, headers=headers, cookies=cookies, timeout=10)
                    if response.text.strip() and "token" in response.text:
                        token = response.json()["data"]["token"]
                        params['not_login_ticket'] = token
                        params['_rticket'] = str(round(random.uniform(1.2, 1.6)*100000000)*-1)+"4632"
                        params['ts'] = str(round(random.uniform(1.2, 1.6)*100000000)*-1)
                        m = SignerPy.sign(params=params, cookie=cookies, version=version)
                        headers.update({'x-ss-req-ticket': m['x-ss-req-ticket'], 'x-ss-stub': m['x-ss-stub'], 'x-gorgon': m["x-gorgon"], 'x-khronos': m["x-khronos"]})
                        user_detail = requests.post("https://api16-normal-c-alisg.tiktokv.com/passport/user/detail/", params=params, headers=headers, cookies=cookies, timeout=10)
                        available_ways = requests.post("https://api16-normal-c-alisg.tiktokv.com/passport/auth/available_ways/", params=params, headers=headers, cookies=cookies, timeout=10)
                        if user_detail.text.strip() and 'success' in user_detail.text:
                            user_data = user_detail.json()["data"]["user"]
                            Name = user_data.get("nickname", "")
                            UserName = user_data.get("unique_id", "")
                            Followers = user_data.get("follower_count", 0)
                            following = user_data.get("following_count", 0)
                            bio = user_data.get("signature", "")
                            id = user_data.get("uid", "")
                            country = user_data.get("region", "")
                            private = user_data.get("private_account", "")
                            like = user_data.get("total_favorited", 0)
                            video = user_data.get("aweme_count", 0)                    
                            Level = level(id) if id else "Not Available"                    
                        if available_ways.text.strip() and 'success' in available_ways.text:
                            ways_data = available_ways.json()["data"]
                            passkey = "Yes" if ways_data.get('has_passkey') else "No"
                            out_passkey = "Yes" if ways_data.get('has_oauth') else "No"
                        else:
                            passkey = "No"
                            out_passkey = "No"                
                        result = {
                            "Name": Name,
                            "UserName": UserName,
                            "Followers": Followers,
                            "following": following,
                            "bio": bio,
                            "country": country,
                            "private": private,
                            "like": like,
                            "video": video,
                            "passkey": passkey,
                            "out_passkey": out_passkey,
                            "Level": Level
                        }
                        return json_response(result)
                except:
                    continue
            return json_response({"error": "Failed to get user info"}, 500)
    except Exception as e:
        return json_response({"error": f"Failed to process request: {str(e)}"}, 500)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False)                url.split('?')[1], x_ss_stub, unix, platform=19, aid=1233,
                license_id=1611921764,
                sec_device_id="AadCFwpTyztA5j9L" + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(9)),
                sdk_version="2.3.1.i18n", sdk_version_int=2
            )
        }
        headers.update(sig)
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)
            level = re.search(r'"default_pattern":"(.*?)"', response.text).group(1)
            return level
    except Exception:
        return "غير متاح"

async def get_user_info_via_api(username: str, user_id: str = None) -> Dict[str, Any]:
    secret = secrets.token_hex(16)
    url = "https://api16-normal-c-alisg.tiktokv.com/passport/find_account/tiktok_username/"
    params = {
        'request_tag_from': "h5", 'iid': str(random.randint(1, 10**19)),
        'device_id': str(random.randint(1, 10**19)), 'ac': "WIFI",
        'channel': "googleplay", 'aid': "567753", 'app_name': "tiktok_studio",
        'version_code': "370301", 'version_name': "37.3.1",
        'device_platform': "android", 'os': "android", 'ab_version': "37.3.1",
        'ssmix': "a", 'device_type': "RMX3269", 'device_brand': "realme",
        'language': "en", 'os_api': "28", 'os_version': "10",
        'openudid': binascii.hexlify(os.urandom(8)).decode(),
        'manifest_version_code': "370301", 'resolution': "720*1448",
        'dpi': "420", 'update_version_code': "370301",
        '_rticket': str(round(random.uniform(1.2, 1.6)*100000000)*-1)+"4632",
        'is_pad': "0", 'current_region': "en", 'app_type': "normal",
        'sys_region': "en", 'last_install_time': "1650243523",
        'mcc_mnc': "41840", 'timezone_name': "Asia/Baghdad",
        'carrier_region_v2': "418", 'residence': "ُen", 'app_language': "en",
        'carrier_region': "IQ", 'ac2': "wifi", 'uoo': "0", 'op_region': "IQ",
        'timezone_offset': "10800", 'build_number': "37.3.1",
        'host_abi': "arm64-v8a", 'locale': "en", 'region': "IQ",
        'ts': str(round(random.uniform(1.2, 1.6)*100000000)*-1),
        'cdid': str(uuid.uuid4()), 'support_webview': "1",
        'cronet_version': "f6248591_2024-09-11",
        'ttnet_version': "4.2.195.9-tiktok", 'use_store_region_cookie': "1",
        'app_version': "37.3.1"
    }
    cookies = {"passport_csrf_token": secret, "passport_csrf_token_default": secret}
    payload = {'mix_mode': "1", 'username': username}
    
    user_info = {}
    for version in [4404, 8404]:
        try:
            m = SignerPy.sign(params=params, cookie=cookies, payload=payload, version=version)
            headers = {
                'User-Agent': 'com.zhiliaoapp.musically/2023105030 (Linux; U; Android 11; ar; RMX3269; Build/RP1A.201005.001; Cronet/TTNetVersion:2fdb62f9 2023-09-06 QuicVersion:bb24d47c 2023-07-19)',
                'x-tt-passport-csrf-token': cookies['passport_csrf_token'],
                'x-ss-req-ticket': m['x-ss-req-ticket'],
                'x-ss-stub': m['x-ss-stub'],
                'x-gorgon': m["x-gorgon"],
                'x-khronos': m["x-khronos"],
                'content-type': "application/x-www-form-urlencoded"
            }
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, params=params, data=payload, headers=headers, cookies=cookies)
                if response.text.strip() and "token" in response.text:
                    token = response.json()["data"]["token"]
                    
                    params['not_login_ticket'] = token
                    params['_rticket'] = str(round(random.uniform(1.2, 1.6)*100000000)*-1)+"4632"
                    params['ts'] = str(round(random.uniform(1.2, 1.6)*100000000)*-1)
                    
                    m = SignerPy.sign(params=params, cookie=cookies, version=version)
                    headers.update({
                        'x-ss-req-ticket': m['x-ss-req-ticket'],
                        'x-ss-stub': m['x-ss-stub'],
                        'x-gorgon': m["x-gorgon"],
                        'x-khronos': m["x-khronos"]
                    })
                    
                    detail_url = "https://api16-normal-c-alisg.tiktokv.com/passport/user/detail/"
                    ways_url = "https://api16-normal-c-alisg.tiktokv.com/passport/auth/available_ways/"
                    
                    task1 = client.post(detail_url, params=params, headers=headers, cookies=cookies)
                    task2 = client.post(ways_url, params=params, headers=headers, cookies=cookies)
                    
                    responses = await asyncio.gather(task1, task2)
                    user_detail_resp, available_ways_resp = responses
                    
                    if user_detail_resp.text.strip() and 'success' in user_detail_resp.text:
                        user_data = user_detail_resp.json()["data"]["user"]
                        user_info = {
                            "Name": user_data.get("nickname", ""),
                            "UserName": user_data.get("unique_id", ""),
                            "Followers": user_data.get("follower_count", 0),
                            "following": user_data.get("following_count", 0),
                            "bio": user_data.get("signature", ""),
                            "id": user_data.get("uid", ""),
                            "country": user_data.get("region", ""),
                            "private": user_data.get("private_account", ""),
                            "like": user_data.get("total_favorited", 0),
                            "video": user_data.get("aweme_count", 0),
                            "Level": "غير متاح",
                            "passkey": "لا",
                            "out_passkey": "لا"
                        }
                    
                    if available_ways_resp.text.strip() and 'success' in available_ways_resp.text:
                        ways_data = available_ways_resp.json()["data"]
                        user_info["passkey"] = "نعم" if ways_data.get('has_passkey') else "لا"
                        user_info["out_passkey"] = "نعم" if ways_data.get('has_oauth') else "لا"
                    
                    if user_info.get("id"):
                        user_info["Level"] = await get_level_async(user_info["id"])
                    
                    return user_info
        except Exception:
            continue
    
    return {}

async def lookup_tiktok_account(email: str) -> Dict[str, Any]:
    result = {"success": False, "message": "", "data": {}}
    
    try:
        url = "https://api32-normal-alisg.tiktokv.com/passport/account_lookup/email/"
        params = {
            "request_tag_from": "h5", "fixed_mix_mode": "1", "mix_mode": "1",
            "account_param": xor(email), "scene": "1", "device_platform": "android",
            "os": "android", "ssmix": "a", "_rticket": "1755466425423",
            "cdid": "cefe6f9c-d9d9-4107-9543-f5226d5b3ccd", "channel": "googleplay",
            "aid": "1233", "app_name": "musical_ly", "version_code": "370805",
            "version_name": "37.8.5", "manifest_version_code": "2023708050",
            "update_version_code": "2023708050", "ab_version": "37.8.5",
            "resolution": "1600*900", "dpi": "240", "device_type": "SM-S908E",
            "device_brand": "samsung", "language": "en", "os_api": "28",
            "os_version": "9", "ac": "wifi", "is_pad": "0", "current_region": "DE",
            "app_type": "normal", "sys_region": "US", "last_install_time": "1754825061",
            "mcc_mnc": "26202", "timezone_name": "Asia/Baghdad",
            "carrier_region_v2": "262", "residence": "DE", "app_language": "en",
            "carrier_region": "DE", "timezone_offset": "10800",
            "host_abi": "arm64-v8a", "locale": "en", "content_language": "en,",
            "ac2": "wifi", "uoo": "1", "op_region": "DE", "build_number": "37.8.5",
            "region": "US", "ts": "1755466424", "iid": "7536212628504381192",
            "device_id": "7536211658156213782", "openudid": "4196494d5939fa86",
            "support_webview": "1", "okhttp_version": "4.2.210.6-tiktok",
            "use_store_region_cookie": "1", "type": "3736", "app_version": "37.8.5"
        }
        cookies = {
            "passport_csrf_token": "d52c500f67607c862972a043a4662972",
            "passport_csrf_token_default": "d52c500f67607c862972a043a4662972",
            "install_id": "7536212628504381192"
        }
        
        m = SignerPy.sign(params=params, cookie=cookies)
        headers = {
            'User-Agent': "com.zhiliaoapp.musically/2023708050 (Linux; U; Android 9; en; SM-S908E; Build/TP1A.220624.014;tt-ok/3.12.13.16)",
            'Accept': "application/json, text/plain, */*", 'Accept-Encoding': "gzip",
            'rpc-persist-pyxis-policy-v-tnc': "1", 'x-ss-stub': m['x-ss-stub'],
            'x-tt-referer': "https://inapp.tiktokv.com/ucenter_web/account_lookup_tool",
            'x-tt-pba-enable': "1", 'x-bd-kmsv': "0",
            'x-tt-dm-status': "login=1;ct=1;rt=1", 'x-ss-req-ticket': m['x-ss-req-ticket'],
            'x-bd-client-key': "#LFLluN0wIdQaDxIXUUvEDzSMeYqmuwelaqRmzYJxN3Sl5PDfyg0ZQMCLkYm+QRisqBm2hpAXzDekRo0e",
            'x-tt-passport-csrf-token': "d52c500f67607c862972a043a4662972",
            'sdk-version': "2", 'tt-ticket-guard-iteration-version': "0",
            'tt-ticket-guard-version': "3", 'passport-sdk-settings': "x-tt-token",
            'passport-sdk-sign': "x-tt-token", 'passport-sdk-version': "6031990",
            'oec-vc-sdk-version': "3.0.5.i18n", 'x-vc-bdturing-sdk-version': "2.3.8.i18n",
            'x-tt-request-tag': "n=0;nr=011;bg=0", 'x-ladon': m['x-ladon'],
            'x-khronos': m['x-khronos'], 'x-argus': m['x-argus'],
            'x-gorgon': m['x-gorgon'], 'content-type': "application/x-www-form-urlencoded"
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(url, headers=headers, params=params, cookies=cookies)
            
            if response.status_code != 200:
                result["message"] = f"فشل في البحث عن الحساب. الرمز: {response.status_code}"
                return result
            
            response_data = response.json()
            if "data" not in response_data or "accounts" not in response_data["data"]:
                result["message"] = "لم يتم العثور على حساب مرتبط بهذا البريد الإلكتروني"
                return result
            
            passport_ticket = response_data["data"]["accounts"][0]["passport_ticket"]
            
            email_resp = await client.post("https://api.internal.temp-mail.io/api/v3/email/new")
            temp_email = email_resp.json()["email"]
            
            params.update({"email": xor(temp_email), "not_login_ticket": passport_ticket})
            url = "https://api16-normal-c-alisg.tiktokv.com/passport/email/send_code/"
            
            m = SignerPy.sign(params=params, cookie=cookies)
            headers = {
                'User-Agent': "com.zhiliaoapp.musically/2023708050 (Linux; U; Android 9; en; SM-S908E; Build/TP1A.220624.014;tt-ok/3.12.13.16)",
                'Accept-Encoding': "gzip", 'x-ss-stub': m['x-ss-stub'],
                'x-tt-pba-enable': "1", 'x-tt-multi-sids': "6639559680287080453%3Af67dac7231a906f233a957f8965344ba",
                'x-bd-kmsv': "0", 'x-tt-dm-status': "login=1;ct=1;rt=1",
                'x-ss-req-ticket': m['x-ss-req-ticket'],
                'x-bd-client-key': "#LFLluN0wIdQaDxIXUUvEDzSMeYqmuwelaqRmzYJxN3Sl5PDfyg0ZQMCLkYm+QRisqBm2hpAXzDekRo0e",
                'x-tt-passport-csrf-token': "d52c500f67607c862972a043a4662972",
                'sdk-version': "2", 'tt-ticket-guard-iteration-version': "0",
                'tt-ticket-guard-version': "3", 'passport-sdk-settings': "x-tt-token",
                'passport-sdk-sign': "x-tt-token", 'passport-sdk-version': "6031990",
                'x-tt-bypass-dp': "1", 'oec-vc-sdk-version': "3.0.5.i18n",
                'x-vc-bdturing-sdk-version': "2.3.8.i18n", 'x-tt-request-tag': "n=0;nr=011;bg=0",
                'x-ladon': m['x-ladon'], 'x-khronos': m['x-khronos'],
                'x-argus': m['x-argus'], 'x-gorgon': m['x-gorgon']
            }
            
            await client.post(url, params=params, headers=headers, cookies=cookies)
            
            await asyncio.sleep(4.5)
            
            message_resp = await client.get(f"https://api.internal.temp-mail.io/api/v3/email/{temp_email}/messages")
            messages = message_resp.json()
            
            if not messages:
                result["message"] = "فشل في استخراج اسم المستخدم من البريد المؤقت"
                return result
            
            username = messages[0]["body_text"].split('This email was generated for')[1].split("\n")[0].strip().rstrip(".")
            
            try:
                web_headers = {
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Android 10; Pixel 3 Build/QKQ1.200308.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.6394.70 Mobile Safari/537.36 trill_350402 JsSdk/1.0 NetType/MOBILE Channel/googleplay AppName/trill app_version/35.3.1 ByteLocale/en ByteFullLocale/en Region/IN AppId/1180 Spark/1.5.9.1 AppVersion/35.3.1 BytedanceWebview/d8a21c6"
                }
                tikinfo_resp = await client.get(f'https://www.tiktok.com/@{username}', headers=web_headers, timeout=10)
                tikinfo = tikinfo_resp.text
                
                if 'webapp.user-detail"' in tikinfo:
                    getting = str(tikinfo.split('webapp.user-detail"')[1]).split('"RecommendUserList"')[0]
                    user_id = str(getting.split('id":"')[1]).split('",')[0]
                    
                    level_task = get_level_async(user_id)
                    api_info_task = get_user_info_via_api(username, user_id)
                    
                    level, api_info = await asyncio.gather(level_task, api_info_task)
                    
                    result["success"] = True
                    result["data"] = {
                        "Name": str(getting.split('nickname":"')[1]).split('",')[0],
                        "UserName": username,
                        "bio": str(getting.split('signature":"')[1]).split('",')[0],
                        "country": str(getting.split('region":"')[1]).split('",')[0],
                        "private": str(getting.split('privateAccount":')[1]).split(',"')[0],
                        "Followers": str(getting.split('followerCount":')[1]).split(',"')[0],
                        "following": str(getting.split('followingCount":')[1]).split(',"')[0],
                        "like": str(getting.split('heart":')[1]).split(',"')[0],
                        "video": str(getting.split('videoCount":')[1]).split(',"')[0],
                        "Level": level,
                        "passkey": api_info.get("passkey", "لا"),
                        "out_passkey": api_info.get("out_passkey", "لا")
                    }
                    return result
            except Exception:
                pass
            
            api_info = await get_user_info_via_api(username)
            if api_info:
                result["success"] = True
                result["data"] = api_info
            else:
                result["message"] = "لم يتم العثور على مستخدم"
                
    except httpx.TimeoutException:
        result["message"] = "انتهت مهلة الطلب. حاول مرة أخرى لاحقًا."
    except Exception as e:
        result["message"] = f"حدث خطأ: {str(e)}"
    
    return result

@app.route('/api/ksj', methods=['GET'])
def lookup_account():
    email = request.args.get('email')
    session_token = request.args.get('session')
    
    if not session_token or session_token != SECRET_TOKEN:
        data = {"success": False, "message": "رمز الجلسة غير صالح أو مفقود", "data": {}}
        return Response(json.dumps(data, ensure_ascii=False), 
                       mimetype='application/json'), 401
    
    if not email:
        data = {"success": False, "message": "الرجاء تقديم بريد إلكتروني", "data": {}}
        return Response(json.dumps(data, ensure_ascii=False), 
                       mimetype='application/json'), 400
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(lookup_tiktok_account(email))
        loop.close()
        
        return Response(json.dumps(result, ensure_ascii=False), 
                       mimetype='application/json')
    except Exception as e:
        data = {"success": False, "message": f"خطأ في الخادم: {str(e)}", "data": {}}
        return Response(json.dumps(data, ensure_ascii=False), 
                       mimetype='application/json'), 500

@app.route('/')
def index():
    return "API is running"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))

    app.run(host='0.0.0.0', port=port, debug=False)

