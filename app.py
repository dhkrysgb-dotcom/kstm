from flask import Flask, request, jsonify
import requests, random, re, secrets, time
import os

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
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
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
