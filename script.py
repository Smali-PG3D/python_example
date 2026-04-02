import requests
import random
import string
import re
import urllib.parse
import time
import json
import sys
import os
import concurrent.futures

# Configuration: Read from environment variables
REGISTRATIONS_COUNT = int(os.getenv("REG_COUNT", 1))
THREADS = int(os.getenv("THREADS", 5))
CLEAR_FILE = os.getenv("CLEAR_FILE", "false").lower() in ("true", "1", "yes")
OUTPUT_FILE_BYPASS = "main.txt"
OUTPUT_FILE_MAIN = "sec.txt"

# Target URLs
login_url = "https://console.rscore.app/login"
main_url = "https://console.rscore.app/"

file_mode = 'w' if CLEAR_FILE else 'a'

def fetch_nodes(uuid, is_bypass=False, suffix="", task_id=1):
    """Fetches and parses VLESS nodes from the API given a UUID."""
    links = []
    random_hwid = ''.join(random.choices(string.digits, k=16))
    api_headers = {
        'User-Agent': 'Happ/3.12.0',
        'X-HWID': random_hwid,
        'X-Device-Model': 'Xaomi Redmi 9', 
        'X-Device-OS': 'Android',
        'X-Ver-OS': '12'
    }
    
    # Garbage remarks to filter out from the main config
    # DO NOT TRANSLATE THESE: They match the exact Cyrillic strings sent by the server
    forbidden_remarks = [
        "⬇️Обход Белых списков ниже⬇️", 
        "Сервера в другом конфиге", 
        "Подключить их можно в боте"
    ]
    
    try:
        api_link = f"https://connect.rsvps.tech/{uuid}"
        api_response = requests.get(api_link, headers=api_headers)
        
        if api_response.status_code == 200:
            config_json = api_response.json()
            if not isinstance(config_json, list): config_json = [config_json]
            
            for idx, conf in enumerate(config_json):
                try:
                    remarks = conf.get("remarks", f"RS_Node_{idx+1}")
                    
                    # Filtering logic based on node type
                    if is_bypass:
                        if "ByPass-" not in remarks: continue
                    else:
                        # Skip if the remark contains any of the forbidden strings
                        if any(bad_word in remarks for bad_word in forbidden_remarks):
                            continue
                    
                    outbounds = conf.get("outbounds", [])
                    vless_out = next((ob for ob in outbounds if ob.get("protocol") == "vless" and ob.get("tag") == "proxy"), None)
                    
                    if not vless_out: continue
                    
                    settings = vless_out.get("settings", {})
                    vnext = settings.get("vnext", [{}])[0]
                    address = vnext.get("address")
                    port = vnext.get("port")
                    
                    users = vnext.get("users", [{}])[0]
                    node_uuid = users.get("id")
                    flow = users.get("flow", "")
                    
                    stream_settings = vless_out.get("streamSettings", {})
                    network = stream_settings.get("network", "tcp")
                    security = stream_settings.get("security", "none")
                    
                    reality_settings = stream_settings.get("realitySettings", {})
                    server_name = reality_settings.get("serverName", "")
                    public_key = reality_settings.get("publicKey", "")
                    
                    vless_url = f"vless://{node_uuid}@{address}:{port}?type={network}&security={security}"
                    
                    if public_key: vless_url += f"&pbk={public_key}"
                    if server_name: vless_url += f"&sni={server_name}"
                    if flow: vless_url += f"&flow={flow}"
                    
                    # Add suffix to indicate it's an extended proxy (e.g. _3Days)
                    encoded_remarks = urllib.parse.quote(f"{remarks}{suffix}")
                    vless_url += f"#{encoded_remarks}"
                    
                    links.append(vless_url)
                    
                except Exception as parse_error:
                    print(f"[Task {task_id}] [-] Error parsing node {idx}: {parse_error}", file=sys.stderr)
        else:
            print(f"[Task {task_id}] [-] API returned status code {api_response.status_code} for UUID {uuid}", file=sys.stderr)
            
    except json.JSONDecodeError:
        print(f"[Task {task_id}] [-] Failed to parse JSON.", file=sys.stderr)
    except Exception as e:
        print(f"[Task {task_id}] [-] Request error during node extraction: {e}", file=sys.stderr)
        
    return links

def generate_vless_links(task_id):
    """Registers an account, extends subscription to 3 days, and returns 2 lists of VLESS URLs."""
    bypass_links = []
    main_links = []
    
    # Generate random user data
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    test_email = f"test_{random_suffix}@example.com"
    test_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    
    test_first_name = "Kali_" + ''.join(random.choices(string.ascii_letters, k=5))
    test_last_name = "User_" + ''.join(random.choices(string.ascii_letters, k=5))
    
    session = requests.Session()
    
    # Step 1: Initialize session (UPDATED HEADERS)
    get_headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "ru-RU,ru;q=0.9,en-RU;q=0.8,en;q=0.7,en-US;q=0.6",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    try:
        session.get(login_url, headers=get_headers, timeout=10)
    except Exception as e:
        print(f"[Task {task_id}] [-] Failed to fetch initial cookies: {e}", file=sys.stderr)
        return bypass_links, main_links

    # Step 2: Login / Registration POST (UPDATED HEADERS & NEXT-ACTION)
    login_router_state_tree = '%5B%22%22%2C%7B%22children%22%3A%5B%22(auth)%22%2C%7B%22children%22%3A%5B%22login%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
    login_headers = {
        "Origin": "https://console.rscore.app",
        "Referer": "https://console.rscore.app/login",
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36", 
        "Accept": "text/x-component",
        "Accept-Language": "ru-RU,ru;q=0.9,en-RU;q=0.8,en;q=0.7,en-US;q=0.6",
        "next-action": "60847de45cc77b728ce188a50c3a992de842ab00b0",
        "next-router-state-tree": login_router_state_tree,
        "DNT": "1",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin"
    }
    
    login_files = {
        '1_tgId': (None, ''),
        '1_refId': (None, ''),
        '1_firstName': (None, test_first_name),
        '1_lastName': (None, test_last_name),
        '1_email': (None, test_email),
        '1_password': (None, test_password),
        '0': (None, '[null,"$K1"]')
    }
    
    try:
        response = session.post(login_url, headers=login_headers, files=login_files, allow_redirects=False)
        
        if response.status_code == 303:
            session_token = session.cookies.get("__Secure-authjs.session-token")
            if session_token:
                
                # Step 3: Loop 3 times to extend the subscription to 3 days
                sub_success = False
                for sub_attempt in range(3):
                    print(f"[Task {task_id}] [~] Purchasing day {sub_attempt + 1}/3 for account {test_email}...")
                    
                    sub_router_state = '%5B%22%22%2C%7B%22children%22%3A%5B%22(root)%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D'
                    sub_headers = {
                        "Origin": "https://console.rscore.app",
                        "Referer": "https://console.rscore.app/",
                        "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36", 
                        "Accept": "text/x-component",
                        "Accept-Language": "ru-RU,ru;q=0.9,en-RU;q=0.8,en;q=0.7,en-US;q=0.6",
                        "next-action": "606d7b49472270b502774a7102f864151bc095d02d", # НУЖНО БУДЕТ ОБНОВИТЬ ЕСЛИ СКРИПТ УПАДЕТ НА ЭТОМ ШАГЕ
                        "next-router-state-tree": sub_router_state,
                        "DNT": "1",
                        "Sec-Fetch-Dest": "empty",
                        "Sec-Fetch-Mode": "cors",
                        "Sec-Fetch-Site": "same-origin"
                    }
                    sub_files = {
                        '1_planId': (None, '1_day'),
                        '0': (None, '[null,"$K1"]')
                    }
                    
                    sub_response = session.post(main_url, headers=sub_headers, files=sub_files)
                    sub_response.encoding = 'utf-8'
                    
                    # DO NOT TRANSLATE: Checking server's exact response string
                    if "Подписка успешно оформлена" in sub_response.text or '"success":true' in sub_response.text:
                        sub_success = True
                        time.sleep(1) # Reduced sleep in multithreading mode to keep it snappy
                    else:
                        print(f"[Task {task_id}] [-] Extension failed on attempt {sub_attempt + 1}. Moving to extraction.", file=sys.stderr)
                        break 
                
                # Step 4: Extract the configuration
                if sub_success:
                    print(f"[Task {task_id}] [+] Subscription extended. Fetching configurations...")
                    cache_buster = ''.join(random.choices(string.digits, k=8))
                    refresh_url = f"{main_url}?bust={cache_buster}"
                    
                    dashboard_headers = get_headers.copy()
                    dashboard_headers["RSC"] = "1"
                    dashboard_headers["Cache-Control"] = "no-cache"
                    dashboard_headers["Pragma"] = "no-cache"
                    
                    dashboard_response = session.get(refresh_url, headers=dashboard_headers)
                    dashboard_data = dashboard_response.text
                    
                    main_uuid, bypass_uuid = None, None
                    
                    main_match = re.search(r'(?<!bypass_)shortUuid\\?["\']?:\\?["\']?([a-zA-Z0-9]+)', dashboard_data)
                    if main_match: main_uuid = main_match.group(1)
                    
                    bypass_match = re.search(r'bypass_shortUuid\\?["\']?:\\?["\']?([a-zA-Z0-9]+)', dashboard_data)
                    if bypass_match: bypass_uuid = bypass_match.group(1)
                    
                    if not main_uuid or not bypass_uuid:
                        fallback_links = re.findall(r'connect\.rsvps\.tech/([a-zA-Z0-9]+)', dashboard_data)
                        unique_links = list(dict.fromkeys(fallback_links))
                        if len(unique_links) >= 1 and not main_uuid: main_uuid = unique_links[0]
                        if len(unique_links) >= 2 and not bypass_uuid: bypass_uuid = unique_links[1]
                    
                    # Step 5: Fetch ByPass nodes
                    if bypass_uuid:
                        bypass_links = fetch_nodes(bypass_uuid, is_bypass=True, suffix="_3Days", task_id=task_id)
                    else:
                        print(f"[Task {task_id}] [-] No ByPass UUID was found.", file=sys.stderr)
                        
                    # Step 6: Fetch Main nodes
                    if main_uuid:
                        main_links = fetch_nodes(main_uuid, is_bypass=False, suffix="_3Days", task_id=task_id)
                    else:
                        print(f"[Task {task_id}] [-] No Main UUID was found.", file=sys.stderr)
                        
                else:
                    print(f"[Task {task_id}] [-] Could not subscribe at all.", file=sys.stderr)

            else:
                print(f"[Task {task_id}] [?] Redirected, but no session token found.", file=sys.stderr)
        else:
            print(f"[Task {task_id}] [-] Unexpected auth response: {response.status_code}", file=sys.stderr)
            
    except Exception as e:
        print(f"[Task {task_id}] [-] Request failed: {e}", file=sys.stderr)

    return bypass_links, main_links

# Main execution logic
if __name__ == "__main__":
    print(f"[*] Starting {REGISTRATIONS_COUNT} registration(s) using {THREADS} parallel threads...")
    print(f"[*] File mode: {'Overwrite' if CLEAR_FILE else 'Append'}")

    # Ensure both files are created if they don't exist, or cleared if CLEAR_FILE is true
    if CLEAR_FILE:
        open(OUTPUT_FILE_BYPASS, 'w').close()
        open(OUTPUT_FILE_MAIN, 'w').close()

    all_bypass_links = []
    all_main_links = []

    # Using ThreadPoolExecutor to run registrations concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        # Submit all tasks
        future_to_task = {executor.submit(generate_vless_links, i + 1): i + 1 for i in range(REGISTRATIONS_COUNT)}
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_task):
            task_id = future_to_task[future]
            try:
                b_links, m_links = future.result()
                if b_links:
                    all_bypass_links.extend(b_links)
                    print(f"[Task {task_id}] [+] Extracted {len(b_links)} ByPass links.")
                if m_links:
                    all_main_links.extend(m_links)
                    print(f"[Task {task_id}] [+] Extracted {len(m_links)} Main links.")
                    
                if not b_links and not m_links:
                    print(f"[Task {task_id}] [-] No links found.")
            except Exception as exc:
                print(f"[Task {task_id}] [-] Generated an exception: {exc}")

    # Write all gathered links to files sequentially at the end to prevent race conditions
    if all_bypass_links:
        with open(OUTPUT_FILE_BYPASS, 'a', encoding='utf-8') as fb:
            for link in all_bypass_links:
                fb.write(link + "\n")
        print(f"\n[+] Successfully saved {len(all_bypass_links)} total ByPass links to {OUTPUT_FILE_BYPASS}")

    if all_main_links:
        with open(OUTPUT_FILE_MAIN, 'a', encoding='utf-8') as fm:
            for link in all_main_links:
                fm.write(link + "\n")
        print(f"[+] Successfully saved {len(all_main_links)} total Main links to {OUTPUT_FILE_MAIN}")

    print("\n[*] Script finished successfully.")
