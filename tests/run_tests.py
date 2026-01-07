import requests
import time
import sys

# ANSI Colors
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"

BASE_URL = "http://localhost:5000"

def print_header(text):
    print(f"\n{BOLD}{BLUE}=== {text} ==={RESET}")

def test_request(name, path, expected_status, description=""):
    print(f"{CYAN}[TEST]{RESET} {name:<25}", end="")
    try:
        start_time = time.time()
        response = requests.get(BASE_URL + path)
        elapsed = (time.time() - start_time) * 1000
        
        if response.status_code == expected_status:
            print(f"{GREEN}[PASS]{RESET} Status: {response.status_code} ({elapsed:.1f}ms)")
            return True
        else:
            print(f"{RED}[FAIL]{RESET} Expected {expected_status}, Got {response.status_code}")
            return False
    except Exception as e:
        print(f"{YELLOW}[ERROR]{RESET} Connection Failed: {e}")
        return False

def run_tests():
    print(f"{BOLD}SentinelShield Automated Verification Suite{RESET}")
    print(f"Target: {BASE_URL}")
    print("-" * 50)
    
    # Define Tests Grouped by Category
    test_groups = {
        "Baseline": [
            ("Normal Request", "/", 200),
            ("Search Query", "/?q=hello", 200),
            ("Dashboard Access", "/dashboard/", 200),
        ],
        "SQL Injection": [
            ("Basic OR payload", "/?id=1' OR '1'='1", 403),
            ("Union Select", "/?p=union select user,password", 403),
            ("SQL Comment", "/?q=admin' --", 403),
            ("Sleep Command", "/?t=sleep(10)", 403),
        ],
        "XSS Detection": [
            ("Script Tag", "/?q=<script>alert(1)</script>", 403),
            ("Mixed Case Script", "/?q=<ScRiPt>alert(1)</sCrIpT>", 403),
            ("Javascript Protocol", "/?url=javascript:alert(1)", 403),
            ("OnError Event", "/?img=<img src=x onerror=alert(1)>", 403),
        ],
        "LFI & Traversal": [
            ("Root Directory", "/?file=../../etc/passwd", 403),
            ("Boot.ini", "/?c=boot.ini", 403),
        ],
        "Command Injection": [
            ("Cat Command", "/?cmd=cat /etc/passwd", 403),
            ("Chained Command", "/?ip=127.0.0.1; ls -la", 403),
            ("Pipe Operator", "/?a=1 | whoami", 403),
        ]
    }

    total_passed = 0
    total_tests = 0

    for category, tests in test_groups.items():
        print_header(category)
        for t in tests:
            total_tests += 1
            name, path, status = t
            if test_request(name, path, status):
                total_passed += 1
            time.sleep(0.1) # Slight text delay for readability

    # Rate Limit Test
    print_header("Rate Limiting Simulation")
    print(f"{YELLOW}Sending burst traffic (50 requests)...{RESET}")
    burst_passed = True
    for i in range(50):
        # We expect eventually a 403, but since limit is 100/60s, this burst might pass all 200 if fresh
        # or start blocking if repeated. 
        # This test is just to ensure it doesn't crash.
        try:
            requests.get(BASE_URL)
        except:
            pass
        if i % 10 == 0:
            print(".", end="", flush=True)
    print(" Done.")

    print("\n" + "=" * 50)
    score_color = GREEN if total_passed == total_tests else RED
    print(f"Summary: {score_color}{total_passed}/{total_tests} Tests Passed{RESET}")
    
    if total_passed == total_tests:
        print(f"{GREEN}SUCCESS: System is behaving as expected.{RESET}")
    else:
        print(f"{RED}WARNING: Some security checks failed.{RESET}")

if __name__ == "__main__":
    try:
        run_tests()
    except KeyboardInterrupt:
        print("\nTest Aborted.")
