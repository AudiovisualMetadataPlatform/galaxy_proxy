#!/bin/env python3

import requests
import requests.cookies
import re
import json
import argparse
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Tested against upstream galaxy, since our fork won't run on
# my workstation.

# The URL prefix has to be changed to /galaxy to make sure none of
# the galaxy URLs end up conflicting with our URLs.  Comment out
# the "module" line in galaxy.yml and uncomment the "mount" option.
# Also enable "manage-script-name"

galaxy_session = None
base_url = None

def main():
    global galaxy_session, base_url
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", default=False, action="store_true", help="Turn on debugging")
    parser.add_argument("base_url", help="Galaxy base url")
    parser.add_argument("username", help="Galaxy username")
    parser.add_argument("password", help="Galaxy password")
    parser.add_argument("bind_addr", default="localhost:8999", help="Proxy binding")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s [%(levelname)-8s] (%(filename)s:%(lineno)d)  %(message)s")

    # First thing to do is log into the back end and
    # get the galaxysession cookie that we're going to 
    # add/remove during the proxying process...
    base_url = args.base_url
    galaxy_session = backend_login(args.base_url, args.username, args.password)
    logging.info(f"Got galaxy session cookie: {galaxy_session}")

    # Proxies have to be both a client and a server.  When running under something
    # like tomcat or uwsgi, the server connection bits are handled automatically.
    # Since this is a standalone thing, I have to set up the webserver bits manually.
    (addr, port) = args.bind_addr.split(':')
    port = int(port)
    webServer = ThreadingHTTPServer((addr, port), GalaxyProxy)
    logging.info(f"Galaxy Proxy available at http://{args.bind_addr}/galaxy")  
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        logging.info("Got Keyboard interrupt. Shutting down")
    webServer.server_close()
    logging.info("BYE!")


class GalaxyProxy(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info(f"Got a GET request for {self.path}")    
        if authorized_url("GET", self.path):
            # One thing that doesn't seem to be working
            # with the rebasing is that /style/base.css isn't found. Prefix
            # it with /static to make it work.  That's one of the nice things
            # with proxies -- we can manipulate the URLs at will.
            if self.path.startswith("/galaxy/style"):
                self.path = self.path.replace("/galaxy/style", "/galaxy/static/style")                
                logging.info(f"Fixed up /style URL to have /static prefix...: {self.path}")

            # build the request that we're going to send to the back end.
            # the galaxysession cookie that we collected earlier needs to
            # be inserted into the cookie jar and included in the request
            jar = requests.cookies.RequestsCookieJar()
            jar['galaxysession'] = galaxy_session
            r = requests.get(f"{base_url}{self.path}", cookies=jar)
            
            # copy the status, headers, and content to the client that called us.
            self.send_response(r.status_code)
            for h, v in r.headers.items():                
                self.send_header(h, v)
            self.end_headers()
            self.wfile.write(r.content)
        else:
            unauthorized(self)        
        
    def do_PUT(self):        
        logging.info(f"Got a PUT request for {self.path}")    
        if authorized_url("PUT", self.path):        
            # build the request that we're going to send to the back end.
            # the galaxysession cookie that we collected earlier needs to
            # be inserted.  We also have to copy the PUT data to the
            # backend.
            jar = requests.cookies.RequestsCookieJar()
            jar['galaxysession'] = galaxy_session
            # read the content coming from the browser          
            data = self.rfile.read(int(self.headers.get('content-length', 0)))
            r = requests.put(f"{base_url}{self.path}", cookies=jar, data=data, headers=self.headers)
            # build the return request.
            self.send_response(r.status_code)            
            for h, v in r.headers.items():
                logging.debug(f"Header: {h} = {v}")
                self.send_header(h, v)
            self.end_headers()
            self.wfile.write(r.content)            
        else:
            unauthorized(self) 

    def do_POST(self):
        # POST is functionally identical to put
        logging.info(f"Got a POST request for {self.path}")    
        if authorized_url("POST", self.path):        
            # build the request that we're going to send to the back end.
            # the galaxysession cookie that we collected earlier needs to
            # be inserted.  We also have to copy the PUT data to the
            # backend.
            jar = requests.cookies.RequestsCookieJar()
            jar['galaxysession'] = galaxy_session
            # read the content coming from the browser          
            data = self.rfile.read(int(self.headers.get('content-length', 0)))
            r = requests.post(f"{base_url}{self.path}", cookies=jar, data=data, headers=self.headers)
            # build the return request.
            self.send_response(r.status_code)            
            for h, v in r.headers.items():
                self.send_header(h, v)
            self.end_headers()
            self.wfile.write(r.content)            
        else:
            unauthorized(self) 
        

    def do_DELETE(self):
        logging.info(f"Got a DELETE request for {self.path}") 
        if(authorized_url("DELETE", self.path)):
            # delete is like get -- there's no content, just a URL
            jar = requests.cookies.RequestsCookieJar()
            jar['galaxysession'] = galaxy_session
            r = requests.get(f"{base_url}{self.path}", cookies=jar)
            self.send_response(r.status_code)
            for h, v in r.headers.items():
                self.send_header(h, v)
            self.end_headers()
            self.wfile.write(r.content)
        else:
            unauthorized(self)

def authorized_url(method, url):
    # make sure that the URL in question is one that the user
    # is allowed to access.  Since I'm not really logging people
    # in for this example, I'm just going to do some pattern 
    # matching.  
    #
    # In a production system one would use logic that denies
    # by default and only allows what is strictly necessary.
    # For this, I'm doing the opposite -- allowing everything
    # except the ability to delete a workflow...
    if method == "DELETE" and url.startswith("/galaxy/api/workflows/"):
        return False
    
    if url.startswith("/galaxy/workflow/editor") and not url.endswith("0a248a1f62a0cc04"):
        return False


    # Allow them by default
    return True

def unauthorized(req):
    "Send back an unauthorized response"
    req.send_response(401, f"You can't use {req.path}")
    req.end_headers()
    req.wfile.write("<html><head><title>NO!</title></head><body><h1>Unauthorized</h1></body></html>".encode('utf-8'))


def backend_login(base_url, username, password):
    "Log in to the back end and return the galaxysession cookie"
    jar = requests.cookies.RequestsCookieJar()
    r = requests.get(f"{base_url}/galaxy/root/login", cookies=jar) # get unauthed cookie
    # find the CSRF token
    m = re.search(r'"session_csrf_token": "(.+?)"', str(r.content, encoding="utf-8")) 
    if not m:
        print("CSRF token not found.")
        exit(1)
    csrf_token = m.group(1)
    login_data = {        
        "login": username,
        "password": password,
        "url": None,
        "messageText": None,
        "messageVariant": None,
        "allowUserCreation": False,
        "redirect": "/",
        "session_csrf_token": csrf_token,
        "enable_oidc": False
    }
    r = requests.post(f"{base_url}/galaxy/user/login", cookies=r.cookies, data=json.dumps(login_data))
    res = r.json()
    if res['message'] != "Success.":
        print(f"Dang it, login didn't work: {res['message']}")
        exit(1)

    return r.cookies['galaxysession']


if __name__ == "__main__":
    main()