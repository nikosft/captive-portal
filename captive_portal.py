#!/usr/bin/python
import subprocess
import BaseHTTPServer
import cgi

# These variables are used as settings
PORT       = 9090         # the port in which the captive portal web server listens 
IFACE      = "wlan0"      # the interface that captive portal protects
IP_ADDRESS = "172.16.0.1" # the ip address of the captive portal (it can be the IP of IFACE) 

'''
This it the http server used by the the captive portal
'''
class CaptivePortal(BaseHTTPServer.BaseHTTPRequestHandler):
    #this is the index of the captive portal
    #it simply redirects the user to the to login page
    html_redirect = """
    <html>
    <head>
        <meta http-equiv="refresh" content="0; url=http://%s:%s/login" />
    </head>
    <body>
        <b>Redirecting to login page</b>
    </body>
    </html>
    """%(IP_ADDRESS, PORT)
    #the login page
    html_login = """
    <html>
    <body>
        <b>Login Form</b>
        <form method="POST" action="do_login">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Submit">
        </form>
    </body>
    </html>
    """
    
    '''
    if the user requests the login page show it, else
    use the redirect page
    '''
    def do_GET(self):
        path = self.path
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        if path == "/login":
            self.wfile.write(self.html_login)
        else:
            self.wfile.write(self.html_redirect)
    '''
    this is called when the user submits the login form
    '''
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        form = cgi.FieldStorage(
            fp=self.rfile, 
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
        username = form.getvalue("username")
        password = form.getvalue("password")
        #dummy security check
        if username == 'nikos' and password == 'fotiou':
            #authorized user
            remote_IP = self.client_address[0]
            print('New authorization from '+ remote_IP)
            print('Updating IP tables')
            subprocess.call(["iptables","-t", "nat", "-I", "PREROUTING","1", "-s", remote_IP, "-j" ,"ACCEPT"])
            subprocess.call(["iptables", "-I", "FORWARD", "-s", remote_IP, "-j" ,"ACCEPT"])
            self.wfile.write("You are now authorized. Navigate to any URL")
        else:
            #show the login form
            self.wfile.write(self.html_login)
        
    #the following function makes server produce no output
    #comment it out if you want to print diagnostic messages
    #def log_message(self, format, *args):
    #    return

print("*********************************************")
print("* Note, if there are already iptables rules *")
print("* this script may not work. Flush iptables  *")
print("* at your own risk using iptables -F        *")
print("*********************************************")
print("Updating iptables")
print(".. Allow TCP DNS")
subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", "53", "-j" ,"ACCEPT"])
print(".. Allow UDP DNS")
subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
print(".. Allow traffic to captive portal")
subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-p", "tcp", "--dport", str(PORT),"-d", IP_ADDRESS, "-j" ,"ACCEPT"])
print(".. Block all other traffic")
subprocess.call(["iptables", "-A", "FORWARD", "-i", IFACE, "-j" ,"DROP"])
print("Starting web server")
httpd = BaseHTTPServer.HTTPServer(('', PORT), CaptivePortal)
print("Redirecting HTTP traffic to captive portal")
subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", IFACE, "-p", "tcp", "--dport", "80", "-j" ,"DNAT", "--to-destination", IP_ADDRESS+":"+str(PORT)])

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    pass
httpd.server_close()
