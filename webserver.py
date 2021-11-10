import http.server
import sockerserver

handler = http.server.SimpleHTTPRequestHandler

with sockerserver.TCPServer((''m 8001), handler) as httpd:
    print('server Listening on port 8001...')
    httpd.serve_forever()
    