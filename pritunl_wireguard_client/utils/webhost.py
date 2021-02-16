from http.server import BaseHTTPRequestHandler, HTTPServer
import segno


class MyHandler(BaseHTTPRequestHandler):
    """Bacis http app to retriev wireguard config
    """
    def __init__(self, config):
        super().__init__()
        self.wg_config = config
        sefl.qr_template = """
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="utf-8" />
            <title>QR Codes</title>
          </head>
          <body>
            <img src="{:s}"><br>
          </body>
        </html>
        """

    def do_GET(self):
        if not self.path.startswith('/qrcode'):
            self.reject()
            return

        if self.path == '/qrcode':
            self.handle_qr()
            
    def reject(self):
        self.send_response(404)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write('<!DOCTYPE html>')
        self.wfile.write('<html>')
        self.wfile.write('<head><title>Unvailable</title></head>')
        self.wfile.write('<body><p>{} not found</p></body>'.format(self.path))
        self.wfile.write('</html>')

    def handle_qr(self):
        self.send_response(200)
        self.send_header('Content-Type', 'image/png')
        self.end_headers()
        qr_code = segno.make('Hello Moto')
        content = self.qr_template.format(qr_code.png_data_uri())
        self.wfile.write(content)
