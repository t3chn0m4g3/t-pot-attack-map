#!/usr/bin/python3

"""
AUTHOR: Matthew May - mcmay.web@gmail.com
"""

# Imports
import json
import redis
import tornadoredis
import tornado.ioloop
import tornado.web
import tornado.websocket

from os import getuid, path
from sys import exit

# Look up service colors
service_rgb = {
    'FTP': '#ff0000',
    'SSH': '#ff8000',
    'TELNET': '#ffff00',
    'EMAIL': '#80ff00',
    'SQL': '#00ff00',
    'DNS': '#00ff80',
    'HTTP': '#00ffff',
    'HTTPS': '#0080ff',
    'VNC': '#0000ff',
    'SNMP': '#8000ff',
    'SMB': '#bf00ff',
    'MEDICAL': '#ff00ff',
    'RDP': '#ff0060',
    'SIP': '#ff0000',
    'ADB': '#ffcccc',
    'OTHER': '#ffffff'
}


class IndexHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(request):
        request.render('index.html')


class WebSocketChatHandler(tornado.websocket.WebSocketHandler):
    def __init__(self, *args, **kwargs):
        super(WebSocketChatHandler, self).__init__(*args, **kwargs)
        self.listen()

    def check_origin(self, origin):
        return True

    @tornado.gen.engine
    def listen(self):

        print('[*] WebSocketChatHandler opened')

        try:
            # This is the IP address of the DataServer
            self.client = tornadoredis.Client('map_redis')
            self.client.connect()
            print('[*] Connected to Redis server')
            yield tornado.gen.Task(self.client.subscribe, 'attack-map-production')
            self.client.listen(self.on_message)
        except Exception as ex:
            print('[*] Could not connect to Redis server.')
            print('[*] {}'.format(str(ex)))

    def on_close(self):
        print('[*] Closing connection.')

    # This function is called everytime a Redis message is received
    def on_message(self, msg):
        try:
            json_data = json.loads(msg.body)
        except Exception as ex:
            print("json error")
            print(msg.body)
            return None
        
        self.write_message(json.dumps(json_data))


def main():
    # Register handler pages
    handlers = [
        (r'/websocket', WebSocketChatHandler),
        (r'/static/(.*)', tornado.web.StaticFileHandler, {'path': 'static'}),
        (r'/flags/(.*)', tornado.web.StaticFileHandler, {'path': 'static/flags'}),
        (r'/', IndexHandler),
        (r'/tv(.*)', tornado.web.StaticFileHandler, {'path': 'tv.html'})
    ]

    # Define the static path
    # static_path = path.join( path.dirname(__file__), 'static' )

    # Define static settings
    settings = {
        # 'static_path': static_path
    }

    # Create and start app listening on port 8888
    try:
        app = tornado.web.Application(handlers, **settings)
        app.listen(64299)
        print('[*] Waiting on browser connections...')
        tornado.ioloop.IOLoop.instance().start()
    except Exception as appFail:
        print(appFail)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nSHUTTING DOWN')
        exit()
