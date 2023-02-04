#!/usr/bin/python3

"""
Original code (tornado based) by Matthew May - mcmay.web@gmail.com
Adjusted code for asyncio, aiohttp and aioredis by t3chn0m4g3
"""


from aiohttp import web
import asyncio
import aioredis
import json
import logging


# Within T-Pot: redis_url = 'redis://map_redis:6379'
# redis_url = 'redis://127.0.0.1:6379'
# web_port = 1234
redis_url = 'redis://map_redis:6379'
web_port = 64299
version = 'Attack Map Server 1.2.0'


# Color Codes for Attack Map
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
    'SIP': '#ffccff',
    'ADB': '#ffcccc',
    'OTHER': '#ffffff'
}


async def redis_subscriber(websockets):
    # Create a Redis connection
    redis = await aioredis.from_url(redis_url)
    # Get the pubsub object for channel subscription
    pubsub = redis.pubsub()
    # Subscribe to a Redis channel
    channel = "attack-map-production"
    await pubsub.subscribe(channel)
    print("Redis connection established.")
    # Start a loop to listen for messages on the channel
    async with redis.pubsub() as pubsub:
        await pubsub.subscribe(channel)
        while True:
            try:
                msg = await pubsub.get_message(ignore_subscribe_messages=True)
                if msg is not None:
                    try:
                        # Only take the data and forward as JSON to the connected websocket clients
                        json_data = json.dumps(json.loads(msg['data']))
                        # print(json_data)
                        # Process all connected websockets in parallel
                        await asyncio.gather(*[ws.send_str(json_data) for ws in websockets])
                    except:
                        print("Something went wrong while sending JSON data.")
                else:
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                print("Cancelled.")
                break


async def my_websocket_handler(request):
    # Get the WebSocket object
    ws = web.WebSocketResponse()
    # Accept the WebSocket connection
    await ws.prepare(request)
    # Add the WebSocket to the list of websockets
    request.app['websockets'].append(ws)
    print(f"New WebSocket connection opened. Clients active: {len(request.app['websockets'])}")
    # Start a loop to listen for messages
    async for msg in ws:
        if msg == aiohttp.WSMsgType.TEXT:
            # Send the message back to the client
            await ws.send_str(msg)
        elif msg == aiohttp.WSMsgType.ERROR:
            print('WebSocket connection closed with exception %s' % ws.exception())
    # Remove the WebSocket from the list of websockets
    request.app['websockets'].remove(ws)
    print(f"Existing WebSocket connection closed. Clients active: {len(request.app['websockets'])}")
    return ws


# Serve index.html as static file
async def my_index_handler(request):
    return web.FileResponse('index.html')


async def start_background_tasks(app):
    # Create an empty list to store WebSocket objects
    app['websockets'] = []
    # Start the Redis subscriber task
    app['redis_subscriber'] = asyncio.create_task(
        redis_subscriber(app['websockets'])
    )


async def cleanup_background_tasks(app):
    # Cancel the Redis subscriber task
    app['redis_subscriber'].cancel()
    # Wait for the Redis subscriber task to finish
    await app['redis_subscriber']


async def make_webapp():
    app = web.Application()
    # logging.basicConfig(level=logging.INFO)
    app.add_routes([
        web.get('/', my_index_handler),
        web.get('/websocket', my_websocket_handler),
        web.static('/static/', 'static'),
        web.static('/images/', 'static/images'),
        web.static('/flags/', 'static/flags')
    ])
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)
    return app


if __name__ == '__main__':
    print(version)
    web.run_app(make_webapp(), port=web_port)
