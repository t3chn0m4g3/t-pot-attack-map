# T-Pot Attack Map - AI Coding Instructions

## Project Overview
Real-time cyber attack visualization tool for the [T-Pot honeypot system](https://github.com/telekom-security/tpotce). Python backend processes honeypot events from Elasticsearch and streams to a Leaflet/D3.js frontend via WebSocket.

## Architecture & Data Flow
**Producer-Consumer model decoupled by Redis Pub/Sub:**

1. **Data Source**: Elasticsearch with `logstash-*` indices (T-Pot honeypot events)
2. **Producer** ([DataServer.py](../DataServer.py)):
   - Polls Elasticsearch every 0.5s for last 100 events
   - Queries stats every 10s (1m/1h/24h aggregations)
   - Maps ports → protocols via `port_to_type()` function
   - Publishes JSON to Redis channel `attack-map-production`
   - **Synchronous** (`redis.StrictRedis`, blocking operations)
3. **Consumer & Web Server** ([AttackMapServer.py](../AttackMapServer.py)):
   - aiohttp server on port 1234 (configurable via `web_port`)
   - Subscribes to Redis channel, forwards to WebSocket clients
   - Serves static files from `static/` directory
   - **Fully async** (`redis.asyncio`, aiohttp, asyncio)
4. **Frontend** ([static/map.js](../static/map.js), [dashboard.js](../static/dashboard.js)):
   - WebSocket client connects to `/websocket`
   - Leaflet.js map (CartoDB basemaps, dark/light themes)
   - D3.js v7 for animated attack lines and circles
   - IndexedDB cache with LocalStorage fallback (24h retention)

## Critical Developer Patterns

### Dual Configuration Toggle
Connection strings are **hardcoded** with production/local variants:
```python
# Production (inside T-Pot Docker): 
# redis_url = 'redis://map_redis:6379'
# Local development:
redis_url = 'redis://127.0.0.1:6379'
```
**Rule**: Always preserve both configurations. Active config is uncommented, production config is commented out.

### Data: service_rgb Dictionary
**Note**: Protocol-to-color mapping exists only in **DataServer.py**:
- [DataServer.py](../DataServer.py#L30-L85) lines 30-85

**Adding a protocol**:
1. Update `port_to_type()` in DataServer.py
2. Add color to `service_rgb` in DataServer.py

### Async/Sync Boundary
- **AttackMapServer.py**: 100% async (use `await`, `asyncio.create_task`)
- **DataServer.py**: 100% sync (no async/await, uses `time.sleep()`)
- Redis clients are different: `redis.asyncio` vs `redis.StrictRedis`

### Frontend Animation Management
[map.js](../static/map.js) handles D3 animations with visibility checks:
- Global `isPageVisible` flag prevents animation backlog when tab hidden
- `isWakingUp` grace period (1s) suppresses burst on tab resume
- D3 elements cleared on zoom to prevent coordinate desync
- Use `d3.easeCircleIn` for consistent easing

## Data Schema

**WebSocket message types**:
```javascript
{type: "Traffic", ...}  // Individual attack event
{type: "Stats", ...}    // Aggregate statistics (1m/1h/24h)
```

**Attack event fields** (DataServer.py, lines 200-233):
- `src_ip`, `src_lat`, `src_long`, `src_port`, `iso_code`
- `dst_ip`, `dst_lat`, `dst_long`, `dst_port`, `dst_iso_code`
- `protocol`, `color`, `honeypot`, `event_time`, `ip_rep`
- `country`, `continent_code`, `tpot_hostname`

## Environment & Dependencies

**Python setup** (use virtual environment):
```bash
source bin/activate  # Virtual env already exists
pip install -r requirements.txt
```

**Dependencies** ([requirements.txt](../requirements.txt)):
- `aiohttp` (async web server)
- `elasticsearch==8.18.1` (specific version!)
- `redis` (includes asyncio support)
- `pytz`, `tzlocal` (timezone handling)

**Frontend assets** (all local in `static/`):
- Leaflet.js, D3.js v7, Bootstrap 5
- Font Awesome, custom fonts (Inter, JetBrains Mono)
- Flagpack icons in `static/flags/`

## Common Workflows

### Local Development Setup
1. **Start Redis**: `redis-server` (port 6379)
2. **Elasticsearch**: SSH tunnel or local instance on port 64298
   ```bash
   ssh -L 64298:localhost:9200 tpot-server
   ```
3. **Data Server**: `python3 DataServer.py` (terminal 1)
4. **Web Server**: `python3 AttackMapServer.py` (terminal 2)
5. **Access**: http://localhost:1234

### Debugging Data Flow
- **No attacks showing**: Check DataServer.py console for Elasticsearch errors
- **WebSocket disconnects**: Check Redis connection in AttackMapServer.py
- **Protocol showing as OTHER**: Add port mapping in `port_to_type()`

### Theme Development
- HTML `data-theme` attribute toggles dark/light
- Map tiles auto-switch via `mapLayers` object ([map.js](../static/map.js#L37-L51))
- CSS custom properties defined in [index.css](../static/index.css)

## Performance Gotchas
- **Elasticsearch query size**: Limited to 100 events per poll (DataServer.py line 189)
- **Cache limits**: Max 10,000 events in IndexedDB ([dashboard.js](../static/dashboard.js#L14))
- **Animation throttling**: Skip D3 animations when tab hidden (prevents memory bloat)
- **Redis pubsub**: Single channel `attack-map-production`, all clients receive all events
