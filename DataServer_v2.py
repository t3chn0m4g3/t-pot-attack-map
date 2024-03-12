import datetime
import json
import time
import os
import pytz
import redis
from elasticsearch import Elasticsearch, exceptions as es_exceptions
from tzlocal import get_localzone

# Within T-Pot: es = Elasticsearch('http://elasticsearch:9200') and redis_ip = 'map_redis'
# es = Elasticsearch('http://127.0.0.1:64298')
# redis_ip = '127.0.0.1'
es = Elasticsearch('http://elasticsearch:9200')
redis_ip = 'map_redis'
redis_instance = None
redis_channel = 'attack-map-production'
version = 'Data Server 2.2.0'
local_tz = get_localzone()
output_text = os.getenv("TPOT_ATTACKMAP_TEXT")

event_count = 1
ips_tracked = {}
ports = {}
ip_to_code = {}
countries_to_code = {}
countries_tracked = {}
continent_tracked = {}

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


def connect_redis(redis_ip):
    r = redis.StrictRedis(host=redis_ip, port=6379, db=0)
    return r


def push_honeypot_stats(honeypot_stats):
    redis_instance = connect_redis(redis_ip)
    tmp = json.dumps(honeypot_stats)
    # print(tmp)
    redis_instance.publish(redis_channel, tmp)


def get_honeypot_stats(timedelta):
    ES_query_stats = {
        "bool": {
            "must": [],
            "filter": [
                {
                    "bool": {
                        "should": [
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Adbhoney"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Ciscoasa"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "CitrixHoneypot"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "ConPot"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Cowrie"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Ddospot"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Dicompot"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Dionaea"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "ElasticPot"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Endlessh"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Glutton"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Hellpot"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Heralding"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Honeytrap"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Honeypots"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Log4pot"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Ipphoney"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Mailoney"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Medpot"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Redishoneypot"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Sentrypeer"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Tanner"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            },
                            {
                                "bool": {
                                    "should": [
                                        {
                                            "match_phrase": {
                                                "type.keyword": "Wordpot"
                                            }
                                        }
                                    ],
                                    "minimum_should_match": 1
                                }
                            }
                        ],
                        "minimum_should_match": 1
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "format": "strict_date_optional_time",
                            "gte": "now-" + timedelta,
                            "lte": "now"
                        }
                    }
                }
            ]
        }
    }
    return ES_query_stats


def update_honeypot_data():
    processed_data = []
    last = {"1m", "1h", "24h"}
    mydelta = 10
    time_last_request = datetime.datetime.utcnow() - datetime.timedelta(seconds=mydelta)
    while True:
        now=(datetime.datetime.utcnow())
        # Get the honeypot stats every 10s (last 1m, 1h, 24h)
        if now.second%10 == 0 and now.microsecond < 500000:
            honeypot_stats = {}
            for i in last:
                try:
                    es_honeypot_stats = es.search(index="logstash-*", aggs={}, size=0, track_total_hits=True, query=get_honeypot_stats(i))
                    honeypot_stats.update({"last_"+i: es_honeypot_stats['hits']['total']['value']})
                except Exception as e:
                    print(e)
            honeypot_stats.update({"type": "Stats"})
            push_honeypot_stats(honeypot_stats)

        # Get the last 100 new honeypot events every 0.5s
        mylast = str(time_last_request).split(" ")
        mynow = str(datetime.datetime.utcnow() - datetime.timedelta(seconds=mydelta)).split(" ")
        ES_query = {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "type:\"Adbhoney\" OR type:\"Ciscoasa\" OR type:\"CitrixHoneypot\" OR type:\"ConPot\" OR type:\"Cowrie\" OR type:\"Ddospot\" OR type:\"Dicompot\" OR type:\"Dionaea\" OR type:\"ElasticPot\" OR type:\"Endlessh\" OR type:\"Glutton\" OR type:\"Hellpot\" OR type:\"Heralding\" OR type:\"Honeypots\" OR type:\"Honeytrap\" OR type: \"Ipphoney\" OR type:\"Log4pot\" OR type:\"Mailoney\" OR type:\"Medpot\" OR type:\"Redishoneypot\" OR type:\"Sentrypeer\" OR type:\"Tanner\" OR type:\"Wordpot\""
                        }
                    }
                ],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": mylast[0] + "T" + mylast[1],
                                "lte": mynow[0] + "T" + mynow[1]
                            }
                        }
                    }
                ]
            }
        }

        res = es.search(index="logstash-*", size=100, query=ES_query)
        hits = res['hits']
        if len(hits['hits']) != 0:
            time_last_request = datetime.datetime.utcnow() - datetime.timedelta(seconds=mydelta)
            for hit in hits['hits']:
                try:
                    process_datas = process_data(hit)
                    if process_datas != None:
                        processed_data.append(process_datas)
                except:
                    pass
        if len(processed_data) != 0:
            push(processed_data)
            processed_data = []
        time.sleep(0.5)


def process_data(hit):
#    global dst_ip, dst_lat, dst_long
    alert = {}
    alert["honeypot"] = hit["_source"]["type"]
    alert["country"] = hit["_source"]["geoip"].get("country_name", "")
    alert["country_code"] = hit["_source"]["geoip"].get("country_code2", "")
    alert["continent_code"] = hit["_source"]["geoip"].get("continent_code", "")
    alert["dst_lat"] = hit["_source"]["geoip_ext"]["latitude"]
    alert["dst_long"] = hit["_source"]["geoip_ext"]["longitude"]
    alert["dst_ip"] = hit["_source"]["geoip_ext"]["ip"]
    alert["dst_iso_code"] = hit["_source"]["geoip_ext"].get("country_code2", "")
    alert["dst_country_name"] = hit["_source"]["geoip_ext"].get("country_name", "")
    alert["tpot_hostname"] = hit["_source"]["t-pot_hostname"]
    alert["event_time"] = str(hit["_source"]["@timestamp"][0:10]) + " " + str(hit["_source"]["@timestamp"][11:19])
    alert["iso_code"] = hit["_source"]["geoip"]["country_code2"]
    alert["latitude"] = hit["_source"]["geoip"]["latitude"]
    alert["longitude"] = hit["_source"]["geoip"]["longitude"]
    alert["dst_port"] = hit["_source"]["dest_port"]
    alert["protocol"] = port_to_type(hit["_source"]["dest_port"])
    alert["src_ip"] = hit["_source"]["src_ip"]
    try:
        alert["src_port"] = hit["_source"]["src_port"]
    except:
        alert["src_port"] = 0
    try:
        alert["ip_rep"] = hit["_source"]["ip_rep"]
    except:
        alert["ip_rep"] = "reputation unknown"
    if not alert["src_ip"] == "":
        try:
            alert["color"] = service_rgb[alert["protocol"].upper()]
        except:
            alert["color"] = service_rgb["OTHER"]
        return alert
    else:
        print("SRC IP EMPTY")


def port_to_type(port):
    port = int(port)
    try:
        if port == 21 or port == 20:
            return "FTP"
        if port == 22 or port == 2222:
            return "SSH"
        if port == 23 or port == 2223:
            return "TELNET"
        if port == 25 or port == 143 or port == 110 or port == 993 or port == 995:
            return "EMAIL"
        if port == 53:
            return "DNS"
        if port == 80 or port == 81 or port == 8080:
            return "HTTP"
        if port == 161:
            return "SNMP"
        if port == 443 or port == 8443:
            return "HTTPS"
        if port == 445:
            return "SMB"
        if port == 1433 or port == 1521 or port == 3306:
            return "SQL"
        if port == 2575 or port == 11112:
            return "MEDICAL"
        if port == 5900:
            return "VNC"
        if port == 3389:
            return "RDP"
        if port == 5060 or port == 5061:
            return "SIP"
        if port == 5555:
            return "ADB"
        else:
            return str(port)
    except:
        return "OTHER"


def push(alerts):
    global ips_tracked, continent_tracked, countries_tracked, ip_to_code, ports, event_count, countries_to_code

    redis_instance = connect_redis(redis_ip)

    for alert in alerts:
        ips_tracked[alert["src_ip"]] = ips_tracked.get(alert["src_ip"], 1) + 1
        continent_tracked[alert["continent_code"]] = ips_tracked.get(alert["continent_code"], 1) + 1
        countries_tracked[alert["country"]] = countries_tracked.get(alert["country"], 1) + 1
        ip_to_code[alert["src_ip"]] = alert["iso_code"]
        countries_to_code[alert["country"]] = alert["country_code"]
        ports[alert["dst_port"]] = ports.get(alert["dst_port"], 0) + 1

        if output_text == "ENABLED":
            # Convert UTC to local time
            my_time = datetime.datetime.strptime(alert["event_time"], "%Y-%m-%d %H:%M:%S")
            my_time = my_time.replace(tzinfo=pytz.UTC)  # Assuming event_time is in UTC
            local_event_time = my_time.astimezone(local_tz)
            local_event_time = local_event_time.strftime("%Y-%m-%d %H:%M:%S")

            # Build the table data
            table_data = [
                [local_event_time, alert["country"], alert["src_ip"], alert["ip_rep"].title(),
                 alert["protocol"], alert["honeypot"], alert["tpot_hostname"]]
            ]

            # Define the minimum width for each column
            min_widths = [19, 20, 15, 18, 10, 14, 14]

            # Format and print each line with aligned columns
            for row in table_data:
                formatted_line = " | ".join(
                    "{:<{width}}".format(str(value), width=min_widths[i]) for i, value in enumerate(row))
                print(formatted_line)

        json_data = {
            "protocol": alert["protocol"],
            "color": alert["color"],
            "iso_code": alert["iso_code"],
            "honeypot": alert["honeypot"],
            "ips_tracked": ips_tracked,
            "src_port": alert["src_port"],
            "event_time": alert["event_time"],
            "src_lat": alert["latitude"],
            "src_ip": alert["src_ip"],
            "ip_rep": alert["ip_rep"].title(),
            "continents_tracked": continent_tracked,
            "type": "Traffic",
            "country_to_code": countries_to_code,
            "dst_long": alert["dst_long"],
            "continent_code": alert["continent_code"],
            "dst_lat": alert["dst_lat"],
            "ip_to_code": ip_to_code,
            "countries_tracked": countries_tracked,
            "event_count": event_count,
            "country": alert["country"],
            "src_long": alert["longitude"],
            "unknowns": {
            },
            "dst_port": alert["dst_port"],
            "dst_ip": alert["dst_ip"],
            "dst_iso_code": alert["dst_iso_code"],
            "dst_country_name": alert["dst_country_name"],
            "tpot_hostname": alert["tpot_hostname"]
        }
        json_data["ips_tracked"] = ips_tracked
        event_count += 1
        tmp = json.dumps(json_data)
        redis_instance.publish(redis_channel, tmp)


if __name__ == '__main__':
    print(version)
    try:
        while True:
            try:
                update_honeypot_data()
            except Exception as e:
                if "6379" in str(e):
                    print("[ ] Waiting for Redis ...")
                if "urllib3.connection" in str(e):
                    print("[ ] Waiting for Elasticsearch ...")
                    time.sleep(5)

    except KeyboardInterrupt:
        print('\nSHUTTING DOWN')
        exit()
