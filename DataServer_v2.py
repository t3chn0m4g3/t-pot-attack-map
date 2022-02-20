from elasticsearch import Elasticsearch
import json
import redis
import datetime
import time
import os
import pickle

es = Elasticsearch('http://elasticsearch:9200')
redis_ip = 'map_redis'
redis_instance = None

dst_ip = str(os.getenv('MY_EXTIP'))
dst_lat = os.getenv('MY_EXTIP_LAT')
dst_long = os.getenv('MY_EXTIP_LONG')

event_count = 1
ips_tracked = {}
ports = {}
ip_to_code = {}
countries_to_code = {}
countries_tracked = {}
continent_tracked = {}

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

def connect_redis(redis_ip):
    r = redis.StrictRedis(host=redis_ip, port=6379, db=0)
    return r




def get_honeypot_data():
    processed_data = []
    mydelta=10
    time_last_request = datetime.datetime.utcnow() - datetime.timedelta(seconds=mydelta)
    while True:
        mylast = str(time_last_request).split(" ")
        mynow = str(datetime.datetime.utcnow() - datetime.timedelta(seconds=mydelta)).split(" ")
        ES_query = {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": "type:\"Adbhoney\" OR type:\"Ciscoasa\" OR type:\"CitrixHoneypot\" OR type:\"ConPot\" OR type:\"Cowrie\" OR type:\"Ddospot\" OR type:\"Dicompot\" OR type:\"Dionaea\" OR type:\"ElasticPot\" OR type:\"Endlessh\" OR type:\"Glutton\" OR type:\"Hellpot\" OR type:\"Heralding\" OR type:\"Honeypots\" OR type:\"Honeytrap\" OR type: \"Ipphoney\" OR type:\"Log4pot\" OR type:\"Mailoney\" OR type:\"Medpot\" OR type:\"Redishoneypot\" OR type:\"Tanner\" OR type:\"Wordpot\""
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
    global dst_ip,dst_lat,dst_long
    alert = {}
    #alert["as_org"] = hit["_source"]["geoip"].get("as_org", "")
    # We want the Honeypot name instead of the AS
    alert["as_org"] = hit["_source"]["type"]
    alert["country"] = hit["_source"]["geoip"].get("country_name", "")
    alert["country_code"] = hit["_source"]["geoip"].get("country_code2", "")
    alert["continent_code"] = hit["_source"]["geoip"].get("continent_code", "")
    alert["dst_lat"] = dst_lat
    alert["dst_long"] = dst_long
    alert["dst_ip"] = dst_ip
    alert["event_time"] = str(hit["_source"]["@timestamp"][0:10]) + " " + str(hit["_source"]["@timestamp"][11:19])
    alert["iso_code"] = hit["_source"]["geoip"]["country_code2"]
    alert["latitude"] = hit["_source"]["geoip"]["latitude"]
    alert["longitude"] = hit["_source"]["geoip"]["longitude"]
    if not hit["_source"]["type"] == "":
        #print(hit["_source"]["type"],"Port:",hit["_source"]["dest_port"])
        alert["detect_source"] = hit["_source"]["type"]
        alert["dst_port"] = hit["_source"]["dest_port"]
        alert["protocol"] = port_to_type(hit["_source"]["dest_port"])
        alert["src_ip"] = hit["_source"]["src_ip"]
        alert["src_port"] = hit["_source"]["src_port"]
    else:
        return
    if not alert["src_ip"] == "":
        alert["color"] = service_rgb[alert["protocol"].upper()]
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
            return "OTHER"
    except:
        return "OTHER"




def push(alerts):
    global ips_tracked,continent_tracked,countries_tracked, ip_to_code, ports, event_count, countries_to_code
    redis_instance = connect_redis(redis_ip)
    for alert in alerts:
        ips_tracked[alert["src_ip"]] = ips_tracked.get(alert["src_ip"], 1) + 1
        continent_tracked[alert["continent_code"]] = ips_tracked.get(alert["continent_code"], 1) + 1
        countries_tracked[alert["country"]] = countries_tracked.get(alert["country"], 1) + 1
        ip_to_code[alert["src_ip"]] = alert["iso_code"]
        countries_to_code[alert["country"]] = alert["country_code"]
        ports[alert["dst_port"]] = ports.get(alert["dst_port"], 0)+ 1
        json_data = {
            "protocol": alert["protocol"],
            "color": alert["color"],
            "postal_code": "null",
            "iso_code": alert["iso_code"],
            "continent": "South America",
            "type3": "source:"+alert["detect_source"]+" port: "+str(alert["dst_port"]),
            "type2": alert["dst_port"],
            "city": alert["as_org"],
            "ips_tracked": ips_tracked,
            "src_port": alert["src_port"],
            "event_time": alert["event_time"],
            "src_lat": alert["latitude"],
            "src_ip": alert["src_ip"],
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
            "dst_ip": alert["dst_ip"]
        }
        json_data["ips_tracked"] = ips_tracked
        event_count+=1
        tmp = json.dumps(json_data)
        redis_instance.publish('attack-map-production', tmp)




if __name__ == '__main__':
    try:
        while True:
            try:
                get_honeypot_data()
            except:
                print("Waiting for Elasticsearch ...")
                time.sleep(5)

    except KeyboardInterrupt:
        print('\nSHUTTING DOWN')
        exit()