from elasticsearch import Elasticsearch
from flask import Flask, render_template
import json
import redis
import datetime
import time
import pickle
import tornado.ioloop
import tornado.web
import tornado.websocket

app = Flask(__name__)
es = Elasticsearch('elasticsearch:64298')
#es2 = Elasticsearch('snorlax.true.nl:9200')
redis_ip = 'map_redis'
redis_instance = None

dst_ip = "87.233.192.218"
dst_lat = 52.305610
dst_long = 4.932533
event_count = 1
ips_tracked = {}
ports = {}
ip_to_code = {}
countries_tracked = {}
continent_tracked = {}

service_rgb = {
    'FTP': '#ff0000',
    'SSH': '#ff8000',
    'TELNET': '#ffff00',
    'EMAIL': '#80ff00',
    'WHOIS': '#00ff00',
    'DNS': '#00ff80',
    'HTTP': '#00ffff',
    'HTTPS': '#0080ff',
    'VNC': '#0000ff',
    'SNMP': '#8000ff',
    'SMB': '#bf00ff',
    'AUTH': '#ff00ff',
    'RDP': '#ff0060',
    'SIP': '#ff0000',
    'ICMP': '#ffcccc',
    'OTHER': '#6600cc'
}

def connect_redis(redis_ip):
    r = redis.StrictRedis(host=redis_ip, port=6379, db=0)
    return r




def get_honeypot_data():
    anti_dedup = []
    processed_data = []
    banned_src = ["8.8.8.8","87.233.192.218"]
    time_last_request = datetime.datetime.utcnow()
    while True:
        tmp = str(time_last_request).split(" ")
        ES_query = {"query": {
            "bool": {
                "must": {
                    "range": {
                        "@timestamp": {
                            "gte": tmp[0] + "T" + tmp[1]
                        }
                    }
                }
            }
        }
        }

        res = es.search(index="logstash-*", size=100, body=ES_query)
#        res2 = es2.search(index="logstash-*", size=100, body=ES_query)
#        print res2
        hits = res['hits']
#        hits.update(res2['hits'])


        #print str(datetime.datetime.now() - time_last_request) + " Got ES1 "+ str(res['hits']['total']) #+ "and ES2 "+ str(res2['hits']['total']) + " Hits:"
        if len(hits['hits']) != 0:
            time_last_request = datetime.datetime.utcnow()
            for hit in hits['hits']:
                try:
                    #print json.dumps(hit)
                    if not (hit["_id"] in anti_dedup or hit["_source"]["src_ip"] in banned_src):
                        process_datas = process_data(hit)
                        if process_datas != None:
                            processed_data.append(process_datas)
                except:
                    pass

        if len(processed_data) != 0:
            push(processed_data)
            processed_data = []


        time.sleep(1)
        #exit()



def process_data(hit):
    global dst_ip,dst_lat,dst_long
    alert = {}
    alert["as_org"] = hit["_source"]["geoip"].get("as_org", "")
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

    #print hit["_source"]["type"]
    # if hit["_source"]["type"] == "NGINX":
    #     alert["src_ip"] == ""


    # if hit["_source"]["type"] == "Cowrie":
    #     alert["detect_source"]  = "Cowrie"
    #     alert["dst_port"]       = "unknown"
    #     alert["msg_type"]       = hit["_source"]["message"]
    #     alert["protocol"]       = "OTHER"
    #     alert["src_ip"]         = hit["_source"]["src_ip"]
    #     alert["src_port"]       = "0"
    #     if "SSH" in hit["_source"]["message"] or ":2222" in hit["_source"]["message"] or ":22" in hit["_source"]["message"] or "SSH" in hit["_source"]["system"]:
    #         alert["dst_port"] = 22
    #         alert["protocol"] = "SSH"
    #     if "Telnet" in hit["_source"]["system"]:
    #         alert["dst_port"] = 23
    #         alert["protocol"] = "Telnet"
    #     if alert["dst_port"] == "unknown":
    #         print "unknown"
    #         print hit
    #         time.sleep(5)
    #
    # elif hit["_source"]["type"] == "Glastopf":
    #     alert["detect_source"]  = "Glastopf"
    #     alert["dst_port"]       = hit["_source"]["dest_port"]
    #     alert["msg_type"]       = hit["_source"]["message"]
    #     alert["protocol"]       = port_to_type(hit["_source"]["dest_port"])
    #     alert["src_ip"]         = hit["_source"]["src_ip"]
    #     alert["src_port"]       = "0"
    # elif hit["_source"]["type"] == "Dionaea":
    #     alert["detect_source"]  = "Dionaea"
    #     alert["dst_port"]       = hit["_source"]["dest_port"]
    #     alert["msg_type"]       = str(hit["_source"]["connection"]["protocol"]) + str(hit["_source"]["connection"]["type"])
    #     alert["protocol"]       = port_to_type(hit["_source"]["dest_port"])
    #     #alert["protocol"]       = str(hit["_source"]["connection"]["protocol"]) + ""
    #     alert["src_ip"]         = hit["_source"]["src_ip"]
    #     alert["src_port"]       = "0"
    # elif hit["_source"]["type"] == "Honeytrap":
    #     alert["detect_source"]  = "Honeytrap"
    #     alert["dst_port"]       = hit["_source"]["dest_port"]
    #     alert["msg_type"]       = hit["_source"].get("payload", 1)
    #     alert["protocol"]       = port_to_type(hit["_source"]["dest_port"])
    #     alert["src_ip"]         = hit["_source"]["src_ip"]
    #     alert["src_port"]       = "0"
    # elif hit["_source"]["type"] == "Vnclowpot":
    #     alert["detect_source"]  = "Vnclowpot"
    #     alert["dst_port"]       = hit["_source"]["dest_port"]
    #     alert["msg_type"]       = hit["_source"].get("payload", 1)
    #     alert["protocol"]       = port_to_type(hit["_source"]["dest_port"])
    #     alert["src_ip"]         = hit["_source"]["src_ip"]
    #     alert["src_port"]       = hit["_source"]["src_port"]
    # elif hit["_source"]["type"] == "Rdpy":
    #     alert["detect_source"]  = "Rdpy"
    #     alert["dst_port"]       = hit["_source"]["dest_port"]
    #     alert["msg_type"]       = hit["_source"].get("message", 1)
    #     alert["protocol"]       = port_to_type(hit["_source"]["dest_port"])
    #     alert["src_ip"]         = hit["_source"]["src_ip"]
    #     alert["src_port"]       = hit["_source"]["src_port"]
    # elif hit["_source"]["type"] == "Heralding":
    #     print json.dumps(hit)
    #     alert["detect_source"] = "Heralding"
    #     alert["dst_port"] = hit["_source"]["dest_port"]
    #     alert["msg_type"] = hit["_source"].get("message", 1)
    #     alert["protocol"] = port_to_type(hit["_source"]["dest_port"])
    #     alert["src_ip"] = hit["_source"]["src_ip"]
    #     alert["src_port"] = hit["_source"]["src_port"]
    # elif hit["_source"]["type"] == "log":
    #     pass
    print(hit["_source"]["type"])
    if hit["_source"]["type"] == "Mailoney":
        alert["detect_source"] = "Mailoney"
        alert["dst_port"] = hit["_source"]["dest_port"]
        alert["msg_type"] = hit["_source"].get("message", 1)
        alert["protocol"] = port_to_type(hit["_source"]["dest_port"])
        alert["src_ip"] = hit["_source"]["src_ip"]
        alert["src_port"] = hit["_source"]["src_port"]
    elif hit["_source"]["type"] == "Heralding":
        alert["detect_source"] = "Heralding"
        alert["dst_port"] = hit["_source"]["dest_port"]
        alert["msg_type"] = hit["_source"].get("ip_rep", 1)
        alert["protocol"] = port_to_type(hit["_source"]["dest_port"])
        print(alert["protocol"],hit["_source"]["dest_port"])
        alert["src_ip"] = hit["_source"]["src_ip"]
        alert["src_port"] = hit["_source"]["src_port"]
    elif hit["_source"]["type"] == "Rdpy":
        alert["detect_source"] = "Rdpy"
        alert["dst_port"] = hit["_source"]["dest_port"]
        alert["msg_type"] = hit["_source"].get("message", 1)
        alert["protocol"] = port_to_type(hit["_source"]["dest_port"])
        alert["src_ip"] = hit["_source"]["src_ip"]
        alert["src_port"] = hit["_source"]["src_port"]

    elif hit["_source"]["type"] == "Tanner":
        alert["detect_source"] = "Tanner"
        alert["dst_port"] = hit["_source"]["dest_port"]
        alert["msg_type"] = hit["_source"]["path"]
        alert["protocol"] = port_to_type(hit["_source"]["dest_port"])
        alert["src_ip"] = hit["_source"]["src_ip"]
        alert["src_port"] = hit["_source"]["src_port"]
    elif hit["_source"]["type"] == "Honeypy":
        alert["detect_source"] = "Honeypy"
        alert["dst_port"] = hit["_source"]["dest_port"]
        alert["msg_type"] = hit["_source"]["dest_port"]
        alert["protocol"] = port_to_type(hit["_source"]["dest_port"])
        alert["src_ip"] = hit["_source"]["src_ip"]
        alert["src_port"] = "0"
    elif hit["_source"]["type"] == "Cowrie":
        try:
            if hit["_source"]["dest_port"] == 23 or hit["_source"]["dest_port"] == 2323:
                alert["dst_port"] = 23
                alert["protocol"] = "TELNET"

            elif "SSH" in hit["_source"]["message"] or ":2222" in hit["_source"]["message"] or ":22" in hit["_source"]["message"] or "SSH" in hit["_source"]["system"]:
                alert["dst_port"] = 22
                alert["protocol"] = "SSH"
            alert["detect_source"]  = "Cowrie"
            alert["src_port"] = "0"
            alert["msg_type"]       = hit["_source"].get("message", 1)
            alert["src_ip"]         = hit["_source"]["src_ip"]
        except:

            pass
            #print json.dumps(hit)




    elif hit["_source"]["type"] == "Dionaea":
        alert["detect_source"] = "Dionaea"
        alert["dst_port"] = hit["_source"]["dest_port"]
        alert["msg_type"] = hit["_source"].get("message", 1)
        alert["protocol"] = port_to_type(hit["_source"]["dest_port"])
        alert["src_ip"] = hit["_source"]["src_ip"]
        alert["src_port"] = hit["_source"]["src_port"]
    else:
        print("no type matched", json.dumps(hit))
        #time.sleep(5)
        #time.sleep(5)
#        print hit
        return

    if not alert["src_ip"] == "":
        alert["color"] = service_rgb[alert["protocol"].upper()]

        return alert
    else:
        print("SRC IP EMPTY")


def port_to_type(port):
    port = int(port)
    try:
        if port == 80 or port == 8080:
            return "HTTP"
        if port == 21:
            return "FTP"
        if port == 22 :
            return "SSH"
        if port == 23 or port == 2223:
            return "TELNET"
        if port == 25 or port == 143 or port == 110 or port == 993 or port == 995:
            return "EMAIL"
        if port == 53:
            return "DNS"
        if port == 443 or port == 4443 or port == 8443:
            return "HTTPS"
        if port == 5900:
            return "VNC"
        if port == 161 or port == 1900:
            return "SNMP"
        if port == 445:
            return "SMB"
        if port == 3389: #or port == 5900:
            return "RDP"
        if port == 5060: #or port == 5900:
            return "SIP"
        else:
            return "OTHER"
    except:
        return "OTHER"


def push(alerts):
    global ips_tracked,continent_tracked,countries_tracked, ip_to_code, ports, event_count
    redis_instance = connect_redis(redis_ip)

    for alert in alerts:

        ips_tracked[alert["src_ip"]] = ips_tracked.get(alert["src_ip"], 1) + 1
        continent_tracked[alert["continent_code"]] = ips_tracked.get(alert["continent_code"], 1) + 1
        countries_tracked[alert["country"]] = countries_tracked.get(alert["country"], 1) + 1
        ip_to_code[alert["src_ip"]] = alert["iso_code"]
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
            "ips_tracked": {
                "170.246.70.172": 1
            },
            "src_port": alert["src_port"],
            "event_time": alert["event_time"],
            "src_lat": alert["latitude"],
            "src_ip": alert["src_ip"],
            "continents_tracked": {
                "Europe": 30
            },
            "type": "Traffic",
            "country_to_code": {
                "Brazil": "BR"
            },
            "dst_long": alert["dst_long"],
            "continent_code": "SA",
            "dst_lat": alert["dst_lat"],
            "ip_to_code": {
                "170.246.70.172": "BR"
            },
            "countries_tracked": {
                "Brazil": 25
            },
            "event_count": event_count,
            "country": alert["country"],
            "src_long": alert["longitude"],
            "unknowns": {

            },
            "dst_port": alert["dst_port"],
            "dst_ip": "172.23.0.2"
        }

        json_data["ips_tracked"] = ips_tracked
        event_count+=1
        json_data["ip_to_code"] = ip_to_code
        #json_data["continents_tracked"] = continent_tracked
        json_data["countries_tracked"] = countries_tracked
        tmp = json.dumps(json_data)
        time.sleep(0.2)
        #print tmp
        redis_instance.publish('attack-map-production', tmp)





if __name__ == '__main__':
    try:
        while True:

#            get_honeypot_data()
            try:
                get_honeypot_data()
            except:
                print("failed")
                time.sleep(5)

    except KeyboardInterrupt:
        print('\nSHUTTING DOWN')
        exit()

