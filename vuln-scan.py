#!/usr/bin/python
import os
import json
import redis

# product, packageName
# (version), lessThanOrEqual

keys_metadata = ["cveId", "dateUpdated"]
keys_affected = ["packageName", "product", "versions"]
keys_details = ["descriptions", "value"]


class CveDescr():
    def __init__(self, data):
        j = json.loads(data)
        self.cve = {}
        try:
            self.cve["cveId"] = j["cveMetadata"]["cveId"]
            self.cve["dateUpdated"] = j["cveMetadata"]["dateUpdated"]
            if "packageName" in j["containers"]["cna"]["affected"][0].keys():
                self.cve["product"] = j["containers"]["cna"]["affected"][0]["packageName"]
            else:
                self.cve["product"] = j["containers"]["cna"]["affected"][0]["product"]
            # todo : multiple versions
            self.cve["versions"] = j["containers"]["cna"]["affected"][0]["versions"][0]["version"]
            self.cve["descriptions"] = j["containers"]["cna"]["descriptions"][0]["value"]

        except:
            print("Key {} not found.".format(k))

class RedisConn():
    def __init__(self):
        self.conn = redis.Redis()
        self.stream = "CVES"

    def load_data(self, data):
        self.conn.xadd(self.stream, data.cve)

def generate_index(path, conn):
    try:
        for year in os.listdir("./cves"):
            for cvex in os.listdir("./cves/" + year):
                for file in os.listdir("./cves/" + year + '/' + cvex):
                    d = CveDescr(file)
                    conn.load_data(d)
    except:
        pass

conn = RedisConn()
generate_index("/home/zyx/src/vuln-scan/", conn)



            

