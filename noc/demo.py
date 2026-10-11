"""Initialize TWO synthetic customer sites for the Acer lab. Never contacts networks."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from .store import NocStore

def private_json(path,value):
    path=Path(path)
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,"w") as out:
        json.dump(value,out,indent=2)
        out.write("\n")

def seed(db,endpoint="http://127.0.0.1:8788"):
    db=Path(db)
    store=NocStore(db)
    with store.db() as c:
        if c.execute("SELECT count(*) FROM customers").fetchone()[0]:
            raise RuntimeError("Refusing to seed a non-empty NOC database")
    def make_customer(customer_label,agent_name):
        cid=store.customer(customer_label)
        sid=store.site(cid,"Main Branch")
        asset=store.asset(sid,"WAN Router","192.168.1.1")
        check=store.check(asset,"WAN availability","shared-upstream")
        agent=store.enroll(sid,agent_name)
        cfg=db.parent/("noc-demo-"+agent_name.lower().replace(" ","-")+".json")
        private_json(cfg,{"endpoint":endpoint,"credential":agent["credential"],"check_ids":[check]})
        return agent,check,cfg
    a,check_a,config_a=make_customer("DEMO — Gros Islet Business","Edge Alpha")
    b,check_b,config_b=make_customer("DEMO — Castries Office","Edge Bravo")
    store.ingest(a["credential"],{"sequence":1,"readings":[
        {"check_id":check_a,"ok":False,"note":"SIMULATED connection failed"}]})
    store.ingest(a["credential"],{"sequence":2,"readings":[
        {"check_id":check_a,"ok":False,"note":"SIMULATED repeated failure"}]})
    store.ingest(b["credential"],{"sequence":1,"readings":[
        {"check_id":check_b,"ok":True,"note":"SIMULATED normal operation"}]})
    return {"customers":2,"sites":2,"assets":2,"agents":2,"open_incidents":1,
            "credential_files":[config_a.name,config_b.name]}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--db",required=True)
    args=p.parse_args()
    result=seed(args.db)
    print(json.dumps(result,indent=2))
if __name__=="__main__":main()
