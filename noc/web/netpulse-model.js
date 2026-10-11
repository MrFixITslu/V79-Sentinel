"use strict";
/* Shared browser/Node model. No network calls; imported evidence is never persisted. */
(function(root){
 const text=(v,max=200)=>typeof v==="string"?v.slice(0,max):"";
 function normalize(data){
  if(data?.format!=="v79-netpulse-investigation-v1"||!Array.isArray(data.analysis?.packets)||data.analysis.packets.length>3000)throw Error("Expected a NetPulse investigation with at most 3,000 frames.");
  const packets=data.analysis.packets.map(p=>{
   if(!p||typeof p!=="object"||typeof p.protocol!=="string"||typeof p.source!=="string"||typeof p.destination!=="string"||!Number.isInteger(p.number)||p.number<0||!Number.isFinite(p.lengthBytes)||p.lengthBytes<0||p.lengthBytes>16777216)throw Error("Invalid packet fields; previous evidence remains unchanged.");
   const port=x=>Number.isInteger(x)&&x>=0&&x<=65535?x:null;
   return {number:p.number,timestamp:Number.isFinite(p.timestamp)?p.timestamp:null,lengthBytes:p.lengthBytes,protocol:text(p.protocol,40),source:text(p.source,100),destination:text(p.destination,100),sourceMac:text(p.sourceMac,32),destinationMac:text(p.destinationMac,32),sourcePort:port(p.sourcePort),destinationPort:port(p.destinationPort),tcpSyn:p.tcpSyn===true,tcpAck:p.tcpAck===true,tcpRetransmission:p.tcpRetransmission===true,dnsQuery:text(p.dnsQuery,253)||null,tlsServerName:text(p.tlsServerName,253)||null};
  });
  return {format:data.format,savedAt:text(data.savedAt,50),analysis:{source:text(data.analysis.source,160),provenance:text(data.analysis.provenance,200),limit:3000,packets}};
 }
 function summarize(packets){
  const endpoints=new Map(),flows=new Map(),domains=new Map();let totalBytes=0,retransmissions=0;
  for(const p of packets){
   totalBytes+=p.lengthBytes;if(p.tcpRetransmission)retransmissions++;
   for(const address of [p.source,p.destination].filter(Boolean)){const e=endpoints.get(address)||{address,frames:0,bytes:0};e.frames++;e.bytes+=p.lengthBytes;endpoints.set(address,e);}
   const ends=[p.source,p.destination].sort(),key=JSON.stringify(ends),f=flows.get(key)||{a:ends[0],b:ends[1],frames:0,bytes:0,protocols:new Set()};f.frames++;f.bytes+=p.lengthBytes;f.protocols.add(p.protocol);flows.set(key,f);
   const name=p.tlsServerName||p.dnsQuery;if(name){const source=p.tlsServerName?"TLS hostname":"DNS message",key=JSON.stringify([p.source,name,source]),d=domains.get(key)||{address:p.source,name,source,count:0,timestamp:p.timestamp};d.count++;if(p.timestamp!==null)d.timestamp=p.timestamp;domains.set(key,d);}
  }
  return {totalBytes,retransmissions,endpoints:[...endpoints.values()].sort((a,b)=>b.bytes-a.bytes),flows:[...flows.values()].sort((a,b)=>b.bytes-a.bytes).map(f=>({...f,protocols:[...f.protocols]})),domains:[...domains.values()]};
 }
 function explain(p){
  if(p.dnsQuery)return "A DNS message mentions "+p.dnsQuery+". It may be a query or response and does not prove someone opened a webpage.";
  if(p.tcpRetransmission)return "TShark flagged a possible retransmission. Loss, reordering or capture conditions may explain it; one flag does not prove a fault.";
  if(p.tcpSyn&&!p.tcpAck)return "This is a TCP connection attempt. A SYN alone does not prove the connection completed.";
  if(["TLS","QUIC"].includes(p.protocol.toUpperCase()))return "Encrypted traffic was observed. Page contents, messages and passwords are not visible here.";
  if(p.protocol.toUpperCase()==="ARP")return "Local address-resolution traffic. This can help correlate network addresses, but does not prove a device owner.";
  return "A recorded "+p.protocol+" frame between these addresses. A protocol or port alone cannot prove which application or person produced it.";
 }
 function review(plan){
  if(!Array.isArray(plan?.devices)||!Array.isArray(plan.links)||plan.devices.length>500||plan.links.length>1000)throw Error("Invalid design or size limit exceeded.");
  if(!plan.devices.every(d=>typeof d.id==="string"&&typeof d.name==="string"&&typeof d.kind==="string"&&typeof d.address==="string")||!plan.links.every(l=>typeof l.id==="string"&&typeof l.from==="string"&&typeof l.to==="string"&&typeof l.capacityMbps==="string"))throw Error("Invalid design fields.");
  const notes=[],ids=new Set(plan.devices.map(d=>d.id));
  for(const [field,label] of [["id","identifiers"],["name","names"],["address","addresses"]]){const vals=plan.devices.map(d=>d[field].trim().toLowerCase()).filter(Boolean);if(new Set(vals).size!==vals.length)notes.push("Duplicate device "+label+"; confirm the intended identity.");}
  const seen=new Set();for(const l of plan.links){const key=JSON.stringify([l.from,l.to].sort());if(seen.has(key))notes.push("Duplicate link between the same endpoints.");seen.add(key);if(l.from===l.to||!ids.has(l.from)||!ids.has(l.to))notes.push("A link has an invalid endpoint.");if(l.capacityMbps&&(!Number.isFinite(Number(l.capacityMbps))||Number(l.capacityMbps)<=0))notes.push("Link capacity must be a positive Mbps value.");}
  return [...new Set(notes)];
 }
 const api={normalize,summarize,explain,review};if(typeof module!=="undefined"&&module.exports)module.exports=api;else root.NetPulseModel=Object.freeze(api);
})(typeof window!=="undefined"?window:globalThis);
