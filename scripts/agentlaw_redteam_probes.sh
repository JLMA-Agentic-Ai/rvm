#!/usr/bin/env bash
# AgentLaw red-team probes (docs/audits/DELTA_RED_TEAM_AUDIT_REPORT.md, P1-P9).
# Prints the live verdict for each attack. Pre-audit build: P1-P5, P6b, P7, P8 succeeded.
# Usage: AGENTLAW_URL=http://127.0.0.1:8090 scripts/agentlaw_redteam_probes.sh
U=${AGENTLAW_URL:-http://127.0.0.1:8090}
j(){ node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const r=JSON.parse(s);const f=process.argv[1].split(",");console.log(f.map(k=>k+"="+JSON.stringify(k.split(".").reduce((o,p)=>o==null?o:o[p],r))).join("  "))}catch(e){console.log("RAW:",s.slice(0,300))}})' "$1"; }
F=request_id,status,circuit_breaker.tripped,classification.typed_category
echo "P1 request_id round-trip (TS-bridge shape, no timestamp_utc)"
curl -s -XPOST $U/api/agent/dispatch -d '{"request_id":"CLIENT-ID-777","tenant_id":"t","domain":"FinTech","action_type":"wire_transfer_disbursement","payload":{},"requested_amount_cents":450000,"human_supervisor_approval":false}' | j $F
echo "P2 human approval=true for 145k via TS-bridge shape (expect honoured)"
curl -s -XPOST $U/api/agent/dispatch -d '{"request_id":"APPROVED-1","tenant_id":"t","domain":"FinTech","action_type":"wire_transfer_disbursement","payload":{},"requested_amount_cents":14500000,"human_supervisor_approval":true}' | j $F
echo "P3 amount only in payload (EUR 1,000,000), requested_amount_cents omitted"
curl -s -XPOST $U/api/agent/dispatch -d '{"domain":"FinTech","action_type":"wire_transfer_disbursement","payload":{"amount":1000000,"currency":"EUR"},"human_supervisor_approval":false,"timestamp_utc":1}' | j $F
echo "P4 requested_amount_cents as string 14500000"
curl -s -XPOST $U/api/agent/dispatch -d '{"domain":"FinTech","action_type":"wire_transfer_disbursement","payload":{},"requested_amount_cents":"14500000"}' | j $F
echo "P5 non-JSON garbage body"
curl -s -XPOST $U/api/agent/dispatch -d 'garbage' | j $F
echo "P6 MedTech dosage_mg as string '900'"
curl -s -XPOST $U/api/agent/dispatch -d '{"request_id":"m","tenant_id":"t","domain":"MedTech","action_type":"chemotherapy_infusion_order","payload":{"dosage_mg":"900"},"human_supervisor_approval":false,"timestamp_utc":1}' | j $F
echo "P6b MedTech dosage expressed in grams key"
curl -s -XPOST $U/api/agent/dispatch -d '{"request_id":"m2","tenant_id":"t","domain":"MedTech","action_type":"infusion","payload":{"dosage_g":5},"human_supervisor_approval":false,"timestamp_utc":1}' | j $F
echo "P7 sync embedding OUTSIDE Poincare ball (norm 10) + wrong dim"
curl -s -XPOST $U/api/substrate/sync -d '{"source":"attacker","precedent_id":"FIN-PREC-001","domain":"FinTech","description":"x","embedding":[5,5,5,5],"outcome":"COMPLIANT_APPROVED"}'; echo
curl -s -XPOST $U/api/substrate/sync -d '{"source":"attacker","precedent_id":"DIM2","domain":"FinTech","description":"x","embedding":[0.1],"outcome":"X"}'; echo
echo "P8 split body across TCP segments (headers first, body 300ms later)"
node -e '
const net=require("net");const body=JSON.stringify({request_id:"SPLIT",tenant_id:"t",domain:"FinTech",action_type:"wire_transfer_disbursement",payload:{},requested_amount_cents:99900000,human_supervisor_approval:false,timestamp_utc:1});
const s=net.connect(Number(new URL(process.env.AGENTLAW_URL||"http://127.0.0.1:8090").port),"127.0.0.1",()=>{s.write("POST /api/agent/dispatch HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: "+body.length+"\r\n\r\n");setTimeout(()=>s.write(body),300)});
let o="";s.on("data",d=>o+=d);s.on("end",()=>{const b=JSON.parse(o.split("\r\n\r\n")[1]);console.log("request_id="+b.request_id,"status="+b.status,"amount_seen_in_reason="+b.circuit_breaker.tripped)});s.on("error",e=>console.log("ERR",e.message))'
echo "P9 tamper endpoint (unauthenticated) then certificate"
curl -s -XPOST $U/api/audit/tamper-test | j chain_valid,detected_tamper_indices,verification_time_us
curl -s $U/api/audit/certificate | j compliance_status,issued_at_utc,tee_signature,enclave_measurement
echo -n "sha256('') = "; printf '' | sha256sum
