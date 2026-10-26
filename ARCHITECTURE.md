# Primadora — Architecture Contract
RULE FOR ALL AI ASSISTANTS: read this first. Never rename files, functions, endpoints,
JSON fields or states below. Only edit the files you were told to edit. Keep code simple:
standard library + packages in requirements.txt only. No databases, no Docker.

## Processes (all local)
cloud_server.py  FastAPI   port 8000  trusted cloud: attestation, decision head, central event log
edge_agent.py    FastAPI   port 8001  simulated edge device: extractor weights, canary thread, attack hooks
app.py           Streamlit port 8501  dashboard; talks to backends ONLY through api_client.py
Every server file ends with: if __name__ == "__main__": uvicorn.run(app, host="127.0.0.1", port=...)

## Files and owners
M1: scanner.py, make_test_files.py, test_scanner.py
M2: split_model.py, attestation.py, train_model.py, cloud_server.py
M3: canary.py, attacks.py, edge_agent.py
M4: config.py, requirements.txt, api_client.py, app.py, ARCHITECTURE.md

## Shared Python functions
scanner.scan_file(path:str)->dict
  {"verdict":"SAFE|SUSPICIOUS|MALICIOUS",
   "findings":[{"pass":1|2,"offset":int,"opcode":str,"detail":str,"severity":"high|medium"}],
   "opcodes_scanned":int,"bytes_scanned":int,
   "opcode_preview":[{"offset":int,"opcode":str,"arg":str}]}   # first 200 opcodes
split_model.EdgeExtractor / split_model.CloudHead   torch nn.Modules: 64 inputs -> 32-dim embedding -> 10 classes
split_model.load_edge_state(path)->state_dict       uses torch.load(weights_only=True)
attestation.compute_weights_hash(state_dict)->hex str   (sha256 over sorted keys + tensor bytes)
attestation.make_quote(key:bytes, nonce:str, weights_hash:str)->hex str   (HMAC-SHA256, simulates a TPM quote)
attestation.verify_quote(key, nonce, weights_hash, signature)->bool
attestation.run_handshake(cloud_url, device_id, key, state_dict)->{"ok":bool,"token":str|None,"reason":str}
canary.load_baseline(path)->dict
canary.check_drift(embed_fn, baseline, threshold)->{"max_drift":float,"per_canary":[float],"passed":bool,"ts":str}
canary.CanaryWorker(get_embed_fn, baseline, interval, threshold, on_result, on_quarantine)  daemon thread, .start() .stop()
attacks.tamper_weights_file(path) / restore_weights_file(path) / bitflip_in_memory(model) / drift_in_memory(model, strength=0.25)

## Data files (train_model.py creates them in models/)
edge_extractor.pt, cloud_head.pt
golden.json    {"device_id","weights_sha256"}
baseline.json  {"inputs":[5 x 64 floats],"embeddings":[5 x 32 floats]}
demo_samples.json  [{"features":[64 floats],"label":int} x 20]

## Cloud API (8000)
GET  /attest/challenge?device_id=  -> {"nonce":str}   (single use, expires in 60s)
POST /attest/verify {"device_id","nonce","weights_hash","signature"} -> {"ok":bool,"token":str|null,"reason":str}
POST /infer {"device_id","token","embedding":[32 floats]} -> {"prediction":int,"confidence":float} or HTTP 403 {"detail":reason}
POST /quarantine {"device_id","reason"} -> {"ok":true}     revokes the token
POST /reset {"device_id"} -> {"ok":true}                   demo reset
GET  /nodes -> {device_id:{"status","reason","last_seen"}}
POST /events {"source","layer","level","message"}   GET /events?limit=50 -> newest first

## Edge API (8001)
GET  /status -> {"device_id","state","attested":bool,"token_present":bool,
                 "last_canary":{"max_drift","threshold","passed","ts"}|null,
                 "drift_history":[last 30 floats],"weights_hash":str}
POST /boot       -> load weights from disk, attest with cloud, start canary worker -> {"ok","state","reason"}
POST /reattest   -> re-hash the CURRENT in-memory weights and re-run the handshake
POST /infer {"sample_index":int} -> {"ok","prediction","confidence","true_label","embedding_preview":[5 floats],"reason"}
POST /attack/{kind}   kind = tamper_file | bitflip_memory | memory_drift -> {"ok","detail"}
POST /attack/reset    restore file, reload, state=OFFLINE, call cloud /reset

## Event record
{"ts":ISO string,"source":"scanner|cloud|edge|dashboard","layer":1-4,"level":"info|warn|critical","message":str}

## States
Edge: OFFLINE, ATTESTING, RUNNING, QUARANTINED, LOCKED_DOWN
Cloud node status: UNKNOWN, TRUSTED, QUARANTINED, REJECTED
# SentinelEdge AI — Architecture Contract
RULE FOR ALL AI ASSISTANTS: read this first. Never rename files, functions, endpoints,
JSON fields or states below. Only edit the files you were told to edit. Keep code simple:
standard library + packages in requirements.txt only. No databases, no Docker.

## Processes (all local)
cloud_server.py  FastAPI   port 8000  trusted cloud: attestation, decision head, central event log
edge_agent.py    FastAPI   port 8001  simulated edge device: extractor weights, canary thread, attack hooks
app.py           Streamlit port 8501  dashboard; talks to backends ONLY through api_client.py
Every server file ends with: if __name__ == "__main__": uvicorn.run(app, host="127.0.0.1", port=...)

## Files and owners
M1: scanner.py, make_test_files.py, test_scanner.py
M2: split_model.py, attestation.py, train_model.py, cloud_server.py
M3: canary.py, attacks.py, edge_agent.py
M4: config.py, requirements.txt, api_client.py, app.py, ARCHITECTURE.md

## Shared Python functions
scanner.scan_file(path:str)->dict
  {"verdict":"SAFE|SUSPICIOUS|MALICIOUS",
   "findings":[{"pass":1|2,"offset":int,"opcode":str,"detail":str,"severity":"high|medium"}],
   "opcodes_scanned":int,"bytes_scanned":int,
   "opcode_preview":[{"offset":int,"opcode":str,"arg":str}]}   # first 200 opcodes
split_model.EdgeExtractor / split_model.CloudHead   torch nn.Modules: 64 inputs -> 32-dim embedding -> 10 classes
split_model.load_edge_state(path)->state_dict       uses torch.load(weights_only=True)
attestation.compute_weights_hash(state_dict)->hex str   (sha256 over sorted keys + tensor bytes)
attestation.make_quote(key:bytes, nonce:str, weights_hash:str)->hex str   (HMAC-SHA256, simulates a TPM quote)
attestation.verify_quote(key, nonce, weights_hash, signature)->bool
attestation.run_handshake(cloud_url, device_id, key, state_dict)->{"ok":bool,"token":str|None,"reason":str}
canary.load_baseline(path)->dict
canary.check_drift(embed_fn, baseline, threshold)->{"max_drift":float,"per_canary":[float],"passed":bool,"ts":str}
canary.CanaryWorker(get_embed_fn, baseline, interval, threshold, on_result, on_quarantine)  daemon thread, .start() .stop()
attacks.tamper_weights_file(path) / restore_weights_file(path) / bitflip_in_memory(model) / drift_in_memory(model, strength=0.25)

## Data files (train_model.py creates them in models/)
edge_extractor.pt, cloud_head.pt
golden.json    {"device_id","weights_sha256"}
baseline.json  {"inputs":[5 x 64 floats],"embeddings":[5 x 32 floats]}
demo_samples.json  [{"features":[64 floats],"label":int} x 20]

## Cloud API (8000)
GET  /attest/challenge?device_id=  -> {"nonce":str}   (single use, expires in 60s)
POST /attest/verify {"device_id","nonce","weights_hash","signature"} -> {"ok":bool,"token":str|null,"reason":str}
POST /infer {"device_id","token","embedding":[32 floats]} -> {"prediction":int,"confidence":float} or HTTP 403 {"detail":reason}
POST /quarantine {"device_id","reason"} -> {"ok":true}     revokes the token
POST /reset {"device_id"} -> {"ok":true}                   demo reset
GET  /nodes -> {device_id:{"status","reason","last_seen"}}
POST /events {"source","layer","level","message"}   GET /events?limit=50 -> newest first

## Edge API (8001)
GET  /status -> {"device_id","state","attested":bool,"token_present":bool,
                 "last_canary":{"max_drift","threshold","passed","ts"}|null,
                 "drift_history":[last 30 floats],"weights_hash":str}
POST /boot       -> load weights from disk, attest with cloud, start canary worker -> {"ok","state","reason"}
POST /reattest   -> re-hash the CURRENT in-memory weights and re-run the handshake
POST /infer {"sample_index":int} -> {"ok","prediction","confidence","true_label","embedding_preview":[5 floats],"reason"}
POST /attack/{kind}   kind = tamper_file | bitflip_memory | memory_drift -> {"ok","detail"}
POST /attack/reset    restore file, reload, state=OFFLINE, call cloud /reset

## Event record
{"ts":ISO string,"source":"scanner|cloud|edge|dashboard","layer":1-4,"level":"info|warn|critical","message":str}

## States
Edge: OFFLINE, ATTESTING, RUNNING, QUARANTINED, LOCKED_DOWN
Cloud node status: UNKNOWN, TRUSTED, QUARANTINED, REJECTED
