import subprocess, json, os, threading, queue, uuid, time
from flask import Flask, request, Response, render_template_string, jsonify

app = Flask(__name__)

# scan_id -> {"q": Queue, "done": bool, "result": dict}
JOBS = {}

def map_path(path):
    p = path.replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        p = "/host/" + p[2:].lstrip("/")
    elif not p.startswith("/host"):
        p = "/host/" + p.lstrip("/")
    return p

def run_scan(scan_id, target):
    job = JOBS[scan_id]
    q = job["q"]
    try:
        proc = subprocess.Popen(
            ["semgrep", "scan", "--config", "auto", "--json", target],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        out_lines = []
        # semgrep envoie sa progression sur stderr
        for line in proc.stderr:
            line = line.rstrip()
            if line:
                q.put(("log", line))
        for line in proc.stdout:
            out_lines.append(line)
        proc.wait()
        data = json.loads("".join(out_lines) or "{}")
        results, counts = [], {"ERROR": 0, "WARNING": 0, "INFO": 0}
        for r in data.get("results", []):
            sev = r.get("extra", {}).get("severity", "INFO")
            if sev not in counts:
                sev = "INFO"
            counts[sev] += 1
            results.append({
                "severity": sev,
                "file": r.get("path", "?"),
                "line": r.get("start", {}).get("line", "?"),
                "message": r.get("extra", {}).get("message", ""),
                "check_id": r.get("check_id", ""),
                "code": (r.get("extra", {}).get("lines", "") or "").strip()[:500],
            })
        order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
        results.sort(key=lambda x: order[x["severity"]])
        job["result"] = {"results": results, "counts": counts, "error": None}
    except Exception as e:
        job["result"] = {"results": [], "counts": {"ERROR":0,"WARNING":0,"INFO":0}, "error": str(e)}
    q.put(("done", None))
    job["done"] = True

@app.route("/")
def index():
    return render_template_string(PAGE)

@app.route("/start", methods=["POST"])
def start():
    path = (request.json.get("path") or "").strip()
    target = map_path(path)
    if not os.path.isdir(target):
        return jsonify({"error": "Dossier introuvable: " + path + " (cherche sur F:\\)"}), 400
    scan_id = uuid.uuid4().hex
    JOBS[scan_id] = {"q": queue.Queue(), "done": False, "result": None}
    threading.Thread(target=run_scan, args=(scan_id, target), daemon=True).start()
    return jsonify({"scan_id": scan_id})

@app.route("/stream/<scan_id>")
def stream(scan_id):
    job = JOBS.get(scan_id)
    if not job:
        return "no job", 404
    def gen():
        q = job["q"]
        while True:
            try:
                kind, payload = q.get(timeout=30)
            except queue.Empty:
                yield ": ping\n\n"
                continue
            if kind == "log":
                yield "event: log\ndata: " + json.dumps(payload) + "\n\n"
            elif kind == "done":
                yield "event: done\ndata: " + json.dumps(job["result"]) + "\n\n"
                break
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

PAGE = r"""
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Semgrep Scan</title>
<style>
 :root{color-scheme:light dark}
 @media (prefers-color-scheme: dark){:root{
   --bg:#0d1117;--card:#161b22;--bd:#30363d;--tx:#e6edf3;--mut:#8b949e;--in:#0d1117}}
 @media (prefers-color-scheme: light){:root{
   --bg:#f6f8fa;--card:#fff;--bd:#d0d7de;--tx:#1f2328;--mut:#656d76;--in:#fff}}
 :root{--hi:#f85149;--med:#d29922;--lo:#3fb950;--acc:#2f81f7}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--tx);
   font:15px/1.5 system-ui,Segoe UI,sans-serif;min-height:100vh;
   display:flex;flex-direction:column;align-items:center;justify-content:flex-start;padding:24px}
 .wrap{width:100%;max-width:1000px}
 /* etat initial: form centre verticalement */
 body.idle{justify-content:center}
 body.idle .wrap{max-width:560px}
 h1{font-size:22px;margin:0 0 20px;text-align:center}
 form{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
 input[type=text]{flex:1;min-width:240px;background:var(--in);border:1px solid var(--bd);
   color:var(--tx);padding:12px 14px;border-radius:10px;font:inherit}
 button{background:var(--acc);color:#fff;border:0;padding:12px 24px;border-radius:10px;
   font:inherit;font-weight:600;cursor:pointer}
 button:disabled{opacity:.55;cursor:default}
 /* progression */
 #prog{display:none;background:var(--card);border:1px solid var(--bd);border-radius:12px;
   padding:16px;margin-bottom:20px}
 #prog.on{display:block}
 .bar{height:6px;background:var(--bd);border-radius:99px;overflow:hidden;margin-bottom:12px}
 .bar>i{display:block;height:100%;width:30%;background:var(--acc);border-radius:99px;
   animation:slide 1.1s ease-in-out infinite}
 @keyframes slide{0%{margin-left:-30%}100%{margin-left:100%}}
 #log{font:12px/1.5 ui-monospace,monospace;color:var(--mut);max-height:160px;
   overflow:auto;white-space:pre-wrap}
 #log div{padding:1px 0}
 .stat{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}
 .pill{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:8px 16px}
 .pill b{font-size:18px}
 .f{background:var(--card);border:1px solid var(--bd);border-left-width:4px;
   border-radius:10px;padding:12px 14px;margin-bottom:10px}
 .f.ERROR{border-left-color:var(--hi)}.f.WARNING{border-left-color:var(--med)}
 .f.INFO{border-left-color:var(--lo)}
 .sev{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
 .ERROR .sev{color:var(--hi)}.WARNING .sev{color:var(--med)}.INFO .sev{color:var(--lo)}
 .loc{color:var(--mut);font-size:13px;font-family:ui-monospace,monospace;margin:4px 0}
 .rid{color:var(--mut);font-size:12px}
 pre{background:var(--in);border:1px solid var(--bd);border-radius:8px;padding:8px;
   overflow:auto;font-size:12px;margin:6px 0 0}
 .err{color:var(--hi);margin-bottom:16px}
 .empty{color:var(--mut);padding:24px;text-align:center}
</style></head><body class="idle"><div class="wrap">
<h1>&#128737; Semgrep Scan</h1>
<form id="frm">
  <input type="text" id="path" placeholder="Chemin dossier (ex: F:\monprojet)" required autofocus>
  <button type="submit" id="btn">Scanner</button>
</form>
<div id="prog"><div class="bar"><i></i></div><div id="log"></div></div>
<div id="err" class="err" style="display:none"></div>
<div id="out"></div>
</div>
<script>
const frm=document.getElementById('frm'),btn=document.getElementById('btn'),
 prog=document.getElementById('prog'),logEl=document.getElementById('log'),
 out=document.getElementById('out'),errEl=document.getElementById('err'),body=document.body;

function esc(s){return (s+'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}

frm.addEventListener('submit',async e=>{
 e.preventDefault();
 const path=document.getElementById('path').value.trim(); if(!path)return;
 btn.disabled=true; body.classList.remove('idle');
 out.innerHTML=''; errEl.style.display='none'; logEl.innerHTML='';
 prog.classList.add('on');
 let r;
 try{ r=await fetch('/start',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({path})}); }catch(x){ fail(x); return; }
 if(!r.ok){ const d=await r.json(); fail(d.error||'erreur'); return; }
 const {scan_id}=await r.json();
 const es=new EventSource('/stream/'+scan_id);
 es.addEventListener('log',ev=>{
   const line=JSON.parse(ev.data);
   const d=document.createElement('div'); d.textContent=line; logEl.appendChild(d);
   logEl.scrollTop=logEl.scrollHeight;
 });
 es.addEventListener('done',ev=>{ es.close(); render(JSON.parse(ev.data)); });
 es.onerror=()=>{ es.close(); };
});

function fail(msg){ prog.classList.remove('on'); btn.disabled=false;
 errEl.textContent='Erreur: '+msg; errEl.style.display='block'; }

function render(d){
 prog.classList.remove('on'); btn.disabled=false;
 if(d.error){ errEl.textContent='Erreur: '+d.error; errEl.style.display='block'; return; }
 const c=d.counts, n=d.results.length;
 let h='<div class="stat">'+
  '<div class="pill"><b>'+n+'</b> findings</div>'+
  '<div class="pill" style="color:var(--hi)"><b>'+c.ERROR+'</b> critiques</div>'+
  '<div class="pill" style="color:var(--med)"><b>'+c.WARNING+'</b> moyens</div>'+
  '<div class="pill" style="color:var(--lo)"><b>'+c.INFO+'</b> infos</div></div>';
 if(!n){ h+='<div class="empty">Aucune vulnerabilite trouvee. &#9989;</div>'; }
 for(const r of d.results){
  h+='<div class="f '+r.severity+'"><span class="sev">'+r.severity+'</span>'+
   '<div class="loc">'+esc(r.file)+':'+r.line+'</div>'+
   '<div>'+esc(r.message)+'</div>'+
   '<div class="rid">'+esc(r.check_id)+'</div>'+
   (r.code?'<pre>'+esc(r.code)+'</pre>':'')+'</div>';
 }
 out.innerHTML=h;
}
</script></body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
