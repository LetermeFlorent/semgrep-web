import subprocess, json, os, threading, queue, uuid, time
from flask import Flask, request, Response, render_template_string, jsonify

app = Flask(__name__)

# scan_id -> {"q": Queue, "done": bool, "result": dict}
JOBS = {}

def map_path(path):
    # "W:\security\stv" -> /host/w/security/stv  (chaque disque monte sous /host/<lettre>)
    p = path.replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        p = "/host/" + p[0].lower() + "/" + p[2:].lstrip("/")
    elif not p.startswith("/host"):
        p = "/host/" + p.lstrip("/")
    return p

CODE_EXT = {".py",".js",".jsx",".ts",".tsx",".java",".go",".rb",".php",".c",".h",
    ".cpp",".cc",".cs",".rs",".kt",".swift",".scala",".sh",".bash",".pl",".lua",
    ".vue",".html",".yaml",".yml",".json",".tf",".dockerfile",".sql",".m",".r"}
SKIP_DIR = {"node_modules",".git","venv",".venv","__pycache__","dist","build",
    "vendor",".next","target",".idea",".vscode","site-packages"}
CHUNK = 25

def list_targets(root):
    files = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIR and not d.startswith(".")]
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext in CODE_EXT or fn.lower() in ("dockerfile",):
                files.append(os.path.join(dp, fn))
    return files

def parse_results(data, results, counts):
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    new = []
    for r in data.get("results", []):
        sev = r.get("extra", {}).get("severity", "INFO")
        if sev not in counts:
            sev = "INFO"
        counts[sev] += 1
        item = {
            "severity": sev,
            "file": r.get("path", "?"),
            "line": r.get("start", {}).get("line", "?"),
            "message": r.get("extra", {}).get("message", ""),
            "check_id": r.get("check_id", ""),
            "code": (r.get("extra", {}).get("lines", "") or "").strip()[:500],
        }
        results.append(item)
        new.append(item)
    return new

def run_scan(scan_id, target):
    job = JOBS[scan_id]
    q = job["q"]
    results, counts = [], {"ERROR": 0, "WARNING": 0, "INFO": 0}
    try:
        q.put(("log", "Recensement des fichiers..."))
        targets = list_targets(target)
        total = len(targets)
        if total == 0:
            q.put(("log", "Aucun fichier de code trouve."))
            q.put(("progress", {"pct": 100, "done": 0, "total": 0,
                                 "counts": counts, "new": []}))
        else:
            q.put(("log", f"{total} fichiers a scanner."))
            done = 0
            for i in range(0, total, CHUNK):
                chunk = targets[i:i+CHUNK]
                proc = subprocess.run(
                    ["semgrep", "scan", "--config", "auto", "--json", "--quiet",
                     "--no-git-ignore", *chunk],
                    capture_output=True, text=True, timeout=600
                )
                try:
                    data = json.loads(proc.stdout or "{}")
                except Exception:
                    data = {}
                new = parse_results(data, results, counts)
                done += len(chunk)
                pct = round(done * 100 / total)
                q.put(("progress", {"pct": pct, "done": done, "total": total,
                                    "counts": dict(counts), "new": new}))
        order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
        results.sort(key=lambda x: order[x["severity"]])
        job["result"] = {"results": results, "counts": counts, "error": None}
    except Exception as e:
        job["result"] = {"results": results, "counts": counts, "error": str(e)}
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
        return jsonify({"error": "Dossier introuvable: " + path + " (disques montes: F:\\ et W:\\)"}), 400
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
            elif kind == "progress":
                yield "event: progress\ndata: " + json.dumps(payload) + "\n\n"
            elif kind == "done":
                yield "event: done\ndata: " + json.dumps(job["result"]) + "\n\n"
                break
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

PAGE = r"""
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>STV &middot; Semgrep Scanner</title>
<style>
 :root{color-scheme:light dark}
 @media (prefers-color-scheme: dark){:root{
   --bg:#0a0c10;--panel:#0f131a;--card:#161b22;--bd:#232a35;--bd2:#2f3846;
   --tx:#e6edf3;--mut:#8b949e;--in:#0b0e13;--glow:rgba(47,129,247,.15)}}
 @media (prefers-color-scheme: light){:root{
   --bg:#f0f2f5;--panel:#fff;--card:#fff;--bd:#e1e4e8;--bd2:#d0d7de;
   --tx:#1f2328;--mut:#656d76;--in:#f6f8fa;--glow:rgba(47,129,247,.1)}}
 :root{--hi:#f85149;--med:#d29922;--lo:#3fb950;--acc:#2f81f7;--acc2:#58a6ff}
 *{box-sizing:border-box}
 html,body{height:100%}
 body{margin:0;background:var(--bg);color:var(--tx);
   font:14px/1.55 -apple-system,system-ui,Segoe UI,Roboto,sans-serif;
   display:grid;grid-template-rows:auto 1fr;height:100vh;overflow:hidden}
 /* topbar */
 .top{display:flex;align-items:center;gap:12px;padding:14px 22px;
   background:var(--panel);border-bottom:1px solid var(--bd)}
 .logo{font-size:18px;font-weight:700;letter-spacing:-.3px;display:flex;align-items:center;gap:9px}
 .logo .dot{width:10px;height:10px;border-radius:50%;background:var(--acc);
   box-shadow:0 0 10px var(--acc)}
 .top .sub{color:var(--mut);font-size:12.5px}
 .top .spacer{flex:1}
 .badge{font-size:11.5px;color:var(--mut);border:1px solid var(--bd);border-radius:20px;
   padding:4px 11px}
 /* layout */
 .app{display:grid;grid-template-columns:340px 1fr;height:100%;overflow:hidden}
 .side{background:var(--panel);border-right:1px solid var(--bd);padding:22px;
   overflow-y:auto;display:flex;flex-direction:column;gap:20px}
 .main{overflow-y:auto;padding:24px 30px}
 .main .inner{max-width:1400px;margin:0 auto}
 /* form */
 label{font-size:12px;font-weight:600;color:var(--mut);text-transform:uppercase;
   letter-spacing:.6px;display:block;margin-bottom:8px}
 .field{display:flex;flex-direction:column;gap:10px}
 input[type=text]{background:var(--in);border:1px solid var(--bd2);color:var(--tx);
   padding:12px 14px;border-radius:10px;font:inherit;width:100%;transition:border .15s,box-shadow .15s}
 input[type=text]:focus{outline:0;border-color:var(--acc);box-shadow:0 0 0 3px var(--glow)}
 button{background:var(--acc);color:#fff;border:0;padding:12px 18px;border-radius:10px;
   font:inherit;font-weight:600;cursor:pointer;width:100%;transition:filter .15s}
 button:hover:not(:disabled){filter:brightness(1.1)}
 button:disabled{opacity:.5;cursor:default}
 .hint{font-size:12px;color:var(--mut)}
 /* progress */
 .prog{display:none;flex-direction:column;gap:10px;background:var(--card);
   border:1px solid var(--bd);border-radius:14px;padding:16px}
 .prog.on{display:flex}
 .phead{display:flex;justify-content:space-between;align-items:baseline}
 .phead .pct{font-size:24px;font-weight:700;font-variant-numeric:tabular-nums}
 .phead .lbl{font-size:12px;color:var(--mut)}
 .bar{height:8px;background:var(--in);border-radius:99px;overflow:hidden}
 .bar>i{display:block;height:100%;width:0;border-radius:99px;
   background:linear-gradient(90deg,var(--acc),var(--acc2));transition:width .3s ease}
 #log{font:11.5px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--mut);
   max-height:120px;overflow:auto;white-space:pre-wrap;
   background:var(--in);border-radius:8px;padding:8px 10px}
 #log:empty{display:none}
 #log div{padding:.5px 0}
 /* stat cards */
 .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
 .stat{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:16px 18px}
 .stat .n{font-size:30px;font-weight:700;line-height:1;font-variant-numeric:tabular-nums}
 .stat .k{font-size:12px;color:var(--mut);margin-top:6px;text-transform:uppercase;letter-spacing:.5px}
 .stat.c-hi{border-top:3px solid var(--hi)} .stat.c-hi .n{color:var(--hi)}
 .stat.c-med{border-top:3px solid var(--med)} .stat.c-med .n{color:var(--med)}
 .stat.c-lo{border-top:3px solid var(--lo)} .stat.c-lo .n{color:var(--lo)}
 .stat.c-all{border-top:3px solid var(--acc)}
 /* findings */
 .f{background:var(--card);border:1px solid var(--bd);border-left-width:4px;
   border-radius:12px;padding:14px 16px;margin-bottom:12px;
   animation:pop .25s ease}
 @keyframes pop{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
 .f.ERROR{border-left-color:var(--hi)}.f.WARNING{border-left-color:var(--med)}
 .f.INFO{border-left-color:var(--lo)}
 .frow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
 .sev{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;
   padding:3px 9px;border-radius:6px}
 .ERROR .sev{color:var(--hi);background:rgba(248,81,73,.12)}
 .WARNING .sev{color:var(--med);background:rgba(210,153,34,.12)}
 .INFO .sev{color:var(--lo);background:rgba(63,185,80,.12)}
 .loc{color:var(--tx);font-size:13px;font-family:ui-monospace,monospace}
 .loc .ln{color:var(--acc2)}
 .msg{margin:8px 0 0;color:var(--tx)}
 .rid{color:var(--mut);font-size:11.5px;margin-top:6px;font-family:ui-monospace,monospace}
 pre{background:var(--in);border:1px solid var(--bd);border-radius:8px;padding:10px 12px;
   overflow:auto;font:12px/1.5 ui-monospace,monospace;margin:10px 0 0}
 .err{color:var(--hi);background:rgba(248,81,73,.1);border:1px solid var(--hi);
   border-radius:12px;padding:14px 16px;margin-bottom:16px}
 .empty{color:var(--mut);padding:60px 20px;text-align:center;font-size:15px}
 .empty .big{font-size:48px;margin-bottom:12px}
 .welcome{color:var(--mut);padding:80px 20px;text-align:center}
 .welcome .big{font-size:56px;margin-bottom:16px;opacity:.5}
 .welcome h2{color:var(--tx);font-weight:600;margin:0 0 8px}
 @media(max-width:820px){.app{grid-template-columns:1fr}
   .side{border-right:0;border-bottom:1px solid var(--bd)}
   .stats{grid-template-columns:repeat(2,1fr)}}
 /* onglets */
 .tabs{display:flex;align-items:center;gap:4px;padding:0 14px;background:var(--panel);
   border-bottom:1px solid var(--bd);overflow-x:auto}
 .tab{display:flex;align-items:center;gap:8px;padding:10px 14px;cursor:pointer;
   border-bottom:2px solid transparent;color:var(--mut);font-size:13px;white-space:nowrap;
   max-width:240px}
 .tab:hover{color:var(--tx)}
 .tab.active{color:var(--tx);border-bottom-color:var(--acc)}
 .tab .tname{overflow:hidden;text-overflow:ellipsis}
 .tab .tdot{width:8px;height:8px;border-radius:50%;flex:0 0 auto}
 .tab .tdot.run{background:var(--acc);animation:pulse 1s infinite}
 .tab .tdot.done{background:var(--lo)}
 .tab .tdot.err{background:var(--hi)}
 @keyframes pulse{50%{opacity:.3}}
 .tab .x{opacity:.5;font-size:15px;line-height:1;padding:0 2px;border-radius:4px}
 .tab .x:hover{opacity:1;background:var(--bd)}
 .tab.newtab{color:var(--acc);font-weight:600}
 .view{display:none}.view.active{display:block}
</style></head><body>
<div class="top">
  <div class="logo"><span class="dot"></span>STV</div>
  <span class="sub">Semgrep Security Scanner</span>
  <div class="spacer"></div>
  <span class="badge">F:\ &middot; W:\ montes (lecture seule)</span>
</div>
<div class="tabs" id="tabs"></div>
<div class="app">
  <aside class="side">
    <form id="frm" class="field">
      <div>
        <label for="path">Dossier a scanner</label>
        <input type="text" id="path" placeholder="F:\monprojet" required autofocus>
      </div>
      <button type="submit" id="btn">Lancer un nouveau scan</button>
      <div class="hint">Chaque scan ouvre un onglet. Ignore node_modules, .git, venv&hellip;</div>
    </form>
  </aside>
  <main class="main"><div class="inner" id="views">
    <div id="welcome" class="welcome"><div class="big">&#128737;</div>
      <h2>Pret a scanner</h2><div>Entre un chemin de dossier et lance le scan.<br>
      Tu peux lancer plusieurs scans en parallele &mdash; chacun a son onglet.</div></div>
  </div></main>
</div>
<script>
const $=id=>document.getElementById(id);
const frm=$('frm'),tabsEl=$('tabs'),viewsEl=$('views'),welcome=$('welcome');
let TABS=[], active=null, seq=0;

function esc(s){return (s+'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function base(p){const s=p.replace(/[\\/]+$/,'').split(/[\\/]/);return s[s.length-1]||p;}
function fcard(r){return '<div class="f '+r.severity+'">'+
   '<div class="frow"><span class="sev">'+r.severity+'</span>'+
   '<span class="loc">'+esc(r.file)+':<span class="ln">'+r.line+'</span></span></div>'+
   '<div class="msg">'+esc(r.message)+'</div>'+
   '<div class="rid">'+esc(r.check_id)+'</div>'+
   (r.code?'<pre>'+esc(r.code)+'</pre>':'')+'</div>';}
function statCards(c){const n=c.ERROR+c.WARNING+c.INFO;return '<div class="stats">'+
   '<div class="stat c-all"><div class="n">'+n+'</div><div class="k">Total</div></div>'+
   '<div class="stat c-hi"><div class="n">'+c.ERROR+'</div><div class="k">Critiques</div></div>'+
   '<div class="stat c-med"><div class="n">'+c.WARNING+'</div><div class="k">Moyens</div></div>'+
   '<div class="stat c-lo"><div class="n">'+c.INFO+'</div><div class="k">Infos</div></div></div>';}

function renderTabs(){
 tabsEl.innerHTML='';
 for(const t of TABS){
   const el=document.createElement('div');
   el.className='tab'+(t.id===active?' active':'');
   el.innerHTML='<span class="tdot '+t.status+'"></span>'+
     '<span class="tname">'+esc(t.name)+'</span><span class="x">&times;</span>';
   el.querySelector('.tname').onclick=()=>select(t.id);
   el.querySelector('.tdot').onclick=()=>select(t.id);
   el.querySelector('.x').onclick=e=>{e.stopPropagation();closeTab(t.id);};
   tabsEl.appendChild(el);
 }
}
function select(id){active=id;
 for(const t of TABS) t.view.classList.toggle('active',t.id===id);
 renderTabs();
}
function closeTab(id){
 const t=TABS.find(x=>x.id===id); if(!t)return;
 if(t.es) t.es.close(); t.view.remove();
 TABS=TABS.filter(x=>x.id!==id);
 if(active===id) active=TABS.length?TABS[TABS.length-1].id:null;
 if(active) select(active);
 renderTabs();
 if(!TABS.length) welcome.style.display='';
}

function newView(name){
 const v=document.createElement('div'); v.className='view';
 v.innerHTML=
  '<div class="prog on"><div class="phead"><span class="pct">0%</span>'+
   '<span class="lbl">Preparation&hellip;</span></div>'+
   '<div class="bar"><i></i></div><div class="log"></div></div>'+
  '<div class="err" style="display:none"></div>'+
  '<div class="stats-wrap"></div><div class="live"></div><div class="out"></div>';
 viewsEl.appendChild(v);
 return v;
}

frm.addEventListener('submit',async e=>{
 e.preventDefault();
 const path=$('path').value.trim(); if(!path)return;
 welcome.style.display='none';
 let r;
 try{ r=await fetch('/start',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({path})}); }catch(x){ alert('Erreur reseau'); return; }
 const data=await r.json();
 const id=++seq;
 const view=newView(base(path));
 const tab={id,name:base(path),path,status:'run',view,es:null};
 TABS.push(tab); select(id);
 if(!r.ok){ tab.status='err'; renderTabs();
   view.querySelector('.prog').classList.remove('on');
   const ev=view.querySelector('.err'); ev.textContent='Erreur: '+(data.error||'?');
   ev.style.display='block'; return; }
 $('path').value='';
 wire(tab, data.scan_id);
});

function wire(tab, scan_id){
 const v=tab.view, prog=v.querySelector('.prog'),
  pbar=v.querySelector('.bar>i'), pct=v.querySelector('.pct'),
  lbl=v.querySelector('.lbl'), logEl=v.querySelector('.log'),
  statsW=v.querySelector('.stats-wrap'), live=v.querySelector('.live'),
  out=v.querySelector('.out'), errEl=v.querySelector('.err');
 const es=new EventSource('/stream/'+scan_id); tab.es=es;
 es.addEventListener('log',ev=>{
   const d=document.createElement('div'); d.textContent=JSON.parse(ev.data);
   logEl.appendChild(d); logEl.scrollTop=logEl.scrollHeight;
 });
 es.addEventListener('progress',ev=>{
   const p=JSON.parse(ev.data);
   pbar.style.width=p.pct+'%'; pct.textContent=p.pct+'%';
   lbl.textContent=p.done+' / '+p.total+' fichiers';
   statsW.innerHTML=statCards(p.counts);
   if(p.new&&p.new.length) for(const r of p.new) live.insertAdjacentHTML('beforeend',fcard(r));
 });
 es.addEventListener('done',ev=>{
   es.close(); const d=JSON.parse(ev.data);
   prog.classList.remove('on'); live.innerHTML='';
   if(d.error){ tab.status='err'; renderTabs();
     errEl.textContent='Erreur: '+d.error; errEl.style.display='block'; return; }
   statsW.innerHTML=statCards(d.counts);
   const n=d.results.length;
   tab.status='done'; tab.name=base(tab.path)+' ('+n+')'; renderTabs();
   let h='';
   if(!n) h='<div class="empty"><div class="big">&#9989;</div>Aucune vulnerabilite trouvee.</div>';
   for(const r of d.results) h+=fcard(r);
   out.innerHTML=h;
 });
 es.onerror=()=>{ es.close(); };
}
</script></body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
