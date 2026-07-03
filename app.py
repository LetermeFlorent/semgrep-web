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
CHUNK = 8

def list_targets(root):
    files = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIR and not d.startswith(".")]
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext in CODE_EXT or fn.lower() in ("dockerfile",):
                files.append(os.path.join(dp, fn))
    return files

class Cancelled(Exception):
    pass

def _safe_json(s):
    try:
        return json.loads(s or "{}")
    except Exception:
        return {}

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

# Persistance des jobs sur disque (survit au redemarrage du conteneur).
STATE_FILE = os.environ.get("STV_STATE", "/state/jobs.json")
JLOCK = threading.Lock()
JCOND = threading.Condition(JLOCK)  # notifie les streams a chaque update

def snapshot(job):
    # etat serialisable expose au client
    return {
        "scan_id": job["scan_id"], "path": job["path"], "status": job["status"],
        "pct": job["pct"], "phase": job["phase"], "total": job["total"],
        "counts": job["counts"], "version": job["version"],
        "results": job["results"] if job["status"] == "done" else None,
        "error": job.get("error"),
    }

def persist():
    # sauve un resume leger (sans les resultats volumineux) pour reprise.
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with JLOCK:
            data = {sid: {"scan_id": j["scan_id"], "path": j["path"],
                          "status": j["status"]} for sid, j in JOBS.items()}
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass

def touch(job, **kw):
    # met a jour l'etat + incremente version + reveille les streams
    with JCOND:
        job.update(kw)
        job["version"] += 1
        JCOND.notify_all()

def run_scan(job, target):
    results, counts = [], {"ERROR": 0, "WARNING": 0, "INFO": 0}
    try:
        touch(job, phase="Recensement des fichiers", pct=1)
        targets = list_targets(target)
        total = len(targets)
        touch(job, total=total)
        if total == 0:
            touch(job, pct=100, phase="Termine")
        else:
            touch(job, pct=2, phase="Chargement des regles")
            est = 7.0 + total * 0.25
            stop = threading.Event()

            def ticker():
                t0 = time.monotonic()
                while not stop.wait(0.5):
                    el = time.monotonic() - t0
                    pct = min(95, round(2 + (el / est) * 93))
                    phase = "Analyse en cours" if el > 4 else "Chargement des regles"
                    touch(job, pct=pct, phase=phase, counts=dict(counts))

            tk = threading.Thread(target=ticker, daemon=True)
            tk.start()
            cmd = ["semgrep", "scan", "--config", "auto", "--json", "--quiet"]
            MAXARG = 4000
            try:
                for i in range(0, total, MAXARG):
                    if job.get("cancel"):
                        raise Cancelled()
                    proc = subprocess.Popen(cmd + targets[i:i+MAXARG],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            text=True)
                    job["proc"] = proc
                    out, _ = proc.communicate(timeout=1800)
                    if job.get("cancel"):
                        raise Cancelled()
                    parse_results(_safe_json(out), results, counts)
            finally:
                stop.set()
                tk.join(timeout=1)
                job["proc"] = None
        order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
        results.sort(key=lambda x: order[x["severity"]])
        touch(job, pct=100, phase="Termine", status="done",
              counts=counts, results=results)
    except Cancelled:
        touch(job, status="cancelled", phase="Annule")
    except Exception as e:
        touch(job, status="err", error=str(e), results=results, counts=counts)
    persist()

def new_job(path, target):
    scan_id = uuid.uuid4().hex
    job = {"scan_id": scan_id, "path": path, "status": "run", "pct": 0,
           "phase": "Preparation", "total": 0,
           "counts": {"ERROR": 0, "WARNING": 0, "INFO": 0},
           "results": [], "error": None, "version": 0}
    with JLOCK:
        JOBS[scan_id] = job
    persist()
    threading.Thread(target=run_scan, args=(job, target), daemon=True).start()
    return job

def resume_jobs():
    # au demarrage: relance les scans qui etaient "run" (process mort au restart).
    try:
        with open(STATE_FILE) as f:
            saved = json.load(f)
    except Exception:
        return
    for sid, s in saved.items():
        if s.get("status") == "run":
            target = map_path(s["path"])
            if os.path.isdir(target):
                new_job(s["path"], target)

@app.route("/")
def index():
    return render_template_string(PAGE)

@app.route("/jobs")
def jobs():
    # snapshot de tous les jobs connus (pour reconstruire les onglets au reload)
    with JLOCK:
        return jsonify([snapshot(j) for j in JOBS.values()])

@app.route("/start", methods=["POST"])
def start():
    path = (request.json.get("path") or "").strip()
    target = map_path(path)
    if not os.path.isdir(target):
        return jsonify({"error": "Dossier introuvable: " + path + " (disques montes: C D F G H I M W)"}), 400
    job = new_job(path, target)
    return jsonify({"scan_id": job["scan_id"]})

@app.route("/close/<scan_id>", methods=["POST"])
def close(scan_id):
    job = JOBS.get(scan_id)
    if job:
        job["cancel"] = True            # signale l'annulation au thread de scan
        p = job.get("proc")
        if p:
            try:
                p.kill()                 # tue le process semgrep en cours
            except Exception:
                pass
    with JLOCK:
        JOBS.pop(scan_id, None)
    persist()
    return jsonify({"ok": True})

@app.route("/stream/<scan_id>")
def stream(scan_id):
    job = JOBS.get(scan_id)
    if not job:
        return "no job", 404
    def gen():
        last = -1
        while True:
            with JCOND:
                if job["version"] == last:
                    JCOND.wait(timeout=25)
                if job["version"] == last:
                    yield ": ping\n\n"
                    continue
                last = job["version"]
                snap = snapshot(job)
            yield "event: state\ndata: " + json.dumps(snap) + "\n\n"
            if snap["status"] in ("done", "err"):
                break
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

PAGE = r"""
<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>STV &middot; Semgrep Scanner</title>
<style>
 /* ---- Palette Zed (One Dark) ---- */
 :root{color-scheme:dark}
 :root{
   --editor:#282c33;   /* zone contenu, la plus sombre */
   --panel:#2f343e;    /* sidebar, barre onglets */
   --titlebar:#3b414d; /* barre de titre */
   --bd:#464b57; --bd2:#363c46;
   --tx:#dce0e5; --mut:#a9afbc; --ph:#878a98;
   --acc:#74ade8; --hi:#d07277; --med:#dec184; --lo:#a1c181;
   --r:4px; --r6:6px;
   --fui:"Zed Plex Sans","IBM Plex Sans",-apple-system,"Segoe UI",system-ui,sans-serif;
   --fmono:"Zed Plex Mono","Lilex","IBM Plex Mono",ui-monospace,Consolas,monospace;
 }
 @media (prefers-color-scheme: light){:root{
   --editor:#fafafa;--panel:#ececec;--titlebar:#e0e0e0;--bd:#d3d3d3;--bd2:#e0e0e0;
   --tx:#242529;--mut:#5a5c63;--ph:#9295a0;--acc:#5c78e2;
   --hi:#c04a4a;--med:#b08500;--lo:#5a9e3a}}
 *{box-sizing:border-box}
 html,body{height:100%}
 body{margin:0;background:var(--editor);color:var(--tx);
   font:13px/1.5 var(--fui);
   display:flex;flex-direction:column;height:100vh;overflow:hidden}
 /* titlebar */
 .top{display:flex;align-items:center;gap:10px;padding:8px 14px;flex:0 0 auto;
   background:var(--titlebar);border-bottom:1px solid var(--bd2);height:36px}
 .logo{font-size:13px;font-weight:600;letter-spacing:.2px;display:flex;align-items:center;gap:7px}
 .logo .dot{width:7px;height:7px;border-radius:50%;background:var(--acc)}
 .top .sub{color:var(--mut);font-size:12px}
 .top .spacer{flex:1}
 .badge{font-size:11px;color:var(--mut);border:1px solid var(--bd);border-radius:var(--r);
   padding:2px 8px}
 /* layout */
 .app{display:grid;grid-template-columns:280px 1fr;flex:1;min-height:0;overflow:hidden}
 .side{background:var(--panel);border-right:1px solid var(--bd2);padding:14px;
   overflow-y:auto;display:flex;flex-direction:column;gap:16px}
 .main{overflow-y:auto;padding:16px 20px;background:var(--editor)}
 .main .inner{max-width:1300px;margin:0 auto}
 /* form */
 label{font-size:11px;font-weight:500;color:var(--mut);
   display:block;margin-bottom:6px}
 .field{display:flex;flex-direction:column;gap:8px}
 input[type=text]{background:var(--editor);border:1px solid var(--bd);color:var(--tx);
   padding:7px 9px;border-radius:var(--r);font:13px var(--fmono);width:100%;transition:border .12s}
 input[type=text]::placeholder{color:var(--ph)}
 input[type=text]:focus{outline:0;border-color:var(--acc)}
 button{background:var(--acc);color:#1a1d23;border:0;padding:7px 12px;border-radius:var(--r);
   font:13px/1 var(--fui);font-weight:500;cursor:pointer;width:100%;transition:filter .12s}
 button:hover:not(:disabled){filter:brightness(1.08)}
 button:disabled{opacity:.5;cursor:default}
 .hint{font-size:11px;color:var(--ph);line-height:1.4}
 /* progress */
 .prog{display:none;flex-direction:column;gap:8px;background:var(--editor);
   border:1px solid var(--bd2);border-radius:var(--r6);padding:12px}
 .prog.on{display:flex}
 .phead{display:flex;justify-content:space-between;align-items:baseline}
 .phead .pct{font-size:20px;font-weight:600;font-variant-numeric:tabular-nums;font-family:var(--fmono)}
 .phead .lbl{font-size:11px;color:var(--mut)}
 .bar{height:5px;background:var(--panel);border-radius:99px;overflow:hidden}
 .bar>i{display:block;height:100%;width:0;border-radius:99px;
   background:var(--acc);transition:width .4s ease}
 .log{font:11px/1.45 var(--fmono);color:var(--ph);
   max-height:100px;overflow:auto;white-space:pre-wrap;
   background:var(--panel);border-radius:var(--r);padding:6px 8px}
 .log:empty{display:none}
 .log div{padding:.5px 0}
 /* stat cards */
 .stats-wrap{margin-bottom:16px}
 .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
 .stat{background:var(--panel);border:1px solid var(--bd2);border-radius:var(--r6);padding:12px 14px}
 .stat .n{font-size:24px;font-weight:600;line-height:1;font-variant-numeric:tabular-nums;font-family:var(--fmono)}
 .stat .k{font-size:11px;color:var(--mut);margin-top:5px}
 .stat.c-hi .n{color:var(--hi)}
 .stat.c-med .n{color:var(--med)}
 .stat.c-lo .n{color:var(--lo)}
 .stat.c-all .n{color:var(--acc)}
 /* findings */
 .f{background:var(--panel);border:1px solid var(--bd2);border-left:2px solid var(--bd);
   border-radius:var(--r);padding:10px 12px;margin-bottom:6px}
 .f.ERROR{border-left-color:var(--hi)}.f.WARNING{border-left-color:var(--med)}
 .f.INFO{border-left-color:var(--lo)}
 .frow{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
 .sev{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;
   padding:2px 6px;border-radius:var(--r)}
 .ERROR .sev{color:var(--hi);background:rgba(208,114,119,.14)}
 .WARNING .sev{color:var(--med);background:rgba(222,193,132,.14)}
 .INFO .sev{color:var(--lo);background:rgba(161,193,129,.14)}
 .loc{color:var(--tx);font-size:12px;font-family:var(--fmono)}
 .loc .ln{color:var(--acc)}
 .msg{margin:6px 0 0;color:var(--tx);font-size:12.5px}
 .rid{color:var(--ph);font-size:11px;margin-top:5px;font-family:var(--fmono)}
 pre{background:var(--editor);border:1px solid var(--bd2);border-radius:var(--r);padding:8px 10px;
   overflow:auto;font:11.5px/1.5 var(--fmono);margin:8px 0 0}
 .err{color:var(--hi);background:rgba(208,114,119,.1);border:1px solid var(--hi);
   border-radius:var(--r);padding:10px 12px;margin-bottom:12px;font-size:12.5px}
 .toolbar{display:flex;justify-content:flex-end;margin-bottom:10px}
 .copybtn{width:auto;background:var(--panel);color:var(--tx);border:1px solid var(--bd);
   padding:5px 12px;font-size:12px;font-weight:500}
 .copybtn:hover:not(:disabled){filter:none;background:var(--bd2);border-color:var(--acc)}
 .empty{color:var(--mut);padding:50px 20px;text-align:center;font-size:13px}
 .empty .big{font-size:38px;margin-bottom:10px}
 .welcome{color:var(--mut);padding:70px 20px;text-align:center}
 .welcome .big{font-size:44px;margin-bottom:12px;opacity:.4}
 .welcome h2{color:var(--tx);font-weight:600;margin:0 0 6px;font-size:16px}
 .welcome div{font-size:12.5px;line-height:1.6}
 @media(max-width:820px){.app{grid-template-columns:1fr}
   .side{border-right:0;border-bottom:1px solid var(--bd2)}
   .stats{grid-template-columns:repeat(2,1fr)}}
 /* onglets style Zed - liste verticale en bas de la sidebar */
 .tabs{display:flex;flex-direction:column;gap:1px;margin-top:auto;
   border-top:1px solid var(--bd2);padding-top:10px;overflow-y:auto;max-height:45%}
 .tabs:empty{display:none;margin-top:0;border-top:0;padding-top:0}
 .tab{display:flex;align-items:center;gap:8px;padding:6px 8px;cursor:pointer;
   color:var(--mut);font-size:12px;white-space:nowrap;border-radius:var(--r)}
 .tab:hover{color:var(--tx);background:var(--editor)}
 .tab.active{color:var(--tx);background:var(--editor)}
 .tab.active .tname{font-weight:500}
 .tab .tname{overflow:hidden;text-overflow:ellipsis;flex:1}
 .tab .tdot{width:7px;height:7px;min-width:7px;min-height:7px;border-radius:50%;
   flex:0 0 7px;align-self:center}
 .tab .tdot.run{background:var(--acc);animation:pulse 1.1s infinite}
 .tab .tdot.done{background:var(--lo)}
 .tab .tdot.err{background:var(--hi)}
 @keyframes pulse{50%{opacity:.3}}
 .tab .x{opacity:0;font-size:14px;line-height:1;padding:1px 4px;border-radius:var(--r);color:var(--ph);flex:0 0 auto}
 .tab:hover .x{opacity:.7}
 .tab .x:hover{opacity:1;background:var(--bd)}
 .view{display:none}.view.active{display:block}
</style></head><body>
<div class="top">
  <div class="logo"><span class="dot"></span>STV</div>
  <span class="sub">Semgrep Security Scanner</span>
  <div class="spacer"></div>
  <span class="badge">C: D: F: G: H: I: M: W: (lecture seule)</span>
</div>
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
    <div class="tabs" id="tabs"></div>
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

function tabLabel(t){
 // pendant le scan: "nom 42%", fini: "nom (n)", erreur: "nom"
 if(t.status==='run') return t.name+' '+(t.pct||0)+'%';
 if(t.status==='done') return t.name+' ('+(t.count||0)+')';
 return t.name;
}
function renderTabs(){
 // MAJ en place: on ne recree pas les noeuds a chaque tick (sinon le clic sur la
 // croix est avale car l'element disparait entre mousedown et click pendant un scan).
 const seen=new Set();
 for(const t of TABS){
   seen.add(t.id);
   let el=tabsEl.querySelector('.tab[data-id="'+t.id+'"]');
   if(!el){
     el=document.createElement('div'); el.dataset.id=t.id;
     el.innerHTML='<span class="tdot"></span><span class="tname"></span><span class="x">&times;</span>';
     el.onclick=()=>select(t.id);
     el.querySelector('.x').onclick=e=>{e.stopPropagation();closeTab(t.id);};
     tabsEl.appendChild(el);
   }
   el.className='tab'+(t.id===active?' active':'');
   el.querySelector('.tdot').className='tdot '+t.status;
   el.querySelector('.tname').textContent=tabLabel(t);
 }
 // retire les onglets disparus
 tabsEl.querySelectorAll('.tab').forEach(el=>{
   if(!seen.has(+el.dataset.id)) el.remove();
 });
}
function select(id){active=id;
 for(const t of TABS) t.view.classList.toggle('active',t.id===id);
 renderTabs();
}
async function closeTab(id){
 const t=TABS.find(x=>x.id===id); if(!t)return;
 if(t.es) t.es.close(); t.view.remove();
 if(t.scan_id){ try{ await fetch('/close/'+t.scan_id,{method:'POST'}); }catch(e){} }
 TABS=TABS.filter(x=>x.id!==id);
 if(active===id) active=TABS.length?TABS[TABS.length-1].id:null;
 if(active) select(active);
 renderTabs(); saveTabs();
 if(!TABS.length) welcome.style.display='';
}
// persiste l'ordre/selection des onglets (les donnees vivent cote serveur)
function saveTabs(){
 try{ localStorage.setItem('stv_tabs', JSON.stringify(
   {order:TABS.map(t=>t.scan_id).filter(Boolean), active:(TABS.find(t=>t.id===active)||{}).scan_id||null}
 )); }catch(e){}
}
// au chargement: recupere les jobs du serveur, reconstruit les onglets
async function restore(){
 let jobs=[]; try{ jobs=await (await fetch('/jobs')).json(); }catch(e){}
 if(!jobs.length){ welcome.style.display=''; return; }
 welcome.style.display='none';
 let pref={order:[],active:null};
 try{ pref=JSON.parse(localStorage.getItem('stv_tabs'))||pref; }catch(e){}
 // ordre: d'abord ceux memorises, puis le reste
 const byId={}; jobs.forEach(j=>byId[j.scan_id]=j);
 const ordered=[...pref.order.filter(id=>byId[id]),
   ...jobs.map(j=>j.scan_id).filter(id=>!pref.order.includes(id))];
 let activeId=null;
 for(const sid of ordered){
   const j=byId[sid];
   const tab=attach(j.scan_id, j.path, {select:false, nowire:true});
   applyState(tab, j);           // etat courant immediat
   if(j.status==='run') wire(tab); // continue a suivre les scans en cours
   if(sid===pref.active) activeId=tab.id;
 }
 select(activeId||TABS[TABS.length-1].id);
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

function norm(p){return p.replace(/[\\/]+$/,'').replace(/\\/g,'/').toLowerCase();}

// cree l'onglet + la vue pour un scan_id serveur, puis s'abonne a son etat.
function attach(scan_id, path, opts){
 opts=opts||{};
 const id=++seq;
 const view=newView(base(path));
 const tab={id,scan_id,name:base(path),path,status:'run',pct:0,count:0,view,es:null};
 TABS.push(tab);
 if(opts.select!==false) select(id); else renderTabs();
 if(opts.err){ tab.status='err'; renderTabs();
   view.querySelector('.prog').classList.remove('on');
   const ev=view.querySelector('.err'); ev.textContent='Erreur: '+opts.err;
   ev.style.display='block'; return tab; }
 if(!opts.nowire) wire(tab);
 return tab;
}

frm.addEventListener('submit',async e=>{
 e.preventDefault();
 const path=$('path').value.trim(); if(!path)return;
 const dup=TABS.find(t=>norm(t.path)===norm(path));
 if(dup){
   select(dup.id);
   if(dup.status!=='run'){
     if(!confirm('Ce dossier a deja un onglet. Relancer le scan ?')){ $('path').value=''; return; }
     await closeTab(dup.id);
   } else { $('path').value=''; return; }
 }
 welcome.style.display='none';
 let r;
 try{ r=await fetch('/start',{method:'POST',headers:{'Content-Type':'application/json'},
   body:JSON.stringify({path})}); }catch(x){ alert('Erreur reseau'); return; }
 const data=await r.json();
 if(!r.ok){ attach(null, path, {err:data.error||'?'}); return; }
 $('path').value='';
 attach(data.scan_id, path);
 saveTabs();
});

// applique un snapshot serveur a l'onglet (progression, fin, erreur)
function applyState(tab, s){
 const v=tab.view, prog=v.querySelector('.prog'),
  pbar=v.querySelector('.bar>i'), pct=v.querySelector('.pct'),
  lbl=v.querySelector('.lbl'), statsW=v.querySelector('.stats-wrap'),
  out=v.querySelector('.out'), errEl=v.querySelector('.err');
 tab.pct=s.pct||0; statsW.innerHTML=statCards(s.counts);
 if(s.status==='run'){
   pbar.style.width=s.pct+'%'; pct.textContent=s.pct+'%';
   lbl.textContent=(s.phase||'')+(s.total?' · '+s.total+' fichiers':'');
   tab.status='run'; renderTabs(); return;
 }
 prog.classList.remove('on');
 if(s.status==='err'){ tab.status='err'; renderTabs();
   errEl.textContent='Erreur: '+(s.error||'?'); errEl.style.display='block';
   saveTabs(); return; }
 // done
 const res=s.results||[]; const n=res.length;
 tab.status='done'; tab.count=n; tab.results=res; renderTabs();
 let h='';
 if(!n){ h='<div class="empty"><div class="big">&#9989;</div>Aucune vulnerabilite trouvee.</div>'; }
 else{
   h='<div class="toolbar"><button type="button" class="copybtn">Copier les '+n+' problemes</button></div>';
   for(const r of res) h+=fcard(r);
 }
 out.innerHTML=h;
 const cb=out.querySelector('.copybtn');
 if(cb) cb.onclick=()=>copyResults(tab, cb);
 saveTabs();
}

function wire(tab){
 if(tab.es) tab.es.close();
 const es=new EventSource('/stream/'+tab.scan_id); tab.es=es;
 es.addEventListener('state',ev=>{
   const s=JSON.parse(ev.data); applyState(tab, s);
   if(s.status!=='run') es.close();
 });
 es.onerror=()=>{ es.close();
   // job absent cote serveur (ex: conteneur relance sans reprise) -> marque perdu
   if(tab.status==='run'){ /* reconnexion auto par EventSource sinon */ } };
}

function copyResults(tab, btn){
 const rs=tab.results||[];
 const lines=rs.map(r=>'['+r.severity+'] '+r.file+':'+r.line+'\n  '+r.message+
   '\n  ('+r.check_id+')').join('\n\n');
 const txt='STV scan · '+tab.path+'\n'+rs.length+' problemes\n\n'+lines;
 const done=()=>{ const o=btn.textContent; btn.textContent='Copie !';
   setTimeout(()=>btn.textContent=o,1500); };
 if(navigator.clipboard&&navigator.clipboard.writeText){
   navigator.clipboard.writeText(txt).then(done).catch(()=>fallbackCopy(txt,done));
 } else fallbackCopy(txt,done);
}
function fallbackCopy(txt,done){
 const ta=document.createElement('textarea'); ta.value=txt;
 ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta);
 ta.select(); try{document.execCommand('copy');}catch(e){} ta.remove(); done();
}
restore();  // reconstruit les onglets/scans au chargement (F5, reouverture)
</script></body></html>
"""

if __name__ == "__main__":
    resume_jobs()  # reprend les scans non finis apres un redemarrage
    app.run(host="0.0.0.0", port=5000, threaded=True)
