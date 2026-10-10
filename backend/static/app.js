
const $=i=>document.getElementById(i),root=document.documentElement;
const esc=s=>{const d=document.createElement('div');d.textContent=s;return d.innerHTML};
const toast=(m,ms=2200)=>{const t=$('toast');t.textContent=m;t.className='s';clearTimeout(toast.h);toast.h=setTimeout(()=>t.className='',ms)};
const T=m=>Date.now()-m*6e4;
const ago=t=>{const m=Math.max(0,Math.floor((Date.now()-t)/6e4));return m<1?'just now':m<60?m+' min ago':m<1440?Math.floor(m/60)+' h ago':Math.floor(m/1440)+' d ago'};
$('theme').onclick=function(){const d=root.getAttribute('data-theme')==='dark'||(!root.getAttribute('data-theme')&&matchMedia('(prefers-color-scheme:dark)').matches);root.setAttribute('data-theme',d?'light':'dark');this.textContent=d?'☀':'☾'};

/* ============ DATA (loaded from the backend) ============ */
let A=[],E=[],P=[],H=[],ME={name:'Analyst',email:''};const LATEST='5.2.1';

/* ============ HELPERS ============ */
const live=a=>a.st==='open'||a.st==='investigating';
const sev=s=>s>=80?'critical':s>=60?'high':s>=40?'medium':'low';
const rc=s=>s>=80?'var(--bad)':s>=60?'var(--warn)':s>=40?'#eab308':'var(--ok)';
const ini=n=>(n.replace(/[^A-Z]/g,'')||n[0]).slice(0,2);
const old=p=>{const x=p.agent.split('.'),y=LATEST.split('.');for(let i=0;i<3;i++)if(+x[i]!==+y[i])return +x[i]<+y[i];return false};
const ST={open:'Open',investigating:'Investigating',blocked:'Blocked',resolved:'Resolved',false_positive:'False positive'};
const STC={open:'r',investigating:'w',blocked:'',resolved:'',false_positive:'m'},SVC={critical:'r',high:'w',medium:'m',low:'m'},EC={active:'',watchlist:'w',suspended:'m'},PC={online:'',offline:'m',isolated:'r'},CAT={alert:'r',employee:'w',endpoint:'',auth:'m'};
const chip=(t,c='')=>`<span class="chip ${c}">${t}</span>`;
const card=(l,v,c='var(--tx)',s='')=>`<div class="card"><div class="lbl">${l}</div><div class="big" style="color:${c}">${v}</div>${s?`<div class="sub">${s}</div>`:''}</div>`;
const btn=(a,l,c='',d=0)=>`<button class="btn ${c}" data-a="${a}"${d?' disabled':''}>${l}</button>`;
const hist=ref=>{const h=H.filter(x=>x.ref===ref).sort((a,b)=>b.ts-a.ts);return `<div class="lbl" style="margin-top:20px">Activity</div><div class="hist">${h.length?h.map(x=>`<div><b>${esc(x.text)}</b> · ${esc(x.by)} · ${ago(x.ts)}</div>`).join(''):'<div>No activity recorded.</div>'}</div>`};
const rel=(l,a)=>a.length?`<div class="lbl" style="margin-top:20px">${l}</div><div class="hist">${a.map(x=>`<div><b>${esc(x.title)}</b> · ${ST[x.st]} · ${ago(x.ts)}</div>`).join('')}</div>`:'';
const cap=s=>s[0].toUpperCase()+s.slice(1),LV=['critical','high','medium','low'].map(s=>[s,cap(s)]);
const alertDet=a=>`<div class="ch"><span class="lbl">${a.id}</span>${chip(ST[a.st],STC[a.st])}</div><h2>${esc(a.title)}</h2><div class="meta"><span>Employee: <b>${esc(a.emp)}, ${esc(a.dept)}</b></span><span>Detected <b>${ago(a.ts)}</b></span><span>Severity <b>${cap(sev(a.score))}</b></span></div><div class="flow">${a.path.map((p,i)=>`<span class="node${i==2?' hot':''}">${esc(p)}</span>`).join('›')}</div><div class="meta" style="margin:0"><span><b>${a.size}</b> transferred</span><span><b>${a.files}</b> files</span><span>Risk <b style="color:var(--bad)">${a.score} / 100</b></span></div><div class="risk"><i style="width:${a.score}%"></i></div><div class="btns">${live(a)?btn('block','Block transfer','d')+(a.st==='open'?btn('open','Investigate'):'')+btn('resolve','Resolve','g')+btn('safe','Mark safe','g'):btn('reopen','Reopen')}</div>`+hist(a.id);

/* ============ VIEW CONFIG ============ */
const C={
alerts:{t:'Alerts 🚨',s:'Review, investigate and respond to data exfiltration alerts',ph:'Search by title, employee, host…',items:()=>A,id:a=>a.id,txt:a=>a.id+a.title+a.emp+a.dept+a.path.join(' '),
 stats:()=>[card('Open alerts',A.filter(live).length),card('Critical',A.filter(a=>live(a)&&a.score>=80).length,'var(--bad)'),card('Blocked',A.filter(a=>a.st==='blocked').length,'var(--ok)'),card('Resolved / safe',A.filter(a=>a.st==='resolved'||a.st==='false_positive').length,'var(--ok)')],
 f:[['st','All statuses',Object.entries(ST)],['sv','All severities',LV]],ok:(a,f)=>(!f.st||a.st===f.st)&&(!f.sv||sev(a.score)===f.sv),
 sorts:[['newest',(a,b)=>b.ts-a.ts],['highest risk',(a,b)=>b.score-a.score]],
 row:a=>`${chip(sev(a.score),SVC[sev(a.score)])}<span class="t"><b>${esc(a.title)}</b><small>${a.id} · ${esc(a.emp)}, ${esc(a.dept)} · ${ago(a.ts)}</small></span><span class="hd">${chip(ST[a.st],STC[a.st])}</span><b>${a.score}</b>`,
 det:alertDet,act:0},
emps:{t:'Employees 👥',s:'Insider-risk overview: who is moving data, and how much',ph:'Search by name, role or department…',items:()=>E,id:e=>e.name,txt:e=>e.name+e.role+e.dept,
 stats:()=>[card('Employees monitored',E.length),card('High / critical risk',E.filter(e=>e.risk>=60).length,'var(--bad)'),card('On watchlist',E.filter(e=>e.st==='watchlist').length,'var(--warn)'),card('Open alerts',A.filter(live).length)],
 f:[['dp','All departments',[...new Set(E.map(e=>e.dept))].sort().map(d=>[d,d])],['rk','All risk levels',LV]],ok:(e,f)=>(!f.dp||e.dept===f.dp)&&(!f.rk||sev(e.risk)===f.rk),
 sorts:[['highest risk',(a,b)=>b.risk-a.risk],['name',(a,b)=>a.name.localeCompare(b.name)]],
 row:e=>`<span class="av">${ini(e.name)}</span><span class="t"><b>${esc(e.name)}</b><small>${esc(e.role)} · ${esc(e.dept)}</small></span><span class="hd">${chip(e.st,EC[e.st])}</span><b style="color:${rc(e.risk)}">${e.risk}</b>`,
 det:e=>{const al=A.filter(a=>a.emp===e.name),ps=P.filter(p=>p.user===e.name),w=e.st==='watchlist',s=e.st==='suspended';
  return `<div class="pf"><span class="av">${ini(e.name)}</span><div><h2 style="margin:0">${esc(e.name)}</h2><span class="sub">${esc(e.role)} · ${esc(e.dept)}</span></div></div><div style="margin-top:12px">${chip(sev(e.risk)+' risk',SVC[sev(e.risk)])} ${chip(e.st,EC[e.st])}</div><div class="kv"><div><span class="lbl">Risk score</span><b style="color:${rc(e.risk)}">${e.risk} / 100</b></div><div><span class="lbl">Open alerts</span><b>${al.filter(live).length}</b></div><div><span class="lbl">Data moved (30 d)</span><b>${e.gb} GB</b></div><div><span class="lbl">Devices</span><b>${ps.length?ps.map(p=>esc(p.host)).join(', '):'None'}</b></div></div><div class="risk"><i style="width:${e.risk}%"></i></div><div class="btns">${btn('watch',w?'Remove from watchlist':'Add to watchlist',w?'g':'')}${btn('susp',s?'Restore access':'Suspend access',s?'':'d')}${btn('remind','Send policy reminder','g')}</div>${rel('Alerts',al)}`+hist(e.name)},
 act:0},
ends:{t:'Endpoints 💻',s:'Health, agent status and data leaving each device',ph:'Search host, user, IP or department…',items:()=>P,id:p=>p.host,txt:p=>p.host+p.user+p.ip+p.dept,
 stats:()=>[card('Listed endpoints',P.length),card('Online',P.filter(p=>p.st==='online').length,'var(--ok)'),card('Isolated',P.filter(p=>p.st==='isolated').length,'var(--bad)'),card('Need attention',P.filter(p=>p.st==='offline'||old(p)).length,'var(--warn)')],
 f:[['st','All statuses',[['online','Online'],['offline','Offline'],['isolated','Isolated']]],['os','All systems',['Windows','macOS','Linux'].map(o=>[o,o])]],ok:(p,f)=>(!f.st||p.st===f.st)&&(!f.os||p.os===f.os),
 sorts:[['highest risk',(a,b)=>b.risk-a.risk],['hostname',(a,b)=>a.host.localeCompare(b.host)],['most data out',(a,b)=>b.out-a.out]],
 row:p=>`<span class="dot ${PC[p.st]}"></span><span class="t"><b>${esc(p.host)}</b><small>${esc(p.user)} · ${esc(p.dept)} · ${esc(p.osv)}</small></span><span class="hd">${old(p)?chip('outdated agent','w')+' ':''}${chip(p.st,PC[p.st])}</span><b style="color:${rc(p.risk)}">${p.risk}</b>`,
 det:p=>{const off=p.st==='offline',al=A.filter(a=>a.path[1]===p.host);
  return `<div class="ch"><span class="lbl">${esc(p.dept)}</span>${chip(p.st,PC[p.st])}</div><h2>${esc(p.host)}</h2><span class="sub">${esc(p.user)} · ${esc(p.osv)}</span><div class="kv"><div><span class="lbl">IP address</span><b>${p.ip}</b></div><div><span class="lbl">Last seen</span><b>${p.seen?ago(T(p.seen)):'now'}</b></div><div><span class="lbl">Agent version</span><b>${p.agent} ${old(p)?chip('update','w'):chip('current')}</b></div><div><span class="lbl">Risk score</span><b style="color:${rc(p.risk)}">${p.risk} / 100</b></div><div><span class="lbl">Data out (24 h)</span><b>${p.out} GB</b></div><div><span class="lbl">USB storage</span><b>${p.ub?'Blocked':p.usb?'Connected':'None'}</b></div></div><div class="btns">${btn('iso',p.st==='isolated'?'Restore network':'Isolate device','d',off)}${btn('scan','Scan now','g',off)}${btn('usb',p.ub?'Allow USB':'Block USB','g')}${old(p)?btn('upd','Update agent'):''}</div>${off?'<p class="sub" style="margin-top:10px">Device is offline. Some actions are unavailable.</p>':''}${rel('Alerts',al)}`+hist(p.host)},
 act:0},
hist:{t:'History 🕘',s:'Audit trail of everything that happened, including your own actions',ph:'Search events, people or items…',items:()=>H,id:h=>h.ts,txt:h=>h.text+h.by+h.ref+h.cat,
 stats:()=>[card('Events logged',H.length),card('Last 24 hours',H.filter(h=>h.ts>Date.now()-864e5).length),card('Analyst actions',H.filter(h=>h.by!=='System').length,'var(--warn)'),card('Alert decisions',H.filter(h=>h.cat==='alert'&&h.by!=='System').length)],
 f:[['ct','All categories',[['alert','Alerts'],['employee','Employees'],['endpoint','Endpoints'],['auth','Sign-ins']]]],ok:(h,f)=>!f.ct||h.cat===f.ct,
 sorts:[['newest',(a,b)=>b.ts-a.ts],['oldest',(a,b)=>a.ts-b.ts]],
 row:h=>`${chip(h.cat,CAT[h.cat])}<span class="t"><b>${esc(h.text)}</b><small>${esc(h.by)} · ${esc(h.ref)}</small></span><small>${ago(h.ts)}</small>`}
};
const NAV=[['dash','Dashboard','<rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/>'],['alerts','Alerts','<path d="M12 3 2 21h20L12 3zM12 10v5M12 18v.5"/>'],['emps','Employees','<circle cx="9" cy="8" r="4"/><path d="M2 21c0-4 3-6 7-6s7 2 7 6"/>'],['ends','Endpoints','<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8"/>'],['hist','History','<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>']];
const ic=p=>`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${p}</svg>`;
$('side').innerHTML=`<div class="logo"><i></i>MYPHEMA</div>`+NAV.map(n=>`<button class="nav" data-v="${n[0]}">${ic(n[2])}${n[1]}${n[0]==='alerts'?'<span class="bdg" id="nb"></span>':''}</button>`).join('')+`<button class="nav out" id="so">${ic('<path d="M9 21H5V3h4M16 17l5-5-5-5M21 12H9"/>')}Sign out</button>`;
document.querySelectorAll('.nav[data-v]').forEach(b=>b.onclick=()=>view(b.dataset.v));

/* ============ ENGINE ============ */
const F={};let cur='dash';
const fs=v=>F[v]=F[v]||{q:'',sel:null,s:0,k:{}};
const badge=()=>{const n=A.filter(live).length,b=$('nb');b.textContent=n;b.classList.toggle('hide',!n)};
function view(v){cur=v;document.querySelectorAll('.nav[data-v]').forEach(n=>n.classList.toggle('on',n.dataset.v===v));window.scrollTo(0,0);
 $('ttl').textContent=(NAV.find(n=>n[0]===v)||[])[1];if(v==='dash')return dash();
 const c=C[v],f=fs(v);
 $('page').innerHTML=`<div><h1>${c.t}</h1><p class="sub">${c.s}</p></div><div class="stats" id="st"></div><div class="tool"><input id="q" class="fi" type="search" placeholder="${c.ph}" aria-label="Search" style="flex:1;min-width:200px">${c.f.map((x,i)=>`<select class="fi" data-i="${i}" aria-label="${x[1]}"><option value="">${x[1]}</option>${x[2].map(o=>`<option value="${o[0]}"${f.k[x[0]]===o[0]?' selected':''}>${o[1]}</option>`).join('')}</select>`).join('')}<select class="fi" id="so2" aria-label="Sort">${c.sorts.map((s,i)=>`<option value="${i}"${f.s===i?' selected':''}>Sort: ${s[0]}</option>`).join('')}</select></div><div class="cols${c.det?'':' one'}"><div class="card" id="ls"></div>${c.det?'<div class="card" id="dt"></div>':''}</div>`;
 $('q').value=f.q;let qt;$('q').oninput=function(){const t=this.value;clearTimeout(qt);qt=setTimeout(()=>{f.q=t.trim();upd()},200)};
 document.querySelectorAll('select[data-i]').forEach(s=>s.onchange=()=>{f.k[c.f[+s.dataset.i][0]]=s.value;upd()});
 $('so2').onchange=function(){f.s=+this.value;upd()};upd()}
function upd(){const c=C[cur],f=fs(cur);$('st').innerHTML=c.stats().join('');badge();
 const q=f.q.toLowerCase(),L=c.items().filter(x=>c.ok(x,f.k)&&(!q||c.txt(x).toLowerCase().includes(q))).sort(c.sorts[f.s][1]);
 if(c.det&&!L.some(x=>c.id(x)===f.sel))f.sel=L.length?c.id(L[0]):null;
 $('ls').innerHTML=L.length?L.map(x=>`<div class="row${c.det&&c.id(x)===f.sel?' sel':''}" data-id="${esc(String(c.id(x)))}" tabindex="0">${c.row(x)}</div>`).join(''):'<p class="sub" style="padding:14px 4px">Nothing matches your filters.</p>';
 if(!c.det)return;
 document.querySelectorAll('#ls .row').forEach(r=>{const go=()=>{f.sel=r.dataset.id;upd()};r.onclick=go;r.onkeydown=e=>{if(e.key==='Enter')go()}});
 const x=c.items().find(x=>c.id(x)===f.sel);$('dt').innerHTML=x?c.det(x):'<p class="sub">Select an item to see its details.</p>';
 document.querySelectorAll('#dt [data-a]').forEach(b=>b.onclick=async()=>{b.disabled=true;try{toast(await c.act(x,b.dataset.a))}catch(e){toast(e.message)}upd()})}

/* ============ DASHBOARD ============ */
let evn=48213;
function dash(){const lv=A.filter(live),a=[...lv].sort((x,y)=>y.score-x.score)[0],cr=lv.filter(x=>x.score>=80).length,on=P.length;
 $('page').innerHTML=`<div><h1>Welcome back, ${esc(ME.name.split(' ')[0])} 🛡️</h1><p class="sub">Your data exfiltration monitoring workspace</p></div><div class="stats">${card('Open alerts',String(lv.length).padStart(2,'0'),'var(--tx)',cr?cr+' critical':'No critical alerts')}${card('Monitored endpoints',P.length,'var(--tx)',P.filter(p=>p.st==='online').length+' online')}${card('Events scanned',`<span id="ev">${evn.toLocaleString()}</span>`,'var(--tx)','per minute')}${card('System status','Protected','var(--ok)','All sensors reporting')}</div>
 <div class="cols"><div class="card" id="cur">${a?`<div class="ch"><span class="lbl">Active incident</span>${chip('LIVE','r')}</div>`+alertDet(a):'<div class="lbl">Active incident</div><h2>No open incidents</h2><p class="sub">All clear right now.</p>'}</div>
 <div class="card"><div class="ch"><span class="lbl">Recent incidents</span><button class="lnk" id="va">View all ›</button></div><div style="margin-top:6px">${[...A].sort((x,y)=>y.ts-x.ts).slice(0,5).map(r=>`<div class="row" data-id="${r.id}" tabindex="0"><span class="dot ${live(r)?(r.score>=80?'r':'w'):''}"></span><span class="t"><b>${esc(r.title)}</b><small>${ago(r.ts)} · ${esc(r.emp)} · ${esc(r.dept)}</small></span><b>${r.score}</b></div>`).join('')}</div></div></div>
 <div class="card"><div class="ch"><span class="lbl">Data leaving the network by channel</span><span class="sub">Last 24 hours</span></div><table class="tbl"><thead><tr><th>Channel</th><th>Volume</th><th>Flagged</th><th>Status</th></tr></thead><tbody>${[['Cloud storage','212 GB',3,'Critical','r'],['USB / removable','38 GB',2,'Review','w'],['Email','14 GB',1,'Review','w'],['Print and screenshots','1.2 GB',0,'Normal','']].map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td><td>${chip(r[3],r[4])}</td></tr>`).join('')}</tbody></table></div>`;
 badge();$('va').onclick=()=>view('alerts');
 document.querySelectorAll('.row[data-id]').forEach(r=>{const go=()=>{fs('alerts').sel=r.dataset.id;view('alerts')};r.onclick=go;r.onkeydown=e=>{if(e.key==='Enter')go()}});
 document.querySelectorAll('#cur [data-a]').forEach(b=>b.onclick=async()=>{b.disabled=true;try{toast(await C.alerts.act(a,b.dataset.a))}catch(e){toast(e.message)}dash()})}
setInterval(()=>{evn+=Math.round((Math.random()-.5)*400);const e=$('ev');if(e&&cur==='dash')e.textContent=evn.toLocaleString()},2000);

/* ============ API / SESSION ============ */
const EXT=/^(chrome|moz)-extension:$/.test(location.protocol);
const ls={get:k=>{try{return localStorage.getItem(k)}catch(e){return null}},set:(k,v)=>{try{v==null?localStorage.removeItem(k):localStorage.setItem(k,v)}catch(e){}}};
let TOKEN=ls.get('st'),BASE=EXT?(ls.get('srv')||'http://localhost:5000'):'';
const sync=()=>{try{chrome.storage.local.set({server:BASE||location.origin,token:TOKEN||''})}catch(e){}};
async function api(path,body){const h={'Content-Type':'application/json'};if(TOKEN)h.Authorization='Bearer '+TOKEN;let r;
 try{r=await fetch(BASE+'/api/'+path,{method:body?'POST':'GET',headers:h,body:body?JSON.stringify(body):undefined})}
 catch(e){throw new Error('Cannot reach the server at '+(BASE||location.origin)+'. Is the backend running?')}
 let j={};try{j=await r.json()}catch(e){}
 if(r.status===401&&TOKEN&&path!=='auth/signout')expired();
 if(!r.ok){const x=new Error(j.error||'Something went wrong');x.data=j;throw x}return j}
async function load(){const d=await api('bootstrap');A=d.alerts;E=d.employees;P=d.endpoints;H=d.history;return d}
const AP={alerts:['incidents',x=>x.id],emps:['employees',x=>x.name],ends:['endpoints',x=>x.host]};
for(const v in AP)C[v].act=async(x,k)=>{const r=await api(`${AP[v][0]}/${encodeURIComponent(AP[v][1](x))}/action`,{action:k});await load();return r.message};
setInterval(async()=>{if(!TOKEN||$('app').classList.contains('hide'))return;try{await load();cur==='dash'?dash():upd()}catch(e){}},20000);
if(EXT){$('srvBox').classList.remove('hide');$('srv').value=BASE;$('srv').oninput=()=>{BASE=$('srv').value.trim().replace(/\/+$/,'');ls.set('srv',BASE)}}
function expired(){TOKEN=null;ls.set('st',null);sync();$('app').classList.add('hide');$('login').classList.remove('hide');resetLogin();toast('Session expired. Please sign in again.')}
async function enter(u){ME=u;$('av').textContent=u.name[0].toUpperCase();$('un').textContent=u.name;
 $('login').classList.add('hide');$('app').classList.remove('hide');try{await load()}catch(e){toast(e.message)}view('dash')}
$('so').onclick=async()=>{if(!confirm('Sign out of Myphema?'))return;try{await api('auth/signout',{})}catch(e){}TOKEN=null;ls.set('st',null);sync();$('app').classList.add('hide');$('login').classList.remove('hide');resetLogin();toast('You have been signed out')};

/* ============ LOGIN ============ */
const emailRe=/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const err=(el,m)=>{el.classList.toggle('err',!!m);el.closest('.f').querySelector('.msg').textContent=m||''};
const lshow=id=>['auth','fOtp'].forEach(x=>$(x).classList.toggle('hide',x!==id));
const mode=up=>{$('tIn').classList.toggle('on',!up);$('tUp').classList.toggle('on',up);$('fIn').classList.toggle('hide',up);$('fUp').classList.toggle('hide',!up)};
const busy=(f,b)=>f.querySelectorAll('button[type=submit]').forEach(x=>x.disabled=b);
let ctx=null,tick,boxes=[];
function resetLogin(){['iEm','iPw','uNm','uEm','uPw','uCp'].forEach(i=>{const e=$(i);e.value='';e.classList.remove('err');if(/Pw|Cp/.test(i))e.type='password'});document.querySelectorAll('.f .msg').forEach(m=>m.textContent='');document.querySelectorAll('.eye').forEach(b=>b.textContent='Show');clearInterval(tick);ctx=null;mode(false);lshow('auth')}
$('tIn').onclick=$('goIn').onclick=()=>mode(false);$('tUp').onclick=$('goUp').onclick=()=>mode(true);
document.querySelectorAll('[data-eye]').forEach(b=>b.onclick=()=>{const i=$(b.dataset.eye),s=i.type==='password';i.type=s?'text':'password';b.textContent=s?'Hide':'Show'});
for(let k=0;k<6;k++){const i=document.createElement('input');i.inputMode='numeric';i.maxLength=1;i.autocomplete=k?'off':'one-time-code';i.setAttribute('aria-label','Digit '+(k+1));
 i.oninput=()=>{i.value=i.value.replace(/\D/g,'');$('otpMsg').textContent='';boxes.forEach(b=>b.classList.remove('err'));if(i.value&&k<5)boxes[k+1].focus()};
 i.onkeydown=e=>{if(e.key==='Backspace'&&!i.value&&k>0)boxes[k-1].focus()};
 i.onpaste=e=>{e.preventDefault();const d=(e.clipboardData.getData('text')||'').replace(/\D/g,'').slice(0,6);[...d].forEach((c,j)=>boxes[j].value=c);boxes[Math.min(d.length,5)].focus()};
 $('otp').appendChild(i);boxes.push(i)}
function countdown(left){$('resend').classList.add('hide');$('timer').classList.remove('hide');$('timer').textContent='Resend code in '+left+'s';clearInterval(tick);
 tick=setInterval(()=>{left--;if(left<=0){clearInterval(tick);$('timer').classList.add('hide');$('resend').classList.remove('hide')}else $('timer').textContent='Resend code in '+left+'s'},1000)}
function startOtp(email,r){ctx={email,purpose:r.purpose};$('shown').textContent=email;lshow('fOtp');boxes.forEach(b=>{b.value='';b.classList.remove('err')});$('otpMsg').textContent='';countdown(r.resendIn||30);boxes[0].focus();
 toast(r.devCode?'Dev mode – your code: '+r.devCode:'We sent a 6-digit code to '+email,r.devCode?10000:4000)}
$('resend').onclick=async()=>{try{startOtp(ctx.email,await api('auth/resend-otp',{email:ctx.email,purpose:ctx.purpose}))}catch(e){toast(e.message)}};
$('back').onclick=()=>{clearInterval(tick);lshow('auth')};
$('fIn').onsubmit=async e=>{e.preventDefault();const m=$('iEm'),p=$('iPw'),em=m.value.trim(),ok=emailRe.test(em);err(m,ok?'':'Enter a valid email');err(p,p.value?'':'Enter your password');if(!ok||!p.value)return;
 busy(e.target,1);try{startOtp(em,await api('auth/signin',{email:em,password:p.value}))}catch(x){err(p,x.message)}busy(e.target,0)};
$('fUp').onsubmit=async e=>{e.preventDefault();const n=$('uNm'),m=$('uEm'),p=$('uPw'),c=$('uCp');let bad=0;const chk=(el,t)=>{err(el,t);if(t)bad=1};
 chk(n,n.value.trim().length<2?'Enter your full name':'');chk(m,emailRe.test(m.value.trim())?'':'Enter a valid email');
 chk(p,p.value.length<8?'Password must be at least 8 characters':!/[A-Za-z]/.test(p.value)||!/\d/.test(p.value)?'Use both letters and numbers':'');
 chk(c,!c.value?'Confirm your password':c.value!==p.value?'Passwords do not match':'');if(bad)return;
 busy(e.target,1);try{startOtp(m.value.trim(),await api('auth/signup',{name:n.value.trim(),email:m.value.trim(),password:p.value,confirmPassword:c.value}))}
 catch(x){const t=x.message;err(/email|account/i.test(t)?m:/name/i.test(t)?n:/match/i.test(t)?c:p,t)}busy(e.target,0)};
$('fOtp').onsubmit=async e=>{e.preventDefault();const v=boxes.map(b=>b.value).join('');if(v.length<6){$('otpMsg').textContent='Enter all 6 digits';return}
 busy(e.target,1);try{const r=await api('auth/verify-otp',{email:ctx.email,purpose:ctx.purpose,code:v});clearInterval(tick);TOKEN=r.token;ls.set('st',TOKEN);sync();await enter(r.user);resetLogin();toast('Welcome to Myphema')}
 catch(x){$('otpMsg').textContent=x.message;boxes.forEach(b=>b.classList.add('err'))}busy(e.target,0)};
sync();(async()=>{if(!TOKEN)return;try{const r=await api('me');await enter(r.user)}catch(e){}})();
