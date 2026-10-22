import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import axios from "axios";
import "./styles.css";

const API = "http://localhost:5000/api";
const api = axios.create({ baseURL: API });
api.interceptors.request.use(config => {
  const token = localStorage.getItem("securetracer_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

function Auth({ onLogin }) {
  const [register, setRegister] = useState(false);
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState("");
  async function submit(e) {
    e.preventDefault(); setError("");
    try {
      const endpoint = register ? "/auth/register" : "/auth/login";
      const { data } = await api.post(endpoint, form);
      localStorage.setItem("securetracer_token", data.token);
      onLogin(data.user);
    } catch (e) {
      const message = e.response?.data?.message;
      setError(message || (e.code === "ERR_NETWORK"
        ? "Cannot reach SecureTracer API. Keep the backend running at http://localhost:5000 and refresh this page."
        : "Request failed. Please check the details and try again."));
    }
  }
  return <main className="auth"><section className="auth-card">
    <div className="brand-mark"><b>SecureTracer</b></div>
    <h1>{register ? "Create account" : "Sign in"}</h1>
    <form onSubmit={submit}>{register && <input placeholder="Full name" value={form.name} onChange={e=>setForm({...form,name:e.target.value})} required />}
      <input type="email" placeholder="Email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})} required />
      <input type="password" placeholder="Password" value={form.password} onChange={e=>setForm({...form,password:e.target.value})} required minLength="8" />
      {error && <div className="error">{error}</div>}<button>{register ? "Create account" : "Login"}</button>
    </form><button className="link" onClick={()=>setRegister(!register)}>{register ? "Already have an account? Login" : "Create account"}</button>
  </section></main>;
}

function App({ user, logout }) {
  const [files,setFiles]=useState([]), [events,setEvents]=useState([]), [stats,setStats]=useState({total:0,critical:0,tampered:0});
  const [message,setMessage]=useState(""), [risk,setRisk]=useState({score:0,level:"LOW"}), [agent,setAgent]=useState("WAITING FOR AGENT");
  const [riskReasons,setRiskReasons]=useState(["No suspicious endpoint activity reported"]);
  const usbEvents = events.filter(x => ["USB_CONNECTED","USB_DISCONNECTED","DATA_EXFILTRATION_ATTEMPT"].includes(x.type)).slice(0,8);
  async function load(){
    const [f,e,s]=await Promise.all([api.get("/files"),api.get("/events"),api.get("/events/stats")]);
    setFiles(f.data);setEvents(e.data);setStats(s.data);
    const agentEvents=e.data.filter(x=>x.metadata?.source==="endpoint-agent");
    if(agentEvents.length){
      setAgent(`AGENT ACTIVE · ${agentEvents[0].metadata?.agentName || "ENDPOINT"}`);
      const latest=agentEvents[0];
      const score=latest.metadata?.aiRiskScore||0;
      const level=latest.metadata?.aiRiskLevel||latest.severity;
      setRisk({score,level});
      const reasons=[];
      if (latest.type === "TAMPER_DETECTED") reasons.push("Protected file was modified");
      if (latest.type === "USB_CONNECTED") reasons.push("USB device was connected");
      if (latest.type === "DATA_EXFILTRATION_ATTEMPT") reasons.push("Protected file was found on removable media");
      if (latest.type === "PROTECTED_FILE_REMOVED") reasons.push("Protected file was removed");
      if (reasons.length === 0) reasons.push("Endpoint activity is being monitored");
      setRiskReasons(reasons);
    }
  }
  useEffect(()=>{load().catch(()=>{}); const timer=setInterval(()=>load().catch(()=>{}),5000); return ()=>clearInterval(timer)},[]);
  async function registerFile(e){const file=e.target.files?.[0];if(!file)return;const data=new FormData();data.append("file",file);try{await api.post("/files/register",data);setMessage(`✓ ${file.name} is now protected with a SHA-256 fingerprint.`);await load()}catch(err){setMessage(err.response?.data?.message||"Upload failed")}e.target.value=""}
  async function verify(id,name){const input=document.createElement("input");input.type="file";input.onchange=async()=>{if(!input.files[0])return;const data=new FormData();data.append("file",input.files[0]);try{const r=await api.post(`/files/${id}/verify`,data);setMessage(r.data.match?`✓ ${name}: integrity verified.`:`🚨 ${name}: TAMPERING DETECTED.`);await load()}catch(err){setMessage(err.response?.data?.message||"Verification failed")}};input.click()}
  async function unregisterFile(id,name){
    const ok=window.confirm(`Unregister ${name} from SecureTracer?\n\nThe protected copy stored by SecureTracer will be removed, but your original local file will not be deleted.`);
    if(!ok)return;
    try{
      await api.delete(`/files/${id}`);
      setMessage(`✓ ${name} was unregistered from SecureTracer.`);
      await load();
    }catch(err){setMessage(err.response?.data?.message||"Unregister failed")}
  }
  return <div className="app"><header><div className="header-brand"><span className="brand">SecureTracer</span></div><div className="user"><span>{user.name}</span><button className="ghost" onClick={logout}>Logout</button></div></header>
    <main className="content"><section className="hero"><div><h1>Security Dashboard</h1><p className="muted">This project checks important files, watches USB activity and records security events. It also uses a small ML check to estimate the current risk.</p><div className="hero-tags"><span>FILE INTEGRITY</span><span>USB ACTIVITY</span><span>RISK CHECK</span></div></div><label className="upload"><input type="file" onChange={registerFile}/>  + Protect file</label></section>
      {message&&<div className="notice">{message}</div>}
      <section className="stats"><Card title="Protected files" value={files.length}/><Card title="Security events" value={stats.total}/><Card title="Tamper alerts" value={stats.tampered} danger/><Card title="Critical events" value={stats.critical} danger/></section>
      <section className="security-grid"><div className="panel agent-panel"><div className="panel-head"><h2>Endpoint Agent</h2><span className="pill live">● {agent}</span></div><div className="agent-body"><div className="risk-box"><span className="muted">CURRENT RISK</span><strong className="risk">{risk.score}%</strong><span className={`risk-level ${risk.level.toLowerCase()}`}>{risk.level}</span></div><div className="agent-points"><span>✓ File monitoring</span><span>✓ USB device detection</span><span>✓ Event reporting</span><span>✓ ML risk check</span></div></div></div>
      <div className="panel"><div className="panel-head"><h2>Risk details</h2><span className="pill">ML CHECK</span></div><div className="reasons">{riskReasons.map((r,i)=><div key={i}><span>{i+1}</span>{r}</div>)}</div></div></section>
      <section className="panel"><div className="panel-head"><h2>What the system does</h2><span className="pill">DETECT + ALERT + LOG</span></div><div className="policy"><div><b>File modification</b><span>SHA-256 check → Alert</span></div><div><b>Unknown USB</b><span>Device detection → Alert</span></div><div><b>Protected-file copy on USB</b><span>Hash match → Copy alert</span></div><div><b>Suspicious activity</b><span>ML check → Risk score</span></div></div></section>
      <section className="panel"><div className="panel-head"><h2>Protected files</h2><span className="muted">{files.length} files</span></div>{files.length===0?<div className="empty">No protected files yet. Click “Protect file” to add one.</div>:<div className="table"><div className="row head"><span>File</span><span>Status</span><span>SHA-256</span><span>Action</span></div>{files.map(f=><div className="row" key={f._id}><span><strong>{f.originalName}</strong><small>{Math.round(f.size/1024)} KB · v{f.version}</small></span><span className={f.status==="TAMPERED"?"pill danger":"pill"}>{f.status}</span><code>{f.sha256.slice(0,18)}…</code><div className="actions"><button className="small" onClick={()=>verify(f._id,f.originalName)}>Verify</button><button className="small danger-btn" onClick={()=>unregisterFile(f._id,f.originalName)}>Unregister</button></div></div>)}</div>}</section>
      <section className="panel"><div className="panel-head"><h2>Recent activity</h2><span className="muted">Updates every 5 sec</span></div>{events.length===0?<div className="empty">No activity yet. Start the endpoint agent to see events.</div>:events.slice(0,15).map(ev=><div className="event" key={ev._id}><span className={`dot ${ev.severity.toLowerCase()}`}></span><div><strong>{ev.type.replaceAll("_"," ")}</strong><p>{ev.message}</p>{ev.metadata?.aiRiskScore!=null&&<small>AI risk {ev.metadata.aiRiskScore}% · {ev.metadata.aiRiskLevel}</small>}</div><time>{new Date(ev.createdAt).toLocaleString()}</time></div>)}</section>
      <section className="panel"><div className="panel-head"><h2>USB Activity</h2><span className="pill">REMOVABLE MEDIA</span></div>{usbEvents.length===0?<div className="empty">No USB activity detected yet. Keep the Security Agent running and reconnect the USB drive.</div>:usbEvents.map(ev=><div className="event" key={ev._id}><span className={`dot ${ev.severity.toLowerCase()}`}></span><div><strong>{ev.type.replaceAll("_"," ")}</strong><p>{ev.message}</p><small>{ev.metadata?.drive || ev.metadata?.destination || "USB event"} · AI risk {ev.metadata?.aiRiskScore ?? 0}%</small></div><time>{new Date(ev.createdAt).toLocaleString()}</time></div>)}</section>
      <footer>SecureTracer</footer>
    </main></div>
}
function Card({title,value,danger}){return <div className={`stat ${danger?"danger-bg":""}`}><span>{title}</span><strong>{value}</strong></div>}
function Root(){const [user,setUser]=useState(()=>JSON.parse(localStorage.getItem("securetracer_user")||"null"));function login(u){localStorage.setItem("securetracer_user",JSON.stringify(u));setUser(u)}function logout(){localStorage.removeItem("securetracer_token");localStorage.removeItem("securetracer_user");setUser(null)}return user?<App user={user} logout={logout}/>:<Auth onLogin={login}/>} 
createRoot(document.getElementById("root")).render(<Root/>);
