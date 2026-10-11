const $=s=>document.querySelector(s);
let token=localStorage.getItem("novabank_token")||"", me=null, accounts=[];
const money=cents=>(Number(cents||0)/100).toLocaleString("en-IN",{minimumFractionDigits:2,maximumFractionDigits:2});
function notice(msg,error=false){const n=$("#notice");n.textContent=msg;n.classList.remove("hidden","error");if(error)n.classList.add("error");window.scrollTo({top:0,behavior:"smooth"});setTimeout(()=>n.classList.add("hidden"),6500)}
async function api(path,opts={}){const headers={"content-type":"application/json",...(opts.headers||{})};if(token)headers.authorization="Bearer "+token;let res;try{res=await fetch("/api"+path,{...opts,headers});}catch(e){throw new Error("API se connection nahi ho pa raha. Cloudflare par deploy hone ke baad try karein.");}let data={};try{data=await res.json()}catch{}if(!res.ok)throw new Error(data.error||"Request failed");return data}
function formData(form){return Object.fromEntries(new FormData(form).entries())}
function setAuth(show){$("#authPanel").classList.toggle("hidden",!show);$("#dashboard").classList.toggle("hidden",show);$("#logoutBtn").classList.toggle("hidden",show)}
$("#loginForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/login",{method:"POST",body:JSON.stringify(formData(e.target))});token=d.token;localStorage.setItem("novabank_token",token);await loadDashboard();notice("Welcome back to NovaBank.");}catch(err){notice(err.message,true)}});
$("#registerForm").addEventListener("submit",async e=>{e.preventDefault();try{await api("/register",{method:"POST",body:JSON.stringify(formData(e.target))});e.target.reset();notice("Demo account created. Ab sign in karein.");}catch(err){notice(err.message,true)}});
$("#logoutBtn").addEventListener("click",async()=>{try{await api("/logout",{method:"POST",body:"{}"})}catch{}token="";me=null;localStorage.removeItem("novabank_token");setAuth(true);notice("You have been logged out.");});
$("#transferForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=formData(e.target);d.amount=Number(d.amount);const r=await api("/transfer",{method:"POST",body:JSON.stringify(d)});e.target.reset();await loadDashboard();notice(r.message)}catch(err){notice(err.message,true)}});
$("#loanForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=formData(e.target);["requestedAmount","monthlyIncome","monthlyExpenses","existingEmi","tenureMonths"].forEach(k=>d[k]=Number(d[k]||0));const r=await api("/loans",{method:"POST",body:JSON.stringify(d)});e.target.reset();closeApplicationModal();await loadDashboard();notice(`${r.message} Suggested eligibility: N₹${money(r.suggestedEligibility*100)}. This is only a demo estimate.`)}catch(err){notice(err.message,true)}});
$("#cardForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=formData(e.target);["requestedLimit","monthlyIncome","monthlyExpenses","existingDebt"].forEach(k=>d[k]=Number(d[k]||0));const r=await api("/cards",{method:"POST",body:JSON.stringify(d)});e.target.reset();closeApplicationModal();await loadDashboard();notice(`${r.message} Suggested limit: N₹${money(r.suggestedLimit*100)}.`)}catch(err){notice(err.message,true)}});
$("#refreshAdmin").addEventListener("click",()=>loadAdmin().catch(e=>notice(e.message,true)));
$("#offerForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=formData(e.target);await api("/admin/offers",{method:"POST",body:JSON.stringify(d)});e.target.reset();await loadOffers();notice("Demo offer published.");}catch(err){notice(err.message,true)}});
async function loadOffers(){const d=await api("/offers");const offers=d.offers||[];const grid=$("#offersGrid");grid.innerHTML=offers.filter(x=>me?.role==="admin"||Number(x.active)===1).map(x=>`<article class="offer-card"><div class="offer-top"><span class="offer-category">${esc(x.category)}</span><span class="offer-star">✦</span></div><h3>${esc(x.title)}</h3><p>${esc(x.description)}</p>${x.benefit?`<div class="offer-benefit">${esc(x.benefit)}</div>`:""}<button class="btn ${x.category==="Personal Loan"?"primary":"secondary"}" type="button" onclick="offerAction('${esc(x.category)}')">${esc(x.cta_label||"Explore offer")} →</button></article>`).join("")||'<p class="empty">No active offers right now.</p>';
const admin=$("#adminOffers");if(admin)admin.innerHTML=me?.role==="admin"?offers.map(x=>`<div class="activity-item"><div><strong>${esc(x.title)}</strong><small>${esc(x.category)} · ${Number(x.active)===1?"Active":"Inactive"}</small></div><button class="btn ghost" type="button" onclick="toggleOffer('${esc(x.id)}',${Number(x.active)===1?"false":"true"})">${Number(x.active)===1?"Deactivate":"Activate"}</button></div>`).join(""):'<p class="empty">Admin access required.</p>';
}
function openApplicationModal(type){
  const modal=$("#applicationModal");
  $("#loanApplicationContent").classList.toggle("hidden",type!=="loan");
  $("#cardOfferDetails").classList.toggle("hidden",type!=="card-details");
  $("#cardApplicationContent").classList.toggle("hidden",type!=="card-form");
  $("#modalTitle").textContent=type==="loan"?"Nova Flexi Loan": "Nova Rewards Card";
  $("#modalSubtitle").textContent=type==="loan"?"Apply for a fictional demo loan. Approval is not guaranteed.":"Fictional card application for learning and play only.";
  modal.classList.remove("hidden");
  document.body.classList.add("modal-open");
  const focusTarget=type==="loan"?$("#loanForm input"):type==="card-form"?$("#cardForm input"):$("#continueCardApplication");
  setTimeout(()=>focusTarget?.focus(),50);
}
function closeApplicationModal(){
  $("#applicationModal").classList.add("hidden");
  document.body.classList.remove("modal-open");
}
window.offerAction=(category)=>{
  if(category==="Personal Loan") openApplicationModal("loan");
  else if(category==="Credit Card") openApplicationModal("card-details");
  else if(category==="Shopping"||category==="Rewards") notice("This is a fictional simulator offer. Rewards are not real money.");
  else notice("This is a fictional simulator offer for learning and play.");
};
$("#closeApplicationModal").addEventListener("click",closeApplicationModal);
$("#backToDashboard").addEventListener("click",closeApplicationModal);
$("#continueCardApplication").addEventListener("click",()=>openApplicationModal("card-form"));
$("#applicationModal").addEventListener("click",e=>{if(e.target.id==="applicationModal")closeApplicationModal();});
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&!$("#applicationModal").classList.contains("hidden"))closeApplicationModal();});
window.toggleOffer=async(id,active)=>{try{await api(`/admin/offers/${id}`,{method:"PATCH",body:JSON.stringify({active})});await loadOffers();notice(active?"Offer activated.":"Offer deactivated.");}catch(e){notice(e.message,true)}};
async function loadDashboard(){const d=await api("/me");me=d.user;setAuth(false);$("#userName").textContent=me.display_name||me.displayName||me.username;$("#roleBadge").textContent=me.role.toUpperCase();$("#adminPanel").classList.toggle("hidden",me.role!=="admin");
const [a,t,l,c]=await Promise.all([api("/accounts"),api("/transactions"),api("/loans"),api("/cards")]);accounts=a.accounts||[];const total=accounts.reduce((s,x)=>s+Number(x.balance||0),0);$("#balance").textContent=money(total);$("#heroBalance").textContent=money(total);$("#txCount").textContent=(t.transactions||[]).length;$("#loanCount").textContent=(l.applications||[]).length;$("#cardCount").textContent=(c.applications||[]).length;
$("#accountNumber").textContent=accounts[0]?`Account • ${accounts[0].account_number}`:"No account";$("#fromAccount").innerHTML=accounts.filter(x=>x.status==="active").map(x=>`<option value="${esc(x.id)}">${esc(x.account_number)} · N₹${money(x.balance)}</option>`).join("")||"<option value=''>No active account</option>";
$("#transactions").innerHTML=(t.transactions||[]).slice(0,8).map(x=>`<div class="activity-item"><div><strong>${esc(x.description||x.type)}</strong><small>${esc(x.created_at||"")}</small></div><span class="amount ${String(x.type).includes("in")||x.type==="deposit"?"positive":"negative"}">${String(x.type).includes("in")||x.type==="deposit"?"+":"−"} N₹${money(x.amount)}</span></div>`).join("")||'<p class="empty">No transactions yet. This is a fresh demo account.</p>';
$("#applications").innerHTML=[...(l.applications||[]).map(x=>({kind:"Loan",amount:x.requested_amount,status:x.status,date:x.created_at})),...(c.applications||[]).map(x=>({kind:"Virtual card",amount:x.requested_limit,status:x.status,date:x.created_at}))].map(x=>`<div class="activity-item"><div><strong>${x.kind} · N₹${money(x.amount)}</strong><small>${esc(x.date||"")}</small></div><span class="status">${esc(x.status)}</span></div>`).join("")||'<p class="empty">No applications yet.</p>';
await loadOffers();if(me.role==="admin")await loadAdmin();}
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
async function loadAdmin(){const [l,c]=await Promise.all([api("/loans"),api("/cards")]);const items=[...(l.applications||[]).map(x=>({...x,kind:"loans",amount:x.requested_amount,limitName:"sanctionedAmount"})),...(c.applications||[]).map(x=>({...x,kind:"cards",amount:x.requested_limit,limitName:"sanctionedLimit"}))];$("#adminQueue").innerHTML=items.map(x=>`<div class="activity-item" style="display:block"><div><strong>${esc(x.kind==="loans"?"Loan":"Virtual card")} · ${esc(x.display_name||x.username||"Customer")}</strong><small>Requested N₹${money(x.amount)} · Suggested N₹${money(x.eligible_suggestion??x.suggested_limit)} · ${esc(x.created_at)}</small><span class="status">${esc(x.status)}</span></div><div class="review-controls"><select id="status-${esc(x.id)}"><option value="verified">Verify</option><option value="need_documents">Need documents</option><option value="approved">Approve</option><option value="rejected">Reject</option></select><input id="amount-${esc(x.id)}" type="number" min="1" placeholder="Sanction N₹"><input id="note-${esc(x.id)}" placeholder="Admin note / reason"><button class="btn secondary" onclick="reviewApp('${esc(x.kind)}','${esc(x.id)}','${x.limitName}')">Save review</button></div></div>`).join("")||'<p class="empty">No applications in the queue.</p>'}
window.reviewApp=async(kind,id,limitName)=>{try{const status=$("#status-"+id).value, amount=Number($("#amount-"+id).value||0), note=$("#note-"+id).value;const d={status,note};if(status==="approved")d[limitName]=amount;await api(`/admin/${kind}/${id}/review`,{method:"POST",body:JSON.stringify(d)});await loadDashboard();notice("Application review saved and customer notified.")}catch(e){notice(e.message,true)}};
(async()=>{if(token){try{await loadDashboard()}catch(e){token="";localStorage.removeItem("novabank_token");setAuth(true);notice(e.message,true)}}else setAuth(true)})();
