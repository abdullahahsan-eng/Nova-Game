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
for (const [formId, requestType] of [["#depositForm","deposit"],["#withdrawForm","withdrawal"]]) {
  $(formId).addEventListener("submit",async e=>{
    e.preventDefault();
    try {
      const d=formData(e.target); d.amount=Number(d.amount); d.type=requestType;
      const r=await api("/money-requests",{method:"POST",body:JSON.stringify(d)});
      e.target.reset(); await loadDashboard();
      notice(`${r.message} Request ID: ${r.requestId}`);
    } catch(err) { notice(err.message,true); }
  });
}

["#statementFrom","#statementTo","#statementType"].forEach(sel=>$(sel)?.addEventListener("change",()=>renderStatement(window.__transactions||[])));
$("#exportStatement")?.addEventListener("click",()=>exportStatement());
$("#loanForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=formData(e.target);["requestedAmount","monthlyIncome","monthlyExpenses","existingEmi","tenureMonths"].forEach(k=>d[k]=Number(d[k]||0));const r=await api("/loans",{method:"POST",body:JSON.stringify(d)});e.target.reset();closeApplicationModal();await loadDashboard();notice(`${r.message} Suggested eligibility: N₹${money(r.suggestedEligibility*100)}. This is only a demo estimate.`)}catch(err){notice(err.message,true)}});
$("#cardForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=formData(e.target);["requestedLimit","monthlyIncome","monthlyExpenses","existingDebt"].forEach(k=>d[k]=Number(d[k]||0));const r=await api("/cards",{method:"POST",body:JSON.stringify(d)});e.target.reset();closeApplicationModal();await loadDashboard();notice(`${r.message} Suggested limit: N₹${money(r.suggestedLimit*100)}.`)}catch(err){notice(err.message,true)}});
$("#refreshAdmin").addEventListener("click",()=>Promise.all([loadAdmin(),loadMoneyRequests()]).catch(e=>notice(e.message,true)));
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
function displayDate(value){
  if(!value) return "Not available";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleDateString("en-IN",{day:"2-digit",month:"short",year:"numeric"});
}
function renderAccountInfo(){
  const account = accounts[0] || {};
  $("#infoDisplayName").textContent = me?.display_name || me?.displayName || me?.username || "—";
  $("#infoUsername").textContent = me?.username || "—";
  $("#infoEmail").textContent = me?.email || "—";
  $("#infoCustomerId").textContent = me?.id ? String(me.id).slice(0,8).toUpperCase() : "—";
  $("#infoAccountNumber").textContent = account.account_number || "No account found";
  $("#infoAccountType").textContent = account.account_type || account.type || "Everyday Demo Account";
  $("#infoAccountStatus").innerHTML = `<span class="status ${account.status==="active"?"status-active":""}">${esc(account.status || "Unknown")}</span>`;
  $("#infoOpenedAt").textContent = displayDate(account.opened_at || account.created_at);
  $("#infoBalance").textContent = "N₹ " + money(accounts.reduce((sum,a)=>sum+Number(a.balance||0),0));
}
$("#copyAccountNumber")?.addEventListener("click",async()=>{
  const accountNumber = accounts[0]?.account_number;
  if(!accountNumber){notice("Account number is not available.",true);return;}
  try{ await navigator.clipboard.writeText(accountNumber); notice("Account number copied."); }
  catch{ notice("Copy is unavailable in this browser. Account number: " + accountNumber, true); }
});
async function loadDashboard(){const d=await api("/me");me=d.user;setAuth(false);$("#userName").textContent=me.display_name||me.displayName||me.username;$("#roleBadge").textContent=me.role.toUpperCase();$("#adminPanel").classList.toggle("hidden",me.role!=="admin");
const [a,t,l,c,p]=await Promise.all([api("/accounts"),api("/transactions"),api("/loans"),api("/cards"),api("/products")]);accounts=a.accounts||[];const total=accounts.reduce((s,x)=>s+Number(x.balance||0),0);$("#balance").textContent=money(total);$("#heroBalance").textContent=money(total);renderAccountInfo();$("#txCount").textContent=(t.transactions||[]).length;$("#loanCount").textContent=(l.applications||[]).length;$("#cardCount").textContent=(c.applications||[]).length;
$("#accountNumber").textContent=accounts[0]?`Account • ${accounts[0].account_number}`:"No account";$("#fromAccount").innerHTML=accounts.filter(x=>x.status==="active").map(x=>`<option value="${esc(x.id)}">${esc(x.account_number)} · N₹${money(x.balance)}</option>`).join("")||"<option value=''>No active account</option>";
const accountOptions=accounts.filter(x=>x.status==="active").map(x=>`<option value="${esc(x.id)}">${esc(x.account_number)} · N₹${money(x.balance)}</option>`).join("")||"<option value=''>No active account</option>";["#depositAccount","#withdrawAccount"].forEach(sel=>{if($(sel))$(sel).innerHTML=accountOptions});
$("#transactions").innerHTML=(t.transactions||[]).slice(0,8).map(x=>`<div class="activity-item"><div><strong>${esc(x.description||x.type)}</strong><small>${esc(x.created_at||"")}</small></div><span class="amount ${String(x.type).includes("in")||x.type==="deposit"?"positive":"negative"}">${String(x.type).includes("in")||x.type==="deposit"?"+":"−"} N₹${money(x.amount)}</span></div>`).join("")||'<p class="empty">No transactions yet. This is a fresh demo account.</p>';
window.__transactions=t.transactions||[];renderStatement(window.__transactions);
renderApplications(l.applications||[],c.applications||[]);renderProducts(p,l.applications||[],c.applications||[]);
await loadOffers();await loadMoneyRequests();if(me.role==="admin")await loadAdmin();}
function transactionDirection(x){const t=String(x.type||"").toLowerCase();return (t.includes("in")||["deposit","loan_disbursement","refund","credit"].includes(t))?"credit":"debit"}
function filteredStatement(rows){const from=$("#statementFrom")?.value||"",to=$("#statementTo")?.value||"",type=$("#statementType")?.value||"all";return rows.filter(x=>{const date=String(x.created_at||"").slice(0,10);return (!from||date>=from)&&(!to||date<=to)&&(type==="all"||transactionDirection(x)===type)}).sort((a,b)=>String(b.created_at||"").localeCompare(String(a.created_at||"")))}
function renderStatement(rows){const filtered=filteredStatement(rows||[]);const credits=filtered.filter(x=>transactionDirection(x)==="credit").reduce((n,x)=>n+Number(x.amount||0),0);const debits=filtered.filter(x=>transactionDirection(x)==="debit").reduce((n,x)=>n+Number(x.amount||0),0);const summary=$("#statementSummary");if(summary)summary.innerHTML=`<span>Entries <b>${filtered.length}</b></span><span>Credits <b class="positive">N₹ ${money(credits)}</b></span><span>Debits <b class="negative">N₹ ${money(debits)}</b></span>`;const tbody=$("#statementRows");if(!tbody)return;tbody.innerHTML=filtered.map(x=>`<tr><td>${esc(displayDate(x.created_at)||"—")}</td><td>${esc(x.description||x.type||"Transaction")}</td><td>${esc(String(x.type||"").replaceAll("_"," "))}</td><td class="${transactionDirection(x)==="credit"?"positive":"negative"}">${transactionDirection(x)==="credit"?"+":"−"} N₹ ${money(x.amount)}</td><td>N₹ ${money(x.balance_after)}</td></tr>`).join("")||'<tr><td colspan="5">No transactions match these filters.</td></tr>'}
function exportStatement(){const rows=filteredStatement(window.__transactions||[]);const cells=[["Date","Description","Type","Direction","Amount (N₹)","Balance after (N₹)","Account number"],...rows.map(x=>[x.created_at||"",x.description||"",x.type||"",transactionDirection(x),Number(x.amount||0)/100,Number(x.balance_after||0)/100,x.account_number||""])];const csv=cells.map(row=>row.map(v=>`"${String(v??"").replaceAll('"','""')}"`).join(",")).join("\r\n");const blob=new Blob(["\ufeff"+csv],{type:"text/csv;charset=utf-8;"});const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download="NovaBank-demo-statement.csv";document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);notice("CSV demo statement downloaded.")}
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function statusInfo(status){
 const map={pending:["Submitted","Your application has been received and is waiting for review."],need_documents:["More information needed","The review team needs more information. Check the admin note."],verified:["Documents verified","Your demo application details have been checked; a decision is still pending."],approved:["Approved","An offer is available. Review the sanctioned amount/limit before continuing."],accepted:["Offer accepted","Your offer has been accepted."],disbursed:["Active / disbursed","The demo loan amount has been added to your demo account."],active:["Active","Your virtual demo card is active."],rejected:["Not approved","This request was not approved. Read the note or apply again with updated details."],closed:["Closed","This demo product is closed."],blocked:["Blocked","This demo card is blocked."]};return map[status]||[String(status||"Unknown"),"Status updated by the simulator."];
}
function renderApplications(loans,cards){
 const items=[...loans.map(x=>({...x,kind:"Loan",amount:x.requested_amount,approved:x.sanctioned_amount,submitted:x.created_at,note:x.admin_note,unit:"loan"})),...cards.map(x=>({...x,kind:"Credit card",amount:x.requested_limit,approved:x.sanctioned_limit,submitted:x.created_at,note:x.admin_note,unit:"card"}))].sort((a,b)=>String(b.submitted||"").localeCompare(String(a.submitted||"")));
 $("#applications").innerHTML=items.map(x=>{const info=statusInfo(x.status);const isLoan=x.unit==="loan";const requested=money(x.amount);const sanctioned=x.approved==null?"Not decided":money(x.approved);const stages=isLoan?["pending","verified","approved","disbursed"]:["pending","verified","approved","active"];const pos=stages.indexOf(x.status);const stageIndex=x.status==="need_documents"?1:x.status==="rejected"?-1:Math.max(0,pos);return `<article class="application-track"><div class="application-track-head"><div><strong>${x.kind}</strong><small>Submitted ${esc(displayDate(x.submitted))}</small></div><span class="status status-${esc(x.status)}">${esc(info[0])}</span></div><div class="application-amounts"><span>Requested <b>N₹ ${requested}</b></span><span>${isLoan?"Sanctioned amount":"Sanctioned limit"} <b>${x.approved==null?"—":"N₹ "+sanctioned}</b></span></div><div class="timeline">${stages.map((s,i)=>`<div class="timeline-step ${x.status!=="rejected"&&i<=stageIndex?"done":""}"><i></i><span>${esc(statusInfo(s)[0])}</span></div>`).join("")}</div><p class="application-status-copy">${esc(info[1])}</p>${x.note?`<p class="admin-note"><b>Review note:</b> ${esc(x.note)}</p>`:""}${isLoan&&x.status==="approved"?`<button class="btn primary full-btn" type="button" onclick="acceptDemoLoan('${esc(x.id)}')">Accept &amp; disburse demo loan →</button>`:""}</article>`}).join("")||'<p class="empty">No applications yet. Explore Offers for You to apply for a demo loan or credit card.</p>';
}
function renderProducts(products,loans,cards){
 const account=accounts[0];const debit=account?`<article class="product-card debit-product"><div class="product-card-top"><span class="product-chip">DEBIT · DEMO</span><span class="product-status">${esc(account.status||"active")}</span></div><div class="demo-card-brand">Nova<span>Bank</span></div><div class="masked-card-number">•••• &nbsp;•••• &nbsp;•••• &nbsp;${esc(String(account.account_number||"").slice(-4))}</div><div class="product-card-bottom"><div><small>ACCOUNT HOLDER</small><b>${esc(me?.display_name||me?.displayName||me?.username||"Customer")}</b></div><div><small>LINKED ACCOUNT</small><b>${esc(String(account.account_number||""))}</b></div></div><p class="tiny muted">Fictional debit card preview only. No real card number or payment network.</p></article>`:`<div class="product-empty"><h4>Demo debit card</h4><p>No account is linked yet.</p></div>`;
 const loanCards=(products.loans||[]).map(x=>`<article class="product-summary"><div class="product-summary-head"><span class="product-type">PERSONAL LOAN</span><span class="status">${esc(x.status)}</span></div><h4>Nova Flexi Loan</h4><div class="product-metrics"><div><small>Outstanding</small><b>N₹ ${money(x.outstanding_amount)}</b></div><div><small>Monthly demo EMI</small><b>N₹ ${money(x.monthly_payment)}</b></div><div><small>Tenure remaining</small><b>${Number(x.remaining_months)} months</b></div></div>${x.status==="active"?`<button class="btn secondary full-btn" type="button" onclick="repayDemoLoan('${esc(x.id)}')">Pay monthly demo EMI →</button>`:'<p class="tiny muted">This demo loan is closed.</p>'}</article>`).join("");
 const approvedCards=(products.cards||[]).map(x=>`<article class="product-summary"><div class="product-summary-head"><span class="product-type">VIRTUAL CREDIT</span><span class="status">${esc(x.status)}</span></div><h4>Nova Rewards Card</h4><div class="masked-card-number small-mask">${esc(x.masked_number||"•••• •••• •••• ••••")}</div><div class="product-metrics"><div><small>Approved limit</small><b>N₹ ${money(x.credit_limit)}</b></div><div><small>Outstanding</small><b>N₹ ${money(x.outstanding)}</b></div><div><small>Available credit</small><b>N₹ ${money(Math.max(0,Number(x.credit_limit||0)-Number(x.outstanding||0)))}</b></div></div><p class="tiny muted">Virtual simulator card; no real payment network.</p></article>`).join("");
 const noApproved=!(products.loans||[]).length&&!(products.cards||[]).length;
 $("#productsGrid").innerHTML=debit+loanCards+approvedCards+(noApproved?`<div class="product-empty"><h4>No active loan or credit card yet</h4><p>When an application is approved, it will appear here with your sanctioned amount/limit, outstanding and remaining tenure.</p><button class="btn secondary full-btn" type="button" onclick="document.querySelector('.offers-section').scrollIntoView({behavior:'smooth',block:'start'})">Explore offers →</button></div>`:"");
}
window.acceptDemoLoan=async(id)=>{if(!confirm("Accept this fictional loan and add the demo amount to your NovaBank demo account?"))return;try{const r=await api(`/loans/${id}/accept`,{method:"POST",body:"{}"});await loadDashboard();notice(r.message||"Demo loan activated.")}catch(e){notice(e.message,true)}};
window.repayDemoLoan=async(id)=>{if(!confirm("Pay one scheduled demo EMI from your NovaBank demo balance?"))return;try{const r=await api(`/loans/${id}/repay`,{method:"POST",body:"{}"});await loadDashboard();notice(r.message||"Demo EMI recorded.")}catch(e){notice(e.message,true)}};
function updateEstimates(){
 const val=id=>Math.max(0,Number($(id)?.value||0));
 const income=val("#loanIncome"), expenses=val("#loanExpenses"), emi=val("#loanExistingEmi"), tenure=Math.max(1,val('#loanForm [name="tenureMonths"]')||12), ask=val("#loanRequestedAmount");
 const free=Math.max(0,income-expenses-emi);const eligible=Math.min(ask||Infinity,Math.floor(free*tenure*.30));
 $("#loanEstimate").textContent=`Estimated affordable demo amount: N₹ ${money((Number.isFinite(eligible)?eligible:0)*100)} · Based on income − expenses − existing EMIs, over ${tenure} months. This is an estimate, not approval.`;
 const ci=val("#cardIncome"),ce=val("#cardExpenses"),debt=val("#cardExistingDebt"),request=val("#cardRequestedLimit");const limit=Math.min(request||Infinity,Math.max(0,Math.floor((ci-ce-debt)*3)));
 $("#cardEstimate").textContent=`Estimated demo credit limit: N₹ ${money((Number.isFinite(limit)?limit:0)*100)} · Considers income, expenses and existing outstanding. Final limit may be lower or the application may be declined.`;
}
["#loanRequestedAmount","#loanIncome","#loanExpenses","#loanExistingEmi",'#loanForm [name="tenureMonths"]',"#cardRequestedLimit","#cardIncome","#cardExpenses","#cardExistingDebt"].forEach(s=>$(s)?.addEventListener("input",updateEstimates));

async function loadMoneyRequests(){
 const d=await api("/money-requests"); const items=d.requests||[]; const box=$("#moneyRequests");
 box.innerHTML=items.map(x=>`<article class="activity-item money-request-item"><div><strong>${esc(x.type==="deposit"?"Deposit request":"Withdrawal request")} · N₹${money(x.amount)}</strong><small>Ref: ${esc(x.id)} · ${esc(x.account_number||"")} · ${esc(x.created_at||"")}</small><small>${esc(x.description||"No note provided")}</small></div><span class="status status-${esc(x.status)}">${esc(x.status)}</span>${x.admin_note?`<small>Admin note: ${esc(x.admin_note)}</small>`:""}</article>`).join("")||'<p class="empty">No deposit or withdrawal requests yet.</p>';
 if(me?.role==="admin"){
   const admin=await api("/admin/money-requests"); const q=admin.requests||[]; const target=$("#adminMoneyRequests");
   target.innerHTML=q.map(x=>`<article class="money-review-card"><div class="activity-item"><div><strong>${esc(x.type==="deposit"?"Deposit":"Withdrawal")} · N₹${money(x.amount)}</strong><small>Customer: ${esc(x.display_name||x.username||"Customer")} · Account: ${esc(x.account_number||"")}</small><small>Request ID: ${esc(x.id)}</small><small>Submitted: ${esc(x.created_at||"")} · ${esc(x.description||"No note")}</small></div><span class="status status-${esc(x.status)}">${esc(x.status)}</span></div>${x.status==="pending"?`<label>Admin note (optional)<input id="money-note-${esc(x.id)}" maxlength="250" placeholder="Reason or review note"></label><div class="review-controls"><button class="btn primary" type="button" onclick="reviewMoneyRequest('${esc(x.id)}','approved')">Approve &amp; ${x.type==="deposit"?"credit":"debit"} demo balance</button><button class="btn ghost" type="button" onclick="reviewMoneyRequest('${esc(x.id)}','rejected')">Reject</button></div>`:x.admin_note?`<p class="tiny muted">Review note: ${esc(x.admin_note)}</p>`:""}</article>`).join("")||'<p class="empty">No money requests waiting for review.</p>';
 }
}
window.reviewMoneyRequest=async(id,status)=>{try{const note=$("#money-note-"+id)?.value||"";const r=await api(`/admin/money-requests/${encodeURIComponent(id)}/review`,{method:"POST",body:JSON.stringify({status,note})});await loadDashboard();notice(r.message||`Request ${status}.`);}catch(e){notice(e.message,true)}};
async function loadAdmin(){const [l,c]=await Promise.all([api("/loans"),api("/cards")]);const items=[...(l.applications||[]).map(x=>({...x,kind:"loans",amount:x.requested_amount,limitName:"sanctionedAmount"})),...(c.applications||[]).map(x=>({...x,kind:"cards",amount:x.requested_limit,limitName:"sanctionedLimit"}))];$("#adminQueue").innerHTML=items.map(x=>`<div class="activity-item" style="display:block"><div><strong>${esc(x.kind==="loans"?"Loan":"Virtual card")} · ${esc(x.display_name||x.username||"Customer")}</strong><small>Requested N₹${money(x.amount)} · Suggested N₹${money(x.eligible_suggestion??x.suggested_limit)} · ${esc(x.created_at)}</small><span class="status">${esc(x.status)}</span></div><div class="review-controls"><select id="status-${esc(x.id)}"><option value="verified">Verify</option><option value="need_documents">Need documents</option><option value="approved">Approve</option><option value="rejected">Reject</option></select><input id="amount-${esc(x.id)}" type="number" min="1" placeholder="Final sanctioned N₹" title="Set the final amount/limit after reviewing affordability"><input id="note-${esc(x.id)}" placeholder="Admin note / reason"><button class="btn secondary" onclick="reviewApp('${esc(x.kind)}','${esc(x.id)}','${x.limitName}')">Save review</button></div></div>`).join("")||'<p class="empty">No applications in the queue.</p>'}
window.reviewApp=async(kind,id,limitName)=>{try{const status=$("#status-"+id).value, amount=Number($("#amount-"+id).value||0), note=$("#note-"+id).value;const d={status,note};if(status==="approved")d[limitName]=amount;await api(`/admin/${kind}/${id}/review`,{method:"POST",body:JSON.stringify(d)});await loadDashboard();notice("Application review saved and customer notified.")}catch(e){notice(e.message,true)}};
(async()=>{if(token){try{await loadDashboard()}catch(e){token="";localStorage.removeItem("novabank_token");setAuth(true);notice(e.message,true)}}else setAuth(true)})();
