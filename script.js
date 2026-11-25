(() => {
  "use strict";
  const input = document.getElementById("entry");
  const label = document.getElementById("input-label");
  const hint = document.getElementById("hint");
  const count = document.getElementById("count");
  const result = document.getElementById("result");
  const analyzeButton = document.getElementById("analyze");
  let mode = "message";
  const LIVE_CHECK_ENDPOINT = "https://safecheck-ai.mexiaeon.workers.dev";
  let liveLookupConfigured = false;

  const modes = {
    message: ["Paste the suspicious text message", "Remove passwords, account numbers, and private information first.", "Example: Your account will be suspended. Verify your details now..."],
    email: ["Paste the email text (remove private details)", "Never include passwords, verification codes, or full account details.", "Example: Your invoice is overdue. Open the attached file..."],
    url: ["Paste the website address", "Do not open the link. Paste the address as text only.", "https://example.com/page"]
  };

  const rules = [
    { id:"urgency", points:18, title:"Urgency or threat", detail:"The message pressures you to act immediately or threatens a negative consequence.", re:/\b(urgent(?:ly)?|immediately|act now|final warning|within\s*\d+\s*hours?|account.{0,30}(?:suspend|close|lock|terminat)|suspend(?:ed|sion)?|limited time|last chance|avoid (?:a )?penalty)\b/i },
    { id:"credential", points:25, title:"Password or verification-code request", detail:"It asks for a password, one-time code, PIN, or account verification. Never share these in response to an unexpected message.", re:/\b(password|passcode|one[- ]time (?:pass)?code|verification code|security code|2fa code|otp|pin number|login credentials|verify your identity|confirm your password)\b/i },
    { id:"personal", points:18, title:"Sensitive personal information", detail:"It appears to request sensitive identity or financial information.", re:/\b(social security(?: number)?|\bssn\b|date of birth|driver'?s license|bank account number|routing number|credit card details|full card number|tax id|taxpayer id)\b/i },
    { id:"payment", points:22, title:"Unexpected payment or fee", detail:"It requests money, a fee, a transfer, or payment to resolve an unexpected problem.", re:/\b(pay (?:a |the )?(?:small |processing |release |delivery |customs )?fee|small fee|payment required|processing fee|release fee|delivery fee|customs fee|wire transfer|bank transfer|send (?:the )?money|pay(?:ment)? outstanding|overdue invoice|past due balance|reconfirm payment|payment failed)\b/i },
    { id:"account-threat", points:20, title:"Account or delivery threat", detail:"A claim that an account or delivery will be blocked can pressure you into acting before checking independently.", re:/\b(package|parcel|delivery|account|subscription|payment)\b.{0,55}\b(on hold|held|suspended|blocked|failed|will be returned|will be cancelled|will be closed)\b|\b(on hold|held|suspended|blocked)\b.{0,55}\b(package|parcel|delivery|account|subscription)\b/i },
    { id:"fake-refund", points:18, title:"Unexpected refund or overpayment", detail:"Unexpected refund notices or requests to return an overpayment can be used to steal money or payment details.", re:/\b(refund (?:is )?pending|claim your refund|overpaid you|overpayment|refund verification|receive your refund)\b/i },
    { id:"advance-fee", points:24, title:"Upfront fee to receive money or a benefit", detail:"Being asked to pay first to receive a prize, job earnings, a loan, or a package is a common scam pattern.", re:/\b(pay|send|deposit)\b.{0,45}\b(to receive|to release|to unlock|to claim|before you can withdraw)\b|\b(release|unlock|claim)\b.{0,35}\b(funds|earnings|prize|package|loan)\b/i },
    { id:"irreversible", points:28, title:"Hard-to-reverse payment method", detail:"Gift cards, cryptocurrency, wire transfers, or payment apps can be difficult to recover once sent.", re:/\b(gift cards?|itunes cards?|google play cards?|steam cards?|bitcoin|\bcrypto(?:currency)?\b|usdt|ethereum|wire transfer|western union|moneygram|cash app|zelle|venmo)\b/i },
    { id:"prize", points:18, title:"Unexpected prize or reward", detail:"Unexpected prizes, giveaways, or guaranteed rewards are commonly used to draw people into scams.", re:/\b(you (?:have )?won|winner|claim your (?:prize|reward)|free money|lottery|sweepstakes|guaranteed (?:profit|return)|risk[- ]free investment)\b/i },
    { id:"remote", points:25, title:"Remote-access or device-control request", detail:"A stranger asking you to install remote-access software or give device access is a serious warning sign.", re:/\b(anydesk|teamviewer|remote access|screen sharing|install (?:this )?app|download (?:this )?software|give me access to your (?:computer|phone|device))\b/i },
    { id:"impersonation", points:16, title:"Possible organization impersonation", detail:"The message claims to represent a bank, government agency, delivery company, or well-known service. Verify using its official app or website.", re:/\b(irs|social security administration|ssa|amazon|paypal|microsoft|apple support|netflix|fedex|ups|usps|bank security|fraud department|police department)\b/i },
    { id:"linkprompt", points:18, title:"Prompt to click a link", detail:"Unexpected links can lead to fake sign-in pages or malware. Navigate to the organization independently instead.", re:/\b(click here|tap (?:this|the) link|open (?:this|the) link|follow this link|verify (?:your )?account|sign in (?:here|now)|track your package|use the link|visit (?:this|the) link|click (?:the )?link|view (?:the )?(?:message|invoice|document)|update (?:your )?(?:payment|account)|confirm (?:your )?(?:details|information|password))\b/i },
    { id:"secrecy", points:20, title:"Secrecy or isolation pressure", detail:"Requests to keep a transaction secret or avoid speaking to others are a major warning sign.", re:/\b(keep (?:this )?secret|don't tell anyone|do not tell anyone|秘密|stay on the line|do not hang up|don't contact your bank|do not contact your bank)\b/i },
    { id:"job", points:26, title:"Unusual job or task offer", detail:"Paying money to get hired, unlock tasks, receive commissions, or withdraw earnings is a common job and task-scam pattern.", re:/\b(task (?:job|work)|pay to start|deposit to withdraw|unlock (?:your )?(?:earnings|tasks)|commission (?:tasks|job)|product boosting|optimization tasks|reshipping|package forwarding|pay (?:an )?(?:application|registration|training|equipment) fee|job offer.{0,45}(?:deposit|fee|payment)|earnings.{0,35}(?:deposit|fee|unlock)|withdraw.{0,35}(?:deposit|fee))\b/i },
    { id:"romance", points:26, title:"Emotional or relationship-based money request", detail:"An online romantic contact asking for money, travel costs, medical bills, emergency help, investments, or gift cards deserves independent verification.", re:/\b(send me money|send (?:you )?money|help me with (?:a )?(?:ticket|medical bill|emergency|rent|bills)|medical bill|emergency funds|emergency ticket|flight ticket|travel (?:costs|expenses)|let\x27s invest together|need gift cards|gift cards? for (?:me|my)|invest(?:ment)? opportunity.{0,35}(?:together|send|transfer))\b/i },
  ];

  const brandDomains = {
    paypal:["paypal.com"], amazon:["amazon.com"], apple:["apple.com"], microsoft:["microsoft.com"], google:["google.com"], netflix:["netflix.com"], usps:["usps.com"], fedex:["fedex.com"], ups:["ups.com"], chase:["chase.com"], bankofamerica:["bankofamerica.com"]
  };
  const knownShorteners = new Set(["bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rebrand.ly","shorturl.at","rb.gy","ow.ly","buff.ly"]);
  const suspiciousTlds = new Set(["zip","mov","top","xyz","click","work","country","gq","tk","ml","cf"]);
  const $ = (tag, cls, text) => { const el=document.createElement(tag); if(cls) el.className=cls; if(text!==undefined) el.textContent=text; return el; };

  function extractUrls(text) {
    const pattern = /(?:https?:\/\/|www\.)[^\s<>"'\])}]+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:\/[^\s<>"'\])}]+)?/gi;
    return [...new Set((text.match(pattern) || []).map(x => x.replace(/[.,!?;:]+$/,"")))].slice(0,10);
  }
  function inspectUrl(raw) {
    const findings=[];
    let url;
    try {
      const cleaned=raw.trim().replace(/^www\./i,"https://www.");
      url=new URL(cleaned.includes("://")?cleaned:"https://"+cleaned);
    } catch { return [{id:"invalid-url",points:8,title:"Address format is unusual",detail:"The address could not be parsed reliably. Do not open it just to test it."}]; }
    const host=url.hostname.toLowerCase().replace(/\.$/,"");
    const labels=host.split(".");
    const add=(id,points,title,detail)=>findings.push({id,points,title,detail});
    if(url.protocol!=="https:") add("no-https",10,"No HTTPS connection","The address does not use HTTPS. This does not prove fraud, but do not enter sensitive information.");
    if(url.username||url.password) add("embedded-credentials",28,"Credentials embedded in the address","The URL contains a username or password section, which can be used to disguise the real destination.");
    if(host.startsWith("xn--")||host.split(".").some(x=>x.startsWith("xn--"))) add("punycode",22,"Encoded domain name","The domain uses an encoded format sometimes used in lookalike-domain attacks. Inspect it carefully.");
    if(/\d+\.\d+\.\d+\.\d+/.test(host)) add("ip-host",20,"Direct IP address","The link points to a numeric IP address instead of a normal domain name.");
    if(knownShorteners.has(host)) add("shortener",12,"Shortened link","The final destination is hidden. Do not follow it unless you can verify the destination independently.");
    if(labels.length>=5) add("deep-subdomain",10,"Unusually deep subdomain","Many subdomain levels can make the registered domain harder to notice. Read the hostname from right to left.");
    if(suspiciousTlds.has(labels[labels.length-1])) add("uncommon-tld",8,"Uncommon top-level domain","This domain ending is used by some legitimate sites too, but deserves extra scrutiny in an unexpected message.");
    if(host.length>45) add("long-domain",7,"Unusually long domain","Long domain names can hide misspellings or misleading brand references.");
    if(/\b(login|verify|secure|account|update|wallet|support|billing|password)\b/i.test(url.pathname+" "+url.search)) add("sensitive-path",7,"Sign-in or account-related URL","The link path contains account or sign-in terms. Verify the domain before entering anything.");
    for(const [brand,domains] of Object.entries(brandDomains)) {
      if(host.includes(brand) && !domains.some(d=>host===d||host.endsWith("."+d))) {
        add("brand-lookalike-"+brand,25,"Possible "+brand+" lookalike domain","The address mentions "+brand+" but does not use its known official domain. This can be an impersonation attempt.");
        break;
      }
    }
    if(/%[0-9a-f]{2}/i.test(url.pathname+url.search) && /%2f|%5c|%40|%2e/i.test(url.pathname+url.search)) add("encoded-url",8,"Encoded URL characters","The address contains encoded separators or symbols that can make its destination harder to read.");
    return findings;
  }

  function analyze(text, selectedMode) {
    const findings=[];
    if(selectedMode==="url") {
      const urls=extractUrls(text);
      if(!urls.length) findings.push(...inspectUrl(text));
      else urls.forEach(u=>findings.push(...inspectUrl(u)));
    } else {
      rules.forEach(rule=>{ if(rule.re.test(text)) findings.push({id:rule.id,points:rule.points,title:rule.title,detail:rule.detail}); });
      extractUrls(text).forEach(u=>findings.push(...inspectUrl(u)));
    }
    const unique=[...new Map(findings.map(f=>[f.id,f])).values()];
    const score=Math.min(100,unique.reduce((sum,f)=>sum+f.points,0));
    const level=score>=55?"high":score>=25?"medium":"low";
    return {score,level,findings:unique};
  }

  function renderReport(report) {
    result.replaceChildren();
    const titles={high:"High concern — stop and verify",medium:"Caution — review before acting",low:"No strong warning pattern found"};
    const intros={
      high:"Several strong warning signals were detected. Do not click, reply, pay, or share information until you verify independently.",
      medium:"Some warning signals were detected. Pause and verify the sender and request through a trusted channel.",
      low:"This engine found few warning signals in the content provided. That is not proof the message or website is legitimate."
    };
    result.className="result risk-"+report.level;
    const header=$("div","report-header");
    header.append($("div","risk-label",titles[report.level]),$("div","score","Signal score: "+report.score+"/100"));
    result.append(header,$("p","report-intro",intros[report.level]));
    if(report.findings.length) {
      const list=$("ul","finding-list");
      report.findings.forEach(f=>{const li=$("li");li.append($("b","",f.title),$("p","",f.detail));list.append(li);});
      result.append(list);
    } else result.append($("p","","No matching warning patterns were identified. Sophisticated scams may not contain obvious keywords."));
    const next=$("div","next-step");
    next.append($("b","","What to do next"),$("p","","Do not use links or phone numbers in the message. Open the company’s official app or type its known website address yourself. For money already sent, contact your bank or payment provider immediately."));
    result.append(next,$("p","engine-note","Local pattern analysis only. Live URL reputation checks are not currently enabled. A low score never means safe."));
    result.hidden=false;
    result.scrollIntoView({behavior:"smooth",block:"nearest"});
  }

  document.querySelectorAll(".tab").forEach(button=>button.addEventListener("click",()=>{
    mode=button.dataset.mode;
    document.querySelectorAll(".tab").forEach(tab=>tab.classList.toggle("active",tab===button));
    label.textContent=modes[mode][0]; hint.textContent=modes[mode][1]; input.placeholder=modes[mode][2];
    input.value=""; count.textContent="0 / 2,000"; result.hidden=true; result.replaceChildren();
  }));
  input.addEventListener("input",()=>{count.textContent=input.value.length+" / 2,000";});
  document.getElementById("year").textContent=new Date().getFullYear();

  async function checkLiveConfiguration() {
    try {
      const response = await fetch(LIVE_CHECK_ENDPOINT + "/health", {headers:{"Accept":"application/json"}});
      if (!response.ok) return;
      const data = await response.json();
      liveLookupConfigured = data.ok === true && data.liveLookupConfigured === true;
    } catch {
      liveLookupConfigured = false;
    }
  }
  checkLiveConfiguration();

  async function runLiveUrlCheck(rawUrl) {
    if (!liveLookupConfigured) {
      result.append($("p","engine-note","Live URL reputation checks are not enabled yet. This report is based on local warning patterns only."));
      return;
    }
    const status = $("p","engine-note","Checking this URL against the live threat database…");
    result.append(status);
    try {
      const response = await fetch(LIVE_CHECK_ENDPOINT + "/check", {
        method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url:rawUrl})
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Live lookup unavailable");
      status.remove();
      const panel = $("div", data.matched ? "live-result live-match" : "live-result live-clear");
      panel.append($("b","",data.matched ? "Live threat database match" : "No match in the live threat database"));
      panel.append($("p","",data.matched ? "The threat database lists this URL as a known unsafe resource. Do not visit it or enter information." : "The threat database did not find this URL on the threat lists checked. This is not proof that the site is safe."));
      result.append(panel);
    } catch (error) {
      status.textContent = "Live lookup unavailable: " + (error.message || "Please try again later.") + ". Local pattern analysis is still shown.";
    }
  }
  analyzeButton.addEventListener("click",async()=>{
    const value=input.value.trim();
    if(!value){input.focus();return;}
    if(value.length>2000)return;
    renderReport(analyze(value,mode));
    if(mode==="url") await runLiveUrlCheck(value);
    else { const urls=extractUrls(value); if(urls.length) await runLiveUrlCheck(urls[0]); }
  });
})();