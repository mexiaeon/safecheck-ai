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

  // Context-aware detection: identify requests and combinations, not isolated brand keywords.
  function detectMessage(text) {
    const t = text.toLowerCase().replace(/\s+/g," ").trim();
    const findings = [];
    const add = (id, severity, title, detail) => {
      if (!findings.some(f => f.id === id)) findings.push({id, points:severity, title, detail});
    };
    const has = re => re.test(t);
    const credential = /\b(password|passcode|one[- ]time (?:pass)?code|verification code|security code|2fa code|otp|pin number|login credentials)\b/i;
    const asksCredential = has(/\b(?:what(?:'s|s| is) your|tell (?:me|us) your|send (?:me|us)|share|reply with|provide|enter(?:ing)?|submit|confirm|give (?:me|us)|type in|text me)\b.{0,85}\b(?:password|passcode|one[- ]time (?:pass)?code|verification code|security code|2fa code|otp|pin number|login credentials)\b/i) ||
      has(/\b(?:password|passcode|one[- ]time (?:pass)?code|verification code|security code|2fa code|otp|pin number|login credentials)\b.{0,65}\b(?:send|share|reply with|provide|enter|submit|confirm|tell|give)\b/i);
    const protective = has(/\b(?:never|do not|don't|dont)\s+(?:share|send|provide|give|reply with|tell anyone)\b.{0,55}\b(?:password|passcode|code|pin|login)\b/i) ||
      has(/\b(?:never|do not|don't|dont)\s+(?:ask for|request)\b.{0,35}\b(?:password|passcode|verification code|otp)\b/i);
    if (asksCredential && !protective) add("credential",85,"Direct request for a password or security code","A message asking you to reveal a password, one-time code, PIN, or login details is a critical warning sign. Legitimate support staff should not ask you to send these secrets in a message.");
    const asksPersonal = has(/\b(?:send|share|provide|enter|submit|upload|confirm|give us)\b.{0,55}\b(?:social security number|ssn|date of birth|driver'?s license|bank account number|routing number|full card number|tax id|taxpayer id)\b/i);
    if (asksPersonal) add("personal",65,"Request for sensitive personal information","The message asks you to send identity or financial details. Verify the request through a trusted official channel.");
    const urgency = has(/\b(?:urgent(?:ly)?|immediately|act now|final warning|within\s*\d+\s*hours?|last chance|avoid (?:a )?penalty|account.{0,25}(?:suspend|lock|close|terminat)|will be (?:suspended|closed|blocked))\b/i);
    if (urgency) add("urgency",15,"Pressure to act quickly","The message creates urgency or threatens a consequence. Scammers use pressure to stop people checking independently.");
    const asksMoney = has(/\b(?:pay|send|transfer|wire|deposit|purchase|buy|settle)\b.{0,65}\b(?:fee|money|payment|funds|gift cards?|bitcoin|crypto(?:currency)?|usdt|ethereum|wire transfer|western union|moneygram|cash app|zelle|venmo|tax|fine|penalty|delivery|customs|processing)\b/i) ||
      has(/\b(?:fee|payment|funds|gift cards?|bitcoin|crypto(?:currency)?|wire transfer|western union|moneygram|cash app|zelle|venmo)\b.{0,65}\b(?:pay|send|transfer|wire|deposit|purchase|buy)\b/i);
    if (asksMoney) add("payment",42,"Request to send money or pay a fee","The message appears to ask you to pay or transfer money. Verify the request independently before paying.");
    const hardToReverse = has(/\b(?:gift cards?|itunes cards?|google play cards?|steam cards?|bitcoin|crypto(?:currency)?|usdt|ethereum|western union|moneygram|wire transfer)\b/i) &&
      has(/\b(?:pay|send|transfer|deposit|purchase|buy|payment)\b/i);
    if (hardToReverse) add("irreversible",68,"Hard-to-reverse payment method","Gift cards, cryptocurrency, and wire transfers are difficult to recover. An unexpected request to pay this way is a serious warning sign.");
    const refundLanguage = has(/\b(?:refund|reimbursement|payment reversal|chargeback)\b/i);
    const refundAction = has(/\b(?:claim|collect|receive|release|verify|confirm|unlock|process|click|open|visit|sign in|log ?in|update|provide|enter)\b/i);
    const refundMoney = has(/\b(?:fee|payment|card|bank|account|details|information|link|url|password|verification)\b/i);
    const refundAlreadyProcessed = has(/\b(?:refund has been processed|refund was processed|refund is complete|refund completed|will be credited|credited to your original payment method)\b/i);
    if (refundLanguage && !refundAlreadyProcessed && (refundAction || refundMoney) && (asksMoney || extractUrls(t).length || has(/\b(?:verify|confirm|update|provide|enter|sign in|log ?in|claim)\b/i))) {
      add("fake-refund",48,"Refund message asks you to take action","Unexpected refund claims that ask you to follow a link, sign in, provide details, or pay a fee can be used to steal money or account access.");
    }
    const brand = /\b(irs|social security administration|ssa|amazon|paypal|coinbase|microsoft|apple|netflix|fedex|ups|usps|chase|bank of america|your bank|bank security|fraud department)\b/i;
    const suspiciousBrandAction = has(/\b(?:verify|suspend|locked|refund|sign in|log ?in|security alert|payment failed|delivery fee|click|link|urgent|confirm your|account restricted|account blocked)\b/i);
    if (brand.test(t) && suspiciousBrandAction && (urgency || asksCredential || asksPersonal || asksMoney || extractUrls(t).length || (refundLanguage && refundAction) || (has(/\bpayment failed\b/i) && has(/\b(?:sign in|log ?in|update your payment|confirm your payment)\b/i)))) {
      add("impersonation",30,"Possible company or agency impersonation","The message combines a recognizable organization with a sensitive request, threat, payment, or link. A company name can be copied; contact the organization through its official app or website.");
    }
    const hasUrl = extractUrls(t).length > 0;
    const linkCallToAction = has(/\b(?:click|tap|open|follow|visit|use)\b.{0,35}\b(?:this |the )?(?:link|url|button)\b|\b(?:sign in|log ?in|verify|claim|update|confirm)\b.{0,45}\b(?:here|using (?:this |the )?link|through (?:this |the )?link)\b/i);
    if (hasUrl && linkCallToAction && (urgency || refundLanguage || asksCredential || asksPersonal || asksMoney || (brand.test(t) && suspiciousBrandAction))) {
      add("linkprompt",38,"Link combined with a suspicious request","The message pairs a link with a request to sign in, verify an account, claim a refund, or pay. Do not use the message link; navigate to the official site yourself.");
    } else if (hasUrl && linkCallToAction) {
      add("linkprompt",12,"Message asks you to open a link","An unexpected link deserves a check, but this wording alone does not prove the message is malicious. Inspect the destination independently.");
    }
    if (has(/\b(?:anydesk|teamviewer|remote access|screen sharing|share your screen|allow me to control|install.{0,30}remote support)\b/i)) {
      add("remote",70,"Remote access or device-control request","An unexpected request to install remote-access software or share device control is a serious warning sign.");
    }
    if (has(/\b(?:task job|task earnings|pay to start|deposit to withdraw|unlock (?:your )?(?:earnings|tasks)|unlock.{0,35}(?:task )?earnings|product boosting|optimization tasks|reshipping|package forwarding|application fee|registration fee|training fee)\b/i)) {
      add("job",55,"Unusual job or task offer","Legitimate employers generally do not require you to pay to get hired or unlock wages. Verify the employer independently.");
    }
    if (has(/\b(?:send me money|send you money|medical bill|emergency funds|flight ticket|travel costs|invest together|gift cards? for me)\b/i)) {
      add("romance",45,"Personal relationship used to request money","A request for money, travel costs, gift cards, or investments from an online-only contact deserves independent verification.");
    }
    if (urgency && asksMoney && !findings.some(f=>f.id==="payment")) add("payment",42,"Urgent payment request","The message combines pressure with a request for money. Verify through a separate trusted channel.");
    return findings;
  }

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
    let findings = [];
    if (selectedMode === "url") {
      const urls = extractUrls(text);
      if (!urls.length) findings.push(...inspectUrl(text));
      else urls.forEach(u => findings.push(...inspectUrl(u)));
    } else {
      findings.push(...detectMessage(text));
      extractUrls(text).forEach(u => findings.push(...inspectUrl(u)));
    }
    const unique = [...new Map(findings.map(f => [f.id, f])).values()];
    const score = Math.min(100, unique.reduce((sum, f) => sum + f.points, 0));
    const critical = unique.some(f => ["credential","personal","remote","irreversible"].includes(f.id));
    const level = critical || score >= 55 ? "high" : score >= 25 ? "medium" : "low";
    return {score,level,findings:unique};
  }

  function getRecommendedActions(report) {
    const ids = new Set(report.findings.map(f => f.id));
    const actions = [];
    if (ids.has("credential") || ids.has("personal") || ids.has("sensitive-path") || [...ids].some(id => id.startsWith("brand-lookalike-"))) {
      actions.push("Do not enter a password, one-time code, identity number, or payment detail. Open the service's official app or type its known address yourself.");
    }
    if (ids.has("payment") || ids.has("advance-fee") || ids.has("irreversible") || ids.has("fake-refund")) {
      actions.push("Do not pay or send money using the message's instructions. Contact your bank or payment provider using the number on your card or its official app if you already paid.");
    }
    if (ids.has("job")) actions.push("Do not pay to get hired, unlock tasks, or withdraw supposed earnings. Verify the employer using contact details found independently.");
    if (ids.has("romance")) actions.push("Do not send money, gift cards, cryptocurrency, or travel funds to someone you have only met online. Verify their story independently.");
    if (ids.has("remote")) actions.push("Do not install remote-access software or share your screen with an unexpected caller or sender.");
    if (ids.has("prize")) actions.push("Do not pay a fee or provide financial details to claim an unexpected prize. Check the promotion through the organizer's official website.");
    if (ids.has("account-threat") || ids.has("impersonation")) actions.push("Check the claimed account, delivery, or agency notice through its official app or website—not through the message.");
    if (ids.has("linkprompt") || ids.has("shortener") || ids.has("punycode") || ids.has("brand-lookalike") || ids.has("ip-host") || ids.has("embedded-credentials")) {
      actions.push("Do not open the link. If you need the service, navigate to its official website yourself.");
    }
    if (!actions.length) actions.push("If this message was unexpected, verify the sender through a separate trusted channel before replying, clicking, or sharing information.");
    return [...new Set(actions)];
  }

  function renderReport(report) {
    result.replaceChildren();
    const titles={high:"High concern",medium:"Caution",low:"No strong warning pattern found"};
    const intros={
      high:"This message or address contains multiple warning signs. Treat it as suspicious until you verify it independently.",
      medium:"This check found warning signs worth reviewing. Pause before clicking, replying, paying, or sharing information.",
      low:"This check found few recognizable warning signs. Scams can still look convincing, so a low score does not establish that something is safe."
    };
    const header=$("div","report-header");
    header.append($("div","risk-label",titles[report.level]),$("div","score","Warning score: "+report.score+"/100"));
    result.className="result risk-"+report.level;
    result.append(header,$("p","report-intro",intros[report.level]));

    const meter=$("div","score-meter");
    meter.setAttribute("role","meter");
    meter.setAttribute("aria-label","Warning score");
    meter.setAttribute("aria-valuemin","0");
    meter.setAttribute("aria-valuemax","100");
    meter.setAttribute("aria-valuenow",String(report.score));
    const fill=$("div","score-meter-fill score-"+report.level);
    fill.style.width=report.score+"%";
    meter.append(fill);
    result.append(meter);

    const meaning=$("p","score-meaning",
      report.level==="high" ? "High: several or stronger warning patterns were found." :
      report.level==="medium" ? "Caution: at least one meaningful warning pattern was found." :
      "Low: few warning patterns matched. This is not a safety certification."
    );
    result.append(meaning,$("p","score-caveat","This is a pattern-based warning score—not a probability that the message is a scam and not a live reputation verdict."));

    const section=$("div","result-section");
    section.append($("h3","","What we noticed ("+report.findings.length+" "+(report.findings.length===1?"signal":"signals")+")"));
    if(report.findings.length) {
      const list=$("ul","finding-list");
      report.findings.forEach(f=>{
        const li=$("li","");
        li.append($("b","",f.title),$("p","",f.detail));
        list.append(li);
      });
      section.append(list);
    } else {
      section.append($("p","no-findings","No matching warning patterns were identified in the text you provided."));
    }
    result.append(section);

    const next=$("div","next-step");
    next.append($("h3","","Recommended next steps"));
    const actions=$("ol","action-list");
    getRecommendedActions(report).forEach(action=>actions.append($("li","",action)));
    next.append(actions);
    result.append(next,$("p","engine-note","SafeCheck AI uses local pattern analysis. Live URL reputation checks are not enabled. When in doubt, verify through a trusted channel."));
    result.hidden=false;
    result.scrollIntoView({behavior:"smooth",block:"start"});
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