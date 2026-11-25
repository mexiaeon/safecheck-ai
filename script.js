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
    { id:"urgency", points:18, title:"Urgency or threat", detail:"The message pressures you to act immediately or threatens a negative consequence.", re:/\b(urgent(?:ly)?|immediately|act now|final warning|within\s*\d+\s*hours?|account.{0,30}(?:suspend|suspension|close|closure|lock|terminat)|suspend(?:ed|sion)?|limited time|last chance|avoid (?:a )?penalty|avoid (?:account )?(?:suspension|closure))\b/i },
    { id:"credential", points:25, title:"Password or verification-code request", detail:"The message appears to ask you to provide or enter a password, one-time code, PIN, or login details. Never share these in response to an unexpected message.", re:/\b(?:send|share|reply with|provide|enter|submit|confirm|tell us|give us)\b.{0,55}\b(password|passcode|one[- ]time (?:pass)?code|verification code|security code|2fa code|otp|pin number|login credentials)\b|\b(password|passcode|one[- ]time (?:pass)?code|verification code|security code|2fa code|otp|pin number|login credentials)\b.{0,55}\b(?:send|share|reply with|provide|enter|submit|confirm|tell us|give us)\b/i },
    { id:"personal", points:18, title:"Sensitive personal information request", detail:"The message appears to ask you to provide sensitive identity or financial information. Verify the request through an official channel.", re:/\b(?:send|share|reply with|provide|enter|submit|confirm|upload|give us)\b.{0,55}\b(social security(?: number)?|\bssn\b|date of birth|driver\x27?s license|bank account number|routing number|credit card details|full card number|tax id|taxpayer id)\b|\b(social security(?: number)?|\bssn\b|date of birth|driver\x27?s license|bank account number|routing number|credit card details|full card number|tax id|taxpayer id)\b.{0,55}\b(?:send|share|provide|enter|submit|upload)\b/i },
    { id:"payment", points:22, title:"Unexpected payment or fee", detail:"The message appears to request money to resolve a problem or complete a transaction. Verify unexpected payment requests independently.", re:/\b(pay (?:a |the )?(?:small |processing |release |delivery |customs )?fee|small fee|payment required|processing fee|release fee|delivery fee|customs fee|wire transfer|bank transfer|send (?:the )?money|pay(?:ment)? outstanding|pay immediately|pay now|overdue invoice|past due balance|reconfirm payment|payment failed|pay.{0,30}(?:fine|penalty|tax|balance))\b/i },
    { id:"account-threat", points:20, title:"Account or delivery threat", detail:"A claim that an account or delivery will be blocked can pressure you into acting before checking independently.", re:/\b(package|parcel|delivery|account|subscription|payment)\b.{0,55}\b(on hold|held|suspended|suspension|locked|temporarily locked|disabled|restricted|blocked|failed|will be returned|will be cancelled|will be closed)\b|\b(on hold|held|suspended|blocked)\b.{0,55}\b(package|parcel|delivery|account|subscription)\b/i },
    { id:"fake-refund", points:22, title:"Unexpected refund or payment reversal", detail:"Unexpected refund or payment-reversal messages that ask you to claim money, verify details, or follow a link can be used to steal money or account information.", re:/\b(?:refund.{0,35}(?:pending|claim|verify|release|failed|available|waiting)|(?:claim|collect|receive|release|verify).{0,35}refund|overpaid you|overpayment|payment reversed|refund.{0,25}(?:link|account|details|information))\b/i },
    { id:"advance-fee", points:24, title:"Upfront fee to receive money or a benefit", detail:"Being asked to pay first to receive a prize, job earnings, a loan, or a package is a common scam pattern.", re:/\b(pay|send|deposit)\b.{0,45}\b(to receive|to release|to unlock|to claim|before you can withdraw)\b|\b(release|unlock|claim)\b.{0,35}\b(funds|earnings|prize|package|loan)\b/i },
    { id:"irreversible", points:28, title:"Request for hard-to-reverse payment", detail:"The message appears to request payment through gift cards, cryptocurrency, wire transfer, or a payment app. These payments can be difficult to recover.", re:/\b(?:pay|send|transfer|deposit|purchase|buy)\b.{0,55}\b(gift cards?|itunes cards?|google play cards?|steam cards?|bitcoin|crypto(?:currency)?|usdt|ethereum|wire transfer|western union|moneygram|cash app|zelle|venmo)\b|\b(gift cards?|itunes cards?|google play cards?|steam cards?|bitcoin|crypto(?:currency)?|usdt|ethereum|wire transfer|western union|moneygram|cash app|zelle|venmo)\b.{0,55}\b(?:payment|pay|send|transfer|deposit|purchase|buy)\b/i },
    { id:"prize", points:18, title:"Unexpected prize or reward", detail:"An unexpected prize or reward can be used to lure people into paying fees or sharing information. Verify it independently before responding.", re:/\b(you (?:have )?won|congratulations.{0,35}(?:winner|won|prize)|claim your (?:prize|reward)|free money|lottery winner|sweepstakes winner|guaranteed (?:profit|return)|risk[- ]free investment)\b/i },
    { id:"remote", points:25, title:"Remote-access or device-control request", detail:"A stranger asking you to install remote-access software, share your screen, or give device control is a serious warning sign.", re:/\b(anydesk|teamviewer|remote access|screen sharing|share your screen|give (?:me|us) (?:remote )?access to your (?:computer|phone|device)|allow (?:me|us) to control your (?:computer|phone|device)|install.{0,35}(?:anydesk|teamviewer|remote support))\b/i },
    { id:"impersonation", points:20, title:"Possible brand or agency impersonation", detail:"A familiar organization is mentioned alongside a suspicious request or account warning. Scammers can copy real company names; verify through the official app or website you open yourself.", re:/(?:(?:irs|social security administration|ssa|amazon|paypal|microsoft|apple support|netflix|fedex|ups|usps|bank security|fraud department|police department).{0,85}(?:verify|suspend|locked|refund|sign in|login|security|delivery fee|click|link|urgent))|(?:(?:verify|suspend|locked|refund|sign in|login|security|delivery fee|click|link|urgent).{0,85}(?:irs|social security administration|ssa|amazon|paypal|microsoft|apple support|netflix|fedex|ups|usps|bank security|fraud department|police department))/i },
    { id:"linkprompt", points:16, title:"Possible phishing link or sign-in prompt", detail:"The message encourages you to use a link to sign in, claim a refund, verify an account, or update payment details. This is a common phishing technique; open the official app or type the known website address yourself.", re:/\b(click here|tap (?:this|the) link|open (?:this|the) link|follow this link|verify (?:your )?(?:account|identity|details)|sign in (?:here|now)|use the link(?: below)?|visit (?:this|the) link|click (?:the )?link|view (?:the )?(?:message|invoice|document|refund)|claim (?:your )?refund|update (?:your )?(?:payment|account)|confirm (?:your )?(?:details|information|password)|reset your password)\b/i },
    { id:"secrecy", points:20, title:"Secrecy or isolation pressure", detail:"Requests to keep a transaction secret or avoid speaking to others are a major warning sign.", re:/\b(keep (?:this )?secret|don't tell anyone|do not tell anyone|秘密|stay on the line|do not hang up|don't contact your bank|do not contact your bank)\b/i },
    { id:"job", points:26, title:"Unusual job or task offer", detail:"Paying money to get hired, unlock tasks, receive commissions, or withdraw earnings is a common job and task-scam pattern.", re:/\b(task (?:job|work)|pay to start|deposit to withdraw|unlock (?:your )?(?:earnings|tasks)|commission (?:tasks|job)|product boosting|optimization tasks|reshipping|package forwarding|pay (?:an )?(?:application|registration|training|equipment) fee|job offer.{0,45}(?:deposit|fee|payment)|earnings.{0,35}(?:deposit|fee|unlock)|withdraw.{0,35}(?:deposit|fee))\b/i },
    { id:"romance", points:26, title:"Emotional or relationship-based money request", detail:"An online romantic contact asking for money, travel costs, medical bills, emergency help, investments, or gift cards deserves independent verification.", re:/\b(send me money|send (?:you )?money|help me with (?:a )?(?:ticket|medical bill|emergency|rent|bills)|medical bill|emergency funds|emergency ticket|flight ticket|travel (?:costs|expenses)|let\x27s invest together|invest together|need gift cards|gift cards? for (?:me|my)|invest(?:ment)? opportunity.{0,35}(?:together|send|transfer))\b/i },
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
      rules.forEach(rule=>{
        const isProtectiveAdvice = rule.id==="credential" && /\b(?:never|do not|don't)\s+(?:share|send|provide|give|reply with)\b/i.test(text);
        if(!isProtectiveAdvice && rule.re.test(text)) findings.push({id:rule.id,points:rule.points,title:rule.title,detail:rule.detail});
      });
      extractUrls(text).forEach(u=>findings.push(...inspectUrl(u)));
    }
    const unique=[...new Map(findings.map(f=>[f.id,f])).values()];
    const score=Math.min(100,unique.reduce((sum,f)=>sum+f.points,0));
    const level=score>=55?"high":score>=25?"medium":"low";
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