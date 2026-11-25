const ALLOWED_ORIGINS = new Set(["https://mexiaeon.github.io","http://localhost:8000","http://127.0.0.1:8000"]);
function cors(origin) {
  const h={"Access-Control-Allow-Methods":"POST, OPTIONS","Access-Control-Allow-Headers":"Content-Type","Access-Control-Max-Age":"86400","Vary":"Origin"};
  if(ALLOWED_ORIGINS.has(origin)) h["Access-Control-Allow-Origin"]=origin;
  return h;
}
function reply(data,status,origin) {
  return new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",...cors(origin)}});
}
function validUrl(value) {
  try { const u=new URL(value); return ["http:","https:"].includes(u.protocol)&&!!u.hostname&&u.hostname.length<=253&&!u.username&&!u.password&&u.hostname!=="localhost"&&!u.hostname.endsWith(".local"); }
  catch { return false; }
}
export default {
  async fetch(request,env) {
    const origin=request.headers.get("Origin")||"";
    if(request.method==="OPTIONS") return ALLOWED_ORIGINS.has(origin)?new Response(null,{status:204,headers:cors(origin)}):new Response(null,{status:403});
    if(origin&&!ALLOWED_ORIGINS.has(origin)) return reply({error:"Origin not allowed"},403,origin);
    const path=new URL(request.url).pathname;
    if(path!=="/check"||request.method!=="POST") return reply({error:"Not found"},404,origin);
    if(!env.WEBRISK_API_KEY) return reply({error:"Server is not configured"},503,origin);
    let body; try { body=await request.json(); } catch { return reply({error:"Invalid JSON"},400,origin); }
    if(!body||typeof body.url!=="string"||body.url.length>2048||!validUrl(body.url)) return reply({error:"Provide one valid HTTP or HTTPS URL, up to 2,048 characters"},400,origin);
    const api=new URL("https://webrisk.googleapis.com/v1/uris:search");
    api.searchParams.set("key",env.WEBRISK_API_KEY); api.searchParams.set("uri",body.url);
    ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"].forEach(t=>api.searchParams.append("threatTypes",t));
    try {
      const upstream=await fetch(api.toString(),{headers:{"Accept":"application/json"}});
      if(!upstream.ok) return reply({error:upstream.status===429?"Live lookup rate limit reached":"Threat lookup provider returned an error"},502,origin);
      const data=await upstream.json();
      return reply({matched:Array.isArray(data.threat)&&data.threat.length>0},200,origin);
    } catch { return reply({error:"Could not reach the threat lookup provider"},502,origin); }
  }
};