(() => {
"use strict";
const input=document.getElementById("entry"),label=document.getElementById("input-label"),hint=document.getElementById("hint"),count=document.getElementById("count"),result=document.getElementById("result"),button=document.getElementById("analyze");
let mode="message";
const modes={
message:["Pega el mensaje de texto sospechoso","Antes de pegarlo, elimina contraseñas, números de cuenta y datos privados.","Ejemplo: Tu cuenta será suspendida. Verifica tus datos ahora..."],
email:["Pega el texto del correo (sin datos privados)","Nunca incluyas contraseñas, códigos de verificación ni datos completos de tu cuenta.","Ejemplo: Tu factura está vencida. Abre el archivo adjunto..."],
url:["Pega la dirección del sitio web","No abras el enlace. Pega únicamente la dirección como texto.","https://ejemplo.com/pagina"]
};
const $=(tag,cls,txt)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=txt;return e};
function urls(s){return [...new Set((s.match(/(?:https?:\/\/|www\.)[^\s<>"'\])}]+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:\/[^\s<>"'\])}]+)?/gi)||[]).map(x=>x.replace(/[.,!?;:]+$/,""))].slice(0,10)}
function analyzeMessage(s){
const t=s.toLowerCase(),f=[],add=(id,p,title,detail)=>{if(!f.some(x=>x.id===id))f.push({id,points:p,title,detail})},has=r=>r.test(t);
if(has(/\b(contraseña|contrasena|password|nip|pin|c[oó]digo de (?:verificaci[oó]n|seguridad|acceso)|c[oó]digo otp)\b/)&&has(/\b(env[ií]a|manda|comparte|proporciona|ingresa|escribe|confirma|responde con|dame|facilita)\b/))
add("credenciales",85,"Solicitud de contraseña o código de seguridad","El mensaje parece pedir una contraseña, NIP o código de un solo uso. No compartas estos datos por mensaje; el personal legítimo de soporte no debe pedírtelos.");
if(has(/\b(n[uú]mero de cuenta|n[uú]mero de tarjeta|curp|rfc|n[uú]mero de seguro social|fecha de nacimiento|identificaci[oó]n oficial|datos bancarios)\b/)&&has(/\b(env[ií]a|manda|comparte|proporciona|ingresa|confirma|facilita)\b/))
add("datos",65,"Solicitud de información personal o financiera","Te piden datos de identidad o información financiera. Verifica la solicitud mediante un canal oficial que encuentres por tu cuenta.");
if(has(/\b(urgente|inmediatamente|act[uú]a ahora|[uú]ltimo aviso|[uú]ltima oportunidad|hoy mismo|evita una multa|ser[aá] suspendida|ser[aá] bloqueada|cuenta bloqueada|cuenta suspendida|en las pr[oó]ximas horas)\b/))
add("urgencia",15,"Presión para actuar rápidamente","El mensaje intenta apresurarte o amenaza con una consecuencia. Los estafadores usan la presión para evitar que verifiques la información.");
if(has(/\b(paga|pagar|dep[oó]sito|transfiere|transfiera|env[ií]a dinero|manda dinero|cubre el cargo|realiza el pago)\b/)&&has(/\b(tarifa|comisi[oó]n|multa|impuesto|paquete|entrega|liberar|desbloquear|cuenta|dinero|pago|reembolso|premio)\b/))
add("pago",48,"Solicitud de dinero o pago","El mensaje parece pedir dinero o una tarifa inesperada. No pagues siguiendo sus instrucciones; verifica por separado.");
if(has(/\b(tarjetas? de regalo|bitcoin|criptomonedas|cripto|transferencia bancaria|western union|moneygram)\b/)&&has(/\b(paga|pagar|env[ií]a|manda|transfiere|dep[oó]sito)\b/))
add("irreversible",68,"Método de pago difícil de recuperar","Las tarjetas de regalo, criptomonedas y transferencias pueden ser difíciles de recuperar. Una solicitud inesperada de este tipo es una señal grave.");
if(has(/\b(reembolso|devoluci[oó]n de dinero|reintegro)\b/)&&has(/\b(reclama|cobra|recibe|libera|verifica|confirma|desbloquea|haz clic|abre|visita|inicia sesi[oó]n|actualiza|proporciona|ingresa)\b/))
add("reembolso",48,"El supuesto reembolso exige que actúes","Los mensajes inesperados que te piden abrir un enlace, iniciar sesión, dar datos o pagar para recibir un reembolso pueden buscar robar tu dinero o acceso.");
if(has(/\b(amazon|paypal|coinbase|microsoft|apple|netflix|fedex|ups|usps|banco|sat|imss|gobierno|mercado libre)\b/)&&has(/\b(verifica|suspendida|bloqueada|reembolso|inicia sesi[oó]n|alerta de seguridad|pago rechazado|cargo|haz clic|enlace|urgente|confirma)\b/))
add("suplantacion",32,"Posible suplantación de una empresa o institución","El mensaje combina el nombre de una organización con una solicitud sensible, amenaza, pago o enlace. El nombre puede copiarse; entra a la aplicación o sitio oficial por tu cuenta.");
if(has(/\b(anydesk|teamviewer|acceso remoto|compartir pantalla|controlar tu dispositivo|instala el programa de soporte)\b/))
add("remoto",70,"Solicitud de acceso remoto o control del dispositivo","Una solicitud inesperada para instalar software de acceso remoto o compartir el control del equipo es una señal grave.");
if(has(/\b(trabajo de tareas|tareas pagadas|desbloquear tareas|desbloquear ganancias|deposita para retirar|debes depositar|paga para empezar|optimización de productos|calificar productos|dar likes|dar me gusta)\b/))
add("empleo",58,"Oferta de empleo o tareas poco habitual","Un empleador legítimo normalmente no te exige pagar para ser contratado ni para desbloquear tu sueldo. Verifica la empresa de forma independiente.");
if(has(/\b(env[ií]ame dinero|m[aá]ndame dinero|gastos m[eé]dicos|boleto de avi[oó]n|tarjetas? de regalo para m[ií]|emergencia econ[oó]mica)\b/))
add("romance",45,"Una relación personal se usa para pedir dinero","Una solicitud de dinero, tarjetas de regalo, gastos de viaje o inversiones de alguien que solo conoces por internet requiere verificación independiente.");
const u=urls(s);if(u.length&&has(/\b(haz clic|abre el enlace|visita el enlace|entra aqu[ií]|inicia sesi[oó]n|verifica aqu[ií]|actualiza tus datos)\b/))
add("enlace",28,"Enlace combinado con una solicitud sospechosa","El mensaje combina un enlace con una solicitud para iniciar sesión, verificar una cuenta, reclamar un reembolso o pagar. No uses el enlace del mensaje.");
return f;
}
function inspectUrl(raw){
const f=[];let u;try{u=new URL(raw.startsWith("http")?raw:"https://"+raw)}catch{return [{id:"url-invalida",points:8,title:"La dirección tiene un formato inusual",detail:"No fue posible interpretar la dirección con seguridad. No la abras para probarla."}]}
const h=u.hostname.toLowerCase(),parts=h.split("."),add=(id,p,title,detail)=>f.push({id,points:p,title,detail});
if(u.protocol!=="https:")add("sin-https",10,"La dirección no usa HTTPS","Esto no demuestra que sea una estafa, pero evita ingresar información sensible.");
if(u.username||u.password)add("credenciales-url",28,"La dirección contiene datos de acceso","La URL incluye una sección de usuario o contraseña que puede ocultar el destino real.");
if(parts.some(x=>x.startsWith("xn--")))add("punycode",22,"Nombre de dominio codificado","El dominio utiliza un formato que a veces se emplea para crear direcciones parecidas a las originales.");
if(/^\d+\.\d+\.\d+\.\d+$/.test(h))add("ip",20,"La dirección usa una IP numérica","El enlace apunta a una dirección IP en lugar de un nombre de dominio habitual.");
if(["bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rb.gy"].includes(h))add("acortado",12,"Enlace acortado","El destino final está oculto. No lo abras si no puedes verificarlo de forma independiente.");
if(parts.length>=5)add("subdominio",10,"Dominio con muchos subdominios","La estructura puede dificultar identificar el dominio principal. Lee el nombre de derecha a izquierda.");
if(["zip","mov","top","xyz","click","work","country","gq","tk","ml","cf"].includes(parts.at(-1)))add("extension",8,"Extensión de dominio poco común","Esta extensión también puede tener usos legítimos, pero merece atención si el enlace llegó inesperadamente.");
if(/(login|verify|secure|account|update|wallet|support|billing|password|acceso|cuenta|verifica|pago)/i.test(u.pathname+u.search))add("ruta",7,"La dirección contiene términos de cuenta o acceso","Verifica el dominio antes de ingresar información.");
const official={"paypal.com":["paypal"],"amazon.com":["amazon"],"apple.com":["apple"],"microsoft.com":["microsoft"],"google.com":["google"],"mercadolibre.com":["mercado libre"]};
for(const [domain,brands] of Object.entries(official)){if(brands.some(b=>h.includes(b))&&h!==domain&&!h.endsWith("."+domain)){add("imitacion",25,"Posible dominio que imita una marca","La dirección menciona una marca pero no utiliza su dominio oficial conocido.");break}}
return f;
}
function report(text,mode){
let f=mode==="url"?inspectUrl(text):analyzeMessage(text);
if(mode!=="url")urls(text).forEach(u=>f.push(...inspectUrl(u)));
f=[...new Map(f.map(x=>[x.id,x])).values()];
const score=Math.min(100,f.reduce((a,x)=>a+x.points,0)),critical=f.some(x=>["credenciales","datos","remoto","irreversible"].includes(x.id)),level=critical||score>=55?"high":score>=25?"medium":"low";
return {f,score,level};
}
function render(r){
result.replaceChildren();result.className="result risk-"+r.level;
const titles={high:"Riesgo alto",medium:"Precaución",low:"No se encontraron señales de alerta importantes"};
const intro={high:"Este mensaje o dirección contiene varias señales de alerta. Trátalo como sospechoso hasta verificarlo por otro medio.",medium:"Encontramos señales que conviene revisar. Haz una pausa antes de abrir enlaces, responder, pagar o compartir información.",low:"Encontramos pocas señales conocidas. Aun así, las estafas pueden parecer legítimas; una puntuación baja no demuestra que algo sea seguro."};
const header=$("div","report-header");header.append($("div","risk-label",titles[r.level]),$("div","score","Puntuación de alerta: "+r.score+"/100"));result.append(header,$("p","report-intro",intro[r.level]));
const meter=$("div","score-meter");meter.setAttribute("role","meter");meter.setAttribute("aria-valuemin","0");meter.setAttribute("aria-valuemax","100");meter.setAttribute("aria-valuenow",String(r.score));const fill=$("div","score-meter-fill score-"+r.level);fill.style.width=r.score+"%";meter.append(fill);result.append(meter);
result.append($("p","score-meaning",r.level==="high"?"Alto: se encontraron varias señales o señales de mayor gravedad.":r.level==="medium"?"Precaución: se encontró al menos una señal importante.":"Bajo: coincidieron pocas señales. Esto no certifica que sea seguro."),$("p","score-caveat","Esta puntuación se basa en patrones de alerta. No es la probabilidad de que sea una estafa ni una verificación de reputación en tiempo real."));
const section=$("div","result-section");section.append($("h3","","Lo que detectamos ("+r.f.length+" "+(r.f.length===1?"señal":"señales")+")"));
if(r.f.length){const list=$("ul","finding-list");r.f.forEach(x=>{const li=$("li","");li.append($("b","",x.title),$("p","",x.detail));list.append(li)});section.append(list)}else section.append($("p","no-findings","No identificamos patrones de alerta en el texto que compartiste."));result.append(section);
const next=$("div","next-step");next.append($("h3","","Qué te recomendamos hacer"));const actions=[];
const ids=new Set(r.f.map(x=>x.id));
if(["credenciales","datos","ruta","imitacion"].some(x=>ids.has(x)))actions.push("No ingreses contraseñas, códigos, datos de identidad ni información de pago. Abre la aplicación oficial o escribe tú mismo la dirección conocida.");
if(["pago","irreversible","reembolso"].some(x=>ids.has(x)))actions.push("No pagues ni envíes dinero siguiendo las instrucciones del mensaje. Si ya pagaste, contacta a tu banco o proveedor de pagos por un canal oficial.");
if(ids.has("empleo"))actions.push("No pagues para conseguir un empleo, desbloquear tareas ni retirar supuestas ganancias. Investiga a la empresa por tu cuenta.");
if(ids.has("remoto"))actions.push("No instales programas de acceso remoto ni compartas tu pantalla con alguien que no esperabas.");
if(ids.has("enlace")||ids.has("acortado")||ids.has("punycode")||ids.has("ip"))actions.push("No abras el enlace. Si necesitas el servicio, entra a su sitio oficial escribiendo la dirección tú mismo.");
if(!actions.length)actions.push("Si el mensaje no lo esperabas, verifica quién lo envió mediante otro canal confiable antes de responder o compartir información.");
const ol=$("ol","action-list");actions.forEach(a=>ol.append($("li","",a)));next.append(ol);result.append(next,$("p","engine-note","SafeCheck AI utiliza análisis local de patrones. Las consultas de reputación de enlaces en tiempo real no están habilitadas. Si tienes dudas, verifica por un canal confiable."));
result.hidden=false;result.scrollIntoView({behavior:"smooth",block:"start"});
}
document.querySelectorAll(".tab").forEach(b=>b.addEventListener("click",()=>{mode=b.dataset.mode;document.querySelectorAll(".tab").forEach(t=>t.classList.toggle("active",t===b));label.textContent=modes[mode][0];hint.textContent=modes[mode][1];input.placeholder=modes[mode][2];input.value="";count.textContent="0 / 2,000";result.hidden=true;result.replaceChildren()}));
input.addEventListener("input",()=>count.textContent=input.value.length+" / 2,000");
document.getElementById("year").textContent=new Date().getFullYear();
button.addEventListener("click",()=>{const v=input.value.trim();if(!v){input.focus();return}if(v.length>2000)return;render(report(v,mode))});
})();