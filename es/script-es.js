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
function urls(text) {
    const pattern = /(?:https?:\/\/|www\.)[^\s<>"'\])}]+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?:\/[^\s<>"'\])}]+)?/gi;
    return [...new Set((text.match(pattern) || []).map(x => x.replace(/[.,!?;:]+$/,"")))].slice(0,10);
  }
function analyzeMessage(s){
const t=s.toLowerCase(),f=[],add=(id,p,title,detail)=>{if(!f.some(x=>x.id===id))f.push({id,points:p,title,detail})},has=r=>r.test(t);
if(has(/\b(contraseña|contrasena|password|nip|pin|c[oó]digo de (?:verificaci[oó]n|seguridad|acceso)|c[oó]digo otp)\b/)&&has(/\b(env[ií]a|env[ií]es|manda|mandes|comparte|compartas|proporciona|proporciones|ingresa|ingreses|escribe|escribas|confirma|confirmes|responde con|dame|facilita)\b/)&&!has(/\b(no compartas|nunca compartas|jam[aá]s compartas|no env[ií]es|nunca env[ií]es|no proporciones|nunca proporciones|no reveles|nunca reveles|no ingreses|nunca ingreses)\b/))
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
if(has(/\b(amazon|paypal|coinbase|microsoft|apple|netflix|fedex|ups|usps|banco|bbva|banorte|santander|sat|imss|gobierno|mercado libre|mercadolibre)\b/)&&has(/\b(verifica|suspendida|bloqueada|reembolso|inicia sesi[oó]n|alerta de seguridad|pago rechazado|cargo|haz clic|enlace|urgente|confirma)\b/))
add("suplantacion",32,"Posible suplantación de una empresa o institución","El mensaje combina el nombre de una organización con una solicitud sensible, amenaza, pago o enlace. El nombre puede copiarse; entra a la aplicación o sitio oficial por tu cuenta.");
if(has(/\b(bbva|banorte|santander|citibanamex|banamex|hsbc|scotiabank|inbursa|banco azteca|nu m[eé]xico|klar|mercado pago)\b/)&&has(/\b(bloquead[ao]|suspendid[ao]|actividad inusual|cargo no reconocido|transferencia retenida|token|nip|contrase[nñ]a|c[oó]digo|verifica|confirma|actualiza|ingresa|inicia sesi[oó]n|haz clic|enlace)\b/)&&!has(/\b(nunca te pedir[aá]|no te pedir[aá]|jam[aá]s te pedir[aá]|no compartas|nunca compartas|jam[aá]s compartas|no debes compartir|nunca debes compartir|jam[aá]s debes compartir|no deber[ií]as compartir|no compartas nunca|no ingreses|nunca ingreses|no proporciones|nunca proporciones|no debes proporcionar|nunca debes proporcionar|no reveles|nunca reveles|no debes revelar|nunca debes revelar|no facilites|nunca facilites)\b/))
add("banco-mx",58,"Alerta que suplanta a un banco o servicio financiero mexicano","El mensaje combina el nombre de una institución financiera con una alerta o petición de acceso, verificación o datos. Revisa tu cuenta desde la aplicación oficial.");
if(has(/\b(sat|servicio de administraci[oó]n tributaria|hacienda|buz[oó]n tributario|declaraci[oó]n anual|devoluci[oó]n de impuestos|cfdi)\b/)&&has(/\b(multa|saldo a favor|devoluci[oó]n|embargo|adeudo|sanci[oó]n|actualiza|verifica|paga|pagar|dep[oó]sito|contrase[nñ]a|e\.firma|haz clic|enlace|urgente)\b/)&&!has(/\b(nunca te pedir[aá]|no te pedir[aá]|jam[aá]s te pedir[aá]|no pagues|no uses enlaces|no hagas clic|no compartas|nunca compartas)\b/))
add("sat-falso",58,"Posible mensaje falso que suplanta al SAT","Verifica cualquier aviso fiscal directamente en sat.gob.mx. No uses enlaces ni teléfonos incluidos en mensajes inesperados.");
if(has(/\b(actualizaci[oó]n bancaria|actualizar datos bancarios|solicitud bancaria|cuenta bancaria)\b/)&&has(/\b(qued[oó] incompleta|pendiente|no se complet[oó]|para continuar|continuar con el proceso)\b/)&&has(/\b(portal|enlace|liga|sitio|p[aá]gina)\b/)&&has(/\b(ingresa|entra|accede|contin[uú]a|inicia sesi[oó]n|portal que te compartimos|enlace enviado)\b/))
add("actualizacion-bancaria",48,"Posible solicitud falsa de actualización bancaria","El mensaje afirma que una actualización quedó incompleta y te dirige a un portal o enlace compartido. No uses enlaces anteriores ni portales enviados por mensaje; abre la aplicación oficial del banco por tu cuenta.");
if(has(/\b(inversiones?|grupo privado de inversiones|oportunidad de inversi[oó]n|participantes)\b/)&&has(/\b(rendimientos diarios|ganancias diarias|rendimiento garantizado|utilidades diarias|duplicar tu dinero)\b/)&&has(/\b(telegram|whatsapp|grupo privado|escr[ií]benos|cont[aá]ctanos)\b/)&&has(/\b(\$\s?\d+|pesos|comenzar con|iniciar con|aportar|dep[oó]sito|depositar)\b/))
add("inversion-mensajeria",65,"Posible fraude de inversión promovido por mensajería","La oferta combina rendimientos diarios con captación de dinero y contacto por mensajería. Las ganancias no están garantizadas; verifica que la entidad esté autorizada y nunca envíes dinero por presión o promesas de rendimiento.");
if(has(/\b(whatsapp|whats app)\b/)&&has(/\b(c[oó]digo de (?:seis|6) d[ií]gitos|c[oó]digo de verificaci[oó]n|vincular dispositivo|escanea (?:el|este) qr|qr|cuenta clonada|cuenta ser[aá] suspendida|soporte de whatsapp|meta support|votaci[oó]n)\b/)&&!has(/\b(no compartas|nunca compartas|jam[aá]s compartas|no env[ií]es|nunca env[ií]es|no proporciones|nunca proporciones|no escanees|nunca escanees)\b/))
add("whatsapp",62,"Posible fraude relacionado con WhatsApp","Podrían intentar robar tu cuenta mediante un código, QR o enlace, o hacerse pasar por soporte. Nunca compartas tu código de registro ni escanees un QR que no solicitaste.");
if(has(/\b(paquete|env[ií]o|pedido|gu[ií]a|rastreo|paqueter[ií]a|estafeta|dhl|fedex|ups|redpack|correos de m[eé]xico|sepomex)\b/)&&has(/\b(retenido|detenido|no se pudo entregar|direcci[oó]n incorrecta|reprograma|tarifa|cargo de entrega|aduana|liberar|paga|pagar|actualiza|haz clic|enlace)\b/))
add("entrega-mx",58,"Posible fraude de entrega o paquetería","Los mensajes falsos inventan paquetes retenidos o cargos pequeños para llevarte a páginas de pago. Verifica el número de guía en el sitio oficial.");
if(has(/\b(empleo|trabajo|vacante|reclutador|recursos humanos|tareas|dar likes|dando likes|dar me gusta|calificar productos|comisiones|ganancias)\b/)&&has(/\b(whatsapp|telegram|dep[oó]sito|deposita|depositar|cuota|inversi[oó]n|recarga|desbloquear|retirar|saldo negativo|paga para|pagar para|cripto)\b/))
add("empleo-mx",62,"Posible fraude de empleo o tareas pagadas","Desconfía de vacantes que llegan por WhatsApp o Telegram y exigen depósitos, recargas o pagos para liberar tareas o retirar ganancias.");
if(has(/\b(anydesk|teamviewer|acceso remoto|compartir pantalla|controlar tu dispositivo|instala el programa de soporte)\b/))
add("remoto",70,"Solicitud de acceso remoto o control del dispositivo","Una solicitud inesperada para instalar software de acceso remoto o compartir el control del equipo es una señal grave.");
if(has(/\b(trabajo de tareas|tareas pagadas|desbloquear tareas|desbloquear ganancias|deposita para retirar|debes depositar|paga para empezar|optimización de productos|calificar productos|dar likes|dando likes|dar me gusta|dando me gusta)\b/)||(has(/\b(tareas|likes|me gusta|calificar productos|ganancias)\b/)&&has(/\b(deposita|depositar|dep[oó]sito|paga|pagar|desbloquear|retirar|retiro)\b/)&&has(/\b(ganancias|dinero|saldo|retirar|retiro|tareas)\b/)))
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
const official={"paypal.com":["paypal.com"],"amazon.com":["amazon.com"],"apple.com":["apple.com"],"microsoft.com":["microsoft.com"],"google.com":["google.com"],"mercadolibre.com.mx":["mercadolibre.com.mx"],"mercadolibre.com":["mercadolibre.com"],"bbva.mx":["bbva.mx"],"bbva.com":["bbva.com"],"banorte.com":["banorte.com"],"santander.com.mx":["santander.com.mx"],"citibanamex.com":["citibanamex.com"],"hsbc.com.mx":["hsbc.com.mx"],"scotiabank.com.mx":["scotiabank.com.mx"],"sat.gob.mx":["sat.gob.mx"],"gob.mx":["gob.mx"],"whatsapp.com":["whatsapp.com"],"estafeta.com":["estafeta.com"],"dhl.com":["dhl.com"],"fedex.com":["fedex.com"],"correosdemexico.gob.mx":["correosdemexico.gob.mx"]};
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
const updateCount=()=>{count.textContent=input.value.length+" / 2,000"};
input.addEventListener("input",updateCount);
input.addEventListener("change",updateCount);
input.addEventListener("paste",()=>setTimeout(updateCount,0));
document.getElementById("year").textContent=new Date().getFullYear();
button.addEventListener("click",()=>{const v=input.value.trim();updateCount();if(!v){input.focus();return}if(v.length>2000)return;render(report(v,mode))});
})();