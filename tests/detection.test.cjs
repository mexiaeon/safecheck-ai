const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const root = path.resolve(__dirname, "..");

function loadSpanish() {
  const source = fs.readFileSync(path.join(root, "es/script-es.js"), "utf8");
  const start = source.indexOf("function urls(text)");
  const end = source.indexOf("function render(r)", start);
  assert.ok(start >= 0 && end > start, "Spanish analyzer functions must remain extractable");
  const code = source.slice(start, end) + "\nmodule.exports={urls,analyzeMessage,inspectUrl,report};";
  const sandbox = { module: { exports: {} }, URL, Set, Map };
  vm.runInNewContext(code, sandbox, { filename: "es/script-es.js" });
  return sandbox.module.exports;
}

function loadEnglish() {
  const source = fs.readFileSync(path.join(root, "script.js"), "utf8");
  const start = source.indexOf("function detectMessage(text)");
  const end = source.indexOf("function getRecommendedActions(report)", start);
  assert.ok(start >= 0 && end > start, "English analyzer functions must remain extractable");
  const code = source.slice(start, end) + "\nmodule.exports={detectMessage,extractUrls,inspectUrl,analyze};";
  const sandbox = { module: { exports: {} }, URL, Set, Map };
  vm.runInNewContext(code, sandbox, { filename: "script.js" });
  return sandbox.module.exports;
}

const es = loadSpanish();
const en = loadEnglish();

const spanishCases = [
  ["BBVA phishing", "BBVA: Detectamos un acceso inusual a tu cuenta. Tu banca móvil será suspendida hoy. Verifica tu NIP y contraseña para evitar el bloqueo.", "high", "banco-mx"],
  ["Banorte transfer scam", "Banorte: Se realizó una transferencia que no reconocemos. Ingresa al siguiente enlace para cancelar el movimiento y recuperar tu dinero.", "high", "banco-mx"],
  ["Fake SAT refund", "SAT: Tu devolución de impuestos está pendiente. Confirma tu e.firma y datos bancarios para liberar tu saldo a favor. Consulta el enlace enviado.", "high", "sat-falso"],
  ["WhatsApp code theft", "Hola, soy del soporte de WhatsApp. Necesitamos confirmar tu identidad. Envíanos el código de seis dígitos que acabas de recibir para mantener activa tu cuenta.", "high", "whatsapp"],
  ["Fake delivery fee", "Estafeta: No pudimos entregar tu paquete debido a una dirección incorrecta. Actualiza tus datos y paga $19 para programar una nueva entrega.", "high", "entrega-mx"],
  ["Task job deposit", "¡Tenemos vacantes disponibles! Gana entre $1,500 y $4,000 diarios dando likes a videos. Solo necesitas WhatsApp. Deposita $200 para activar tu cuenta y comenzar a retirar ganancias.", "high", "empleo-mx"],
  ["Fake Mercado Pago refund", "Mercado Pago: Tu reembolso está pendiente. Para recibirlo, confirma tu identidad e inicia sesión en https://mercadopago-login.example para liberar tu dinero.", "high", "banco-mx"],
  ["Private investment group", "Estamos aceptando nuevos participantes en nuestro grupo privado de inversiones. Puedes comenzar con $500 y recibir rendimientos diarios. Escríbenos por Telegram para conocer los detalles.", "high", "inversion-mensajeria"],
  ["Incomplete bank update", "Hola, tu solicitud de actualización bancaria quedó incompleta. Para continuar, ingresa desde el portal que te compartimos anteriormente.", "medium", "actualizacion-bancaria"],
  ["Legitimate BBVA safety warning", "BBVA te recuerda que nunca debes compartir tu NIP, contraseña ni códigos de seguridad. Si recibes llamadas sospechosas, cuelga y comunícate directamente con el banco.", "low", null],
  ["General SAT safety advice", "El SAT nunca te pedirá contraseñas por mensaje. No hagas clic en enlaces sospechosos y consulta directamente sat.gob.mx.", "low", null],
  ["Normal delivery update", "Tu pedido ha sido enviado. Puedes consultar el estado de tu entrega desde la aplicación oficial de la tienda. Gracias por tu compra.", "low", null],
  ["Normal personal message", "Hola, ¿a qué hora nos vemos mañana para tomar un café?", "low", null]
];

for (const [name, message, expectedLevel, expectedFinding] of spanishCases) {
  test("ES: " + name, () => {
    const result = es.report(message, "message");
    assert.equal(result.level, expectedLevel, "unexpected level; score=" + result.score + "; findings=" + result.f.map(x => x.id).join(","));
    if (expectedFinding) assert.ok(result.f.some(x => x.id === expectedFinding), "missing finding " + expectedFinding);
    else assert.ok(result.score < 25, "legitimate message should stay below caution; findings=" + result.f.map(x => x.id).join(","));
  });
}

const englishCases = [
  ["credential phishing", "Your bank account is locked. Send us your password and one-time code immediately to restore access.", true],
  ["fake refund", "Your PayPal refund is pending. Click here and sign in to claim your money.", true],
  ["task deposit scam", "Earn money doing online tasks. Deposit $50 to unlock your tasks and withdraw your earnings.", true],
  ["remote access scam", "Install AnyDesk and give our support agent access to your computer to fix your account.", true],
  ["ordinary greeting", "Hi, are we still meeting for lunch tomorrow?", false],
  ["legitimate security advice", "Your bank will never ask for your password or one-time code. Never share these details with anyone.", false]
];

for (const [name, message, shouldWarn] of englishCases) {
  test("EN: " + name, () => {
    const result = en.analyze(message, "message");
    assert.equal(result.findings.length > 0, shouldWarn, "findings=" + result.findings.map(x => x.id).join(","));
  });
}

test("URL: flags a lookalike brand domain", () => {
  const findings = es.inspectUrl("https://paypal.com.example.test/login");
  assert.ok(findings.length > 0);
});

test("URL: does not call HTTPS alone proof of safety", () => {
  const findings = es.inspectUrl("https://example.com");
  assert.equal(findings.length, 0);
});

test("score is capped at 100", () => {
  const result = es.report("BBVA: Tu cuenta será bloqueada hoy. Verifica tu contraseña y NIP, paga la tarifa urgente para liberar tu cuenta en este enlace https://bit.ly/example", "message");
  assert.ok(result.score <= 100);
});
