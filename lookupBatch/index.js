const crypto = require("crypto");
const https = require("https");
const { URL } = require("url");

const BLOB_CONTAINER = process.env.BLOB_CONTAINER;
const INPUT_BLOB = process.env.INPUT_BLOB || "numbers_in.csv";
const OUTPUT_BLOB = process.env.OUTPUT_BLOB || "number_lookup_results.csv";
const ACS_CONNECTION_STRING = process.env.ACS_CONNECTION_STRING;
const AZURE_WEBJOBS_STORAGE = process.env.AzureWebJobsStorage;

function parseConnStringKV(conn) {
  const kv = {};
  for (const part of conn.split(";")) {
    const i = part.indexOf("=");
    if (i > -1) kv[part.slice(0, i)] = part.slice(i + 1);
  }
  return kv;
}
function hmacSHA256Base64(keyBase64, stringToSign) {
  const key = Buffer.from(keyBase64, "base64");
  return crypto.createHmac("sha256", key).update(stringToSign, "utf8").digest("base64");
}
function sha256Base64(body) {
  return crypto.createHash("sha256").update(body, "utf8").digest("base64");
}
function rfc1123Now() { return new Date().toUTCString(); }

function signBlobRequest({ method, url, headers, accountName, accountKeyBase64 }) {
  headers["x-ms-date"] = headers["x-ms-date"] || rfc1123Now();
  headers["x-ms-version"] = headers["x-ms-version"] || "2021-08-06";
  const canonHeaders = Object.keys(headers)
    .filter((k) => k.toLowerCase().startsWith("x-ms-"))
    .sort((a, b) => a.localeCompare(b))
    .map((k) => `${k.toLowerCase().trim()}:${String(headers[k]).trim()}\n`)
    .join("");
  const u = new URL(url);
  const path = u.pathname;
  const qp = [];
  u.searchParams.forEach((value, name) => { qp.push([name.toLowerCase(), value]); });
  qp.sort((a, b) => a[0].localeCompare(b[0]));
  const canonResource = `/${accountName}${path}` + (qp.length ? "\n" + qp.map(([n, v]) => `${n}:${v}`).join("\n") : "");
  const contentLength = headers["Content-Length"] || "";
  const contentType = headers["Content-Type"] || "";
  const contentEncoding = headers["Content-Encoding"] || "";
  const contentLanguage = headers["Content-Language"] || "";
  const contentMD5 = headers["Content-MD5"] || "";
  const IfModifiedSince = headers["If-Modified-Since"] || "";
  const IfMatch = headers["If-Match"] || "";
  const IfNoneMatch = headers["If-None-Match"] || "";
  const IfUnmodifiedSince = headers["If-Unmodified-Since"] || "";
  const Range = headers["Range"] || "";
  const stringToSign = [
    method.toUpperCase(),
    contentEncoding,
    contentLanguage,
    contentLength,
    contentMD5,
    contentType,
    "",
    IfModifiedSince,
    IfMatch,
    IfNoneMatch,
    IfUnmodifiedSince,
    Range,
    canonHeaders + canonResource,
  ].join("\n");
  const signature = hmacSHA256Base64(accountKeyBase64, stringToSign);
  headers["Authorization"] = `SharedKey ${accountName}:${signature}`;
  return headers;
}
function httpRequest(method, url, headers, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const opts = { method, hostname: u.hostname, path: u.pathname + (u.search || ""), headers };
    const req = https.request(opts, (res) => {
      let data = ""; res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}
async function readCsv(accountName, accountKey, container, blob) {
  const url = `https://${accountName}.blob.core.windows.net/${encodeURIComponent(container)}/${encodeURIComponent(blob)}`;
  const headers = signBlobRequest({
    method: "GET", url,
    headers: { "x-ms-date": rfc1123Now(), "x-ms-version": "2021-08-06" },
    accountName, accountKeyBase64: accountKey,
  });
  const res = await httpRequest("GET", url, headers);
  if (res.status !== 200) throw new Error(`Blob GET failed ${res.status}: ${res.body}`);
  return res.body;
}
async function writeCsv(accountName, accountKey, container, blob, content) {
  const url = `https://${accountName}.blob.core.windows.net/${encodeURIComponent(container)}/${encodeURIComponent(blob)}`;
  const headers = {
    "x-ms-date": rfc1123Now(),
    "x-ms-version": "2021-08-06",
    "x-ms-blob-type": "BlockBlob",
    "Content-Type": "text/csv",
    "Content-Length": Buffer.byteLength(content, "utf8"),
  };
  signBlobRequest({ method: "PUT", url, headers, accountName, accountKeyBase64: accountKey });
  const res = await httpRequest("PUT", url, headers, content);
  if (!(res.status === 201 || res.status === 200)) throw new Error(`Blob PUT failed ${res.status}: ${res.body}`);
}
// Calls ACS Operator Information Search with a *list* of E.164 numbers
async function numberLookup(acsEndpoint, acsAccessKeyBase64, numbers) {
  const pathAndQuery = "/operatorInformation/:search?api-version=2025-06-01";
  const base = acsEndpoint.replace(/\/+$/, "");
  const url = `${base}${pathAndQuery}`;
  const host = new URL(base).host;

  const bodyObj = { phoneNumbers: numbers, options: { includeAdditionalOperatorDetails: true } };
  const body = JSON.stringify(bodyObj);
  const contentHash = sha256Base64(body);
  const date = rfc1123Now();

  const stringToSign = `POST\n${pathAndQuery}\n${date};${host};${contentHash}`;
  const signature = hmacSHA256Base64(acsAccessKeyBase64, stringToSign);
  const auth = `HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=${signature}`;

  const headers = {
    "Content-Type": "application/json",
    "x-ms-date": date,
    "x-ms-content-sha256": contentHash,
    Authorization: auth,
    Host: host
  };

  const res = await httpRequest("POST", url, headers, body);
  if (res.status !== 200) throw new Error(`ACS lookup failed ${res.status}: ${res.body}`);
  const parsed = JSON.parse(res.body);
  return parsed.values || [];
}

function parseNumbers(csvText) {
  csvText = csvText.replace(/^\uFEFF/, "");
  const lines = csvText.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return [];
  const header = lines[0].split(",").map((h) => h.trim().toLowerCase());
  const idx = header.indexOf("number");
  if (idx === -1) throw new Error("CSV header must include 'number'");
  const nums = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(",");
    let raw = (cols[idx] || "").trim();
    if (!raw) continue;
    if (!raw.startsWith("+")) raw = "+" + raw.replace(/[^\d]/g, "");
    nums.push(raw);
  }
  return nums;
}
function toCsv(results) {
  const header = ["phoneNumber","internationalFormat","nationalFormat","numberType","isoCountryCode","operatorName","mcc","mnc"];
  const rows = results.map((r) => [
    r.phoneNumber || "",
    r.internationalFormat || "",
    r.nationalFormat || "",
    r.numberType || "",
    r.isoCountryCode || "",
    r.operatorDetails?.name || "",
    r.operatorDetails?.mobileCountryCode || "",
    r.operatorDetails?.mobileNetworkCode || "",
  ]);
  return [header.join(","), ...rows.map((a) => a.map((v) => String(v).replace(/,/g, " ")).join(","))].join("\n");
}
module.exports = async function (context, req) {
  try {
    const inputBlob = (req.query.input || INPUT_BLOB).trim();
    const outputBlob = (req.query.output || OUTPUT_BLOB).trim();
    if (!BLOB_CONTAINER) throw new Error("BLOB_CONTAINER app setting is missing.");
    const s = parseConnStringKV(AZURE_WEBJOBS_STORAGE || "");
    const accountName = s.AccountName;
    const accountKey = s.AccountKey;
    if (!accountName || !accountKey) throw new Error("AzureWebJobsStorage must include AccountName and AccountKey.");
    const a = parseConnStringKV(ACS_CONNECTION_STRING || "");
    const acsEndpoint = a.endpoint || a.Endpoint;
    const acsKey = a.accesskey || a.AccessKey;
    if (!acsEndpoint || !acsKey) throw new Error("ACS_CONNECTION_STRING must include endpoint and accesskey.");
    const csvIn = await readCsv(accountName, accountKey, BLOB_CONTAINER, inputBlob);
    const numbers = parseNumbers(csvIn);
    if (numbers.length === 0) throw new Error("No numbers found in CSV.");
    const allResults = [];
// Send up to 100 numbers per request
context.log("parsed numbers count:", numbers.length, "example:", numbers[0]);

for (let i = 0; i < numbers.length; i += 100) {
  const chunk = numbers.slice(i, i + 100);
  const vals = await numberLookup(acsEndpoint, acsKey, chunk);
  allResults.push(...vals);
}  
    const outCsv = toCsv(allResults);
    await writeCsv(accountName, accountKey, BLOB_CONTAINER, outputBlob, outCsv);
    context.res = {
      status: 200,
      body: JSON.stringify({ ok: true, container: BLOB_CONTAINER, input: inputBlob, output: outputBlob, totalInput: numbers.length, totalReturned: allResults.length }),
      headers: { "Content-Type": "application/json" },
    };
  } catch (err) {
    context.log.error(err.stack || err.message || String(err));
    context.res = { status: 500, body: String(err && err.message ? err.message : err) };
  }
};
