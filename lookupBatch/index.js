// lookupBatch — reads numbers_in.csv from blob, calls ACS Operator Information Search,
// writes number_lookup_results.csv back to the same container.
// CommonJS, Node 20, no npm packages.

const crypto = require("crypto");
const https = require("https");
const { URL } = require("url");

// ---- ENV ----
const BLOB_CONTAINER = process.env.BLOB_CONTAINER;
const INPUT_BLOB = process.env.INPUT_BLOB || "numbers_in.csv";
const OUTPUT_BLOB = process.env.OUTPUT_BLOB || "number_lookup_results.csv";
const ACS_CONNECTION_STRING = process.env.ACS_CONNECTION_STRING; // endpoint=...communication.azure.com/;accesskey=...
const AZURE_WEBJOBS_STORAGE = process.env.AzureWebJobsStorage;

// ---- Helpers ----
function parseConnStringKV(conn) {
  const kv = {};
  for (const part of String(conn || "").split(";")) {
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

// ---- Azure Blob (Shared Key) signing ----
function signBlobRequest({ method, url, headers, accountName, accountKeyBase64 }) {
  headers["x-ms-date"] = headers["x-ms-date"] || rfc1123Now();
  headers["x-ms-version"] = headers["x-ms-version"] || "2021-08-06";
  const canonHeaders = Object.keys(headers)
    .filter((k) => k.toLowerCase().startsWith("x-ms-"))
    .sort()
    .map((k) => `${k.toLowerCase().trim()}:${String(headers[k]).trim()}\n`)
    .join("");
  const u = new URL(url);
  const path = u.pathname;
  const qp = [];
  u.searchParams.forEach((value, name) => qp.push([name.toLowerCase(), value]));
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

// ---- Read/Write CSV from Blob ----
async function readCsv(accountName, accountKey, container, blob) {
  const url = `https://${accountName}.blob.core.windows.net/${encodeURIComponent(container)}/${encodeURIComponent(blob)}`;
  const headers = signBlobRequest({
    method: "GET",
    url,
    headers: { "x-ms-date": rfc1123Now(), "x-ms-version": "2021-08-06" },
    accountName,
    accountKeyBase64: accountKey,
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

// ---- ACS Operator Information Search (array payload) ----
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
  const headers = {
    "Content-Type": "application/json",
    "x-ms-date": date,
    "x-ms-content-sha256": contentHash,
    Authorization: `HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=${signature}`,
    Host: host,
  };

  // debug
  console.log("ACS URL:", url, "count:", numbers.length);

  const res = await httpRequest("POST", url, headers, body);
  if (res.status !== 200) throw new Error(`ACS lookup failed ${res.status}: ${res.body}`);
  const parsed = JSON.parse(res.body);
  return parsed.values || [];
}

// ---- CSV helpers ----
function parseNumbers(csvText) {
  // Strip BOM + normalize line endings + trim trailing spaces
  csvText = String(csvText || "").replace(/^\uFEFF/, "");
  const lines = csvText.split(
