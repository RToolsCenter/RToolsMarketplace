import http from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { MemoryStore } from "./store.js";
import { MySqlStore } from "./mysql-store.js";
import { objectStoreFromEnv } from "./object-store.js";
import { inspectPackage } from "./package-scan.js";
import { createMarketSigner } from "./market-signing.js";
import { createHash } from "node:crypto";

const root=resolve(dirname(fileURLToPath(import.meta.url)),"../..","RToolsPluginSDK","schemas");
const json=async name=>JSON.parse(await readFile(resolve(root,name),"utf8"));
const send=(res,status,value)=>{res.writeHead(status,{"content-type":"application/json; charset=utf-8","cache-control":"no-store"});res.end(JSON.stringify(value));};
const html=(res,value)=>{res.writeHead(200,{"content-type":"text/html; charset=utf-8","cache-control":"no-store"});res.end(value);};
const body=req=>new Promise((ok,fail)=>{let value="";req.on("data",chunk=>{value+=chunk;if(value.length>2_000_000){fail(Object.assign(new Error("Body too large"),{code:"BODY_TOO_LARGE",status:413}));req.destroy();}});req.on("end",()=>{try{ok(JSON.parse(value||"{}"));}catch(error){fail(error);}});});
const binaryBody=req=>new Promise((ok,fail)=>{const chunks=[];let size=0,done=false;req.on("data",chunk=>{size+=chunk.length;if(size>64*1024*1024){done=true;fail(Object.assign(new Error("Package exceeds 64 MB"),{code:"PLUGIN_SIZE_INVALID",status:413}));req.destroy();}else chunks.push(chunk);});req.on("end",()=>{if(!done)ok(Buffer.concat(chunks));});req.on("error",fail);});
const sendBinary=(res,bytes,headers={})=>{res.writeHead(200,{"content-type":"application/vnd.rtools.plugin","content-length":bytes.length,...headers});res.end(bytes);};
const error=(code,message,details,requestId=crypto.randomUUID())=>({code,message,details,requestId});
const compare=(a,b)=>{const x=a.split(".").map(Number),y=b.split(".").map(Number);for(let i=0;i<3;i++){if(x[i]!==y[i])return(x[i]||0)-(y[i]||0);}return 0;};
const requireRole=(admin,roles)=>{if(!roles.includes(admin.role))throw Object.assign(new Error("Administrator role is insufficient"),{code:"ADMIN_ROLE_DENIED",status:403});};

async function validatePreflight(input,pluginId) {
  const manifest=input.manifest,schema=await json("rtools.schema.v1.json"),ajv=new Ajv2020({allErrors:true,strict:false});addFormats(ajv);const validate=ajv.compile(schema);
  if(!manifest||!validate(manifest)) throw Object.assign(new Error("Manifest schema validation failed"),{code:"PLUGIN_SCHEMA_INVALID",status:422,details:(validate.errors||[]).map(item=>`${item.instancePath} ${item.message}`)});
  if(pluginId&&pluginId!==manifest.id) throw Object.assign(new Error("Path plugin ID does not match manifest"),{code:"PLUGIN_ID_MISMATCH",status:422});
  const permissions=await json("permissions.v1.json"),known=new Set(permissions.permissions.map(item=>item.id)),unknown=(manifest.permissions||[]).find(item=>!known.has(item));
  if(unknown) throw Object.assign(new Error(`Unknown permission: ${unknown}`),{code:"PLUGIN_PERMISSION_UNKNOWN",status:422});
  if(!/^[a-f0-9]{64}$/.test(input.packageSha256||"")) throw Object.assign(new Error("Invalid package SHA-256"),{code:"PLUGIN_HASH_INVALID",status:422});
  if(!Number.isSafeInteger(input.packageSize)||input.packageSize<1||input.packageSize>64*1024*1024) throw Object.assign(new Error("Invalid package size"),{code:"PLUGIN_SIZE_INVALID",status:422});
  return manifest;
}

export function createServer({store=new MemoryStore(),objectStore=objectStoreFromEnv(),marketSigner=createMarketSigner(),adminToken=process.env.MARKETPLACE_ADMIN_TOKEN||"test-admin-token",logger=()=>{}}={}) { const rateLimits=new Map();return http.createServer(async(req,res)=>{const requestId=crypto.randomUUID(),started=Date.now();res.setHeader("x-request-id",requestId);res.once("finish",()=>logger(JSON.stringify({requestId,method:req.method,path:req.url,status:res.statusCode,durationMs:Date.now()-started})));try{
  const url=new URL(req.url,"http://localhost"),parts=url.pathname.split("/").filter(Boolean);
  const clientKey=req.socket.remoteAddress||"unknown",minute=Math.floor(Date.now()/60000),rateKey=`${clientKey}:${minute}`,used=(rateLimits.get(rateKey)||0)+1;rateLimits.set(rateKey,used);if(rateLimits.size>10000)for(const key of rateLimits.keys())if(!key.endsWith(`:${minute}`))rateLimits.delete(key);if(used>300)throw Object.assign(new Error("Too many requests"),{code:"RATE_LIMITED",status:429});
  if(req.method==="GET"&&url.pathname==="/admin")return html(res,await readFile(resolve(dirname(fileURLToPath(import.meta.url)),"../public/admin.html"),"utf8"));
  if(req.method==="GET"&&url.pathname==="/api/v1/market/metadata")return send(res,200,marketSigner.metadata(process.env.RTOOLS_MARKET_BASE_URL||`${req.headers["x-forwarded-proto"]||"http"}://${req.headers.host}`));
  if(req.method==="GET"&&url.pathname==="/api/v1/market/public-keys")return send(res,200,{marketId:marketSigner.marketId,items:marketSigner.publicKeys});
  if(req.method==="GET"&&url.pathname==="/api/v1/revocations")return send(res,200,{marketId:marketSigner.marketId,items:[]});
  if(req.method==="GET"&&url.pathname==="/api/v1/protocol/schema")return send(res,200,await json("rtools.schema.v1.json"));
  if(req.method==="GET"&&url.pathname==="/api/v1/protocol/permissions")return send(res,200,await json("permissions.v1.json"));
  if(req.method==="GET"&&url.pathname==="/api/v1/protocol/market-key")return send(res,200,{algorithm:"Ed25519",marketId:marketSigner.marketId,keyId:marketSigner.keyId,publicKey:marketSigner.publicKey});
  if(req.method==="GET"&&url.pathname==="/api/v1/compatibility"){const host=url.searchParams.get("hostVersion"),min=url.searchParams.get("minVersion"),max=url.searchParams.get("maxVersion");return send(res,200,{compatible:Boolean(host&&min)&&compare(host,min)>=0&&(!max||compare(host,max)<=0)});}
  if(req.method==="GET"&&url.pathname==="/api/v1/plugins")return send(res,200,{items:await store.catalog({query:url.searchParams.get("q")||"",category:url.searchParams.get("category")||"",tag:url.searchParams.get("tag")||""})});
  if(req.method==="GET"&&url.pathname==="/api/v1/categories")return send(res,200,{items:await store.categories()});
  if(req.method==="GET"&&url.pathname==="/api/v1/tags")return send(res,200,{items:await store.tags()});
  if(req.method==="GET"&&parts.slice(0,3).join("/")==="api/v1/plugins"&&parts[4]==="versions"&&parts[6]==="download"){const item=await store.download(parts[3],parts[5]),bytes=await objectStore.get(item.objectKey);await store.incrementDownload(parts[3],parts[5]);return sendBinary(res,bytes,{"x-package-sha256":item.packageSha256,"x-rtools-market-id":marketSigner.marketId,"x-rtools-market-key-id":marketSigner.keyId,"x-market-signature":Buffer.from(typeof item.marketSignature==="string"?item.marketSignature:JSON.stringify(item.marketSignature||{})).toString("base64url"),"content-disposition":`attachment; filename="${parts[3]}-${parts[5]}.rtools"`});}
  if(req.method==="GET"&&parts.length===4&&parts.slice(0,3).join("/")==="api/v1/plugins"){const items=await store.catalog({query:parts[3]}),item=items.find(plugin=>plugin.id===parts[3]);if(!item)throw Object.assign(new Error("Plugin not found"),{code:"PLUGIN_NOT_FOUND",status:404});return send(res,200,item);}
  if(req.method==="GET"&&parts.length===5&&parts.slice(0,3).join("/")==="api/v1/plugins"&&parts[4]==="updates"){const items=await store.catalog({query:parts[3]}),plugin=items.find(item=>item.id===parts[3]),host=url.searchParams.get("hostVersion"),current=url.searchParams.get("currentVersion")||"0.0.0",version=plugin?.versions?.find(item=>{const min=item.minHostVersion||item.manifest?.rtools?.minVersion||"0.0.0",max=item.maxHostVersion||item.manifest?.rtools?.maxVersion;return compare(item.version,current)>0&&(!host||compare(host,min)>=0&&(!max||compare(host,max)<=0));});return send(res,200,{updateAvailable:Boolean(version),version:version||null});}
  if(req.method==="POST"&&parts.length===5&&parts.slice(0,3).join("/")==="api/v1/plugins"&&parts[4]==="ratings"){const input=await body(req),score=Number(input.score);if(!Number.isInteger(score)||score<1||score>5||String(input.comment||"").length>4000)throw Object.assign(new Error("Rating is invalid"),{code:"RATING_INVALID",status:422});const userKey=createHash("sha256").update(String(req.headers["x-client-id"]||clientKey)).digest("hex");return send(res,201,await store.ratePlugin(parts[3],userKey,score,String(input.comment||"")));}
  if(req.method==="GET"&&parts.length===5&&parts.slice(0,3).join("/")==="api/v1/plugins"&&parts[4]==="ratings")return send(res,200,{items:await store.pluginRatings(parts[3])});
  if(req.method==="POST"&&parts.length===5&&parts.slice(0,3).join("/")==="api/v1/plugins"&&parts[4]==="reports"){const input=await body(req);if(typeof input.reason!=="string"||input.reason.length<3||input.reason.length>80||String(input.details||"").length>4000)throw Object.assign(new Error("Report is invalid"),{code:"REPORT_INVALID",status:422});const userKey=createHash("sha256").update(String(req.headers["x-client-id"]||clientKey)).digest("hex");return send(res,201,await store.reportPlugin(parts[3],userKey,input));}
  if(req.method==="GET"&&url.pathname==="/health"){await store.health?.();return send(res,200,{status:"ok"});}
  if(req.method==="POST"&&url.pathname==="/api/v1/auth/register"){const input=await body(req);if(!/^\S+@\S+\.\S+$/.test(input.email||"")||typeof input.displayName!=="string"||input.displayName.trim().length<2)throw Object.assign(new Error("Valid email and displayName are required"),{code:"ACCOUNT_INVALID",status:422});return send(res,201,await store.register({email:input.email.toLowerCase(),displayName:input.displayName.trim()}));}
  if(req.method==="POST"&&url.pathname==="/api/v1/admin/login"){const input=await body(req);return send(res,200,await store.adminLogin(String(input.username||""),String(input.password||"")));}
  const token=req.headers.authorization?.match(/^Bearer (.+)$/)?.[1],developer=store.authenticate(token);
  if(url.pathname.startsWith("/api/v1/admin/")) {
    const admin=token===adminToken?{id:"marketplace-admin",role:"super_admin"}:await store.authenticateAdmin?.(token);if(!admin)throw Object.assign(new Error("Administrator session required"),{code:"ADMIN_AUTH_REQUIRED",status:401});
    const versionId=parts[4],action=parts[5];
    if(req.method==="POST"&&parts.slice(0,4).join("/")==="api/v1/admin/versions"&&action==="review"){const input=await body(req);if(!["approved","rejected"].includes(input.decision))throw Object.assign(new Error("Decision must be approved or rejected"),{code:"REVIEW_DECISION_INVALID",status:422});return send(res,200,await store.reviewVersion(admin,versionId,input.decision,String(input.note||"").slice(0,4000)));}
    if(req.method==="POST"&&parts.slice(0,4).join("/")==="api/v1/admin/versions"&&["publish","unpublish"].includes(action)){requireRole(admin,["admin","super_admin"]);const published=await store.publishVersion(admin,versionId,action==="publish");if(action==="publish")return send(res,200,await store.setMarketSignature(admin,versionId,marketSigner.sign(published)));return send(res,200,published);}
    if(req.method==="GET"&&url.pathname==="/api/v1/admin/audit")return send(res,200,{items:await store.auditLogs()});
    if(req.method==="GET"&&url.pathname==="/api/v1/admin/versions")return send(res,200,{items:await store.reviewQueue()});
    if(req.method==="GET"&&url.pathname==="/api/v1/admin/developers")return send(res,200,{items:await store.listDevelopers()});
    if(req.method==="GET"&&url.pathname==="/api/v1/admin/reports")return send(res,200,{items:await store.listReports()});
    if(req.method==="POST"&&parts.slice(0,4).join("/")==="api/v1/admin/developers"&&parts[5]==="status"){requireRole(admin,["super_admin"]);const input=await body(req);if(!["active","suspended"].includes(input.status))throw Object.assign(new Error("Developer status is invalid"),{code:"DEVELOPER_STATUS_INVALID",status:422});return send(res,200,await store.setDeveloperStatus(admin,parts[4],input.status));}
    if(req.method==="POST"&&parts.slice(0,4).join("/")==="api/v1/admin/developers"&&parts[5]==="revoke-tokens"){requireRole(admin,["super_admin"]);return send(res,200,await store.revokeDeveloperTokens(admin,parts[4]));}
    if(req.method==="POST"&&parts.slice(0,4).join("/")==="api/v1/admin/reports"&&parts[5]==="resolve"){const input=await body(req);if(!["resolved","dismissed"].includes(input.status))throw Object.assign(new Error("Report status is invalid"),{code:"REPORT_STATUS_INVALID",status:422});return send(res,200,await store.resolveReport(admin,parts[4],input.status,String(input.note||"").slice(0,4000)));}
    if(req.method==="POST"&&parts.slice(0,4).join("/")==="api/v1/admin/plugins"&&parts[5]==="suspend"){requireRole(admin,["admin","super_admin"]);return send(res,200,await store.suspendPlugin(admin,parts[4]));}
    if(req.method==="PUT"&&parts.slice(0,4).join("/")==="api/v1/admin/plugins"&&parts[5]==="taxonomy"){requireRole(admin,["admin","super_admin"]);const input=await body(req),categories=Array.isArray(input.categories)?input.categories.slice(0,5):[],tags=Array.isArray(input.tags)?input.tags.slice(0,20):[];return send(res,200,await store.setTaxonomy(admin,parts[4],{categories,tags}));}
    if(req.method==="PUT"&&parts.slice(0,4).join("/")==="api/v1/admin/plugins"&&parts[5]==="trust"){requireRole(admin,["admin","super_admin"]);const input=await body(req);if(!["community","verified","official"].includes(input.trustLevel))throw Object.assign(new Error("Plugin trust level is invalid"),{code:"PLUGIN_TRUST_INVALID",status:422});return send(res,200,await store.setTrustLevel(admin,parts[4],input.trustLevel));}
    return send(res,404,error("NOT_FOUND","Admin endpoint not found"));
  }
  const authenticated=await developer;
  if(!authenticated)throw Object.assign(new Error("Valid developer token required"),{code:"AUTH_REQUIRED",status:401});
  if(req.method==="GET"&&url.pathname==="/api/v1/developer/tokens")return send(res,200,{items:await store.listTokens(authenticated)});
  if(req.method==="POST"&&url.pathname==="/api/v1/developer/tokens"){const input=await body(req),name=String(input.name||"token").trim().slice(0,80);return send(res,201,await store.createToken(authenticated,name));}
  if(req.method==="DELETE"&&parts.slice(0,4).join("/")==="api/v1/developer/tokens")return send(res,200,await store.revokeToken(authenticated,parts[4]));
  if(req.method==="GET"&&url.pathname==="/api/v1/developer/plugins")return send(res,200,{items:await store.listPlugins(authenticated)});
  const pluginId=parts[4];
  if(req.method==="POST"&&parts.length===5&&parts.slice(0,4).join("/")==="api/v1/developer/plugins"){const input=await body(req),manifest=input.manifest;if(!manifest?.id)throw Object.assign(new Error("Manifest required"),{code:"PLUGIN_SCHEMA_INVALID",status:422});if(pluginId!==manifest.id)throw Object.assign(new Error("Path plugin ID does not match manifest"),{code:"PLUGIN_ID_MISMATCH",status:422});return send(res,201,await store.createPlugin(authenticated,manifest));}
  if(req.method==="POST"&&/\/versions\/preflight$/.test(url.pathname)){const input=await body(req),manifest=await validatePreflight(input,pluginId);return send(res,200,{valid:true,pluginId:manifest.id,version:manifest.version});}
  if(req.method==="POST"&&/\/versions$/.test(url.pathname)){const input=await body(req),manifest=await validatePreflight(input,pluginId);await store.createPlugin(authenticated,manifest);const version=await store.submitVersion(authenticated,manifest,input);return send(res,201,await store.scanVersion(authenticated,version.id));}
  if(req.method==="PUT"&&parts.slice(0,4).join("/")==="api/v1/developer/plugins"&&parts[5]==="versions"&&parts[7]==="package"){
    const bytes=await binaryBody(req),signatureHeader=req.headers["x-developer-signature"];let developerSignature=null;if(signatureHeader){try{developerSignature=JSON.parse(Buffer.from(signatureHeader,"base64url").toString("utf8"));}catch{throw Object.assign(new Error("Developer signature header is invalid"),{code:"PLUGIN_SIGNATURE_INVALID",status:422});}}
    const inspected=await inspectPackage(bytes,{expectedSha256:req.headers["x-package-sha256"],developerSignature});if(inspected.manifest.id!==pluginId||inspected.manifest.version!==parts[6])throw Object.assign(new Error("Upload path does not match package manifest"),{code:"PLUGIN_ID_MISMATCH",status:422});await validatePreflight(inspected,pluginId);await store.createPlugin(authenticated,inspected.manifest);const objectKey=`packages/${pluginId}/${parts[6]}/${inspected.packageSha256}.rtools`;await objectStore.put(objectKey,bytes);const version=await store.submitVersion(authenticated,inspected.manifest,{...inspected,developerSignature,objectKey});return send(res,201,await store.scanVersion(authenticated,version.id));
  }
  return send(res,404,error("NOT_FOUND","Endpoint not found"));
}catch(cause){send(res,cause.status||400,error(cause.code||"REQUEST_INVALID",cause.message,cause.details,requestId));}});}

if(process.argv[1]===fileURLToPath(import.meta.url)){const store=process.env.DATABASE_URL?new MySqlStore(process.env.DATABASE_URL):new MemoryStore();await store.ensureAdmin?.(process.env.MARKETPLACE_ADMIN_USER||"admin",process.env.MARKETPLACE_ADMIN_PASSWORD||"admin888888");createServer({store,objectStore:objectStoreFromEnv(),logger:line=>console.log(line)}).listen(Number(process.env.PORT||8787));}
