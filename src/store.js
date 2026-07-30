import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

const hash = value => createHash("sha256").update(value).digest("hex");

export class MemoryStore {
  constructor() { this.developers=new Map(); this.tokens=new Map(); this.plugins=new Map(); this.versions=new Map(); this.audit=[]; }
  register({email,displayName}) {
    if (![...this.developers.values()].some(item=>item.email===email)) {
      const developer={id:randomUUID(),email,displayName,status:"active",createdAt:new Date().toISOString()};
      this.developers.set(developer.id,developer);
      const token=`rtm_${randomBytes(24).toString("base64url")}`;
      this.tokens.set(hash(token),{id:randomUUID(),developerId:developer.id,name:"default",createdAt:new Date().toISOString()});
      this.log(developer.id,"developer.register",developer.id,{});
      return {developer,token};
    }
    throw Object.assign(new Error("Email already registered"),{code:"EMAIL_EXISTS",status:409});
  }
  authenticate(token) {
    if (!token?.startsWith("rtm_")) return null;
    const digest=hash(token), match=[...this.tokens.entries()].find(([candidate,metadata])=>!metadata.revokedAt&&timingSafeEqual(Buffer.from(candidate),Buffer.from(digest)));
    const developer=match ? this.developers.get(match[1].developerId) : null;
    return developer?.status==="active" ? developer : null;
  }
  createPlugin(owner,manifest) {
    const existing=this.plugins.get(manifest.id);
    if(existing && existing.ownerId!==owner.id) throw Object.assign(new Error("Plugin ID is owned by another developer"),{code:"PLUGIN_OWNERSHIP_DENIED",status:403});
    const plugin=existing||{id:manifest.id,ownerId:owner.id,status:"draft",trustLevel:"community",createdAt:new Date().toISOString()};
    Object.assign(plugin,{name:manifest.name,description:manifest.description||"",license:manifest.license||null,screenshots:manifest.screenshots||[],updatedAt:new Date().toISOString()}); this.plugins.set(plugin.id,plugin);
    this.log(owner.id,existing?"plugin.update":"plugin.create",plugin.id,{}); return plugin;
  }
  submitVersion(owner,manifest,input) {
    const plugin=this.plugins.get(manifest.id); if(!plugin||plugin.ownerId!==owner.id) throw Object.assign(new Error("Plugin ownership required"),{code:"PLUGIN_OWNERSHIP_DENIED",status:403});
    const key=`${manifest.id}@${manifest.version}`; if(this.versions.has(key)) throw Object.assign(new Error("Version already exists"),{code:"PLUGIN_VERSION_EXISTS",status:409});
    const version={id:randomUUID(),pluginId:manifest.id,version:manifest.version,manifest,changelog:manifest.changelog||"",packageSha256:input.packageSha256,packageSize:input.packageSize,fileManifest:input.fileManifest||[],developerSignature:input.developerSignature||null,objectKey:input.objectKey||null,status:"pending_scan",createdAt:new Date().toISOString()};
    this.versions.set(key,version); this.log(owner.id,"version.submit",key,{packageSha256:version.packageSha256}); return version;
  }
  scanVersion(actor,versionId) { const version=[...this.versions.values()].find(item=>item.id===versionId); if(!version)throw Object.assign(new Error("Version not found"),{code:"PLUGIN_VERSION_NOT_FOUND",status:404}); const report=scan(version); version.scanReport=report; version.status=report.errors.length?"scan_failed":"pending_review"; this.log(actor.id,"version.scan",`${version.pluginId}@${version.version}`,report); return version; }
  reviewVersion(actor,versionId,decision,note="") { const version=[...this.versions.values()].find(item=>item.id===versionId); if(!version)throw Object.assign(new Error("Version not found"),{code:"PLUGIN_VERSION_NOT_FOUND",status:404}); if(!["pending_review","rejected"].includes(version.status))throw Object.assign(new Error("Version is not reviewable"),{code:"PLUGIN_STATE_INVALID",status:409}); version.status=decision; version.review={reviewerId:actor.id,note,updatedAt:new Date().toISOString()}; this.log(actor.id,`version.${decision}`,`${version.pluginId}@${version.version}`,{note}); return version; }
  publishVersion(actor,versionId,publish=true) { const version=[...this.versions.values()].find(item=>item.id===versionId); if(!version)throw Object.assign(new Error("Version not found"),{code:"PLUGIN_VERSION_NOT_FOUND",status:404}); if(publish&&version.status!=="approved")throw Object.assign(new Error("Only approved versions can be published"),{code:"PLUGIN_STATE_INVALID",status:409}); if(!publish&&version.status!=="published")throw Object.assign(new Error("Only published versions can be unpublished"),{code:"PLUGIN_STATE_INVALID",status:409}); version.status=publish?"published":"unpublished"; version.publishedAt=publish?new Date().toISOString():null; const plugin=this.plugins.get(version.pluginId); plugin.status=publish?"published":"draft"; this.log(actor.id,publish?"version.publish":"version.unpublish",`${version.pluginId}@${version.version}`,{}); return version; }
  catalog({query="",category="",tag=""}={}) { const needle=query.toLowerCase();return [...this.plugins.values()].filter(item=>item.status==="published"&&(!needle||`${item.id} ${item.name} ${item.description}`.toLowerCase().includes(needle))&&(!category||item.categories?.includes(category))&&(!tag||item.tags?.includes(tag))).map(plugin=>({...plugin,versions:[...this.versions.values()].filter(v=>v.pluginId===plugin.id&&v.status==="published"),ratingAverage:0,ratingCount:0})); }
  download(pluginId,version) { const item=this.versions.get(`${pluginId}@${version}`);if(!item||item.status!=="published")throw Object.assign(new Error("Published version not found"),{code:"PLUGIN_VERSION_NOT_FOUND",status:404});return item; }
  setMarketSignature(actor,versionId,signature) { const version=[...this.versions.values()].find(item=>item.id===versionId);if(!version)throw Object.assign(new Error("Version not found"),{code:"PLUGIN_VERSION_NOT_FOUND",status:404});version.marketSignature=signature;this.log(actor.id,"version.market-sign",`${version.pluginId}@${version.version}`,{});return version; }
  auditLogs() { return [...this.audit].reverse(); }
  reviewQueue() { return [...this.versions.values()].map(version=>({...version,plugin:this.plugins.get(version.pluginId)})).sort((a,b)=>b.createdAt.localeCompare(a.createdAt)); }
  listDevelopers() { return [...this.developers.values()].map(developer=>({...developer,pluginCount:[...this.plugins.values()].filter(p=>p.ownerId===developer.id).length,activeTokenCount:[...this.tokens.values()].filter(t=>t.developerId===developer.id&&!t.revokedAt).length})); }
  setDeveloperStatus(actor,id,status) { const developer=this.developers.get(id); if(!developer)throw Object.assign(new Error("Developer not found"),{code:"DEVELOPER_NOT_FOUND",status:404}); developer.status=status;if(status==="suspended")for(const plugin of this.plugins.values())if(plugin.ownerId===id){plugin.status="suspended";for(const version of this.versions.values())if(version.pluginId===plugin.id&&version.status==="published")version.status="unpublished";}this.log(actor.id,"developer.status",id,{status}); return developer; }
  revokeDeveloperTokens(actor,id) { if(!this.developers.has(id))throw Object.assign(new Error("Developer not found"),{code:"DEVELOPER_NOT_FOUND",status:404}); let revoked=0; for(const token of this.tokens.values())if(token.developerId===id&&!token.revokedAt){token.revokedAt=new Date().toISOString();revoked++;} this.log(actor.id,"developer.tokens.revoke",id,{revoked}); return {revoked}; }
  createToken(owner,name){const token=`rtm_${randomBytes(24).toString("base64url")}`,metadata={id:randomUUID(),developerId:owner.id,name,createdAt:new Date().toISOString()};this.tokens.set(hash(token),metadata);this.log(owner.id,"token.create",metadata.id,{name});return {token,...metadata};}
  listTokens(owner){return [...this.tokens.values()].filter(item=>item.developerId===owner.id).map(({developerId,...item})=>item);}
  revokeToken(owner,id){const item=[...this.tokens.values()].find(token=>token.id===id&&token.developerId===owner.id);if(!item)throw Object.assign(new Error("Token not found"),{code:"TOKEN_NOT_FOUND",status:404});item.revokedAt=new Date().toISOString();this.log(owner.id,"token.revoke",id,{});return {revoked:true};}
  incrementDownload(pluginId,version){const item=this.download(pluginId,version);item.downloadCount=(item.downloadCount||0)+1;}
  ratePlugin(pluginId,userKey,score,comment){if(!this.plugins.has(pluginId))throw Object.assign(new Error("Plugin not found"),{code:"PLUGIN_NOT_FOUND",status:404});this.ratings??=new Map();this.ratings.set(`${pluginId}:${userKey}`,{id:randomUUID(),pluginId,userKey,score,comment,createdAt:new Date().toISOString()});return {ok:true};}
  pluginRatings(pluginId){return [...(this.ratings?.values()||[])].filter(item=>item.pluginId===pluginId).map(({userKey,...item})=>item);}
  reportPlugin(pluginId,userKey,input){if(!this.plugins.has(pluginId))throw Object.assign(new Error("Plugin not found"),{code:"PLUGIN_NOT_FOUND",status:404});this.reports??=[];const report={id:randomUUID(),pluginId,userKey,version:input.version||null,reason:input.reason,details:input.details||"",status:"open",createdAt:new Date().toISOString()};this.reports.push(report);return report;}
  listReports(){return [...(this.reports||[])].reverse();}
  resolveReport(actor,id,status,note){const report=(this.reports||[]).find(item=>item.id===id);if(!report)throw Object.assign(new Error("Report not found"),{code:"REPORT_NOT_FOUND",status:404});Object.assign(report,{status,resolutionNote:note});this.log(actor.id,"report.resolve",id,{status});return report;}
  suspendPlugin(actor,id){const plugin=this.plugins.get(id);if(!plugin)throw Object.assign(new Error("Plugin not found"),{code:"PLUGIN_NOT_FOUND",status:404});plugin.status="suspended";for(const version of this.versions.values())if(version.pluginId===id&&version.status==="published")version.status="unpublished";this.log(actor.id,"plugin.suspend",id,{});return plugin;}
  categories(){return [{id:"productivity",name:"效率工具"},{id:"developer",name:"开发工具"},{id:"utilities",name:"实用工具"},{id:"entertainment",name:"娱乐"}];}
  tags(){const values=new Set([...this.plugins.values()].flatMap(plugin=>plugin.tags||[]));return [...values].sort().map(id=>({id,name:id}));}
  setTaxonomy(actor,id,{categories=[],tags=[]}){const plugin=this.plugins.get(id);if(!plugin)throw Object.assign(new Error("Plugin not found"),{code:"PLUGIN_NOT_FOUND",status:404});plugin.categories=categories;plugin.tags=tags;this.log(actor.id,"plugin.taxonomy",id,{categories,tags});return plugin;}
  setTrustLevel(actor,id,trustLevel){const plugin=this.plugins.get(id);if(!plugin)throw Object.assign(new Error("Plugin not found"),{code:"PLUGIN_NOT_FOUND",status:404});plugin.trustLevel=trustLevel;this.log(actor.id,"plugin.trust",id,{trustLevel});return {id,trustLevel};}
  adminLogin(username,password){if(username!=="admin"||password!=="test-admin")throw Object.assign(new Error("Invalid administrator credentials"),{code:"ADMIN_LOGIN_INVALID",status:401});const token=`rta_${randomBytes(24).toString("base64url")}`;this.adminTokens??=new Map();this.adminTokens.set(hash(token),{id:"test-admin",role:"super_admin",expiresAt:Date.now()+8*3600000});return {token,expiresIn:28800,admin:{id:"test-admin",username:"admin",role:"super_admin"}};}
  authenticateAdmin(token){const session=this.adminTokens?.get(hash(token||""));return session&&session.expiresAt>Date.now()?session:null;}
  listPlugins(owner) { return [...this.plugins.values()].filter(item=>item.ownerId===owner.id).map(plugin=>({...plugin,versions:[...this.versions.values()].filter(v=>v.pluginId===plugin.id)})); }
  log(actorId,action,target,details) { this.audit.push({id:this.audit.length+1,actorId,action,target,details,createdAt:new Date().toISOString()}); if(this.audit.length>10000)this.audit.shift(); }
}

export function scan(version) { const errors=[],warnings=[]; if(!version.developerSignature)warnings.push("DEVELOPER_SIGNATURE_MISSING"); if(!version.fileManifest.length)warnings.push("FILE_MANIFEST_EMPTY"); let total=0; for(const file of version.fileManifest){if(typeof file.path!=="string"||file.path.startsWith("/")||file.path.includes("..")||file.path.includes("\\"))errors.push("PACKAGE_PATH_INVALID");if(!/^[a-f0-9]{64}$/.test(file.sha256||""))errors.push("FILE_HASH_INVALID");if(!Number.isSafeInteger(file.size)||file.size<0)errors.push("FILE_SIZE_INVALID");else total+=file.size;} if(total>64*1024*1024)errors.push("PACKAGE_CONTENT_TOO_LARGE"); const critical=(version.manifest.permissions||[]).filter(item=>["shell:execute","clipboard:read"].includes(item)); if(critical.length)warnings.push(`CRITICAL_PERMISSIONS:${critical.join(",")}`); return {passed:errors.length===0,errors:[...new Set(errors)],warnings,totalSize:total,scannedAt:new Date().toISOString()}; }
