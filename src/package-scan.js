import { createHash, createPublicKey, verify } from "node:crypto";
import unzipper from "unzipper";

const sha=bytes=>createHash("sha256").update(bytes).digest("hex");
const failure=(code,message)=>Object.assign(new Error(message),{code,status:422});

export async function inspectPackage(bytes,{expectedSha256,developerSignature}={}) {
  if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>64*1024*1024)throw failure("PLUGIN_SIZE_INVALID","Package must be between 1 byte and 64 MB");
  const packageSha256=sha(bytes); if(expectedSha256&&expectedSha256!==packageSha256)throw failure("PLUGIN_HASH_MISMATCH","Server package SHA-256 does not match client value");
  let directory;try{directory=await unzipper.Open.buffer(bytes);}catch{throw failure("PLUGIN_ARCHIVE_INVALID","Package is not a valid ZIP archive");}
  if(directory.files.length>1024)throw failure("PLUGIN_ENTRY_LIMIT","Package contains too many entries");
  const files=new Map();let totalSize=0;
  for(const entry of directory.files){const path=entry.path.replaceAll("\\","/");if(!path||path.startsWith("/")||/^[A-Za-z]:/.test(path)||path.split("/").some(part=>part===".."||part===""))throw failure("PLUGIN_PATH_INVALID",`Unsafe package path: ${path}`);const mode=entry.vars?.unixPermissions||0;if((mode&0o170000)===0o120000)throw failure("PLUGIN_SYMLINK_FORBIDDEN",`Symbolic link is forbidden: ${path}`);if(entry.type==="Directory")continue;if(files.has(path))throw failure("PLUGIN_PATH_DUPLICATE",`Duplicate package path: ${path}`);const content=await entry.buffer();if(content.length>16*1024*1024)throw failure("PLUGIN_FILE_TOO_LARGE",`File exceeds 16 MB: ${path}`);totalSize+=content.length;if(totalSize>64*1024*1024)throw failure("PLUGIN_CONTENT_TOO_LARGE","Expanded package exceeds 64 MB");files.set(path,content);}
  const manifestBytes=files.get("rtools.json"),digestBytes=files.get(".rtools-manifest.json");if(!manifestBytes||!digestBytes)throw failure("PLUGIN_PACKAGE_MANIFEST_MISSING","rtools.json and .rtools-manifest.json are required");
  let manifest,digestManifest;try{manifest=JSON.parse(manifestBytes);digestManifest=JSON.parse(digestBytes);}catch{throw failure("PLUGIN_PACKAGE_JSON_INVALID","Package metadata is not valid JSON");}
  const expected=new Map((digestManifest.files||[]).map(file=>[file.path,file]));const actual=[];for(const [path,content] of files){if(path===".rtools-manifest.json")continue;const digest={path,size:content.length,sha256:sha(content)},declared=expected.get(path);if(!declared||declared.size!==digest.size||declared.sha256!==digest.sha256)throw failure("PLUGIN_FILE_MANIFEST_MISMATCH",`File manifest mismatch: ${path}`);actual.push(digest);expected.delete(path);}if(expected.size)throw failure("PLUGIN_FILE_MANIFEST_MISMATCH",`Missing declared file: ${expected.keys().next().value}`);
  let signatureValid=false;if(developerSignature){try{if(developerSignature.algorithm!=="Ed25519"||developerSignature.packageSha256!==packageSha256)throw new Error();signatureValid=verify(null,Buffer.from(packageSha256,"hex"),createPublicKey(developerSignature.publicKey),Buffer.from(developerSignature.signature,"base64"));}catch{throw failure("PLUGIN_SIGNATURE_INVALID","Developer signature is invalid");}if(!signatureValid)throw failure("PLUGIN_SIGNATURE_INVALID","Developer signature is invalid");}
  return {manifest,packageSha256,packageSize:bytes.length,fileManifest:actual.sort((a,b)=>a.path.localeCompare(b.path)),expandedSize:totalSize,signatureValid};
}
