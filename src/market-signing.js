import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export function createMarketSigner(keySource=process.env.MARKETPLACE_SIGNING_KEY) {
  let privateKey;if(keySource){if(keySource.includes("BEGIN"))privateKey=createPrivateKey(keySource);else if(existsSync(keySource))privateKey=createPrivateKey(readFileSync(keySource,"utf8"));else{privateKey=generateKeyPairSync("ed25519").privateKey;mkdirSync(dirname(keySource),{recursive:true});writeFileSync(keySource,privateKey.export({type:"pkcs8",format:"pem"}),{mode:0o600});}}else privateKey=generateKeyPairSync("ed25519").privateKey;
  const marketId=process.env.RTOOLS_MARKET_ID||"official.rtools.app";
  const keyId=process.env.RTOOLS_MARKET_KEY_ID||`${marketId}-ed25519-2026`;
  const name=process.env.RTOOLS_MARKET_NAME||"RTools Official Marketplace";
  const publicKey=createPublicKey(privateKey).export({type:"spki",format:"pem"}).toString();
  const publicKeys=[{keyId,algorithm:"Ed25519",publicKey}];
  return {
    marketId,
    keyId,
    name,
    publicKey,
    publicKeys,
    metadata(baseUrl){
      return {
        protocolVersion:1,
        marketId,
        name,
        baseUrl,
        publicKeys,
        capabilities:["plugins","ratings","reports","revocations"]
      };
    },
    sign(input){
      const payload=typeof input==="string"?{packageSha256:input}:input;
      const body={
        algorithm:"Ed25519",
        marketId,
        keyId,
        pluginId:payload.pluginId,
        version:payload.version,
        packageSha256:payload.packageSha256,
        developerSignature:payload.developerSignature||null,
        publicKey
      };
      body.signature=sign(null,Buffer.from(body.packageSha256,"hex"),privateKey).toString("base64");
      return body;
    }
  };
}
