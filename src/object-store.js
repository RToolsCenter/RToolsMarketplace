import { CreateBucketCommand, GetObjectCommand, HeadBucketCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";

export class MemoryObjectStore { constructor(){this.objects=new Map();} async ready(){} async put(key,bytes){this.objects.set(key,Buffer.from(bytes));return key;} async get(key){const value=this.objects.get(key);if(!value)throw Object.assign(new Error("Package not found"),{code:"PACKAGE_NOT_FOUND",status:404});return value;} }

export class S3ObjectStore {
  constructor({endpoint,region="us-east-1",bucket,accessKey,secretKey}) { this.bucket=bucket; this.client=new S3Client({endpoint,region,forcePathStyle:true,credentials:{accessKeyId:accessKey,secretAccessKey:secretKey}}); }
  async ready(){try{await this.client.send(new HeadBucketCommand({Bucket:this.bucket}));}catch{await this.client.send(new CreateBucketCommand({Bucket:this.bucket}));}}
  async put(key,bytes){await this.ready();await this.client.send(new PutObjectCommand({Bucket:this.bucket,Key:key,Body:bytes,ContentType:"application/vnd.rtools.plugin"}));return key;}
  async get(key){const result=await this.client.send(new GetObjectCommand({Bucket:this.bucket,Key:key}));return Buffer.from(await result.Body.transformToByteArray());}
}

export const objectStoreFromEnv=()=>process.env.S3_ENDPOINT?new S3ObjectStore({endpoint:process.env.S3_ENDPOINT,region:process.env.S3_REGION,bucket:process.env.S3_BUCKET,accessKey:process.env.S3_ACCESS_KEY,secretKey:process.env.S3_SECRET_KEY}):new MemoryObjectStore();
