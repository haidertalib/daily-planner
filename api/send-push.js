const crypto = require("crypto");
const https  = require("https");

const VAPID_PUBLIC  = "BAkVcxqpkXzhO0zagvvzIx1Krcw54fxoBCEWAI9bwueHn9ZfJsGRnGPO8PH2x-eOOwf_uz4PRY_KJ9yikylCSsc";
const VAPID_PRIVATE = "uyAWe-S1vwx9rSgMYyGorh8mYwkZTn6sVE1yx27TNj0";
const VAPID_EMAIL   = "mailto:hayder.talib@gmail.com";

function b64url(buf){return Buffer.from(buf).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function fromb64url(s){s=s.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";return Buffer.from(s,"base64");}

async function buildJWT(endpoint){
  const u=new URL(endpoint);
  const exp=Math.floor(Date.now()/1000)+43200;
  const hdr=b64url(JSON.stringify({typ:"JWT",alg:"ES256"}));
  const pld=b64url(JSON.stringify({aud:u.origin,exp,sub:VAPID_EMAIL}));
  const msg=hdr+"."+pld;
  const ecdh=crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(fromb64url(VAPID_PRIVATE));
  const key=crypto.createPrivateKey({format:"jwk",key:{kty:"EC",crv:"P-256",
    d:fromb64url(VAPID_PRIVATE).toString("base64"),
    x:ecdh.getPublicKey().slice(1,33).toString("base64"),
    y:ecdh.getPublicKey().slice(33,65).toString("base64")}});
  const sig=crypto.sign("sha256",Buffer.from(msg),{key,dsaEncoding:"ieee-p1363"});
  return msg+"."+b64url(sig);
}

function encryptPayload(sub,payload){
  const clientPub=fromb64url(sub.keys.p256dh);
  const clientAuth=fromb64url(sub.keys.auth);
  const ecdh=crypto.createECDH("prime256v1");
  ecdh.generateKeys();
  const serverPub=ecdh.getPublicKey();
  const sharedSecret=ecdh.computeSecret(clientPub);
  const salt=crypto.randomBytes(16);
  function hkdf(s,i,inf,l){
    const p=crypto.createHmac("sha256",s).update(i).digest();
    return crypto.createHmac("sha256",p).update(Buffer.concat([Buffer.from(inf),Buffer.from([1])])).digest().slice(0,l);
  }
  const prk=crypto.createHmac("sha256",clientAuth).update(sharedSecret).digest();
  const ctx=Buffer.concat([Buffer.from("P-256\x00"),Buffer.from([0,clientPub.length]),clientPub,Buffer.from([0,serverPub.length]),serverPub]);
  const cek=hkdf(salt,prk,"Content-Encoding: aesgcm\x00"+ctx,16);
  const nonce=hkdf(salt,prk,"Content-Encoding: nonce\x00"+ctx,12);
  const cipher=crypto.createCipheriv("aes-128-gcm",cek,nonce);
  const padded=Buffer.concat([Buffer.alloc(2),Buffer.from(payload)]);
  const enc=Buffer.concat([cipher.update(padded),cipher.final(),cipher.getAuthTag()]);
  return{enc,salt,serverPub};
}

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin","*");
  res.setHeader("Access-Control-Allow-Headers","Content-Type");
  if(req.method==="OPTIONS"){res.status(200).end();return;}
  if(req.method!=="POST"){res.status(405).json({error:"Method not allowed"});return;}
  try{
    const{subscription,title,body,url}=req.body;
    if(!subscription?.endpoint){res.status(400).json({error:"Missing subscription"});return;}
    const payload=JSON.stringify({title:title||"Daily Planner",body:body||"You have tasks waiting.",url:url||"/"});
    const jwt=await buildJWT(subscription.endpoint);
    const{enc,salt,serverPub}=encryptPayload(subscription,payload);
    const u=new URL(subscription.endpoint);
    await new Promise((resolve,reject)=>{
      const r=https.request({hostname:u.hostname,path:u.pathname+u.search,method:"POST",
        headers:{"Content-Type":"application/octet-stream","Content-Encoding":"aesgcm",
          "Content-Length":enc.length,"Encryption":"salt="+b64url(salt),
          "Crypto-Key":"dh="+b64url(serverPub)+";p256ecdsa="+VAPID_PUBLIC,
          "Authorization":"WebPush "+jwt,"TTL":"86400"}
      },resp=>{resp.on("data",()=>{});resp.on("end",()=>resp.statusCode<300?resolve():reject(new Error(resp.statusCode)));});
      r.on("error",reject);r.write(enc);r.end();
    });
    res.status(200).json({ok:true});
  }catch(e){res.status(500).json({error:e.message});}
};
