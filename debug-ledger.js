const r=require('./dist/check-registry.js');
const crypto=require('crypto');
const cbor=require('cbor');
const { publicKey, privateKey }=crypto.generateKeyPairSync('ed25519');
const pkPem=publicKey.export({type:'spki',format:'pem'}).toString();
function makeQC(e,root){ const msg=Buffer.from(`epoch:${e}|root:${root}`); const sig=crypto.sign(null,msg, privateKey).toString('base64'); return { epoch:e, signatures:[{validator:'v1',weight:10,sig}], rootHash:root }; }
const qc1=makeQC(1,'r1');
const qc2=makeQC(2,'r2');
const b64s=[qc1,qc2].map(q=>cbor.encode(q).toString('base64'));
const evidence={ governance:{ validatorKeys:{ v1: pkPem } }, ledger:{ quorumCertificatesCbor:b64s, finalityDepth:2, chains:[{name:'c1',finalityDepth:2, weightSum:0.7, epoch:1, signatures:[{signer:'v1', weight:10, valid:true}]},{name:'c2',finalityDepth:2, weightSum:0.8, epoch:2, signatures:[{signer:'v1', weight:10, valid:true}]}] } };
(async()=>{ for (const chk of r.ALL_CHECKS){ if (chk.id===16){ const res= await chk.evaluate({ evidence }); console.log('res', res); console.log('ledger mutated', JSON.stringify(evidence.ledger,null,2)); } }})();
