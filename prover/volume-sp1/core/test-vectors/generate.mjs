// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
// Independent reference vectors. Requires the existing pinned viem 2.56.1; no network use.
import { readFileSync, writeFileSync } from 'node:fs';
const moduleUrl = import.meta.resolve(process.env.VIEM_MODULE || 'viem');
const { encodeAbiParameters, decodeAbiParameters, keccak256, toHex, padHex, fromRlp, toRlp, size } = await import(moduleUrl);
const version = JSON.parse(readFileSync(new URL('../package.json', moduleUrl),'utf8')).version;
if (version !== '2.56.1') throw new Error(`Expected viem 2.56.1; found ${version}`);
const fields = (pairs) => pairs.map(([name,type])=>({name,type}));
const venueFields = fields([
 ['kind','uint8'],['account','address'],['accountCodeHash','bytes32'],['currency0','address'],['currency1','address'],
 ['fee','uint24'],['tickSpacing','int24'],['hooks','address'],['hookCodeHash','bytes32'],['poolId','bytes32'],['quoteAsset','address'],['minNotional','uint256']
]);
const termsFields = [
 ...fields([['domain','bytes32'],['rulesHash','bytes32'],['proofMethodId','bytes32'],['chainId','uint64'],['controller','address'],['adapter','address'],['pool','address'],['raceId','uint256'],['headerFormat','uint8'],['entrantCount','uint8'],['entrants','address[8]'],['entrantsHash','bytes32']]),
 {name:'venues',type:'tuple[8]',components:venueFields},
 ...fields([['startBlock','uint64'],['snapshotBlock','uint64'],['bettingCutoff','uint64'],['confirmationBlocks','uint64'],['quietBlocks','uint64'],['submissionDeadline','uint64'],['terminalExpiry','uint64'],['history','address'],['historyCodeHash','bytes32'],['historyWindow','uint64'],['wrappedNative','address'],['wrappedNativeCodeHash','bytes32'],['quoteAsset','address'],['quoteDecimals','uint8'],['collateral','address'],['collateralDecimals','uint8'],['economicPolicyHash','bytes32'],['proofSuiteHash','bytes32'],['sp1Verifier','address'],['sp1VerifierCodeHash','bytes32'],['circuitIdentity','bytes32']])
];
const journalFields = fields([['domain','bytes32'],['termsHash','bytes32'],['proofSuiteHash','bytes32'],['beneficiary','address'],['coverageMask','uint8'],['fromExclusive','uint64'],['toInclusive','uint64'],['beforeHash','bytes32'],['endHash','bytes32'],['volumeQuote','uint256[8]'],['qualifyingSwapCount','uint256[8]']]);
const keyFields=fields([['currency0','address'],['currency1','address'],['fee','uint24'],['tickSpacing','int24'],['hooks','address']]);
const zaddr='0x'+'00'.repeat(20), zhash='0x'+'00'.repeat(32);
const addr = (n)=>padHex(toHex(BigInt(n)),{size:20});
const hash=(s)=>keccak256(toHex(s));
const word=(n)=>padHex(toHex(BigInt(n)),{size:32});
const keyHash=(v)=>keccak256(encodeAbiParameters(keyFields,[v.currency0,v.currency1,v.fee,v.tickSpacing,v.hooks]));
const zeroVenue=()=>({kind:0,account:zaddr,accountCodeHash:zhash,currency0:zaddr,currency1:zaddr,fee:0,tickSpacing:0,hooks:zaddr,hookCodeHash:zhash,poolId:zhash,quoteAsset:zaddr,minNotional:0n});
function terms(n,native=true) {
 const wrapper=addr(0x9000),quote=native?wrapper:addr(0xffff),tokens=Array.from({length:n},(_,i)=>addr(0x1000+i));
 const venues=tokens.map((token,i)=>{
  const v={kind:1,account:addr(0x2000),accountCodeHash:hash('manager-code'),currency0:native?zaddr:token,currency1:native?token:quote,
   fee:i*500,tickSpacing:200+i,hooks:addr(0x3000),hookCodeHash:hash('hook-code'),poolId:zhash,quoteAsset:quote,minNotional:BigInt(100+i)};
  v.poolId=keyHash(v);return v;
 });
 return {domain:hash('synthetic-terms-domain'),rulesHash:hash('synthetic-rules'),proofMethodId:hash('synthetic-method'),chainId:46630n,
  controller:addr(0x4000),adapter:addr(0x4001),pool:addr(0x4002),raceId:(1n<<200n)+BigInt(n),headerFormat:0,entrantCount:n,
  entrants:[...tokens,...Array(8-n).fill(zaddr)],entrantsHash:keccak256(encodeAbiParameters([{type:'address[]'}],[tokens])),
  venues:[...venues,...Array.from({length:8-n},zeroVenue)],startBlock:1000n,snapshotBlock:37000n,bettingCutoff:36400n,
  confirmationBlocks:12n,quietBlocks:300n,submissionDeadline:73000n,terminalExpiry:90000n,history:addr(0x5000),historyCodeHash:hash('history-code'),historyWindow:393168n,
  wrappedNative:wrapper,wrappedNativeCodeHash:hash('wrapper-code'),quoteAsset:quote,quoteDecimals:native?18:6,
  collateral:addr(0x6000),collateralDecimals:6,economicPolicyHash:hash('synthetic-policy-not-approved'),proofSuiteHash:hash('synthetic-suite'),
  sp1Verifier:addr(0x7000),sp1VerifierCodeHash:hash('verifier-code'),circuitIdentity:hash('synthetic-circuit')};
}
const termsAbi=(t)=>encodeAbiParameters([{type:'tuple',components:termsFields}],[t]);
const jsonTerms=(t)=>({...t,raceId:word(t.raceId),venues:t.venues.map(v=>({...v,minNotional:word(v.minNotional)}))});
const cases=[];
for(const [name,n,native,mask] of [['native3-mask5',3,true,5],['native4',4,true,15],['native8',8,true,255],['erc20-token0',3,false,7]]) {
 const t=terms(n,native),encoded=termsAbi(t),th=keccak256(encoded);
 const j={domain:hash('KAI_VOLUME_SP1_RANGE_V1'),termsHash:th,proofSuiteHash:t.proofSuiteHash,beneficiary:addr(0x8000),coverageMask:mask,
  fromExclusive:1100n,toInclusive:1200n,beforeHash:hash('before'),endHash:hash('end'),
  volumeQuote:Array.from({length:8},(_,i)=>mask&(1<<i)?(1n<<200n)+BigInt(i):0n),
  qualifyingSwapCount:Array.from({length:8},(_,i)=>mask&(1<<i)?BigInt(i+1):0n)};
 const publicValues=encodeAbiParameters([{type:'tuple',components:journalFields}],[j]);
 if(size(encoded)!==4352 || size(publicValues)!==800) throw new Error('ABI width mismatch');
 const executionContextHash=keccak256(encodeAbiParameters(fields([['domain','bytes32'],['terms','bytes32'],['suite','bytes32'],['beneficiary','address'],['mask','uint8']]),[j.domain,j.termsHash,j.proofSuiteHash,j.beneficiary,j.coverageMask]));
 cases.push({name,kind:'synthetic ABI vector; no approved policy/deployment',terms:jsonTerms(t),termsAbi:encoded,termsHash:th,
  journal:{...j,volumeQuote:j.volumeQuote.map(word),qualifyingSwapCount:j.qualifyingSwapCount.map(word)},journalAbi:publicValues,executionContextHash});
}
const signedVenues=[-8388608,-1,0,8388607].map(tickSpacing=>{
 const v={...terms(3).venues[0],tickSpacing,fee:0xffffff};v.poolId=keyHash(v);
 return {tickSpacing,kind:'synthetic ABI width only; dynamic fee is not an active volume venue',venue:{...v,minNotional:word(v.minNotional)},abi:encodeAbiParameters([{type:'tuple',components:venueFields}],[v]),poolKeyHash:v.poolId};
});
const swapTypes=fields([['amount0','int128'],['amount1','int128'],['sqrtPriceX96','uint160'],['liquidity','uint128'],['tick','int24'],['fee','uint24']]);
function swapCase(name,t,a0,a1,expectedQuote,output,accepted=true) {
 const data=encodeAbiParameters(swapTypes,[a0,a1,(1n<<159n)+5n,(1n<<127n)+6n,-8388608,0xffffff]);
 const decoded=decodeAbiParameters(swapTypes,data);
 if(decoded[0]!==a0 || decoded[1]!==a1)throw new Error('viem signed delta mismatch');
 return {name,terms:jsonTerms(t),termsAbi:termsAbi(t),log:{emitter:t.venues[0].account,topics:[hash('Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)'),t.venues[0].poolId,word(0x8001)],data},
  expected:{accepted,quoteAmount:word(expectedQuote),tokenIsOutput:output,amount0:a0.toString(),amount1:a1.toString(),sender:addr(0x8001)}};
}
const n=terms(3),e=terms(3,false);
const swaps=[swapCase('native-buy-at-floor',n,-100n,7n,100n,true),swapCase('native-sell',n,101n,-7n,101n,false),
 swapCase('below-floor',n,-99n,7n,99n,true,false),swapCase('erc20-token0-buy',e,7n,-100n,100n,true),
 swapCase('erc20-token0-sell',e,-7n,100n,100n,false),swapCase('int128-min-quote',n,-(1n<<127n),1n,1n<<127n,true)];
const attribution=[3,4,8].map(n=>{
 const t=terms(n);const logs=t.venues.slice(0,n).map((v,i)=>({emitter:v.account,topics:[hash('Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)'),v.poolId,word(0x8001)],
  data:encodeAbiParameters(swapTypes,[-v.minNotional,7n,11n,13n,0,v.fee]),entrantIndex:i}));
 return {terms:jsonTerms(t),logs,expectedVolumes:t.venues.map((v,i)=>word(i<n?v.minNotional:0n))};
});
// Kind-2 (Uniswap V3) venues: the pool itself is the account, poolId is bytes32(uint160(pool)),
// no hook (zero hook and zero hook code hash), tickSpacing 0. Two sides: the entrant token as
// currency0 (quote address above it) and as currency1 (quote address below it).
const V3_TOPIC=hash('Swap(address,address,int256,int256,uint160,uint128,int24)');
const addrWord=(a)=>padHex(a,{size:32});
function v3Terms(side) {
 const t=terms(4,true);
 if(side==='token1'){const wrapper=addr(0x0900);t.wrappedNative=wrapper;t.quoteAsset=wrapper;for(const v of t.venues.slice(0,4))v.quoteAsset=wrapper;}
 const pool=addr(0xe500),token=t.entrants[0],quote=t.wrappedNative;
 const [c0,c1]=side==='token1'?[quote,token]:[token,quote];
 if(!(c0<c1))throw new Error('V3 venue currency order');
 t.venues[0]={kind:2,account:pool,accountCodeHash:hash('v3-pool-code'),currency0:c0,currency1:c1,fee:3000,tickSpacing:0,hooks:zaddr,hookCodeHash:zhash,poolId:addrWord(pool),quoteAsset:quote,minNotional:100n};
 return t;
}
const v3SwapTypes=fields([['amount0','int256'],['amount1','int256'],['sqrtPriceX96','uint160'],['liquidity','uint128'],['tick','int24']]);
const signedWord=(n)=>toHex(BigInt.asUintN(256,n),{size:32});
function v3SwapCase(name,t,a0,a1,expectedQuote,output,accepted=true) {
 const data=encodeAbiParameters(v3SwapTypes,[a0,a1,(1n<<159n)+5n,(1n<<127n)+6n,-8388608]);
 const decoded=decodeAbiParameters(v3SwapTypes,data);
 if(decoded[0]!==a0 || decoded[1]!==a1)throw new Error('viem signed int256 mismatch');
 if(size(data)!==160)throw new Error('V3 Swap data width');
 const encoded=termsAbi(t);
 return {name,terms:jsonTerms(t),termsAbi:encoded,termsHash:keccak256(encoded),log:{emitter:t.venues[0].account,topics:[V3_TOPIC,word(0x8001),word(0x8002)],data},
  expected:{accepted,quoteAmount:word(expectedQuote),tokenIsOutput:output,amount0:a0.toString(),amount1:a1.toString(),amount0Word:signedWord(a0),amount1Word:signedWord(a1),sender:addr(0x8001)}};
}
const v3t0=v3Terms('token0'),v3t1=v3Terms('token1'),I256_MIN=-(1n<<255n),I256_MAX=(1n<<255n)-1n;
const v3Swaps=[
 v3SwapCase('v3-token0-buy-at-floor',v3t0,-5n,100n,100n,true),v3SwapCase('v3-token0-sell',v3t0,5n,-101n,101n,false),
 v3SwapCase('v3-token0-below-floor',v3t0,-5n,99n,99n,true,false),v3SwapCase('v3-token0-zero-token-delta',v3t0,0n,100n,100n,false),
 v3SwapCase('v3-token1-buy',v3t1,100n,-5n,100n,true),v3SwapCase('v3-token1-sell',v3t1,-100n,5n,100n,false),
 v3SwapCase('v3-int256-min-quote',v3t0,-5n,I256_MIN,1n<<255n,true),v3SwapCase('v3-int256-max-quote',v3t0,5n,I256_MAX,I256_MAX,false)];
const real=JSON.parse(readFileSync(new URL('nitro-117903561.json',import.meta.url),'utf8'));
const realTerms=terms(4);
realTerms.entrants[0]=real.poolKey.currency1.toLowerCase();
realTerms.entrantsHash=keccak256(encodeAbiParameters([{type:'address[]'}],[realTerms.entrants.slice(0,4)]));
realTerms.venues[0]={...realTerms.venues[0],...real.poolKey,currency0:real.poolKey.currency0.toLowerCase(),currency1:real.poolKey.currency1.toLowerCase(),hooks:real.poolKey.hooks.toLowerCase(),account:real.logs[0].address,minNotional:1n,poolId:real.expectedSwap.poolId};
if(keyHash(realTerms.venues[0])!==real.expectedSwap.poolId)throw new Error('Real pool key mismatch');
const realHeaderFields=fromRlp(real.block.canonicalHeaderRlp);
if(size(real.block.canonicalHeaderRlp)!==550 || keccak256(real.block.canonicalHeaderRlp)!==real.block.hash)throw new Error('Real header mismatch');
const mutated=(label,index,value)=>{const f=[...realHeaderFields];f[index]=value;return {label,rlp:toRlp(f)};};
const badHeaders=[
 mutated('number leading zero',8,'0x00'+realHeaderFields[8].slice(2)),mutated('number exceeds uint64',8,'0x010000000000000000'),
 mutated('gas limit exceeds uint64',9,'0x010000000000000000'),mutated('timestamp exceeds uint64',11,'0x010000000000000000'),
 mutated('base fee exceeds uint256',15,'0x01'+'00'.repeat(32)),mutated('receipt root width',5,'0x12'),mutated('parent root width',0,'0x12'),
 mutated('miner width',2,'0x'+'11'.repeat(21)),mutated('bloom width',6,'0x'+'00'.repeat(255)),mutated('nonce width',14,'0x00'),
 mutated('gas used exceeds limit',10,toHex(BigInt(realHeaderFields[9])+1n)),mutated('nested header field',12,['0x01']),
 {label:'fifteen fields',rlp:toRlp(realHeaderFields.slice(0,15))},{label:'PRICE twenty-one fields',rlp:toRlp([...realHeaderFields,...Array(5).fill('0x')])},
 {label:'trailing byte',rlp:real.block.canonicalHeaderRlp+'00'},{label:'truncated header',rlp:real.block.canonicalHeaderRlp.slice(0,-2)},
 {label:'noncanonical long length',rlp:'0xfa000223'+real.block.canonicalHeaderRlp.slice(8)}
];
const result={generator:'viem 2.56.1 encodeAbiParameters/decodeAbiParameters/keccak256/toRlp; independent of Rust implementation',cases,signedVenues,swaps,attribution,v3Swaps,
 real:{terms:jsonTerms(realTerms),termsAbi:termsAbi(realTerms),expectedParentHash:realHeaderFields[0],expectedNumber:'117903561',expectedGasLimit:BigInt(realHeaderFields[9]).toString(),expectedGasUsed:BigInt(realHeaderFields[10]).toString(),expectedTimestamp:BigInt(realHeaderFields[11]).toString(),expectedBaseFee:word(BigInt(realHeaderFields[15]))},badHeaders};
writeFileSync(new URL('abi-vectors.json',import.meta.url),JSON.stringify(result,(_,v)=>typeof v==='bigint'?v.toString():v,2)+'\n');
console.log(`Generated ${cases.length} complete terms/journal vectors, ${signedVenues.length} signed venue vectors, ${swaps.length} swap vectors, ${v3Swaps.length} V3 swap vectors, ${badHeaders.length} invalid headers with viem ${version}.`);
