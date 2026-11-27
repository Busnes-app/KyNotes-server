import legacyVectors from "../../testdata/protocol/envelope_vectors.json";
import { base64 } from "./crypto";
import { LEGACY_ENVELOPE_ALG } from "./teamKeys";
import { describe, expect, it } from "vitest";
import { hexToBytes as h } from "@noble/ciphers/utils.js";
import v from "../../testdata/protocol/pq_vectors.json";
import { ENVELOPE_ALG, ENVELOPE_BYTES, unwrapEnvelope, wrapEnvelope, wrapIdentity, unwrapIdentity } from "./teamKeys";
import { generatePQIdentityReady, identityPublic } from "./pqIdentity";
import { openKeyring, waitingKey, reminderIDKey } from "./keyring";

describe("v4 X-Wing envelopes",()=>{
  it("opens the Go envelope with both signature halves, and binds tenant, container, generation and devices",async()=>{
    const env=h(v.Envelope), privateKey=h(v.RecipientPrivate),pub=h(v.SenderPublic);
    expect(env.length).toBe(ENVELOPE_BYTES);
    const open=(env:Uint8Array,org=v.OrgID,cid=v.ContainerID,g=v.Generation,did=v.RecipientID,sender=pub)=>unwrapEnvelope(ENVELOPE_ALG,env,privateKey,cid,g,did,sender,org);
    expect(await open(env)).toEqual(new Uint8Array(32).fill(42));
    for(const at of [0,1,31,32,100,1152,env.length-65,env.length-1]){const bad=env.slice();bad[at]^=1;await expect(open(bad)).rejects.toThrow();}
    await expect(open(env,"other-org")).rejects.toThrow();
    await expect(open(env,v.OrgID,`cnt_${"z".repeat(26)}`)).rejects.toThrow();
    await expect(open(env,v.OrgID,v.ContainerID,v.Generation+1)).rejects.toThrow();
    await expect(open(env,v.OrgID,v.ContainerID,v.Generation,`dev_${"z".repeat(26)}`)).rejects.toThrow();
    await expect(open(env,v.OrgID,v.ContainerID,v.Generation,v.RecipientID,h(v.RecipientPublic))).rejects.toThrow();
    const fresh=await wrapEnvelope(new Uint8Array(32).fill(42),h(v.RecipientPublic),v.ContainerID,v.Generation,v.RecipientID,{deviceId:v.SenderID,privateKey:h(v.SenderPrivate)},v.OrgID);
    expect(fresh).not.toEqual(env);expect(await open(fresh)).toEqual(new Uint8Array(32).fill(42));
    await expect(wrapEnvelope(new Uint8Array(32),new Uint8Array(32),v.ContainerID,7,v.RecipientID,{deviceId:v.SenderID,privateKey:h(v.SenderPrivate)},v.OrgID)).rejects.toThrow("upgrade");
  });
  it("retains drafts and reminder IDs, and validates wrapped PQ identities",()=>{
    const privateKey=h(v.SenderPrivate),pub=h(v.SenderPublic),legacy={privateKey:privateKey.subarray(1,33)};
    expect(identityPublic(privateKey)).toEqual(pub);
    expect(waitingKey({privateKey})).toEqual(waitingKey(legacy));expect(reminderIDKey({privateKey})).toEqual(reminderIDKey(legacy));
    const kek=new Uint8Array(32).fill(17),uid=`usr_${"a".repeat(26)}`;
    const wrapped=wrapIdentity(kek,privateKey,uid);expect(unwrapIdentity(kek,wrapped,uid)).toEqual({privateKey,publicKey:pub});
    const bad=privateKey.slice();bad[100]^=1;expect(()=>identityPublic(bad)).toThrow();
    expect(generatePQIdentityReady(legacy.privateKey).publicKey.subarray(1,33)).toEqual(pub.subarray(1,33));
  });
});

import { loadPQ } from "./pq";

it("PQ identities open legacy history but refuse a classical envelope at the write generation",async()=>{
  const old=legacyVectors.envelopes[0], me={...generatePQIdentityReady(h(old.recipientPrivateKey)),deviceId:old.recipientDeviceId,userId:`usr_${"a".repeat(26)}`};
  const sender=generatePQIdentityReady(h(old.senderPrivateKey));
  const member={userId:`usr_${"b".repeat(26)}`,username:"owner",role:"owner",identity:{deviceId:old.senderDeviceId,publicKey:base64(sender.publicKey)}};
  const row={deviceId:me.deviceId,keyGeneration:old.keyGeneration,alg:LEGACY_ENVELOPE_ALG,envelope:base64(h(old.envelope))};
  const open=(generation:number)=>openKeyring({containerID:old.containerId,envelopes:[row],me,members:[member],pins:{},known:{generation,mark:0,digests:{}}});
  expect((await open(old.keyGeneration)).ring.size).toBe(0);
  expect((await open(old.keyGeneration+1)).ring.get(old.keyGeneration)).toEqual(h(old.contentKey));
});

it("loadPQ clears a failed load promise so subsequent retries succeed", async () => {
  const savedPQ = globalThis.pqwasm;
  const savedGo = globalThis.Go;
  const savedFetch = globalThis.fetch;
  // Valid minimal WebAssembly module (magic + version 1) so real WebAssembly.instantiate runs.
  const emptyWasm = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
  try {
    let fetchCalls = 0;
    globalThis.pqwasm = undefined;
    globalThis.Go = class {
      importObject: WebAssembly.Imports = {};
      run(_instance: WebAssembly.Instance): Promise<void> {
        globalThis.pqwasm = savedPQ;
        return Promise.resolve();
      }
    };
    globalThis.fetch = (async () => {
      fetchCalls++;
      if (fetchCalls === 1) throw new Error("transient network error");
      return new Response(emptyWasm, { status: 200 });
    }) as typeof fetch;

    await expect(loadPQ()).rejects.toThrow("transient network error");
    const loaded = await loadPQ();
    expect(loaded).toBe(savedPQ);
    expect(fetchCalls).toBe(2);
  } finally {
    globalThis.pqwasm = savedPQ;
    globalThis.Go = savedGo;
    globalThis.fetch = savedFetch;
  }
});
