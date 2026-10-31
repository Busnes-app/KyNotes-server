import { describe, expect, it } from "vitest";
import { parseBackupStatus, scheduleNote } from "./backup";
const status = {mirror:{configured:false,target:"",pending:0,last:null},key_id:"",paired:false,remote_url:"",local_directory:"",local_copies:[],interval_seconds:0,next_run:null,last_attempt:"",last_result:"",receipt:null,blob_count:2,blob_bytes:100,allow_private_recovery:false};
describe("backup status boundary", () => {
  it("represents an unconfigured instance without inventing coverage", () => { const result = parseBackupStatus(status); expect(result.keyID).toBe(""); expect(result.paired).toBe(false); expect(result.blobCount).toBe(2); expect(result.receipt).toBeNull(); });
  it("validates a deposit receipt", () => { const result = parseBackupStatus({...status,receipt:{capsule_id:"cap-test",digest:"digest",deposited_at:"2026-09-05T12:00:00Z"}}); expect(result.receipt?.id).toBe("cap-test"); });
  it("rejects malformed and unsafe counters", () => { for (const value of [null,{}, {...status,blob_count:-1},{...status,mirror:{configured:true,target:"file:///mirror",pending:-1,last:null}},{...status,receipt:{}},{...status,local_copies:null}]) expect(() => parseBackupStatus(value)).toThrow(); });
});
describe("backup schedule note", () => {
  const ready = parseBackupStatus({...status,key_id:"k1",paired:true,interval_seconds:86400,next_run:"2026-10-31T12:00:00Z"});
  it("waits for a recovery key instead of promising a next run", () => expect(scheduleNote({...ready,keyID:""})).toBe("Waiting for recovery key"));
  it("waits for a destination when a key is pinned but nothing is paired or local", () => expect(scheduleNote({...ready,paired:false})).toBe("Waiting for a destination"));
  it("shows the next run only when a backup can actually run", () => { expect(scheduleNote(ready)).toMatch(/^Next /); expect(scheduleNote({...ready,paired:false,localDirectory:"/backups"})).toMatch(/^Next /); expect(scheduleNote({...ready,intervalSeconds:0})).toBe("Manual only"); });
});
