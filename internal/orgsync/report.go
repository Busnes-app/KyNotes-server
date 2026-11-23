package orgsync

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Busnes-app/ky-primitives/suitedir"
	"github.com/Busnes-app/kynotes-server/internal/storage"
)

const (
	reportBatch = 500       // the contract's most reports per request
	minWant     = 256 << 20 // the smallest grant asked for: 256 MiB
)

// Reporter sends each serving org's charged bytes to KyIdentity's storage pool (POST
// /api/suite/storage, report-and-grant) and stores the grant it answers (tenancy N10, owner
// decision 14). It runs on the elected worker in multi mode.
type Reporter struct {
	DB  *sql.DB
	Dir suitedir.Client // Issuer, ClientID, ClientSecret and HTTP, as for the org poll
	now func() time.Time
}

type storageReport struct {
	OrgID     string `json:"org_id"`
	UsedBytes int64  `json:"used_bytes"`
	Seq       int64  `json:"seq"`
	WantBytes int64  `json:"want_bytes"`
}

type storageResult struct {
	OrgID        string `json:"org_id"`
	Result       string `json:"result"`
	Seq          int64  `json:"seq"`
	CeilingBytes int64  `json:"ceiling_bytes"`
	TTLSeconds   int64  `json:"ttl_seconds"`
	PoolBytes    int64  `json:"pool_bytes"`
}

// Report sends every report that is due: an org never reported, whose usage changed, whose grant
// is half spent or half way to expiring, or that has none. A whole answer is applied or nothing.
func (r *Reporter) Report(ctx context.Context) error {
	tenancy, err := storage.TenancyOf(r.DB)
	if err != nil || !tenancy.Multi() {
		return err
	}
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT o.id,COALESCE(p.reported_bytes,-1),COALESCE(p.ceiling_bytes,0),COALESCE(p.expires_at,''),COALESCE(p.pool_bytes,0) FROM orgs o LEFT JOIN org_pool p ON p.org_id=o.id WHERE o.status='active' AND o.enabled=1 AND o.home_region=? AND o.id<>? ORDER BY o.id`, tenancy.Region, tenancy.StaffOrg)
	if err != nil {
		return err
	}
	type due struct {
		org            string
		reported, ceil int64
		expires        string
		pool           int64
	}
	var orgs []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.org, &d.reported, &d.ceil, &d.expires, &d.pool); err != nil {
			rows.Close()
			return err
		}
		orgs = append(orgs, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var batch []storageReport
	for _, d := range orgs {
		used, err := storage.OrgChargedBytes(r.DB, d.org, "")
		if err != nil {
			return err
		}
		until, perr := time.Parse(time.RFC3339Nano, d.expires)
		halfTime := perr != nil || now().After(until.Add(-450*time.Second)) // half the 900 s grant
		halfSpent := d.ceil > d.reported && used-d.reported >= (d.ceil-d.reported)/2
		if d.reported >= 0 && used == d.reported && !halfTime && !halfSpent {
			continue
		}
		var seq int64
		if err := r.DB.QueryRowContext(ctx, `INSERT INTO org_pool(org_id,seq) VALUES(?,1) ON CONFLICT(org_id) DO UPDATE SET seq=org_pool.seq+1 RETURNING seq`, d.org).Scan(&seq); err != nil {
			return err
		}
		batch = append(batch, storageReport{OrgID: d.org, UsedBytes: used, Seq: seq, WantBytes: max(minWant, d.pool/10)})
		if len(batch) == reportBatch {
			if err := r.send(ctx, batch, now); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}
	if len(batch) == 0 {
		return nil
	}
	return r.send(ctx, batch, now)
}

// errAnswer: KyIdentity's answer does not match the reports; nothing of it is applied.
var errAnswer = errors.New("storage pool: the answer does not match the reports")

func (r *Reporter) send(ctx context.Context, reports []storageReport, now func() time.Time) error {
	u, err := url.Parse(r.Dir.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !loopback(u.Hostname())) {
		return errors.New("storage pool: the issuer must be an HTTPS URL")
	}
	body, err := json.Marshal(map[string]any{"reports": reports})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.JoinPath("/api/suite/storage").String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(r.Dir.ClientID, r.Dir.ClientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := r.Dir.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	sent := now() // a grant expires ttl_seconds after the request was sent
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("storage pool: KyIdentity answered %d", resp.StatusCode)
	}
	var answer struct {
		Results []storageResult `json:"results"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&answer); err != nil || len(answer.Results) != len(reports) {
		return errAnswer
	}
	for i, res := range answer.Results {
		ok := res.OrgID == reports[i].OrgID
		switch res.Result {
		case "ok":
			ok = ok && res.Seq == reports[i].Seq && res.TTLSeconds > 0 && res.CeilingBytes >= 0
		case "stale":
			ok = ok && res.Seq > 0 && res.TTLSeconds > 0 && res.CeilingBytes >= 0
		case "unknown_org":
		default:
			ok = false
		}
		if !ok {
			return errAnswer
		}
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i, res := range answer.Results {
		ceiling, expires, seq := int64(0), "", reports[i].Seq
		if res.Result != "unknown_org" {
			ceiling, expires = res.CeilingBytes, sent.Add(time.Duration(res.TTLSeconds)*time.Second).UTC().Format(time.RFC3339Nano)
		}
		if res.Result == "stale" {
			seq = res.Seq // KyIdentity's stored seq: the next report goes above it (after a restore)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE org_pool SET seq=CASE WHEN seq>? THEN seq ELSE ? END,reported_bytes=?,ceiling_bytes=?,expires_at=?,pool_bytes=? WHERE org_id=?`, seq, seq, reports[i].UsedBytes, ceiling, expires, res.PoolBytes, res.OrgID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}
