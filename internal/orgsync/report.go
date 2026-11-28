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
	reportBatch  = 250 // below both the 500-report and 64 KiB wire limits, even at maximum integers
	minWant      = 256 << 20
	maxPoolBytes = 1 << 53
)

// Reporter renews org grants on the elected worker. Call each second: ordinary changes report
// at most once per minute; half-consumed grants and lower usage report at the next call.
type Reporter struct {
	DB  *sql.DB
	Dir suitedir.Client
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
	Seq          *int64 `json:"seq"`
	CeilingBytes *int64 `json:"ceiling_bytes"`
	TTLSeconds   *int64 `json:"ttl_seconds"`
	PoolBytes    *int64 `json:"pool_bytes"`
	OrgUsedBytes *int64 `json:"org_used_bytes"`
	OverSince    *int64 `json:"over_since"`
}

func (r *Reporter) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

func (r *Reporter) Report(ctx context.Context) error {
	tenancy, err := storage.TenancyOfContext(ctx, r.DB)
	if err != nil || !tenancy.Multi() {
		return err
	}
	// Keep stopped orgs with an old grant so their next report releases it. No customer data is
	// served here; suspended orgs' retained bytes still count in KyIdentity.
	rows, err := r.DB.QueryContext(ctx, `SELECT o.id FROM orgs o LEFT JOIN org_pool p ON p.org_id=o.id WHERE `+storage.InServedCell("o")+` AND o.id<>? AND ((o.status='active' AND o.enabled=1) OR p.org_id IS NOT NULL) ORDER BY o.id`, tenancy.StaffOrg)
	if err != nil {
		return err
	}
	var orgs []string
	for rows.Next() {
		var org string
		if err := rows.Scan(&org); err != nil {
			rows.Close()
			return err
		}
		orgs = append(orgs, org)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var batch []storageReport
	for _, org := range orgs {
		report, due, err := r.prepare(ctx, org)
		if err != nil {
			return err
		}
		if !due {
			continue
		}
		batch = append(batch, report)
		if len(batch) == reportBatch {
			if err := r.send(ctx, batch); err != nil {
				return err
			}
			batch = nil
		}
	}
	if len(batch) > 0 {
		return r.send(ctx, batch)
	}
	return nil
}

// prepare snapshots usage and stops growth in one short writer transaction. KyIdentity replaces
// the old grant on receipt: allowing writes against it while the request is in flight would
// let this app spend headroom KyIdentity has already made available to another app.
func (r *Reporter) prepare(ctx context.Context, org string) (storageReport, bool, error) {
	rep := storageReport{OrgID: org}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return rep, false, err
	}
	defer tx.Rollback()
	var reported, ceiling, pool int64
	var expires, attempted string
	err = tx.QueryRowContext(ctx, `SELECT reported_bytes,ceiling_bytes,pool_bytes,expires_at,attempted_at FROM org_pool WHERE org_id=?`, org).Scan(&reported, &ceiling, &pool, &expires, &attempted)
	fresh := errors.Is(err, sql.ErrNoRows)
	if err != nil && !fresh {
		return rep, false, err
	}
	var serving bool
	if err := tx.QueryRowContext(ctx, `SELECT status='active' AND enabled=1 FROM orgs WHERE id=?`, org).Scan(&serving); err != nil {
		return rep, false, err
	}
	used, err := storage.OrgChargedBytes(r.DB, tx, org, "")
	if err != nil {
		return rep, false, err
	}
	if used < 0 || used > maxPoolBytes {
		return rep, false, errors.New("storage pool: usage outside wire limit")
	}
	now := r.clock()
	until, _ := time.Parse(time.RFC3339Nano, expires)
	tried, _ := time.Parse(time.RFC3339Nano, attempted)
	halfSpent := ceiling > reported && used > reported && used-reported >= (ceiling-reported+1)/2
	if !fresh {
		if !serving && used == reported && ceiling == 0 {
			return rep, false, nil
		}
		// Retry failures and zero grants once per minute. A lower figure is reported immediately.
		if used >= reported && now.Before(tried.Add(time.Minute)) && !halfSpent {
			return rep, false, nil
		}
		// Only usable headroom earns the unchanged-usage shortcut. Charged bytes include
		// pending reservations, so a positive ceiling can still be exhausted.
		if serving && ceiling > used && used == reported && now.Before(until.Add(-450*time.Second)) {
			return rep, false, nil
		}
	}
	if storage.IsPostgres(r.DB) {
		// Nontransactional sequence survives rollback. N3 serializes allocation and resync, including
		// after a restored database has received a higher seq in a stale response.
		if err := tx.QueryRowContext(ctx, `SELECT nextval('org_storage_report_seq')`).Scan(&rep.Seq); err != nil {
			return rep, false, err
		}
		var last int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0) FROM org_pool`).Scan(&last); err != nil {
			return rep, false, err
		}
		if rep.Seq <= last {
			if last == int64(^uint64(0)>>1) {
				return rep, false, errors.New("storage pool: sequence exhausted")
			}
			if err := tx.QueryRowContext(ctx, `SELECT setval('org_storage_report_seq',?)`, last+1).Scan(&rep.Seq); err != nil {
				return rep, false, err
			}
		}
	} else {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq),0)+1 FROM org_pool`).Scan(&rep.Seq); err != nil {
			return rep, false, err
		}
	}
	rep.UsedBytes = used
	if serving {
		rep.WantBytes = max(minWant, pool/10)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO org_pool(org_id,seq,attempted_at) VALUES(?,?,?) ON CONFLICT(org_id) DO UPDATE SET seq=excluded.seq,attempted_at=excluded.attempted_at,ceiling_bytes=0,expires_at=''`, org, rep.Seq, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return rep, false, err
	}
	return rep, true, tx.Commit()
}

var errAnswer = errors.New("storage pool: the answer does not match the reports")

func (r *Reporter) send(ctx context.Context, reports []storageReport) error {
	u, err := url.Parse(r.Dir.Issuer)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname()))) {
		return errors.New("storage pool: the issuer must be an HTTPS URL")
	}
	body, err := json.Marshal(map[string]any{"reports": reports})
	if err != nil {
		return err
	}
	if len(body) > 64<<10 {
		return errors.New("storage pool: report exceeds wire limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.JoinPath("api", "suite", "storage").String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.SetBasicAuth(r.Dir.ClientID, r.Dir.ClientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := http.Client{Timeout: 15 * time.Second}
	if r.Dir.HTTP != nil {
		client = *r.Dir.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirects are refused") }
	sent := r.clock()
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("storage pool: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("storage pool: KyIdentity answered %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return err
	}
	var answer struct {
		Results []storageResult `json:"results"`
	}
	if len(raw) > 1<<20 || json.Unmarshal(raw, &answer) != nil || len(answer.Results) != len(reports) {
		return errAnswer
	}
	for i, res := range answer.Results {
		if res.OrgID != reports[i].OrgID {
			return errAnswer
		}
		if res.Result == "unknown_org" {
			continue
		}
		if (res.Result != "ok" && res.Result != "stale") || res.Seq == nil || res.CeilingBytes == nil || res.TTLSeconds == nil || res.PoolBytes == nil || res.OrgUsedBytes == nil {
			return errAnswer
		}
		if *res.Seq < reports[i].Seq || (res.Result == "ok" && *res.Seq != reports[i].Seq) || *res.TTLSeconds != 900 || *res.CeilingBytes < 0 || *res.CeilingBytes > maxPoolBytes || *res.PoolBytes < 0 || *res.PoolBytes > maxPoolBytes || *res.OrgUsedBytes < 0 || *res.OrgUsedBytes > maxPoolBytes {
			return errAnswer
		}
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i, res := range answer.Results {
		seq, used, ceiling, expiry, pool, orgUsed := reports[i].Seq, reports[i].UsedBytes, int64(0), "", int64(0), int64(0)
		if res.Result == "ok" {
			ceiling, expiry = *res.CeilingBytes, sent.Add(time.Duration(*res.TTLSeconds)*time.Second).UTC().Format(time.RFC3339Nano)
			pool, orgUsed = *res.PoolBytes, *res.OrgUsedBytes
		}
		if res.Result == "stale" {
			seq = *res.Seq
			used = -1
		} // resync, then send a fresh report; never extend an old grant
		if _, err := tx.ExecContext(ctx, `UPDATE org_pool SET seq=?,reported_bytes=?,ceiling_bytes=?,expires_at=?,pool_bytes=?,org_used_bytes=?,over_since=? WHERE org_id=? AND seq=?`, seq, used, ceiling, expiry, pool, orgUsed, res.OverSince, res.OrgID, reports[i].Seq); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func loopback(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }
