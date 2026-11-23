package httpapi

import (
	"database/sql"
	"errors"
)

// eraseMemberTx is steps 1 to 3 of a member's Delete everything (tenancy spec, Lifecycle, "A
// member erases"), in the user.erased event's transaction, after deactivation ended its access:
// the account is marked erased, its pending invitations (sent or received) go, every notebook it
// owns that still has another approved member passes to the successor of open question 4 (a),
// and it leaves every other notebook through removeMemberTx, so the keys it held open nothing new.
// The notebooks it still owns alone, its comments and the account itself are deleted later, in
// batches (storage.EraseMembers).
func eraseMemberTx(tx *sql.Tx, user string) error {
	if _, err := tx.Exec(`UPDATE users SET status='erased' WHERE id=?`, user); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM invitations WHERE (inviter_id=? OR invitee_id=?) AND status='pending'`, user, user); err != nil {
		return err
	}
	owned, err := idsOf(tx, `SELECT id FROM containers WHERE owner_user_id=? AND deleted_at=''`, user)
	if err != nil {
		return err
	}
	for _, cid := range owned {
		// The longest-standing approved admin, else editor, else any approved member.
		var successor string
		err := tx.QueryRow(`SELECT user_id FROM memberships WHERE container_id=? AND user_id<>? AND revoked_at='' AND approved=1 ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'editor' THEN 1 ELSE 2 END, created_at, id LIMIT 1`, cid, user).Scan(&successor)
		if errors.Is(err, sql.ErrNoRows) {
			continue // a notebook it alone holds: deleted with its data
		}
		if err != nil {
			return err
		}
		for _, q := range []string{
			`UPDATE containers SET owner_user_id=?2 WHERE id=?1`,
			`UPDATE memberships SET role='owner' WHERE container_id=?1 AND user_id=?2`,
			`UPDATE memberships SET role='viewer' WHERE container_id=?1 AND user_id=?3`, // no longer an owner, so it can leave
		} {
			if _, err := tx.Exec(q, cid, successor, user); err != nil {
				return err
			}
		}
	}
	member, err := idsOf(tx, `SELECT m.container_id FROM memberships m JOIN containers c ON c.id=m.container_id WHERE m.user_id=? AND m.revoked_at='' AND m.role<>'owner' AND c.team_id=''`, user)
	if err != nil {
		return err
	}
	for _, cid := range member {
		if err := removeMemberTx(tx, cid, user); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	return nil
}

func idsOf(tx *sql.Tx, q string, args ...any) ([]string, error) {
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
