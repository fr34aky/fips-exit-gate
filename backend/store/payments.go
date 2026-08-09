package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// AttachInvoice records the BTCPay invoice id and checkout URL on a pending
// purchase, so later webhooks can find the purchase by invoice id.
func (s *Store) AttachInvoice(ctx context.Context, purchaseID, invoiceID, checkoutURL string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE purchases SET btcpay_invoice_id = $2, checkout_url = $3 WHERE id = $1`,
		purchaseID, invoiceID, checkoutURL)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPurchaseNotFound
	}
	return nil
}

// MarkProcessing records that a payment for invoiceID has been SEEN but is not
// yet final (BTCPay InvoiceProcessing) — e.g. an on-chain tx in the mempool at
// 0-conf, or an unconfirmed Monero payment. It updates the purchase status for
// the dashboard ("confirming…") but grants NO access: access is withheld until
// the payment is finalized (see GrantByInvoice). This avoids granting on a
// reversible 0-conf transaction. Idempotent; only advances pending -> processing
// (never downgrades a settled purchase, never revives a voided one).
func (s *Store) MarkProcessing(ctx context.Context, invoiceID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE purchases SET status = 'processing'
		 WHERE btcpay_invoice_id = $1 AND status = 'pending'`, invoiceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Either unknown invoice, or already past 'pending' (settled/processing/
		// voided). Distinguish unknown so the webhook can ack-and-ignore it.
		var exists bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM purchases WHERE btcpay_invoice_id = $1)`, invoiceID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrPurchaseNotFound
		}
	}
	return nil
}

// GrantByInvoice grants the entitlement for the purchase tied to invoiceID and
// marks it 'settled'. It is called ONLY on BTCPay InvoiceSettled — i.e. after
// the payment is final per the store's confirmation policy (>= 1 block for
// on-chain BTC; immediate for Lightning; the plugin's confirmations for Monero).
// This is what actually unlocks access. Idempotent and safe against
// replayed/out-of-order webhooks:
//
//   - already 'settled'         -> no-op (won't double-grant)
//   - 'invalid'/'expired' + Settled -> re-grants (payment ultimately cleared)
func (s *Store) GrantByInvoice(ctx context.Context, invoiceID string) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var purchaseID, status string
		err := tx.QueryRow(ctx,
			`SELECT id::text, status FROM purchases WHERE btcpay_invoice_id = $1 FOR UPDATE`,
			invoiceID).Scan(&purchaseID, &status)
		if err == pgx.ErrNoRows {
			return ErrPurchaseNotFound
		}
		if err != nil {
			return err
		}
		if status == "settled" {
			return nil // terminal — already granted
		}
		return grantEntitlementTx(ctx, tx, purchaseID, "settled")
	})
	if err != nil {
		return err
	}
	_, _, err = s.RecomputeAuthz(ctx)
	return err
}

// VoidByInvoice revokes the entitlement for the purchase tied to invoiceID and
// marks it status ('invalid' or 'expired'). It never voids an already-settled
// purchase (a settled invoice does not later become invalid). Idempotent.
func (s *Store) VoidByInvoice(ctx context.Context, invoiceID, status string) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var purchaseID, cur string
		err := tx.QueryRow(ctx,
			`SELECT id::text, status FROM purchases WHERE btcpay_invoice_id = $1 FOR UPDATE`,
			invoiceID).Scan(&purchaseID, &cur)
		if err == pgx.ErrNoRows {
			return ErrPurchaseNotFound
		}
		if err != nil {
			return err
		}
		if cur == "settled" {
			return nil
		}
		if _, err := tx.Exec(ctx, `DELETE FROM entitlements WHERE purchase_id = $1`, purchaseID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE purchases SET status = $2 WHERE id = $1`, purchaseID, status)
		return err
	})
	if err != nil {
		return err
	}
	_, _, err = s.RecomputeAuthz(ctx)
	return err
}

// PurchaseView is a purchase awaiting or undergoing payment, shown on the
// dashboard so the buyer can resume checkout.
type PurchaseView struct {
	ID          string
	PackageName string
	PriceMsat   int64
	Status      string // pending | processing
	CheckoutURL string
	CreatedAt   time.Time
}

// OpenPurchases lists an account's purchases that are not yet settled or voided
// (pending or processing), newest first.
func (s *Store) OpenPurchases(ctx context.Context, npub string) ([]PurchaseView, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT p.id::text, pt.name, pt.price_msat, p.status, COALESCE(p.checkout_url, ''), p.created_at
		 FROM purchases p
		 JOIN accounts a ON a.id = p.account_id
		 JOIN package_types pt ON pt.id = p.package_type_id
		 WHERE a.npub = $1 AND p.status IN ('pending', 'processing')
		 ORDER BY p.created_at DESC`, npub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PurchaseView
	for rows.Next() {
		var v PurchaseView
		if err := rows.Scan(&v.ID, &v.PackageName, &v.PriceMsat, &v.Status, &v.CheckoutURL, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
