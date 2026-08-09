package payments

import "context"

// Provider is a payment rail that turns a purchase into an invoice. Both the
// BTCPay client and the phoenixd (Lightning) client implement it, so the portal
// buy flow and the store settlement seam are provider-agnostic.
//
// How settlement reaches the store differs by provider and is wired separately:
//   - BTCPay pushes a signed webhook (InvoiceProcessing/Settled/Invalid/Expired).
//   - phoenixd pushes a payment_received webhook AND is polled by a reconciler,
//     so a missed/late webhook still settles and unpaid invoices expire.
//
// Either way settlement lands on the same idempotent store methods
// (GrantByInvoice / VoidByInvoice), keyed by the provider's invoice id.
type Provider interface {
	CreateInvoice(ctx context.Context, req InvoiceRequest) (Invoice, error)
}
