-- Phase 4: the BTCPay checkout link for a purchase, so the portal can redirect
-- the buyer there and re-offer an unpaid ("pay again") link on the dashboard.
ALTER TABLE purchases ADD COLUMN checkout_url text;
