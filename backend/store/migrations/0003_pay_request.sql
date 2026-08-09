-- Lightning: store the BOLT11 payment request so the portal can display the
-- invoice (QR/copy) and the reconciler can identify Lightning purchases.
ALTER TABLE purchases ADD COLUMN pay_request text;
