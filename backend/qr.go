package main

import (
	"encoding/base64"
	"html/template"

	qrcode "github.com/skip2/go-qrcode"
)

// qrDataURI renders text as a PNG QR code and returns it as a data: URI for an
// <img src>. Typed template.URL so html/template doesn't sanitize the data: URL
// away. Returns "" on error, so the pay page falls back to just the bolt11.
func qrDataURI(text string) template.URL {
	png, err := qrcode.Encode(text, qrcode.Medium, 320)
	if err != nil {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}
