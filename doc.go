// Package ofauth provides typed OFAuth V3 resource clients and standard OAuth helpers.
//
// Supply a StaticToken or a TokenFunc from your auth framework to NewClient.
// Choose each linked account explicitly through Config.LinkedAccountID.
//
// Link builds S256 PKCE authorization URLs and exchanges, refreshes, or revokes
// tokens. Your application owns session-bound callback state and ordinary token
// persistence. Refresh tokens remain stable for confidential backend clients.
package ofauth
