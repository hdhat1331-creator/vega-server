# VEGA Server

Backend foundation for the VEGA Android app.

## Current status
- Worker health endpoint: `/health`
- D1 connectivity check: `/api/v1/health`
- Initial D1 schema for users, conversations, members, and messages

Authentication and messaging endpoints are not implemented yet. Do not connect the public app to this server until authentication, authorization, validation, rate limiting, and privacy controls are implemented and tested.

## Cloudflare setup
1. Create a Cloudflare Worker named `vega-server`.
2. Create a D1 database named `vega-db`.
3. Replace `REPLACE_WITH_D1_DATABASE_ID` in `wrangler.toml` with the database ID from Cloudflare.
4. Apply migrations with Wrangler after configuring the D1 binding.
