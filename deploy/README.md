# RelaySecret deploy

One-shot deploy of the RelaySecret stack (Worker + R2 + KV + Pages + DNS)
to your own Cloudflare account. Pure bash — no Terraform, no Node, no Python.

## Prereqs

- `wrangler >= 3` (`npm i -g wrangler` or `brew install cloudflare-wrangler2`)
- `curl`
- `jq`
- `openssl`
- A Cloudflare account
- Your apex domain (e.g. `relaysecret.com`) already added as a **zone** in
  that account (dashboard -> Add a site -> update nameservers)

## 1. Create a Cloudflare API token

Go to: <https://dash.cloudflare.com/profile/api-tokens> -> **Create Token** -> **Create Custom Token**.

Grant these permissions:

| Scope    | Permission                     | Level |
|----------|--------------------------------|-------|
| Account  | Workers R2 Storage             | Edit  |
| Account  | Workers Scripts                | Edit  |
| Account  | Workers KV Storage             | Edit  |
| Account  | Cloudflare Pages               | Edit  |
| Account  | Account Settings               | Read  |
| Zone     | DNS                            | Edit  |
| Zone     | Workers Routes                 | Edit  |
| Zone     | Zone                           | Read  |

- **Account Resources**: include the target account.
- **Zone Resources**: include the target zone (your `DOMAIN`).
- **TTL**: your choice. 1 year is fine.

Copy the generated token — you only see it once.

### R2 credentials trade-off

The Worker needs S3-compatible R2 creds so it can sign presigned PUT/GET URLs.
You have two options:

1. **Recommended:** pre-create an R2 API token in the dashboard
   (R2 -> **Manage R2 API Tokens** -> **Create API Token**,
   permission **Object Read & Write**, scoped to the three buckets that
   deploy.sh will create) and paste the access key id + secret into
   `config.env` as `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY`. This is
   the least-privilege path — the deploy token does **not** need to be
   able to mint R2 tokens.

2. **Automatic:** leave `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` blank
   and deploy.sh will call `POST /accounts/:id/r2/tokens` to create a
   scoped token for you. This requires the "Workers R2 Storage: Edit"
   permission on the deploy token to also cover token creation. The
   secret is shown once and immediately piped into a Worker secret — it
   is never written to disk.

## 2. Configure

```bash
cp deploy/config.example.env deploy/config.env
$EDITOR deploy/config.env
```

`deploy/config.env` is gitignored. Do not commit it.

## 3. Run

```bash
./deploy/deploy.sh --yes
```

This will (in order):

1. Verify your token and tooling.
2. Create R2 buckets `relaysecret-us|eu|apac` with location hints
   `wnam`/`eeur`/`apac` and apply the lifecycle rules from `lifecycle.json`
   (1/2/3/4/5/10-day prefix expiry).
3. Optionally mint an R2 API token for the worker.
4. Create KV namespace `relaysecret-clipboard`.
5. Render `worker/wrangler.toml` from `worker/wrangler.toml.example`.
6. `wrangler deploy` the worker, then pipe every secret in with
   `wrangler secret put` (one pipe per secret, nothing written to disk).
7. Bind `API_HOST` as a custom domain on the worker.
8. Substitute `<WORKER_ORIGIN_PLACEHOLDER>` in `frontend/_headers` and
   `frontend/assets/config.js` with `https://$API_HOST`.
9. Create the Pages project `relaysecret` if needed and
   `wrangler pages deploy frontend`.
10. Attach `FRONTEND_HOST` and the apex `DOMAIN` as Pages custom domains.
11. Upsert proxied CNAMEs for `FRONTEND_HOST`, `API_HOST`, and the apex.
12. Hit `GET /sha1/000...` and `HEAD /` to smoke-test.

The script is **idempotent** — running it twice is safe.

## Flags

- `--yes` — skip interactive confirmations. Required when running
  non-interactively (CI, cron, ssh without a tty).
- `--dry-run` — print every Cloudflare API call and every `wrangler`
  invocation without executing any of them. No network mutation.
- `--teardown` — delete everything: Pages project, Worker, KV, R2
  buckets (emptied first), and the `FRONTEND_HOST` / `API_HOST` DNS
  records. Requires two confirmations (or `--yes`).

## Recovery: what to do if step N fails

Every step is re-runnable. Fix the cause, then re-run `./deploy/deploy.sh --yes`.

| Step        | If it fails...                                                           |
|-------------|--------------------------------------------------------------------------|
| Preflight   | Check `CF_API_TOKEN` permissions (see table above).                      |
| R2 buckets  | Existing buckets are skipped. Permission errors -> re-check token.       |
| R2 token    | Pre-create an R2 token in the dashboard and paste into `config.env`.    |
| KV          | Re-run — `kv_create_namespace` is lookup-first.                          |
| Worker      | Inspect `worker/wrangler.toml`. Run `wrangler deploy` manually to debug. |
| Secrets     | Each `wrangler secret put` is independent; re-run the script.            |
| Pages       | `wrangler pages deploy frontend --project-name=relaysecret` manually.    |
| DNS         | The upsert is idempotent; delete a stuck record in the dashboard.        |
| Smoke test  | Wait ~60s for DNS propagation, then `curl -I https://$FRONTEND_HOST`.    |

## Secret rotation

```bash
cd worker
printf 'new-vt-key' | wrangler secret put VT_API_KEY
printf 'new-hmac'   | wrangler secret put HMAC_SECRET
```

## Teardown

```bash
./deploy/deploy.sh --teardown --yes
```

This empties and deletes the R2 buckets, deletes the KV namespace,
unpublishes the worker, deletes the Pages project, and deletes the two
DNS records. It does **not** delete the zone itself or your apex record.
