# Jenkins CI shadow candidate

GitHub Actions in `.github/workflows/ci.yml` remains authoritative. This definition adds a reviewable shadow lane; it does not remove workflows, register jobs, grant access, emit GitHub statuses, publish packages, or deploy. Install the reviewed Jenkinsfile in a trusted Pipeline job from a fixed reviewed revision. Never use a pull request's Jenkinsfile or load Groovy/shared libraries from the target checkout.

## Event and checkout contract

- Map push events for **main** and pull requests targeting **all branches** to one trusted job per event ref. Keep branch/tag filtering in the trusted event router; this manual shadow definition registers no webhooks or polling.
- Supply `TARGET_SHA` as a lowercase full 40-hex commit. For a PR, use the exact event's GitHub synthetic merge commit (the Actions checkout default), including forks; a source head build is a separate probe and does not establish merge parity. Do not resolve a moving branch name at execution time. If that historical merge object is unavailable, fail and retain Actions.
- The Git checkout fetches full branch/tag history plus only the requested event commit and verifies `git rev-parse HEAD` before any target command. Other PR merge refs are excluded, preserving history-scan inputs.
- The source has no workflow concurrency group. The pipeline does not cancel earlier independent runs. Matrix branches use Actions default fail-fast behavior.

## Runner prerequisites and trust

Provision a fresh, single-use agent for every matrix leg; `ci-linux-node${version}-ephemeral` is a required label pattern, not a claim that an agent exists. Match the source runner (ubuntu-latest) image, architecture, installed utilities, and runtime 20/22. Runtime versions are checked before installation. Linux image parity must be recorded with the Actions baseline; a different distribution does not prove parity. Job timeout is 15 minutes (the source timeout), excluding agent provisioning.

Agents must have no deployment, controller, signing, vault, or status-write credentials, shared home/cache, host Docker socket, private network access, or access to other workspaces. Jenkins agent transport credentials must be short lived and unable to administer the controller. Target code and artifacts are untrusted. Isolation and runner provisioning require operator review before execution; labels do not enforce that policy by themselves.

Public checkout requires no GitHub credential. Required Jenkins steps: Pipeline, Git plugin, archiveArtifacts, writeFile, timeout, and parallel. No credential, grant, webhook, agent, controller setting, or job was changed by this branch.

## Gates and evidence

- `install`: `npm ci`
- `tests`: `npm test`
- `audit`: `npm audit --omit=dev`
- `privacy`: `npm run privacy:check`
- `history`: `npm run privacy:history`
- `package`: `npm pack --dry-run`

Every matrix leg archives safe logs and existing outputs under its own runtime/version directory before workspace deletion, including failed gates.  A trusted Python3 helper captures tracked path/type/mode/byte hashes before target commands; its reference stays in controller state. Final integrity compares a fresh manifest with that reference, checks HEAD equality, clears index suppression flags, and checks staged/unstaged differences. Finalization is bounded to 5 minutes and deletion to 1 minute. Symlinks, FIFOs and other special archive inputs fail artifact safety; unsafe diagnostics are skipped while a failure receipt is retained only if its parent and target pass separate path checks. Linked ancestors and unsafe receipt paths skip writes and archives; the controller console retains the error. Jenkins console output remains the failure diagnostic. Receipts contain schema 1, repository, exact commit, checkout verification, build URL, result, individual gate states, matrix dimension, and `mode: shadow`. Unstarted gates remain `NOT_RUN`; failure or interruption cannot become a success receipt. Logs, receipts, and artifacts copied from an agent are untrusted diagnostics: compare them with controller-owned stage outcomes before any external status or promotion. Status writes must happen in a separate trusted service outside these executors.



## Promotion and rollback

Run shadow checks against the same exact Actions commit. Compare all matrix gates, tools, logs, failures, artifacts, cancellation, and timeouts. Required proof includes a known passing commit, a deliberately failing gate, invalid SHA rejection, checkout mismatch, and a superseded event where applicable. Live Jenkins execution and image/credential isolation are separate operator gates. Do not replace branch protection or disable Actions until that proof is accepted. Rollback is to stop the shadow job; Actions continues to provide the current check.
