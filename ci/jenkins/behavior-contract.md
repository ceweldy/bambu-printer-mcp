# Shadow pipeline behavior contract

1. Reject empty, shortened, uppercase, and shell-bearing SHA input before allocating an executor.
2. Fetch and verify the full requested commit before executing any target gate; a mismatch fails.
3. Run the fixed source workflow gates in order for every declared runtime matrix leg. Before target code, capture a controller-held tracked path/type/mode/byte-hash manifest. Before success, verify HEAD, manifest equality and tracked-worktree/index integrity with suppression flags cleared. Failed gates fail the leg and leave later gates unstarted. Source mutation cannot produce a success receipt.
4. A receipt identifies the repository, exact commit, matrix, build URL, checkout verification, shadow mode, and all gate states. It reports success only after every gate passed.
5. Archive safe diagnostics and the receipt before deletion, on success and failure. Reject symlink/FIFO/special archive inputs and retain a failure receipt through a separately checked parent and target while skipping unsafe diagnostics. Linked ancestors and unsafe receipt paths skip writes and archives; the controller console retains the error. Finalization is bounded to 5 minutes and deletion to 1 minute. Maintain source concurrency semantics through one job per event ref.
6. Keep Actions authoritative and avoid status writes, credential creation, controller changes, release, deployment, and paid operations.

Local validation may use a source-blind Jenkins step fixture to exercise operator outcomes. Fixture proof covers orchestration, not a live Jenkins CPS sandbox or provisioned runner. Actual application gates, controller execution, cancellation, image parity, and credential isolation must be reported separately as pass or blocked. Do not infer them from a clean source review.
