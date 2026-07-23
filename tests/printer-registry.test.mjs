import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { PrinterRegistry } from "../dist/printer-registry.js";

function makeWorkspace(t) {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "bambu-registry-test-"));
  t.after(() => fs.rmSync(workspace, { recursive: true, force: true }));
  return workspace;
}

let isolatedRegistryCounter = 0;
const isolatedRegistryRoot = fs.mkdtempSync(
  path.join(os.tmpdir(), "bambu-registry-isolated-")
);
test.after(() => fs.rmSync(isolatedRegistryRoot, { recursive: true, force: true }));

function isolatedRegistry(options = {}) {
  isolatedRegistryCounter += 1;
  return new PrinterRegistry({
    ...options,
    configPath: path.join(
      isolatedRegistryRoot,
      `printers-${isolatedRegistryCounter}.json`
    ),
  });
}

test("registry resolves named printers from secret environment references", (t) => {
  const workspace = makeWorkspace(t);
  const configPath = path.join(workspace, "config", "printers.json");
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(
    configPath,
    JSON.stringify({
      version: 1,
      defaultPrinter: "shop-p1s",
      printers: [
        {
          id: "shop-p1s",
          name: "Shop P1S",
          host: "printer-one.local",
          model: "p1s",
          serialEnv: "BAMBU_SHOP_SERIAL",
          accessTokenEnv: "BAMBU_SHOP_TOKEN",
          bedType: "textured_plate",
          nozzleDiameter: "0.4",
        },
      ],
    })
  );

  const registry = new PrinterRegistry({
    configPath,
    env: {
      BAMBU_SHOP_SERIAL: "SERIAL_FROM_ENV",
      BAMBU_SHOP_TOKEN: "TOKEN_FROM_ENV",
    },
  });

  assert.equal(registry.size, 1);
  assert.deepEqual(registry.list(), [
    {
      id: "shop-p1s",
      name: "Shop P1S",
      model: "p1s",
      is_default: true,
      ready: true,
      source: "file",
      host_configured: true,
      serial_source: "environment",
      credential_source: "environment",
      missing_environment_variables: [],
      bed_type: "textured_plate",
      nozzle_diameter: "0.4",
    },
  ]);

  const resolved = registry.resolve();
  assert.equal(resolved.id, "shop-p1s");
  assert.equal(resolved.host, "printer-one.local");
  assert.equal(resolved.serial, "SERIAL_FROM_ENV");
  assert.equal(resolved.accessToken, "TOKEN_FROM_ENV");
});

test("registry summaries never expose host, serial, or access token values", () => {
  const registry = isolatedRegistry({
    env: {
      BAMBU_PRINTERS_JSON: JSON.stringify({
        version: 1,
        printers: [
          {
            id: "alpha",
            host: "private-printer.local",
            model: "x1c",
            serial: "PRIVATE_SERIAL",
            accessToken: "PRIVATE_TOKEN",
          },
        ],
      }),
    },
  });

  const serializedSummary = JSON.stringify(registry.list());
  assert.doesNotMatch(serializedSummary, /private-printer\.local/i);
  assert.doesNotMatch(serializedSummary, /PRIVATE_SERIAL/);
  assert.doesNotMatch(serializedSummary, /PRIVATE_TOKEN/);
});

test("legacy environment configuration defaults to the local network host", () => {
  const registry = isolatedRegistry({
    env: {
      BAMBU_SERIAL: "LEGACY_SERIAL",
      BAMBU_TOKEN: "test-token-placeholder",
      BAMBU_MODEL: "p1s",
    },
  });

  assert.equal(registry.size, 1);
  assert.equal(registry.resolve().host, "localhost");
  assert.equal(registry.list()[0].ready, true);
});

test("multiple printers require an explicit target unless one is default", () => {
  const noDefault = isolatedRegistry({
    env: {
      BAMBU_PRINTERS_JSON: JSON.stringify([
        { id: "alpha", host: "alpha.local", model: "p1s", serial: "A", accessToken: "TA" },
        { id: "beta", host: "beta.local", model: "a1", serial: "B", accessToken: "TB" },
      ]),
    },
  });
  assert.throws(() => noDefault.resolve(), /Multiple printers are configured/);
  assert.throws(() => noDefault.targetId(), /Multiple printers are configured/);
  assert.equal(noDefault.resolve("beta").model, "a1");
  assert.equal(noDefault.targetId("beta"), "beta");

  const withDefault = isolatedRegistry({
    env: {
      BAMBU_PRINTERS_JSON: JSON.stringify({
        version: 1,
        defaultPrinter: "beta",
        printers: [
          { id: "alpha", host: "alpha.local", model: "p1s", serial: "A", accessToken: "TA" },
          { id: "beta", host: "beta.local", model: "a1", serial: "B", accessToken: "TB" },
        ],
      }),
    },
  });
  assert.equal(withDefault.resolve().id, "beta");
  assert.equal(withDefault.targetId(), "beta");
});

test("registry rejects profiles that resolve to the same physical printer", () => {
  assert.throws(
    () =>
      isolatedRegistry({
        env: {
          FIRST_SERIAL: "SHARED_SERIAL",
          SECOND_SERIAL: "SHARED_SERIAL",
          FIRST_TOKEN: "FIRST_TOKEN_VALUE",
          SECOND_TOKEN: "SECOND_TOKEN_VALUE",
          BAMBU_PRINTERS_JSON: JSON.stringify([
            {
              id: "alpha",
              host: "shared.local",
              model: "p1s",
              serialEnv: "FIRST_SERIAL",
              accessTokenEnv: "FIRST_TOKEN",
            },
            {
              id: "beta",
              host: "shared.local",
              model: "p1s",
              serialEnv: "SECOND_SERIAL",
              accessTokenEnv: "SECOND_TOKEN",
            },
          ]),
        },
      }),
    /resolve to the same physical printer/
  );
});

test("runtime duplicate rejection leaves the existing profile usable", () => {
  const registry = isolatedRegistry({ env: {} });
  registry.add({
    id: "alpha",
    host: "shared.local",
    model: "p1s",
    serial: "SHARED_SERIAL",
    accessToken: "FIRST_TOKEN_VALUE",
  });

  assert.throws(
    () =>
      registry.add({
        id: "beta",
        host: "same-printer-alias.local",
        model: "p1s",
        serial: "SHARED_SERIAL",
        accessToken: "SECOND_TOKEN_VALUE",
      }),
    /resolve to the same physical printer/
  );
  assert.equal(registry.size, 1);
  assert.equal(registry.resolve("alpha").id, "alpha");
});

test("unresolved profile identities are not treated as duplicates", () => {
  const registry = isolatedRegistry({
    env: {
      BAMBU_PRINTERS_JSON: JSON.stringify([
        {
          id: "alpha",
          host: "alpha.local",
          model: "p1s",
          serialEnv: "ALPHA_SERIAL_REF",
          accessTokenEnv: "ALPHA_ACCESS_REF",
        },
        {
          id: "beta",
          host: "beta.local",
          model: "a1",
          serialEnv: "BETA_SERIAL_REF",
          accessTokenEnv: "BETA_ACCESS_REF",
        },
      ]),
    },
  });

  assert.equal(registry.size, 2);
  assert.deepEqual(registry.list().map((profile) => profile.ready), [false, false]);
});

test("persisted profiles use private permissions and omit plaintext tokens", (t) => {
  const workspace = makeWorkspace(t);
  const configPath = path.join(workspace, "private", "printers.json");
  const registry = new PrinterRegistry({ configPath, env: { SAFE_TOKEN: "runtime-secret" } });

  registry.add(
    {
      id: "alpha",
      host: "alpha.local",
      model: "p1s",
      serial: "runtime-serial",
      serialEnv: "SAFE_SERIAL",
      accessToken: "runtime-secret",
      accessTokenEnv: "SAFE_TOKEN",
      devIdEnv: "SAFE_DEVICE_ID",
    },
    { persist: true }
  );

  const persisted = fs.readFileSync(configPath, "utf8");
  assert.doesNotMatch(persisted, /runtime-secret/);
  assert.doesNotMatch(persisted, /runtime-serial/);
  assert.doesNotMatch(persisted, /"serial":/);
  assert.doesNotMatch(persisted, /"devId":/);
  assert.match(persisted, /"accessTokenEnv": "SAFE_TOKEN"/);
  assert.match(persisted, /"devIdEnv": "SAFE_DEVICE_ID"/);
  assert.equal(fs.statSync(configPath).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(configPath)).mode & 0o777, 0o700);
});

test("persistence does not change permissions on an existing custom directory", (t) => {
  const workspace = makeWorkspace(t);
  const sharedDirectory = path.join(workspace, "shared");
  const configPath = path.join(sharedDirectory, "printers.json");
  fs.mkdirSync(sharedDirectory, { mode: 0o755 });
  fs.chmodSync(sharedDirectory, 0o755);
  const registry = new PrinterRegistry({ configPath, env: {} });

  registry.add(
    {
      id: "alpha",
      host: "alpha.local",
      model: "p1s",
      serialEnv: "SAFE_SERIAL",
      accessTokenEnv: "SAFE_TOKEN",
    },
    { persist: true }
  );

  assert.equal(fs.statSync(sharedDirectory).mode & 0o777, 0o755);
  assert.equal(fs.statSync(configPath).mode & 0o777, 0o600);
});

test("registry keeps BambuNetwork device identifiers reference-only", (t) => {
  const workspace = makeWorkspace(t);
  const configPath = path.join(workspace, "private", "printers.json");
  const registry = new PrinterRegistry({ configPath, env: {} });

  assert.throws(
    () =>
      registry.add(
        {
          id: "alpha",
          host: "alpha.local",
          model: "p1s",
          serialEnv: "SAFE_SERIAL",
          accessTokenEnv: "SAFE_TOKEN",
          devId: "INLINE_DEVICE_ID",
        },
        { persist: true }
      ),
    /Refusing to persist an inline BambuNetwork device identifier/
  );
  assert.equal(fs.existsSync(configPath), false);

  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(
    configPath,
    JSON.stringify({
      version: 1,
      printers: [
        {
          id: "alpha",
          host: "alpha.local",
          model: "p1s",
          serialEnv: "SAFE_SERIAL",
          accessTokenEnv: "SAFE_TOKEN",
          devId: "INLINE_DEVICE_ID",
        },
      ],
    })
  );
  assert.throws(
    () => new PrinterRegistry({ configPath, env: {} }),
    /plaintext devId in the config file/
  );
});

test("registry refuses to persist a plaintext-only access token", (t) => {
  const workspace = makeWorkspace(t);
  const configPath = path.join(workspace, "private", "printers.json");
  const registry = new PrinterRegistry({ configPath, env: {} });

  assert.throws(
    () =>
      registry.add(
        {
          id: "alpha",
          host: "alpha.local",
          model: "p1s",
          serialEnv: "SAFE_SERIAL",
          accessToken: "plaintext-token",
        },
        { persist: true }
      ),
    /Refusing to persist runtime-only printer identifiers or credentials/
  );
  assert.equal(fs.existsSync(configPath), false);
  assert.equal(registry.size, 0, "failed persistence must roll back the new profile");
});

test("registry refuses to persist when any existing profile is runtime-only", (t) => {
  const workspace = makeWorkspace(t);
  const configPath = path.join(workspace, "private", "printers.json");
  const registry = new PrinterRegistry({ configPath, env: {} });

  registry.add({
    id: "runtime",
    host: "runtime.local",
    model: "p1s",
    serial: "RUNTIME_SERIAL",
    accessToken: "RUNTIME_TOKEN",
  });

  assert.throws(
    () =>
      registry.add(
        {
          id: "persisted",
          host: "persisted.local",
          model: "x1c",
          serialEnv: "PERSISTED_SERIAL",
          accessTokenEnv: "PERSISTED_TOKEN",
        },
        { persist: true }
      ),
    /Cannot persist the registry.*runtime/
  );
  assert.equal(fs.existsSync(configPath), false);
  assert.equal(registry.size, 1, "failed persistence must roll back the new profile");
});

test("registry rejects plaintext access tokens already present in a config file", (t) => {
  const workspace = makeWorkspace(t);
  const configPath = path.join(workspace, "printers.json");
  fs.writeFileSync(
    configPath,
    JSON.stringify({
      version: 1,
      printers: [
        {
          id: "alpha",
          host: "alpha.local",
          model: "p1s",
          serialEnv: "SAFE_SERIAL",
          accessToken: "plaintext-token",
        },
      ],
    })
  );

  assert.throws(
    () => new PrinterRegistry({ configPath, env: {} }),
    /plaintext accessToken in the config file/
  );
});

test("registry rejects plaintext serials already present in a config file", (t) => {
  const workspace = makeWorkspace(t);
  const configPath = path.join(workspace, "printers.json");
  fs.writeFileSync(
    configPath,
    JSON.stringify({
      version: 1,
      printers: [
        {
          id: "alpha",
          host: "alpha.local",
          model: "p1s",
          serial: "PLAINTEXT_SERIAL",
          accessTokenEnv: "SAFE_TOKEN",
        },
      ],
    })
  );

  assert.throws(
    () => new PrinterRegistry({ configPath, env: {} }),
    /plaintext serial in the config file/
  );
});

test("registry rejects the reserved all profile id", () => {
  assert.throws(
    () =>
      isolatedRegistry({
        env: {
          BAMBU_PRINTERS_JSON: JSON.stringify([
            {
              id: "all",
              host: "fleet.local",
              model: "p1s",
              serial: "SERIAL",
              accessToken: "TOKEN",
            },
          ]),
        },
      }),
    /reserved for fleet operations/
  );
});

test("per-printer operations are serialized while different printers can proceed", async () => {
  const registry = isolatedRegistry({ env: {} });
  const events = [];

  const first = registry.runExclusive("alpha", async () => {
    events.push("alpha-1-start");
    await new Promise((resolve) => setTimeout(resolve, 30));
    events.push("alpha-1-end");
  });
  const second = registry.runExclusive("alpha", async () => {
    events.push("alpha-2-start");
    events.push("alpha-2-end");
  });
  const otherPrinter = registry.runExclusive("beta", async () => {
    events.push("beta-start");
    events.push("beta-end");
  });

  await Promise.all([first, second, otherPrinter]);
  assert.ok(events.indexOf("alpha-1-end") < events.indexOf("alpha-2-start"));
  assert.ok(events.indexOf("beta-start") < events.indexOf("alpha-1-end"));
});
