import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  verify as verifySignature,
} from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { BambuClient } from "bambu-node";
import JSZip from "jszip";
import { hasAmsMappingInput, normalizeAmsMappingObject } from "../dist/ams-mapping.js";
import { analyze3MFAmsRequirements, analyze3MFPlateObjects } from "../dist/3mf_parser.js";
import {
  BambuImplementation,
  canonicalJson,
  createSignedPrintEnvelope,
  requiresEncryptedGcodeLine,
} from "../dist/printers/bambu.js";
import {
  BambuNetworkBridge,
  createBambuNetworkSubmissionNames,
  isBambuNetworkControlMethod,
  isManagedBambuNetworkCallMethod,
  redactBambuNetworkDiagnostic,
  requiresBambuNetworkAgentForRawCall,
  requiresBambuNetworkProjectFileAcknowledgement,
  stageBambuNetworkCertificates,
} from "../dist/bambu-network-bridge.js";
import { redactPrinterConnectionError } from "../dist/redaction.js";
import { STLManipulator } from "../dist/stl/stl-manipulator.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..");
const SERVER_ENTRY = path.join(REPO_ROOT, "dist", "index.js");
const SAMPLE_STL = path.join(REPO_ROOT, "test", "sample_cube.stl");
const EXPECTED_BAMBU_MODELS = ["p1s", "p1p", "p2s", "x1c", "x1e", "a1", "a1mini", "h2d", "h2s", "h2c"];
const BEHAVIOR_TEMP_DIR = fs.mkdtempSync(
  path.join(os.tmpdir(), "bambu-behavior-run-")
);
process.env.BAMBU_PRINTERS_FILE = path.join(BEHAVIOR_TEMP_DIR, "printers.json");
test.after(() => fs.rmSync(BEHAVIOR_TEMP_DIR, { recursive: true, force: true }));

async function writeSliced3mfFixture({
  name = "h2-project-filament",
  projectFilamentIds = ["GFG02", "GFG01", "GFL00", "GFL03"],
  projectFilamentColors = ["#FFFFFF", "#FF911A80", "#DCF478", "#DCF478"],
  projectFilamentTypes = ["PETG", "PETG", "PLA", "PLA"],
  plateFilamentIds = [1],
} = {}) {
  const zip = new JSZip();
  const gcode = [
    `; filament_ids = ${projectFilamentIds.join(";")}`,
    `; filament_colour = ${projectFilamentColors.join(";")}`,
    `; filament_type = ${projectFilamentTypes.join(";")}`,
    "G1 X0 Y0",
    "",
  ].join("\n");
  const md5 = createHash("md5").update(Buffer.from(gcode)).digest("hex");
  zip.file("Metadata/plate_1.gcode", gcode);
  zip.file("Metadata/plate_1.gcode.md5", md5);
  zip.file(
    "3D/3dmodel.model",
    '<?xml version="1.0" encoding="UTF-8"?><model unit="millimeter" xml:lang="en-US" xmlns="http://schemas.microsoft.com/3dmanufacturing/core/2015/02"><resources><object id="1" type="model" name="cube.stl"><mesh><vertices/><triangles/></mesh></object></resources><build><item objectid="1"/></build></model>'
  );
  zip.file(
    "Metadata/plate_1.json",
    JSON.stringify({
      filament_ids: plateFilamentIds,
      bbox_objects: [{ id: 1, name: "cube.stl", area: 1 }],
      version: 2,
    })
  );
  const tempPath = path.join(os.tmpdir(), `${name}-${Date.now()}-${Math.random().toString(16).slice(2)}.gcode.3mf`);
  fs.writeFileSync(tempPath, await zip.generateAsync({ type: "nodebuffer" }));
  return tempPath;
}

function createClient() {
  return new Client({
    name: "bambu-printer-mcp-behavior-tests",
    version: "0.0.1",
  });
}

async function getFreePort() {
  return await new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address !== "object") {
        server.close(() => reject(new Error("Unable to resolve free port")));
        return;
      }
      server.close((error) => {
        if (error) { reject(error); return; }
        resolve(address.port);
      });
    });
  });
}

async function waitForHttpServerReady(endpoint, attempts = 40, delayMs = 150) {
  let lastStatus = "unreachable";
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(endpoint, { method: "PUT" });
      lastStatus = String(response.status);
      if (response.status === 405 || response.status === 400) return;
    } catch {
      lastStatus = "unreachable";
    }
    await sleep(delayMs);
  }
  throw new Error(`HTTP server did not become ready in time (last status: ${lastStatus})`);
}

async function closeTransport(transport) {
  try { await transport.close(); } catch { }
}

test("signed print envelopes use canonical RSA-SHA256 payloads", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const payload = {
    print: {
      sequence_id: "42",
      command: "project_file",
      nested: { z: 1, a: 2 },
      ams_mapping: [-1, -1, -1, -1, 3],
    },
  };
  const certId = "00112233445566778899aabbccddeeffCN=TEST.bambulab.com";

  const envelope = createSignedPrintEnvelope(payload, privateKey, certId);
  const bytesToSign = Buffer.from(
    `{"print":${canonicalJson(payload.print)}}`,
    "utf8"
  );

  assert.equal(envelope.header.sign_ver, "v1.0");
  assert.equal(envelope.header.sign_alg, "RSA_SHA256");
  assert.equal(envelope.header.cert_id, certId);
  assert.equal(envelope.header.payload_len, bytesToSign.length);
  assert.equal(
    verifySignature(
      "RSA-SHA256",
      bytesToSign,
      publicKey,
      Buffer.from(envelope.header.sign_string, "base64")
    ),
    true
  );
  assert.equal(payload.header, undefined, "signing must not mutate the caller payload");
});

test("gcode_line encryption gating is scoped to known signed-firmware printers", () => {
  const previous = process.env.BAMBU_REQUIRE_ENCRYPTED_GCODE_LINE;
  try {
    delete process.env.BAMBU_REQUIRE_ENCRYPTED_GCODE_LINE;
    assert.equal(requiresEncryptedGcodeLine("01P00TEST"), false);
    assert.equal(requiresEncryptedGcodeLine("09300TEST"), true);
    assert.equal(requiresEncryptedGcodeLine("09400TEST"), true);

    process.env.BAMBU_REQUIRE_ENCRYPTED_GCODE_LINE = "1";
    assert.equal(requiresEncryptedGcodeLine("01P00TEST"), true);
    process.env.BAMBU_REQUIRE_ENCRYPTED_GCODE_LINE = "0";
    assert.equal(requiresEncryptedGcodeLine("09300TEST"), false);
  } finally {
    if (previous === undefined) {
      delete process.env.BAMBU_REQUIRE_ENCRYPTED_GCODE_LINE;
    } else {
      process.env.BAMBU_REQUIRE_ENCRYPTED_GCODE_LINE = previous;
    }
  }
});

async function terminateChildProcess(childProcess) {
  if (childProcess.exitCode !== null) return;
  childProcess.kill("SIGTERM");
  await Promise.race([
    once(childProcess, "exit"),
    sleep(2000).then(() => { if (childProcess.exitCode === null) childProcess.kill("SIGKILL"); }),
  ]);
}

function parseJsonResult(toolResult) {
  const text = toolResult.content?.[0]?.text;
  assert.equal(typeof text, "string", "Expected text result payload");
  return JSON.parse(text);
}

function assertCommonToolPresence(listToolsResult) {
  const names = listToolsResult.tools.map((tool) => tool.name);
  assert.ok(names.includes("list_printers"));
  assert.ok(names.includes("add_printer"));
  assert.ok(names.includes("remove_printer"));
  assert.ok(names.includes("set_default_printer"));
  assert.ok(names.includes("get_fleet_status"));
  assert.ok(names.includes("reconnect_printer"));
  assert.ok(names.includes("get_printer_status"));
  assert.ok(names.includes("resolve_3mf_ams_slots"));
  assert.ok(names.includes("list_3mf_plate_objects"));
  assert.ok(names.includes("set_fan_speed"));
  assert.ok(names.includes("set_light"));
  assert.ok(names.includes("clear_hms_errors"));
  assert.ok(names.includes("reset_ams"));
  assert.ok(names.includes("load_ams_filament"));
  assert.ok(names.includes("unload_ams_filament"));
  assert.ok(names.includes("reboot_printer"));
  assert.ok(names.includes("set_print_speed"));
  assert.ok(names.includes("set_airduct_mode"));
  assert.ok(names.includes("reread_ams_rfid"));
  assert.ok(names.includes("skip_objects"));
  assert.ok(names.includes("get_stl_info"));
  assert.ok(names.includes("blender_mcp_edit_model"));
  assert.ok(names.includes("print_3mf"), "print_3mf tool must be registered");
  assert.ok(names.includes("print_3mf_bambu_network"), "print_3mf_bambu_network tool must be registered");
  assert.ok(names.includes("bambu_network_bridge_status"), "bambu_network_bridge_status tool must be registered");
  assert.ok(names.includes("bambu_network_call"), "bambu_network_call tool must be registered");
  assert.ok(names.includes("upload_gcode"), "upload_gcode tool must be registered");
  assert.ok(names.includes("start_print"), "start_print compatibility alias must be registered");
  assert.ok(names.includes("start_print_job"), "start_print_job tool must be registered");
  assert.ok(names.includes("slice_stl"), "slice_stl tool must be registered");
}

function assertBambuStudioSlicerSupport(listToolsResult) {
  const sliceTool = listToolsResult.tools.find((t) => t.name === "slice_stl");
  assert.ok(sliceTool, "slice_stl tool must exist");
  const desc = sliceTool.inputSchema?.properties?.slicer_type?.description || "";
  assert.ok(
    desc.includes("bambustudio"),
    `slice_stl slicer_type description must mention bambustudio, got: ${desc}`
  );
}

// Canonical schema contracts for BambuStudio slicer options on slice_stl.
// Each entry: [property_name, expected_json_type, description_must_contain]
// Description fragments should be domain-stable keywords, not exact phrasing.
const BAMBU_SLICER_OPTION_CONTRACTS = [
  ["uptodate",              "boolean", "preset"],
  ["repetitions",           "number",  "copies"],
  ["orient",                "boolean", "orient"],
  ["arrange",               "boolean", "arrange"],
  ["ensure_on_bed",         "boolean", "bed"],
  ["clone_objects",         "string",  "clone"],
  ["skip_objects",          "string",  "skip"],
  ["load_filaments",        "string",  "filament"],
  ["load_filament_ids",     "string",  "filament"],
  ["bed_type",              "string",  "bed"],
  ["enable_timelapse",      "boolean", "timelapse"],
  ["allow_mix_temp",        "boolean", "temperature"],
  ["scale",                 "number",  "scale"],
  ["rotate",                "number",  "z-axis"],
  ["rotate_x",              "number",  "x-axis"],
  ["rotate_y",              "number",  "y-axis"],
  ["min_save",              "boolean", "smaller"],
  ["skip_modified_gcodes",  "boolean", "gcode"],
  ["slice_plate",           "number",  "plate"],
];

test("printer model safety: schemas accept profile defaults while runtime rejects missing or invalid models", async (t) => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_SERIAL: "TEST_SERIAL",
      BAMBU_TOKEN: "TEST_TOKEN",
      BAMBU_MODEL: "", // Explicitly empty to override dotenv .env file
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);

  const listToolsResult = await client.listTools();
  assertBambuStudioSlicerSupport(listToolsResult);

  // Model fields remain constrained, but printer profiles may supply them.
  const print3mfTool = listToolsResult.tools.find((t) => t.name === "print_3mf");
  assert.ok(print3mfTool, "print_3mf tool must exist");
  assert.ok(
    print3mfTool.inputSchema.properties.ams_mapping,
    "print_3mf must have ams_mapping property"
  );
  assert.ok(
    print3mfTool.inputSchema.properties.auto_match_ams,
    "print_3mf must have auto_match_ams property"
  );
  assert.ok(
    print3mfTool.inputSchema.properties.bambu_model,
    "print_3mf must have bambu_model property"
  );
  assert.equal(print3mfTool.inputSchema.required.includes("bambu_model"), false);
  assert.ok(
    print3mfTool.inputSchema.properties.bed_type,
    "print_3mf must have bed_type property"
  );
  assert.deepEqual(
    print3mfTool.inputSchema.properties.bambu_model.enum,
    EXPECTED_BAMBU_MODELS,
    "print_3mf bambu_model must enumerate all valid models"
  );
  const toolsWithModel = listToolsResult.tools
    .filter((tool) => Array.isArray(tool.inputSchema?.properties?.bambu_model?.enum))
    .map((tool) => tool.name)
    .sort();
  assert.deepEqual(
    toolsWithModel,
    [
      "get_printer_filaments",
      "print_3mf",
      "print_3mf_bambu_network",
      "resolve_3mf_ams_slots",
      "slice_stl",
      "slice_with_template",
      "start_print",
      "start_print_job",
      "upload_file",
    ],
    "all tools that expose bambu_model must be covered by the model enum invariant"
  );
  for (const toolName of toolsWithModel) {
    const tool = listToolsResult.tools.find((t) => t.name === toolName);
    assert.ok(tool, `${toolName} tool must exist`);
    assert.deepEqual(
      tool.inputSchema.properties.bambu_model.enum,
      EXPECTED_BAMBU_MODELS,
      `${toolName} bambu_model must enumerate all valid models`
    );
  }

  const sliceTool = listToolsResult.tools.find((t) => t.name === "slice_stl");
  assert.ok(sliceTool, "slice_stl tool must exist");
  assert.ok(
    sliceTool.inputSchema.properties.bambu_model,
    "slice_stl must have bambu_model property"
  );
  assert.equal(sliceTool.inputSchema.required.includes("bambu_model"), true);

  const speedTool = listToolsResult.tools.find((t) => t.name === "set_print_speed");
  assert.ok(speedTool, "set_print_speed tool must exist");
  assert.ok(speedTool.inputSchema.properties.mode, "set_print_speed must accept mode");
  assert.ok(speedTool.inputSchema.required.includes("mode"), "set_print_speed.mode must be required");

  const airductTool = listToolsResult.tools.find((t) => t.name === "set_airduct_mode");
  assert.ok(airductTool, "set_airduct_mode tool must exist");
  assert.deepEqual(
    airductTool.inputSchema.properties.mode.enum,
    ["cooling", "heating"],
    "set_airduct_mode must enumerate cooling/heating"
  );

  const rfidTool = listToolsResult.tools.find((t) => t.name === "reread_ams_rfid");
  assert.ok(rfidTool, "reread_ams_rfid tool must exist");
  assert.ok(rfidTool.inputSchema.required.includes("ams_id"), "reread_ams_rfid.ams_id must be required");
  assert.ok(rfidTool.inputSchema.required.includes("slot_id"), "reread_ams_rfid.slot_id must be required");

  const uploadGcodeTool = listToolsResult.tools.find((t) => t.name === "upload_gcode");
  assert.ok(uploadGcodeTool, "upload_gcode tool must exist");
  assert.ok(uploadGcodeTool.inputSchema.properties.gcode_path, "upload_gcode must accept gcode_path");
  assert.deepEqual(uploadGcodeTool.inputSchema.required, ["filename"]);

  const startPrintTool = listToolsResult.tools.find((t) => t.name === "start_print");
  assert.ok(startPrintTool, "start_print compatibility alias must exist");
  assert.equal(startPrintTool.inputSchema.required.includes("bambu_model"), false);

  const networkPrintTool = listToolsResult.tools.find((t) => t.name === "print_3mf_bambu_network");
  assert.ok(networkPrintTool, "print_3mf_bambu_network tool must exist");
  assert.equal(networkPrintTool.inputSchema.required.includes("bambu_model"), false);
  assert.equal(networkPrintTool.inputSchema.properties.plate_index.type, "number");
  assert.equal(
    networkPrintTool.inputSchema.properties.bambu_network_method.enum.includes(
      "start_local_print_with_record"
    ),
    false,
    "unconfirmed local-with-record print must not be exposed"
  );

  // No 'type' param should exist on any tool (Bambu-only)
  for (const tool of listToolsResult.tools) {
    assert.ok(
      !tool.inputSchema?.properties?.type,
      `Tool ${tool.name} should not have a 'type' property (Bambu-only server)`
    );
  }

  // Runtime validation still fails closed when neither a profile nor a model exists.
  // The server will attempt elicitation, which fails in test (no client support),
  // then falls back to a clear error about bambu_model being required.
  const noModelResult = await client.callTool({
    name: "print_3mf",
    arguments: { three_mf_path: "/tmp/nonexistent_test.3mf" },
  });
  assert.equal(noModelResult.isError, true, "print_3mf without bambu_model must error");
  const noModelError = noModelResult.content?.[0]?.text || "";
  assert.ok(
    noModelError.toLowerCase().includes("bambu_model") || noModelError.toLowerCase().includes("model"),
    `Error must mention model is required, got: ${noModelError}`
  );

  // --- Runtime validation: print_3mf with invalid model must error ---
  const badModelResult = await client.callTool({
    name: "print_3mf",
    arguments: { three_mf_path: "/tmp/nonexistent_test.3mf", bambu_model: "ender3" },
  });
  assert.equal(badModelResult.isError, true, "print_3mf with invalid model must error");
  const badModelError = badModelResult.content?.[0]?.text || "";
  assert.ok(
    badModelError.includes("Invalid bambu_model"),
    `Error must reject invalid model, got: ${badModelError}`
  );

  // --- Runtime validation: every valid model, including H2C, passes model validation ---
  for (const bambuModel of EXPECTED_BAMBU_MODELS) {
    const validModelResult = await client.callTool({
      name: "print_3mf",
      arguments: { three_mf_path: "/tmp/nonexistent_test.3mf", bambu_model: bambuModel },
    });
    assert.equal(validModelResult.isError, true, "Missing file should still error");
    const validModelError = validModelResult.content?.[0]?.text || "";
    assert.ok(
      !validModelError.includes("bambu_model"),
      `Error with valid model ${bambuModel} should not be about model, got: ${validModelError}`
    );
  }
});

test("3MF AMS requirement analysis maps plate filament_ids to slice_info tray_info_idx", async () => {
  const fixture = path.join(REPO_ROOT, "tests/fixtures/h2d_gui_sliced");
  const zip = new JSZip();
  zip.file("Metadata/plate_1.json", fs.readFileSync(path.join(fixture, "plate_1.json"), "utf8"));
  zip.file("Metadata/slice_info.config", fs.readFileSync(path.join(fixture, "slice_info.config"), "utf8"));
  const tempPath = path.join(os.tmpdir(), `ams-requirements-${Date.now()}.3mf`);
  fs.writeFileSync(tempPath, await zip.generateAsync({ type: "nodebuffer" }));

  try {
    const requirements = await analyze3MFAmsRequirements(tempPath, 0);
    assert.deepEqual(requirements.usedFilamentPositions, [4]);
    assert.deepEqual(requirements.filaments, [
      {
        filamentPosition: 4,
        filamentId: 5,
        tray_info_idx: "GFG02",
        type: "PETG",
        color: "#FFFFFF",
      },
    ]);
  } finally {
    fs.rmSync(tempPath, { force: true });
  }
});

test("3MF AMS requirement analysis falls back when slice_info.config is not XML", async () => {
  const zip = new JSZip();
  zip.file("Metadata/plate_1.json", JSON.stringify({ filament_ids: [0, 2] }));
  zip.file("Metadata/slice_info.config", "not xml at all");
  const tempPath = path.join(os.tmpdir(), `ams-bad-slice-info-${Date.now()}.3mf`);
  fs.writeFileSync(tempPath, await zip.generateAsync({ type: "nodebuffer" }));

  try {
    const requirements = await analyze3MFAmsRequirements(tempPath, 0);
    assert.deepEqual(requirements.usedFilamentPositions, [0, 2]);
    assert.deepEqual(
      requirements.filaments.map((filament) => ({
        filamentPosition: filament.filamentPosition,
        tray_info_idx: filament.tray_info_idx,
        type: filament.type,
        color: filament.color,
      })),
      [
        { filamentPosition: 0, tray_info_idx: null, type: null, color: null },
        { filamentPosition: 2, tray_info_idx: null, type: null, color: null },
      ]
    );
  } finally {
    fs.rmSync(tempPath, { force: true });
  }
});

test("3MF plate object analysis lists Bambu object ids for skip_objects", async () => {
  const fixture = path.join(REPO_ROOT, "tests/fixtures/h2d_gui_sliced");
  const zip = new JSZip();
  zip.file("Metadata/plate_1.json", fs.readFileSync(path.join(fixture, "plate_1.json"), "utf8"));
  zip.file("Metadata/slice_info.config", fs.readFileSync(path.join(fixture, "slice_info.config"), "utf8"));
  const tempPath = path.join(os.tmpdir(), `plate-objects-${Date.now()}.3mf`);
  fs.writeFileSync(tempPath, await zip.generateAsync({ type: "nodebuffer" }));

  try {
    const plateObjects = await analyze3MFPlateObjects(tempPath, 0);
    assert.equal(plateObjects.objects.length, 20);
    assert.deepEqual(
      plateObjects.objects.slice(0, 2).map((object) => object.id),
      [5997, 6277]
    );
    assert.equal(plateObjects.objects[0].name, "sample_part.stl_1");
    assert.equal(plateObjects.objects[0].area, 1152.0546875);
  } finally {
    fs.rmSync(tempPath, { force: true });
  }
});

test("3MF plate object analysis falls back to bbox ids without slice_info object ids", async () => {
  const fixture = path.join(REPO_ROOT, "tests/fixtures/h2d_gui_sliced");
  const zip = new JSZip();
  zip.file("Metadata/plate_1.json", fs.readFileSync(path.join(fixture, "plate_1.json"), "utf8"));
  const tempPath = path.join(os.tmpdir(), `plate-objects-bbox-${Date.now()}.3mf`);
  fs.writeFileSync(tempPath, await zip.generateAsync({ type: "nodebuffer" }));

  try {
    const plateObjects = await analyze3MFPlateObjects(tempPath, 0);
    assert.deepEqual(
      plateObjects.objects.slice(0, 2).map((object) => object.id),
      [6495, 6496]
    );
  } finally {
    fs.rmSync(tempPath, { force: true });
  }
});

test("printer model safety: BAMBU_MODEL env var accepted as default", async (t) => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_SERIAL: "TEST_SERIAL",
      BAMBU_TOKEN: "TEST_TOKEN",
      BAMBU_MODEL: "p1s",
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);

  // With BAMBU_MODEL=p1s set in env, print_3mf should NOT error about missing model
  // (it will error about missing file instead)
  const result = await client.callTool({
    name: "print_3mf",
    arguments: { three_mf_path: "/tmp/nonexistent_test.3mf" },
  });
  assert.equal(result.isError, true);
  const errorText = result.content?.[0]?.text || "";
  assert.ok(
    !errorText.includes("bambu_model") && !errorText.includes("BAMBU_MODEL"),
    `With BAMBU_MODEL env set, error should be about file not model, got: ${errorText}`
  );
});

test("H2 family print_3mf rejects pre-sliced filament jobs without explicit AMS mapping", async (t) => {
  const threeMfPath = await writeSliced3mfFixture({ plateFilamentIds: [1] });
  t.after(() => { fs.rmSync(threeMfPath, { force: true }); });

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_PRINTER_HOST: "127.0.0.1",
      BAMBU_PRINTER_SERIAL: "0938TEST0000000",
      BAMBU_PRINTER_ACCESS_TOKEN: "TEST_TOKEN",
      BAMBU_PRINTER_MODEL: "h2s",
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);
  for (const bambuModel of ["h2s"]) {
    const result = await client.callTool({
      name: "print_3mf",
      arguments: {
        three_mf_path: threeMfPath,
        bambu_model: bambuModel,
        bed_type: "supertack_plate",
      },
    });

    assert.equal(result.isError, true, `${bambuModel} should reject unmapped filament jobs`);
    const errorText = result.content?.[0]?.text || "";
    assert.match(errorText, /require ams_slots, ams_mapping, or auto_match_ams/i);
    assert.match(errorText, /project filament positions \[1\]/i);
    assert.doesNotMatch(errorText, /ECONNREFUSED|control socket/i);
  }
});

test("P1S project_file uses firmware-safe local metadata and waits for acceptance", async () => {
  const fixturePath = await writeSliced3mfFixture({
    projectFilamentIds: ["GFSNL08"],
    projectFilamentColors: ["#161616"],
    projectFilamentTypes: ["PETG"],
    plateFilamentIds: [0],
  });
  const threeMfPath = fixturePath.replace(/\.gcode\.3mf$/, ".3mf");
  fs.renameSync(fixturePath, threeMfPath);
  const bambu = new BambuImplementation();
  let publishedPayload = null;
  let messageListener = null;

  bambu.ftpUpload = async () => {};
  bambu.getPrinter = async () => ({
    data: { gcode_state: "FINISH", subtask_name: "previous.3mf" },
    on: (event, listener) => {
      if (event === "message") messageListener = listener;
    },
    off: () => {},
    publish: async (payload) => {
      publishedPayload = payload;
      queueMicrotask(() => {
        messageListener?.("device/test/report", "print", {
          command: "project_file",
          sequence_id: payload.print.sequence_id,
          result: "SUCCESS",
          reason: "SUCCESS",
        });
      });
    },
  });

  try {
    const result = await bambu.print3mf(
      "127.0.0.1",
      "01P00TEST0000000",
      "TEST_TOKEN",
      {
        projectName: "p1s-coupon",
        filePath: threeMfPath,
        bambuModel: "p1s",
        plateIndex: 0,
        useAMS: true,
        amsSlots: [3],
        bedType: "supertack_plate",
      }
    );

    const expectedFile = path.basename(threeMfPath);
    assert.equal(result.status, "success");
    assert.equal(result.acceptance?.result, "SUCCESS");
    assert.equal(publishedPayload.print.bed_type, "auto");
    assert.equal(publishedPayload.print.bed_leveling, true);
    assert.equal(publishedPayload.print.bed_levelling, true);
    assert.equal(publishedPayload.print.file, expectedFile);
    assert.equal(publishedPayload.print.subtask_name, expectedFile);
    assert.equal(publishedPayload.print.plate_idx, 0);
    assert.deepEqual(publishedPayload.print.ams_mapping, [-1, -1, -1, -1, 3]);
  } finally {
    fs.rmSync(threeMfPath, { force: true });
  }
});

test("P1S ignores a result-less local project_file echo", async () => {
  const fixturePath = await writeSliced3mfFixture({ plateFilamentIds: [0] });
  const threeMfPath = fixturePath.replace(/\.gcode\.3mf$/, ".3mf");
  fs.renameSync(fixturePath, threeMfPath);
  const bambu = new BambuImplementation();
  let messageListener = null;

  bambu.ftpUpload = async () => {};
  bambu.getPrinter = async () => ({
    data: {
      gcode_state: "FAILED",
      subtask_name: "previous.3mf",
    },
    on: (event, listener) => {
      if (event === "message") messageListener = listener;
    },
    off: () => {},
    publish: async (payload) => {
      queueMicrotask(() => {
        messageListener?.("device/test/report", "print", {
          ...payload.print,
        });
        messageListener?.("device/test/report", "print", {
          command: "project_file",
          sequence_id: payload.print.sequence_id,
          result: "SUCCESS",
          reason: "SUCCESS",
        });
      });
    },
  });

  try {
    const result = await bambu.print3mf(
      "127.0.0.1",
      "01P00TEST0000000",
      "TEST_TOKEN",
      {
        projectName: "p1s-echo",
        filePath: threeMfPath,
        bambuModel: "p1s",
        plateIndex: 0,
        useAMS: true,
        amsSlots: [3],
      }
    );

    assert.equal(result.status, "success");
    assert.equal(result.acceptance?.result, "SUCCESS");
  } finally {
    fs.rmSync(threeMfPath, { force: true });
  }
});

test("P1S rejects a result-less project_file response with an error code", async () => {
  const fixturePath = await writeSliced3mfFixture({ plateFilamentIds: [0] });
  const threeMfPath = fixturePath.replace(/\.gcode\.3mf$/, ".3mf");
  fs.renameSync(fixturePath, threeMfPath);
  const bambu = new BambuImplementation();
  let messageListener = null;

  bambu.ftpUpload = async () => {};
  bambu.getPrinter = async () => ({
    data: { gcode_state: "FINISH", subtask_name: "previous.3mf" },
    on: (event, listener) => {
      if (event === "message") messageListener = listener;
    },
    off: () => {},
    publish: async (payload) => {
      queueMicrotask(() => {
        messageListener?.("device/test/report", "print", {
          command: "project_file",
          sequence_id: payload.print.sequence_id,
          err_code: 84033543,
        });
      });
    },
  });

  try {
    await assert.rejects(
      bambu.print3mf("127.0.0.1", "01P00TEST0000000", "TEST_TOKEN", {
        projectName: "p1s-error-code",
        filePath: threeMfPath,
        bambuModel: "p1s",
        plateIndex: 0,
        useAMS: true,
        amsSlots: [3],
      }),
      /Printer rejected the project file: 84033543\. MQTT message verification failed\./
    );
  } finally {
    fs.rmSync(threeMfPath, { force: true });
  }
});

test("P1S project_file rejects a negative printer acknowledgement", async () => {
  const fixturePath = await writeSliced3mfFixture({ plateFilamentIds: [0] });
  const threeMfPath = fixturePath.replace(/\.gcode\.3mf$/, ".3mf");
  fs.renameSync(fixturePath, threeMfPath);
  const bambu = new BambuImplementation();
  let messageListener = null;

  bambu.ftpUpload = async () => {};
  bambu.getPrinter = async () => ({
    data: { gcode_state: "FINISH", subtask_name: "previous.3mf" },
    on: (event, listener) => {
      if (event === "message") messageListener = listener;
    },
    off: () => {},
    publish: async (payload) => {
      queueMicrotask(() => {
        messageListener?.("device/test/report", "print", {
          command: "project_file",
          sequence_id: payload.print.sequence_id,
          result: "FAILURE",
          reason: "INVALID_PROJECT",
          return_code: "05024007",
        });
      });
    },
  });

  try {
    await assert.rejects(
      bambu.print3mf("127.0.0.1", "01P00TEST0000000", "TEST_TOKEN", {
        projectName: "bad-coupon",
        filePath: threeMfPath,
        bambuModel: "p1s",
        plateIndex: 0,
        useAMS: true,
        amsSlots: [3],
      }),
      /Printer rejected the project file: INVALID_PROJECT \/ 05024007\. MQTT message verification failed\./
    );
  } finally {
    fs.rmSync(threeMfPath, { force: true });
  }
});

test("P1S does not treat a pre-existing active job as project_file acceptance", async () => {
  const bambu = new BambuImplementation();
  const listeners = new Map();
  let published = false;
  const printer = {
    data: {
      gcode_state: "RUNNING",
      subtask_name: "same-project.3mf",
    },
    on: (event, listener) => listeners.set(event, listener),
    off: (event) => listeners.delete(event),
    publish: async () => {
      published = true;
    },
  };

  await assert.rejects(
    bambu.publishProjectFileAndWait(
      printer,
      {
        print: {
          command: "project_file",
          sequence_id: "77",
        },
      },
      "same-project.3mf",
      20
    ),
    /did not acknowledge the project_file command/i
  );
  assert.equal(published, true);
  assert.equal(listeners.size, 0);
});

test("BambuNetwork diagnostics redact callback payloads before status exposure", () => {
  const source = [
    'ordinary bridge status',
    '[PJBRIDGE] {"kind":"net.change_user","payload":{"user_id":"private-user","callback_marker":"private-marker"}}',
    '[PJBRIDGE] {"kind":"net.local_task_update","payload":{"dev_id":"private-device"}}',
  ].join("\n");
  const redacted = redactBambuNetworkDiagnostic(source);

  assert.match(redacted, /ordinary bridge status/);
  assert.match(redacted, /"kind":"net\.change_user","payload":"\[redacted\]"/);
  assert.match(redacted, /"kind":"net\.local_task_update","payload":"\[redacted\]"/);
  assert.doesNotMatch(redacted, /private-user|private-marker|private-device/);
});

test("BambuNetwork certificate staging requires and copies the complete LAN trust bundle", (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bambu-network-certs-"));
  const sourceDir = path.join(tempRoot, "source");
  const configDir = path.join(tempRoot, "config");
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.writeFileSync(path.join(sourceDir, "slicer_base64.cer"), "slicer-public-cert");
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  const incomplete = stageBambuNetworkCertificates(configDir, [sourceDir]);
  assert.equal(incomplete.certDir, undefined);
  assert.deepEqual(incomplete.missing, ["printer.cer"]);

  fs.writeFileSync(path.join(sourceDir, "printer.cer"), "printer-public-ca-bundle");
  const complete = stageBambuNetworkCertificates(configDir, [sourceDir]);
  assert.equal(complete.certDir, path.join(configDir, "cert"));
  assert.deepEqual(complete.missing, []);
  assert.equal(
    fs.readFileSync(path.join(complete.certDir, "printer.cer"), "utf8"),
    "printer-public-ca-bundle"
  );

  fs.rmSync(sourceDir, { recursive: true, force: true });
  const reused = stageBambuNetworkCertificates(configDir, []);
  assert.equal(reused.certDir, path.join(configDir, "cert"));
  assert.deepEqual(reused.missing, []);

  const replacementDir = path.join(tempRoot, "replacement");
  fs.mkdirSync(replacementDir, { recursive: true });
  fs.writeFileSync(path.join(replacementDir, "slicer_base64.cer"), "new-slicer-certificate");
  fs.writeFileSync(path.join(replacementDir, "printer.cer"), "new-printer-certificate");
  const replaced = stageBambuNetworkCertificates(configDir, [replacementDir]);
  assert.notEqual(replaced.fingerprint, reused.fingerprint);
  assert.equal(
    fs.readFileSync(path.join(configDir, "cert", "printer.cer"), "utf8"),
    "new-printer-certificate"
  );

  const incompleteReplacementDir = path.join(tempRoot, "incomplete-replacement");
  fs.mkdirSync(incompleteReplacementDir, { recursive: true });
  fs.writeFileSync(
    path.join(incompleteReplacementDir, "slicer_base64.cer"),
    "incomplete-new-slicer-certificate"
  );
  const rejectedReplacement = stageBambuNetworkCertificates(
    configDir,
    [incompleteReplacementDir],
    incompleteReplacementDir
  );
  assert.equal(rejectedReplacement.certDir, undefined);
  assert.deepEqual(rejectedReplacement.missing, ["printer.cer"]);
  assert.equal(
    fs.readFileSync(path.join(configDir, "cert", "slicer_base64.cer"), "utf8"),
    "new-slicer-certificate"
  );
  assert.equal(
    fs.readFileSync(path.join(configDir, "cert", "printer.cer"), "utf8"),
    "new-printer-certificate"
  );

  const splitConfigDir = path.join(tempRoot, "split-config");
  const splitSlicerDir = path.join(tempRoot, "split-slicer");
  const splitPrinterDir = path.join(tempRoot, "split-printer");
  fs.mkdirSync(splitSlicerDir, { recursive: true });
  fs.mkdirSync(splitPrinterDir, { recursive: true });
  fs.writeFileSync(path.join(splitSlicerDir, "slicer_base64.cer"), "split-slicer");
  fs.writeFileSync(path.join(splitPrinterDir, "printer.cer"), "split-printer");
  const rejectedSplit = stageBambuNetworkCertificates(
    splitConfigDir,
    [splitSlicerDir, splitPrinterDir]
  );
  assert.equal(rejectedSplit.certDir, undefined);
  assert.deepEqual(rejectedSplit.missing, ["printer.cer"]);
  assert.equal(fs.existsSync(path.join(splitConfigDir, "cert")), false);
});

test("BambuNetwork connection reports a dispatched void device-certificate request", async () => {
  const bridge = new BambuNetworkBridge();
  bridge.ensureAgent = async () => {
    bridge.agentCertDir = "/tmp/test-bambu-network-certs";
    return { agent: 7, handshake: {} };
  };
  bridge.request = async (method, payload) => {
    if (method === "net.connect_printer") {
      return { ok: true, value: 0 };
    }
    if (method === "bridge.poll_events") {
      return {
        ok: true,
        events: [
          {
            name: "on_local_connect",
            payload: { dev_id: "TEST-DEVICE", status: 0 },
          },
        ],
      };
    }
    if (method === "net.install_device_cert") {
      return { ok: true, value: 9 };
    }
    throw new Error(`Unexpected bridge method ${method}`);
  };

  const connected = await bridge.connectPrinter({
      devId: "TEST-DEVICE",
      devIp: "192.0.2.10",
      username: "bblp",
      accessCode: "test-access-code",
      useSsl: true,
    });
  assert.equal(connected.connected, true);
  assert.equal(connected.deviceCertificateRequested, true);
});

test("BambuNetwork agent startup rejects failed certificate initialization", async (t) => {
  const bridge = new BambuNetworkBridge();
  let destroyedAgent = null;
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bambu-network-agent-certs-"));
  const sourceDir = path.join(tempRoot, "source");
  const configDir = path.join(tempRoot, "config");
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.writeFileSync(path.join(sourceDir, "slicer_base64.cer"), "slicer-certificate");
  fs.writeFileSync(path.join(sourceDir, "printer.cer"), "printer-certificate");
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  bridge.request = async (method, payload) => {
    if (method === "bridge.handshake") {
      return { ok: true };
    }
    if (method === "net.create_agent") {
      return { ok: true, value: 7 };
    }
    if (method === "net.set_cert_file") {
      return { ok: true, value: 5 };
    }
    if (method === "net.destroy_agent") {
      destroyedAgent = payload.agent;
      return { ok: true, value: 0 };
    }
    return { ok: true, value: 0 };
  };

  await assert.rejects(
    bridge.ensureAgent({
      bridgeCommand: "test-bridge",
      configDir,
      certDir: sourceDir,
    }),
    /set_cert_file returned non-zero result 5/i
  );
  assert.equal(destroyedAgent, 7);
});

test("BambuNetwork agent startup rejects an incomplete explicit certificate bundle", async (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bambu-network-incomplete-explicit-"));
  const sourceDir = path.join(tempRoot, "source");
  const configDir = path.join(tempRoot, "config");
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.writeFileSync(path.join(sourceDir, "slicer_base64.cer"), "slicer-public-cert");
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  const bridge = new BambuNetworkBridge();
  bridge.request = async () => {
    throw new Error("Bridge startup must not run with an incomplete explicit bundle.");
  };

  await assert.rejects(
    bridge.ensureAgent({
      bridgeCommand: "test-bridge",
      configDir,
      certDir: sourceDir,
    }),
    /explicitly configured.*incomplete.*printer\.cer/i
  );
});

test("BambuNetwork runtime directories remain certificate fallbacks", (t) => {
  const runtimeDir = path.join(os.tmpdir(), `bambu-network-runtime-${Date.now()}`);
  const explicitDir = path.join(os.tmpdir(), `bambu-network-explicit-${Date.now()}`);
  const originalPluginDir = process.env.PJARCZAK_BAMBU_PLUGIN_DIR;
  const originalCertDir = process.env.BAMBU_NETWORK_CERT_DIR;
  process.env.PJARCZAK_BAMBU_PLUGIN_DIR = runtimeDir;
  delete process.env.BAMBU_NETWORK_CERT_DIR;
  t.after(() => {
    if (originalPluginDir === undefined) {
      delete process.env.PJARCZAK_BAMBU_PLUGIN_DIR;
    } else {
      process.env.PJARCZAK_BAMBU_PLUGIN_DIR = originalPluginDir;
    }
    if (originalCertDir === undefined) {
      delete process.env.BAMBU_NETWORK_CERT_DIR;
    } else {
      process.env.BAMBU_NETWORK_CERT_DIR = originalCertDir;
    }
  });

  const bridge = new BambuNetworkBridge();
  const fallbackSources = bridge.resolveCertificateSources({});
  assert.equal(fallbackSources.strictDirectory, undefined);
  assert.ok(fallbackSources.directories.includes(runtimeDir));

  process.env.BAMBU_NETWORK_CERT_DIR = explicitDir;
  const explicitSources = bridge.resolveCertificateSources({});
  assert.equal(explicitSources.strictDirectory, explicitDir);
  assert.equal(explicitSources.directories[0], explicitDir);
});

test("BambuNetwork stops after failed initialization cleanup", async (t) => {
  const bridge = new BambuNetworkBridge();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bambu-network-agent-cleanup-"));
  const sourceDir = path.join(tempRoot, "source");
  const configDir = path.join(tempRoot, "config");
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.writeFileSync(path.join(sourceDir, "slicer_base64.cer"), "slicer-certificate");
  fs.writeFileSync(path.join(sourceDir, "printer.cer"), "printer-certificate");
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  let stopped = false;
  bridge.stop = async () => {
    stopped = true;
  };
  bridge.request = async (method) => {
    if (method === "bridge.handshake") return { ok: true };
    if (method === "net.create_agent") return { ok: true, value: 7 };
    if (method === "net.set_cert_file") return { ok: true, value: 5 };
    if (method === "net.destroy_agent") return { ok: true, value: 9 };
    return { ok: true, value: 0 };
  };

  await assert.rejects(
    bridge.ensureAgent({
      bridgeCommand: "test-bridge",
      configDir,
      certDir: sourceDir,
    }),
    /set_cert_file returned non-zero result 5/i
  );
  assert.equal(stopped, true);
});

test("BambuNetwork certificate rotation destroys the previous agent", async (t) => {
  const bridge = new BambuNetworkBridge();
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bambu-network-agent-rotation-"));
  const sourceDir = path.join(tempRoot, "source");
  const configDir = path.join(tempRoot, "config");
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.writeFileSync(path.join(sourceDir, "slicer_base64.cer"), "slicer-certificate-v1");
  fs.writeFileSync(path.join(sourceDir, "printer.cer"), "printer-certificate-v1");
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  let nextAgent = 7;
  const destroyedAgents = [];
  bridge.request = async (method, payload) => {
    if (method === "bridge.handshake") return { ok: true };
    if (method === "net.create_agent") {
      return { ok: true, value: nextAgent++ };
    }
    if (method === "net.destroy_agent") {
      destroyedAgents.push(payload.agent);
      return { ok: true, value: 0 };
    }
    return { ok: true, value: 0 };
  };

  const first = await bridge.ensureAgent({
    bridgeCommand: "test-bridge",
    configDir,
    certDir: sourceDir,
  });
  assert.equal(first.agent, 7);

  fs.writeFileSync(path.join(sourceDir, "printer.cer"), "printer-certificate-v2");
  const second = await bridge.ensureAgent({
    bridgeCommand: "test-bridge",
    configDir,
    certDir: sourceDir,
  });
  assert.equal(second.agent, 8);
  assert.deepEqual(destroyedAgents, [7]);
});

test("BambuNetwork waits for every local method that publishes project_file", () => {
  assert.equal(requiresBambuNetworkProjectFileAcknowledgement("start_local_print"), true);
  assert.equal(
    requiresBambuNetworkProjectFileAcknowledgement("start_local_print_with_record"),
    false
  );
  assert.equal(requiresBambuNetworkProjectFileAcknowledgement("start_sdcard_print"), true);
  assert.equal(
    requiresBambuNetworkProjectFileAcknowledgement("start_send_gcode_to_sdcard"),
    false
  );
  assert.equal(requiresBambuNetworkProjectFileAcknowledgement("start_print"), false);
});

test("BambuNetwork raw diagnostics cannot bypass managed lifecycle methods", () => {
  assert.equal(isManagedBambuNetworkCallMethod("net.connect_printer"), true);
  assert.equal(isManagedBambuNetworkCallMethod("net.set_cert_file"), true);
  assert.equal(isManagedBambuNetworkCallMethod("net.start_local_print"), true);
  assert.equal(isManagedBambuNetworkCallMethod("net.start_print"), true);
  assert.equal(isManagedBambuNetworkCallMethod("net.send_message"), true);
  assert.equal(isManagedBambuNetworkCallMethod("net.send_message_to_printer"), true);
  assert.equal(isManagedBambuNetworkCallMethod("bridge.poll_events"), false);
  assert.equal(isManagedBambuNetworkCallMethod("bridge.job_wait_reply"), false);
  assert.equal(isManagedBambuNetworkCallMethod("ft.job_cancel"), false);
  assert.equal(isBambuNetworkControlMethod("bridge.poll_events"), true);
  assert.equal(isBambuNetworkControlMethod("bridge.job_wait_reply"), true);
  assert.equal(isBambuNetworkControlMethod("bridge.job_cancel"), true);
  assert.equal(isBambuNetworkControlMethod("bridge.cancel_job"), false);
  assert.equal(isBambuNetworkControlMethod("bridge.callback_reply"), true);
  assert.equal(isBambuNetworkControlMethod("ft.job_cancel"), true);
  assert.equal(isBambuNetworkControlMethod("net.is_user_login"), false);
  assert.equal(
    requiresBambuNetworkAgentForRawCall("bridge.job_wait_reply", undefined),
    false
  );
  assert.equal(
    requiresBambuNetworkAgentForRawCall("bridge.callback_reply", true),
    false
  );
  assert.equal(
    requiresBambuNetworkAgentForRawCall("net.is_user_login", undefined),
    true
  );
  assert.equal(
    requiresBambuNetworkAgentForRawCall("net.is_user_login", false),
    false
  );
});

test("BambuNetwork submission names use a server-generated unique marker", () => {
  const first = createBambuNetworkSubmissionNames("holder-v2", "desk-holder");
  const second = createBambuNetworkSubmissionNames("holder-v2", "desk-holder");

  assert.match(first.projectName, /^holder-v2__mcp_[0-9a-f]{12}$/);
  assert.match(first.taskName, /^desk-holder__mcp_[0-9a-f]{12}$/);
  assert.notEqual(first.nonce, second.nonce);
  assert.notEqual(first.projectName, second.projectName);
  assert.notEqual(first.taskName, second.taskName);

  const bounded = createBambuNetworkSubmissionNames("x".repeat(200));
  assert.equal(bounded.projectName.length, 96);
  assert.equal(Buffer.byteLength(bounded.projectName, "utf8"), 96);
  assert.match(bounded.projectName, /__mcp_[0-9a-f]{12}$/);

  const unicodeBounded = createBambuNetworkSubmissionNames(
    `${"é".repeat(40)}${"😀".repeat(20)}`
  );
  assert.ok(Buffer.byteLength(unicodeBounded.projectName, "utf8") <= 96);
  assert.equal(
    Buffer.from(unicodeBounded.projectName, "utf8").toString("utf8"),
    unicodeBounded.projectName
  );
  assert.doesNotMatch(unicodeBounded.projectName, /[\uD800-\uDFFF]/);
  assert.match(unicodeBounded.projectName, /__mcp_[0-9a-f]{12}$/);
});

test("BambuNetwork sequence correlation requires an explicit host capability", () => {
  const bridge = new BambuNetworkBridge();
  bridge.handshake = { network_loaded: true };
  assert.equal(bridge.supportsProjectFileSequenceCorrelation(), false);
  bridge.handshake = {
    network_loaded: true,
    project_file_sequence_id: true,
  };
  assert.equal(bridge.supportsProjectFileSequenceCorrelation(), true);
});

test("BambuNetwork acknowledgement ignores result-less responses", async () => {
  const bridge = new BambuNetworkBridge();
  const acceptedSequenceId = 23;
  let requestCount = 0;
  bridge.request = async (method) => {
    assert.equal(method, "bridge.poll_events");
    requestCount += 1;
    return {
      ok: true,
      events:
        requestCount === 1
          ? [
              {
                name: "job.wait",
                payload: { job_id: 7, request_id: 8 },
              },
              {
                name: "on_local_message",
                payload: {
                  dev_id: "TEST-DEVICE",
                  msg: JSON.stringify({
                    print: {
                      command: "project_file",
                      sequence_id: String(acceptedSequenceId),
                    },
                  }),
                },
              },
            ]
          : [
              {
                name: "on_local_message",
                payload: {
                  dev_id: "TEST-DEVICE",
                  msg: JSON.stringify({
                    print: {
                      command: "project_file",
                      result: "success",
                      sequence_id: String(acceptedSequenceId),
                    },
                  }),
                },
              },
            ],
    };
  };

  const acknowledgementPromise = bridge.waitForLocalPrintAcknowledgement(
    "TEST-DEVICE",
    String(acceptedSequenceId)
  );
  await sleep(20);
  const control = await bridge.pollEventsForControl({ limit: 64 });
  assert.equal(control.events[0]?.name, "job.wait");
  const acknowledgement = await acknowledgementPromise;
  assert.equal(requestCount, 2);
  assert.deepEqual(acknowledgement, {
    errCode: 0,
    command: "project_file",
    sequenceId: String(acceptedSequenceId),
  });
});

test("BambuNetwork control polling preserves managed print messages", async () => {
  const bridge = new BambuNetworkBridge();
  let requests = 0;
  bridge.request = async (method) => {
    requests += 1;
    assert.equal(method, "bridge.poll_events");
    return {
      ok: true,
      events: [
        {
          name: "job.wait",
          payload: { job_id: 7, request_id: 8 },
        },
        {
          name: "on_local_message",
          payload: {
            dev_id: "TEST-DEVICE",
            msg: JSON.stringify({
              print: {
                command: "project_file",
                sequence_id: "42",
                result: "success",
              },
            }),
          },
        },
      ],
    };
  };

  const controlPoll = await bridge.pollEventsForControl({ limit: 64 });
  assert.equal(controlPoll.events.length, 2);
  const acknowledgement = await bridge.waitForLocalPrintAcknowledgement(
    "TEST-DEVICE",
    "42"
  );
  assert.equal(requests, 1);
  assert.equal(acknowledgement.sequenceId, "42");
});

test("BambuNetwork control calls stay bound to the active bridge command", async () => {
  const bridge = new BambuNetworkBridge();
  const activeChild = { exitCode: null };
  bridge.child = activeChild;
  bridge.commandLine = "active-bridge";
  let receivedOptions;
  bridge.request = async (_method, _payload, options) => {
    receivedOptions = options;
    return { ok: true, value: 0 };
  };

  await bridge.requestControl("bridge.job_wait_reply", {
    job_id: 7,
    request_id: 8,
    reply: true,
  });
  assert.equal(receivedOptions.bridgeCommand, "active-bridge");

  await assert.rejects(
    bridge.requestControl(
      "bridge.job_cancel",
      { job_id: 7, cancel: true },
      { bridgeCommand: "different-bridge" }
    ),
    /cannot switch bridge_command/i
  );
});

test("BambuNetwork control polling preserves managed connection callbacks", async () => {
  const bridge = new BambuNetworkBridge();
  bridge.ensureAgent = async () => ({ agent: 1, handshake: {} });
  bridge.discardQueuedEvents = async () => 0;
  bridge.request = async (method) => {
    if (method === "bridge.poll_events") {
      return {
        ok: true,
        events: [
          {
            name: "on_local_connect",
            payload: { dev_id: "TEST-DEVICE", status: 0 },
          },
        ],
      };
    }
    if (method === "net.connect_printer") {
      return { ok: true, value: 0 };
    }
    if (method === "net.install_device_cert") {
      return { ok: true };
    }
    throw new Error(`Unexpected bridge method ${method}`);
  };

  await bridge.pollEventsForControl({ limit: 64 });
  const connected = await bridge.connectPrinter({
    devId: "TEST-DEVICE",
    devIp: "127.0.0.1",
    username: "bblp",
    accessCode: "TEST_TOKEN",
    useSsl: false,
  });
  assert.equal(connected.connected, true);
  assert.equal(connected.deviceCertificateRequested, true);
});

test("BambuNetwork preserves push_status delivered with the acknowledgement", async () => {
  const bridge = new BambuNetworkBridge();
  let requests = 0;
  bridge.request = async () => {
    requests += 1;
    if (requests > 1) {
      throw new Error("The preserved push_status event should satisfy confirmation.");
    }
    return {
      ok: true,
      events: [
        {
          name: "job.wait",
          payload: { job_id: 7, request_id: 8 },
        },
        {
          name: "on_local_message",
          payload: {
            dev_id: "TEST-DEVICE",
            msg: JSON.stringify({
              print: {
                command: "push_status",
                gcode_state: "PREPARE",
                subtask_name: "holder-v2__mcp_42",
              },
            }),
          },
        },
        {
          name: "on_local_message",
          payload: {
            dev_id: "TEST-DEVICE",
            msg: JSON.stringify({
              print: {
                command: "project_file",
                result: "success",
                sequence_id: "42",
              },
            }),
          },
        },
      ],
    };
  };

  await bridge.waitForLocalPrintAcknowledgement("TEST-DEVICE", "42");
  const job = await bridge.waitForPrinterJobStart(
    "TEST-DEVICE",
    ["holder-v2__mcp_42"]
  );
  assert.deepEqual(job, {
    state: "PREPARE",
    filename: "holder-v2__mcp_42",
  });
  const control = await bridge.pollEventsForControl({ limit: 64 });
  assert.ok(
    control.events.some(
      (event) =>
        event?.name === "job.wait" &&
        event?.payload?.job_id === 7 &&
        event?.payload?.request_id === 8
    ),
    "the acknowledgement and job-start waiters must preserve control events"
  );
});

test("BambuNetwork acknowledgement never treats a result-less response as success", async () => {
  const bridge = new BambuNetworkBridge();
  bridge.request = async (method) => {
    assert.equal(method, "bridge.poll_events");
    return {
      ok: true,
      events: [
        {
          name: "on_local_message",
          payload: {
            dev_id: "TEST-DEVICE",
            msg: JSON.stringify({
              print: {
                command: "project_file",
                sequence_id: "41",
              },
            }),
          },
        },
        {
          name: "on_local_message",
          payload: {
            dev_id: "TEST-DEVICE",
            msg: JSON.stringify({
              print: {
                command: "project_file",
                sequence_id: "42",
                err_code: 84033543,
              },
            }),
          },
        },
      ],
    };
  };

  await assert.rejects(
    bridge.waitForLocalPrintAcknowledgement("TEST-DEVICE", "42"),
    /84033543.*verification failed/i
  );
});

test("BambuNetwork acknowledgement ignores stale project_file responses", async () => {
  const bridge = new BambuNetworkBridge();
  bridge.request = async () => ({
    ok: true,
    events: [
      {
        name: "on_local_message",
        payload: {
          dev_id: "TEST-DEVICE",
          msg: JSON.stringify({
            print: {
              command: "project_file",
              sequence_id: "41",
              err_code: 84033543,
            },
          }),
        },
      },
      {
        name: "on_local_message",
        payload: {
          dev_id: "TEST-DEVICE",
          msg: JSON.stringify({
            print: {
              command: "project_file",
              sequence_id: "42",
              result: "success",
            },
          }),
        },
      },
    ],
  });

  const acknowledgement = await bridge.waitForLocalPrintAcknowledgement(
    "TEST-DEVICE",
    "42"
  );
  assert.deepEqual(acknowledgement, {
    errCode: 0,
    command: "project_file",
    sequenceId: "42",
  });
});

test("BambuNetwork bridge lifecycles are serialized", async () => {
  const bridge = new BambuNetworkBridge();
  const order = [];
  const first = bridge.withExclusiveLifecycle(async () => {
    order.push("first-start");
    await sleep(20);
    order.push("first-end");
  });
  const second = bridge.withExclusiveLifecycle(async () => {
    order.push("second-start");
    order.push("second-end");
  });

  await Promise.all([first, second]);
  assert.deepEqual(order, [
    "first-start",
    "first-end",
    "second-start",
    "second-end",
  ]);
});

test("BambuNetwork managed print lifecycle keeps the raw control lane open", async () => {
  const bridge = new BambuNetworkBridge();
  let release;
  const active = bridge.withExclusiveLifecycle(
    async () =>
      await new Promise((resolve) => {
        release = resolve;
      }),
    { allowRawControl: true }
  );

  await sleep(0);
  assert.equal(bridge.isRawControlLaneOpen(), true);
  release();
  await active;
  assert.equal(bridge.isRawControlLaneOpen(), false);
});

test("BambuNetwork success requires the exact live printer job", async () => {
  const bridge = new BambuNetworkBridge();
  bridge.request = async () => ({
    ok: true,
    events: [
      {
        name: "on_local_message",
        payload: {
          dev_id: "TEST-DEVICE",
          msg: JSON.stringify({
            print: {
              command: "push_status",
              gcode_state: "RUNNING",
              subtask_name: "holder-v2",
            },
          }),
        },
      },
    ],
  });
  const confirmed = await bridge.waitForPrinterJobStart(
    "TEST-DEVICE",
    ["holder-v2.3mf"],
    { timeoutMs: 1_000 }
  );
  assert.deepEqual(confirmed, { state: "RUNNING", filename: "holder-v2" });

  const unrelatedBridge = new BambuNetworkBridge();
  let requestCount = 0;
  unrelatedBridge.request = async () => {
    requestCount += 1;
    return {
      ok: true,
      events: [
        {
          name: "on_local_message",
          payload: {
            dev_id: "TEST-DEVICE",
            msg: JSON.stringify({
              print: {
                command: "push_status",
                gcode_state: "RUNNING",
                subtask_name:
                  requestCount === 1 ? "different-job" : "holder-v2",
              },
            }),
          },
        },
      ],
    };
  };
  const confirmedAfterUnrelated = await unrelatedBridge.waitForPrinterJobStart(
    "TEST-DEVICE",
    ["holder-v2.3mf"],
    { confirmationTimeoutMs: 1_000 }
  );
  assert.equal(requestCount, 2);
  assert.deepEqual(confirmedAfterUnrelated, {
    state: "RUNNING",
    filename: "holder-v2",
  });
});

test("BambuNetwork waits through sparse active push_status reports", async () => {
  const bridge = new BambuNetworkBridge();
  let requestCount = 0;
  bridge.request = async () => {
    requestCount += 1;
    return {
      ok: true,
      events: [
        ...(requestCount === 1
          ? [
              {
                name: "job.wait",
                payload: { job_id: 9, request_id: 10 },
              },
            ]
          : []),
        {
          name: "on_local_message",
          payload: {
            dev_id: "TEST-DEVICE",
            msg: JSON.stringify({
              print: requestCount === 1
                ? {
                    command: "push_status",
                    gcode_state: "IDLE",
                    subtask_name: "holder-v2__mcp_42",
                  }
                : {
                    command: "push_status",
                    gcode_state: "PREPARE",
                  },
            }),
          },
        },
      ],
    };
  };

  const confirmationPromise = bridge.waitForPrinterJobStart(
    "TEST-DEVICE",
    ["holder-v2__mcp_42"],
    { confirmationTimeoutMs: 1_000 }
  );
  await sleep(20);
  const control = await bridge.pollEventsForControl({ limit: 64 });
  assert.equal(control.events[0]?.name, "job.wait");
  const confirmed = await confirmationPromise;
  assert.equal(requestCount, 2);
  assert.deepEqual(confirmed, {
    state: "PREPARE",
    filename: "holder-v2__mcp_42",
  });
});

test("BambuNetwork does not carry an old job state into a new job name", async () => {
  const bridge = new BambuNetworkBridge();
  let requestCount = 0;
  bridge.request = async () => {
    requestCount += 1;
    const print =
      requestCount === 1
        ? {
            command: "push_status",
            gcode_state: "RUNNING",
            subtask_name: "older-job",
          }
        : requestCount === 2
          ? {
              command: "push_status",
              subtask_name: "holder-v2__mcp_42",
            }
          : {
              command: "push_status",
              gcode_state: "PREPARE",
            };
    return {
      ok: true,
      events: [
        {
          name: "on_local_message",
          payload: {
            dev_id: "TEST-DEVICE",
            msg: JSON.stringify({ print }),
          },
        },
      ],
    };
  };

  const confirmed = await bridge.waitForPrinterJobStart(
    "TEST-DEVICE",
    ["holder-v2__mcp_42"],
    { confirmationTimeoutMs: 1_000 }
  );
  assert.equal(requestCount, 3);
  assert.deepEqual(confirmed, {
    state: "PREPARE",
    filename: "holder-v2__mcp_42",
  });
});

test("BambuNetwork does not count a paused job as start confirmation", async () => {
  const bridge = new BambuNetworkBridge();
  let requestCount = 0;
  bridge.request = async () => {
    requestCount += 1;
    return {
      ok: true,
      events: [
        {
          name: "on_local_message",
          payload: {
            dev_id: "TEST-DEVICE",
            msg: JSON.stringify({
              print: {
                command: "push_status",
                gcode_state: requestCount === 1 ? "PAUSED" : "RUNNING",
                subtask_name: "holder-v2__mcp_42",
              },
            }),
          },
        },
      ],
    };
  };

  const confirmed = await bridge.waitForPrinterJobStart(
    "TEST-DEVICE",
    ["holder-v2__mcp_42"],
    { confirmationTimeoutMs: 1_000 }
  );
  assert.equal(requestCount, 2);
  assert.deepEqual(confirmed, {
    state: "RUNNING",
    filename: "holder-v2__mcp_42",
  });
});

test("BambuNetwork job confirmation requires the current submission marker", async () => {
  const bridge = new BambuNetworkBridge();
  let requestCount = 0;
  bridge.request = async () => {
    requestCount += 1;
    return {
      ok: true,
      events: [
        {
          name: "on_local_message",
          payload: {
            dev_id: "TEST-DEVICE",
            msg: JSON.stringify({
              print: {
                command: "push_status",
                gcode_state: "RUNNING",
                subtask_name:
                  requestCount === 1
                    ? "widget"
                    : "widget_plate_1__mcp_a1b2c3d4e5f6",
              },
            }),
          },
        },
      ],
    };
  };

  const confirmed = await bridge.waitForPrinterJobStart(
    "TEST-DEVICE",
    ["widget_plate_1__mcp_a1b2c3d4e5f6"],
    { confirmationTimeoutMs: 1_000 }
  );
  assert.equal(requestCount, 2);
  assert.equal(confirmed.filename, "widget_plate_1__mcp_a1b2c3d4e5f6");
});

test("H2 ams_slots expand into project-level ams_mapping and ams_mapping2", async () => {
  const threeMfPath = await writeSliced3mfFixture({ plateFilamentIds: [1] });
  const bambu = new BambuImplementation();
  let uploaded = false;
  let publishedPayload = null;

  bambu.ftpUpload = async () => {
    uploaded = true;
  };
  bambu.getPrinter = async () => ({
    publish: async (payload) => {
      publishedPayload = payload;
    },
  });

  try {
    const result = await bambu.print3mf("127.0.0.1", "0938TEST0000000", "TEST_TOKEN", {
      projectName: "cube",
      filePath: threeMfPath,
      plateIndex: 0,
      useAMS: true,
      amsSlots: [1],
      bedType: "supertack_plate",
    });

    assert.equal(uploaded, true, "print3mf should upload before publishing");
    assert.equal(result.status, "success");
    assert.ok(publishedPayload?.print, "project_file payload should be published");
    assert.equal(publishedPayload.print.command, "project_file");
    assert.equal(publishedPayload.print.param, "Metadata/plate_1.gcode");
    assert.deepEqual(publishedPayload.print.ams_mapping, [-1, 1, -1, -1]);
    assert.deepEqual(publishedPayload.print.ams_mapping2, [
      { ams_id: 255, slot_id: 255 },
      { ams_id: 0, slot_id: 1 },
      { ams_id: 255, slot_id: 255 },
      { ams_id: 255, slot_id: 255 },
    ]);
  } finally {
    fs.rmSync(threeMfPath, { force: true });
  }
});

test("H2C model routes project files through the H2 print path independent of serial prefix", async () => {
  const threeMfPath = await writeSliced3mfFixture({ plateFilamentIds: [1] });
  const bambu = new BambuImplementation();
  let uploadedPath = null;
  let publishedPayload = null;

  bambu.ftpUpload = async (_host, _token, _filePath, remotePath) => {
    uploadedPath = remotePath;
  };
  bambu.getPrinter = async () => ({
    publish: async (payload) => {
      publishedPayload = payload;
    },
  });

  try {
    const result = await bambu.print3mf("127.0.0.1", "01P00TEST0000000", "TEST_TOKEN", {
      projectName: "h2c-cube",
      filePath: threeMfPath,
      bambuModel: "h2c",
      plateIndex: 0,
      useAMS: true,
      amsSlots: [1],
      bedType: "textured_plate",
    });

    assert.equal(result.status, "success");
    assert.equal(uploadedPath, `/${path.basename(threeMfPath)}`);
    assert.ok(publishedPayload?.print, "H2C should publish a project_file payload");
    assert.equal(publishedPayload.print.command, "project_file");
    assert.match(publishedPayload.print.url, /^ftp:\/\/\//);
    assert.deepEqual(publishedPayload.print.ams_mapping, [-1, 1, -1, -1]);
    assert.deepEqual(publishedPayload.print.ams_mapping2, [
      { ams_id: 255, slot_id: 255 },
      { ams_id: 0, slot_id: 1 },
      { ams_id: 255, slot_id: 255 },
      { ams_id: 255, slot_id: 255 },
    ]);
  } finally {
    fs.rmSync(threeMfPath, { force: true });
  }
});

test("H2 two-color ams_slots expand at sparse project-level filament positions", async () => {
  const threeMfPath = await writeSliced3mfFixture({
    name: "h2d-two-color-project-filament",
    projectFilamentIds: ["GFG01", "GFG02", "GFG60", "GFG02", "GFG02", "GFG60", "GFG02", "GFL01"],
    projectFilamentColors: ["#FF911A80", "#39541A", "#F72323", "#000000", "#FFFFFF", "#0D6284", "#000000", "#46A8F9"],
    projectFilamentTypes: ["PETG", "PETG", "PETG", "PETG", "PETG", "PETG", "PETG", "PLA"],
    plateFilamentIds: [3, 4],
  });
  const bambu = new BambuImplementation();
  let publishedPayload = null;

  bambu.ftpUpload = async () => {};
  bambu.getPrinter = async () => ({
    publish: async (payload) => {
      publishedPayload = payload;
    },
  });

  try {
    const result = await bambu.print3mf("127.0.0.1", "0938TEST0000000", "TEST_TOKEN", {
      projectName: "h2d-two-color",
      filePath: threeMfPath,
      plateIndex: 0,
      useAMS: true,
      amsSlots: [1, 2],
      bedType: "textured_plate",
    });

    assert.equal(result.status, "success");
    assert.ok(publishedPayload?.print, "project_file payload should be published");
    assert.deepEqual(publishedPayload.print.ams_mapping, [-1, -1, -1, 1, 2, -1, -1, -1]);
    assert.deepEqual(publishedPayload.print.ams_mapping2, [
      { ams_id: 255, slot_id: 255 },
      { ams_id: 255, slot_id: 255 },
      { ams_id: 255, slot_id: 255 },
      { ams_id: 0, slot_id: 1 },
      { ams_id: 0, slot_id: 2 },
      { ams_id: 255, slot_id: 255 },
      { ams_id: 255, slot_id: 255 },
      { ams_id: 255, slot_id: 255 },
    ]);
  } finally {
    fs.rmSync(threeMfPath, { force: true });
  }
});

test("H2 ams_mapping2 preserves external spool and HT tray encodings", async () => {
  const threeMfPath = await writeSliced3mfFixture({
    name: "h2-external-and-ht-mapping",
    projectFilamentIds: ["GFG01", "GFG02", "GFG60", "GFL01"],
    projectFilamentColors: ["#111111", "#222222", "#333333", "#444444"],
    projectFilamentTypes: ["PETG", "PETG", "PETG", "PLA"],
    plateFilamentIds: [0, 1, 2, 3],
  });
  const bambu = new BambuImplementation();
  let publishedPayload = null;

  bambu.ftpUpload = async () => {};
  bambu.getPrinter = async () => ({
    publish: async (payload) => {
      publishedPayload = payload;
    },
  });

  try {
    await bambu.print3mf("127.0.0.1", "0938TEST0000000", "TEST_TOKEN", {
      projectName: "h2-external-and-ht",
      filePath: threeMfPath,
      plateIndex: 0,
      useAMS: true,
      amsMapping: [254, 128, 131, 15],
      bedType: "supertack_plate",
    });

    assert.ok(publishedPayload?.print, "project_file payload should be published");
    assert.deepEqual(publishedPayload.print.ams_mapping, [254, 128, 131, 15]);
    assert.deepEqual(publishedPayload.print.ams_mapping2, [
      { ams_id: 254, slot_id: 254 },
      { ams_id: 128, slot_id: 0 },
      { ams_id: 128, slot_id: 3 },
      { ams_id: 3, slot_id: 3 },
    ]);
  } finally {
    fs.rmSync(threeMfPath, { force: true });
  }
});

test("ams_mapping object preserves filament-position order instead of tray sorting", () => {
  assert.deepEqual(
    normalizeAmsMappingObject({ 0: 4, 1: 1 }),
    [4, 1],
    "filament position 0 must stay mapped to tray 4 even though tray 1 sorts first"
  );
  assert.deepEqual(
    normalizeAmsMappingObject({ 10: "2", 2: "5" }),
    [5, 2],
    "numeric object keys must drive position order before tray value order"
  );
});

test("ams_mapping input treats empty arrays and objects as absent", () => {
  assert.equal(hasAmsMappingInput(undefined), false);
  assert.equal(hasAmsMappingInput(null), false);
  assert.equal(hasAmsMappingInput([]), false);
  assert.equal(hasAmsMappingInput({}), false);
  assert.equal(hasAmsMappingInput([4]), true);
  assert.equal(hasAmsMappingInput({ 0: 4 }), true);
});

test("BambuNetwork print rejects invalid ams_slots values before bridge payload", async (t) => {
  const threeMfPath = await writeSliced3mfFixture({ name: "bridge-invalid-ams-slots" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_SERIAL: "TEST_DEV",
      BAMBU_TOKEN: "TEST_TOKEN",
      BAMBU_MODEL: "h2s",
      BAMBU_NETWORK_BRIDGE_COMMAND: "/definitely/missing/bambu-network-bridge",
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(() => fs.rmSync(threeMfPath, { force: true }));
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);

  for (const invalidSlot of [null, "", "not-a-slot", 1.5, 16]) {
    const result = await client.callTool({
      name: "print_3mf_bambu_network",
      arguments: {
        three_mf_path: threeMfPath,
        bambu_model: "h2s",
        dev_id: "TEST_DEV",
        connection_type: "cloud",
        ams_slots: [invalidSlot],
      },
    });

    assert.equal(result.isError, true, `invalid ams_slots value should fail: ${JSON.stringify(invalidSlot)}`);
    const errorText = result.content?.[0]?.text || "";
    assert.match(errorText, /ams_slots\[0\].*integer/i);
    assert.doesNotMatch(errorText, /BAMBU_NETWORK_BRIDGE_COMMAND|FULU BambuNetwork bridge/i);
  }

  const emptyMappingResult = await client.callTool({
    name: "print_3mf_bambu_network",
    arguments: {
      three_mf_path: threeMfPath,
      bambu_model: "h2s",
      dev_id: "TEST_DEV",
      connection_type: "cloud",
      ams_mapping: [],
      ams_slots: [null],
    },
  });
  assert.equal(emptyMappingResult.isError, true);
  const emptyMappingErrorText = emptyMappingResult.content?.[0]?.text || "";
  assert.match(emptyMappingErrorText, /ams_slots\[0\].*integer/i);
  assert.doesNotMatch(emptyMappingErrorText, /BAMBU_NETWORK_BRIDGE_COMMAND|FULU BambuNetwork bridge/i);
});

test("SuperTack rewrite uses plate filaments and preserves initial versus normal temperatures", async (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "supertack-rewrite-"));
  const threeMfPath = path.join(tempRoot, "temperature-transition.3mf");
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

  const zip = new JSZip();
  zip.file(
    "Metadata/project_settings.config",
    JSON.stringify({
      curr_bed_type: "High Temp Plate",
      supertack_plate_temp_initial_layer: ["0", "75"],
      supertack_plate_temp: ["0", "70"],
    })
  );
  zip.file(
    "Metadata/plate_1.json",
    JSON.stringify({
      bed_type: "hot_plate",
      filament_ids: [1],
    })
  );
  zip.file(
    "Metadata/slice_info.config",
    [
      '<?xml version="1.0" encoding="UTF-8"?>',
      "<config>",
      "  <plate>",
      '    <metadata key="curr_bed_type" value="High Temp Plate"/>',
      "  </plate>",
      "</config>",
    ].join("\n")
  );
  const originalGcode = [
    "; curr_bed_type = High Temp Plate",
    "M190 S60 ; initial wait",
    "; layer num/total_layer_count: 1/3",
    "M140 S60 ; remain at initial temperature",
    "; layer num/total_layer_count: 2/3",
    "M140 S60 ; normal layers",
    "M140 S0 ; turn off bed",
    "",
  ].join("\n");
  zip.file("Metadata/plate_1.gcode", originalGcode);
  zip.file(
    "Metadata/plate_1.gcode.md5",
    createHash("md5").update(originalGcode).digest("hex")
  );
  fs.writeFileSync(threeMfPath, await zip.generateAsync({ type: "nodebuffer" }));

  const manipulator = new STLManipulator(tempRoot);
  await manipulator.rewriteSuperTackSliceArchive(threeMfPath);

  const rewrittenZip = await JSZip.loadAsync(fs.readFileSync(threeMfPath));
  const rewrittenGcode = await rewrittenZip
    .file("Metadata/plate_1.gcode")
    .async("string");
  const embeddedMd5 = await rewrittenZip
    .file("Metadata/plate_1.gcode.md5")
    .async("string");
  const plate = JSON.parse(
    await rewrittenZip.file("Metadata/plate_1.json").async("string")
  );
  const project = JSON.parse(
    await rewrittenZip
      .file("Metadata/project_settings.config")
      .async("string")
  );
  const sliceInfo = await rewrittenZip
    .file("Metadata/slice_info.config")
    .async("string");

  assert.match(rewrittenGcode, /^M190 S75 ; initial wait$/m);
  assert.match(
    rewrittenGcode,
    /^M140 S75 ; remain at initial temperature$/m
  );
  assert.match(rewrittenGcode, /^M140 S70 ; normal layers$/m);
  assert.match(rewrittenGcode, /^M140 S0 ; turn off bed$/m);
  assert.equal(
    embeddedMd5.toLowerCase(),
    createHash("md5").update(rewrittenGcode).digest("hex")
  );
  assert.equal(plate.bed_type, "supertack_plate");
  assert.equal(project.curr_bed_type, "Bambu Cool Plate SuperTack");
  assert.match(
    sliceInfo,
    /<metadata key="curr_bed_type" value="Bambu Cool Plate SuperTack"\/>/
  );
});

test("slice archive validation checks every supported Bambu bed type", async (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bed-validation-"));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const manipulator = new STLManipulator(tempRoot);
  const bedTypes = {
    textured_plate: "Textured PEI Plate",
    cool_plate: "Cool Plate",
    engineering_plate: "Engineering Plate",
    hot_plate: "High Temp Plate",
    supertack_plate: "Bambu Cool Plate SuperTack",
  };

  for (const [requested, embedded] of Object.entries(bedTypes)) {
    const validPath = path.join(tempRoot, `${requested}-valid.3mf`);
    const validZip = new JSZip();
    validZip.file(
      "Metadata/project_settings.config",
      JSON.stringify({ curr_bed_type: embedded })
    );
    validZip.file("Metadata/plate_1.gcode", "G1 X0 Y0\n");
    if (requested === "supertack_plate") {
      validZip.file(
        "Metadata/slice_info.config",
        `<config><plate><metadata key="curr_bed_type" value="${embedded}"/></plate></config>`
      );
    }
    fs.writeFileSync(
      validPath,
      await validZip.generateAsync({ type: "nodebuffer" })
    );
    await manipulator.validateBambuSliceArchive(validPath, [], requested);

    const invalidPath = path.join(tempRoot, `${requested}-invalid.3mf`);
    const invalidZip = new JSZip();
    invalidZip.file(
      "Metadata/project_settings.config",
      JSON.stringify({
        curr_bed_type:
          requested === "supertack_plate" ? embedded : "Unexpected Plate",
      })
    );
    invalidZip.file("Metadata/plate_1.gcode", "G1 X0 Y0\n");
    if (requested === "supertack_plate") {
      invalidZip.file(
        "Metadata/slice_info.config",
        '<config><plate><metadata key="curr_bed_type" value="High Temp Plate"/></plate></config>'
      );
    }
    fs.writeFileSync(
      invalidPath,
      await invalidZip.generateAsync({ type: "nodebuffer" })
    );
    await assert.rejects(
      manipulator.validateBambuSliceArchive(invalidPath, [], requested),
      /output bed mismatch/i
    );
  }
});

test("sliceSTL allows slicer executables resolved from PATH", async (t) => {
  if (process.platform === "win32") {
    t.skip("PATH executable resolution test uses a POSIX executable shim");
    return;
  }

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "path-slicer-"));
  const binDir = path.join(tempRoot, "bin");
  const commandName = `fake-prusaslicer-${process.pid}-${Date.now()}`;
  const commandPath = path.join(binDir, commandName);
  const originalPath = process.env.PATH || "";
  t.after(() => {
    process.env.PATH = originalPath;
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(
    commandPath,
    [
      "#!/bin/sh",
      "while [ \"$#\" -gt 0 ]; do",
      "  if [ \"$1\" = \"--output\" ]; then",
      "    shift",
      "    printf 'G1 X0\\n' > \"$1\"",
      "    exit 0",
      "  fi",
      "  shift",
      "done",
      "exit 2",
      "",
    ].join("\n"),
    { mode: 0o755 }
  );
  process.env.PATH = `${binDir}${path.delimiter}${originalPath}`;

  const manipulator = new STLManipulator(tempRoot);
  const outputPath = await manipulator.sliceSTL(SAMPLE_STL, "prusaslicer", commandName);

  assert.equal(outputPath, path.join(tempRoot, "sample_cube.gcode"));
  assert.equal(fs.readFileSync(outputPath, "utf8"), "G1 X0\n");
});

test("sliceSTL redacts local paths from non-debug failures", async (t) => {
  const previousDebug = process.env.BAMBU_MCP_DEBUG_SLICER;
  delete process.env.BAMBU_MCP_DEBUG_SLICER;
  t.after(() => {
    if (previousDebug === undefined) delete process.env.BAMBU_MCP_DEBUG_SLICER;
    else process.env.BAMBU_MCP_DEBUG_SLICER = previousDebug;
  });

  const manipulator = new STLManipulator();
  const privateRoot = "/Users/example/private-printer";
  await assert.rejects(
    () =>
      manipulator.sliceSTL(
        `${privateRoot}/model.stl`,
        "prusaslicer",
        `${privateRoot}/bin/slicer`
      ),
    (error) => {
      assert.doesNotMatch(error.message, /Users|example|private-printer/);
      assert.match(error.message, /<slicer>/);
      return true;
    }
  );
});

test("camera_snapshot routes H2 series through RTSP", async () => {
  const bambu = new BambuImplementation();
  const fakeJpeg = Buffer.from([0xff, 0xd8, 0x12, 0x34, 0xff, 0xd9]);
  let rtspCalls = 0;
  let tcpCalls = 0;
  bambu.fetchRtspCameraFrame = async () => { rtspCalls++; return fakeJpeg; };
  bambu.fetchTcpCameraFrame = async () => { tcpCalls++; return fakeJpeg; };

  for (const model of ["h2", "h2s", "h2d", "h2c", "h2dpro"]) {
    const out = await bambu.cameraSnapshot("127.0.0.1", "S", "T", { bambuModel: model });
    assert.equal(out.status, "success", `${model} should succeed via RTSP`);
    assert.equal(out.transport, "rtsps-322", `${model} transport should be rtsps-322`);
  }
  assert.equal(rtspCalls, 5, "RTSP path should run once per H2 variant");
  assert.equal(tcpCalls, 0, "TCP-on-6000 path should not run for H2");
});

test("camera_snapshot routes X1/P2S through RTSP", async () => {
  const bambu = new BambuImplementation();
  const fakeJpeg = Buffer.from([0xff, 0xd8, 0xab, 0xcd, 0xff, 0xd9]);
  bambu.fetchRtspCameraFrame = async () => fakeJpeg;
  bambu.fetchTcpCameraFrame = async () => {
    throw new Error("RTSP models must not reach the TCP wire path");
  };

  for (const model of ["x1", "x1c", "x1carbon", "x1e", "p2s"]) {
    const out = await bambu.cameraSnapshot("127.0.0.1", "S", "T", { bambuModel: model });
    assert.equal(out.transport, "rtsps-322", `${model} should use rtsps-322`);
    assert.equal(out.format, "image/jpeg");
    assert.deepEqual(Buffer.from(out.base64, "base64"), fakeJpeg);
  }
});

test("camera_snapshot rejects unknown model strings", async () => {
  const bambu = new BambuImplementation();
  await assert.rejects(
    bambu.cameraSnapshot("127.0.0.1", "S", "T", { bambuModel: "ender3" }),
    /not a known Bambu Lab printer model/i
  );
});

test("camera_snapshot requires a model before choosing a wire protocol", async () => {
  const bambu = new BambuImplementation();
  bambu.fetchTcpCameraFrame = async () => {
    throw new Error("missing model must not default to TCP");
  };
  bambu.fetchRtspCameraFrame = async () => {
    throw new Error("missing model must not default to RTSP");
  };

  await assert.rejects(
    bambu.cameraSnapshot("127.0.0.1", "S", "T", {}),
    /requires bambu_model or BAMBU_MODEL/i
  );
});

test("camera_snapshot supported models reach the wire path (mocked) and decode a JPEG frame", async () => {
  const bambu = new BambuImplementation();

  // Stub the private wire fetcher so we can verify the routing without
  // talking to a real printer. Returns a tiny synthetic JPEG.
  const fakeJpeg = Buffer.from([0xff, 0xd8, 0x00, 0x11, 0x22, 0xff, 0xd9]);
  bambu.fetchTcpCameraFrame = async () => fakeJpeg;

  for (const model of ["a1", "a1mini", "p1s", "p1p"]) {
    const out = await bambu.cameraSnapshot("127.0.0.1", "S", "T", { bambuModel: model });
    assert.equal(out.status, "success", `${model} should succeed`);
    assert.equal(out.format, "image/jpeg");
    assert.equal(out.sizeBytes, fakeJpeg.length);
    assert.equal(out.base64, fakeJpeg.toString("base64"));
  }
});

test("camera_snapshot RTSP path: ffmpeg ENOENT yields a clear, actionable error", async () => {
  const bambu = new BambuImplementation();
  // Don't mock fetchRtspCameraFrame -- exercise it with a bogus binary
  // path and confirm the surfacing.
  await assert.rejects(
    bambu.cameraSnapshot("127.0.0.1", "S", "T", {
      bambuModel: "h2s",
      ffmpegPath: "/no/such/ffmpeg-binary",
    }),
    /ffmpeg binary not found.*brew install ffmpeg/i
  );
});

test("camera_snapshot save_path writes the jpeg to disk", async (t) => {
  const bambu = new BambuImplementation();
  const fakeJpeg = Buffer.from([0xff, 0xd8, 0x42, 0x42, 0xff, 0xd9]);
  bambu.fetchTcpCameraFrame = async () => fakeJpeg;

  const outPath = path.join(os.tmpdir(), `snap-${Date.now()}.jpg`);
  t.after(() => { fs.rmSync(outPath, { force: true }); });

  const out = await bambu.cameraSnapshot("127.0.0.1", "S", "T", {
    bambuModel: "p1s",
    savePath: outPath,
  });

  assert.equal(out.savedTo, outPath);
  const onDisk = fs.readFileSync(outPath);
  assert.deepEqual(Buffer.from(onDisk), fakeJpeg);
});

test("delete_printer_file requires confirm:true and skips FTP when omitted", async () => {
  const bambu = new BambuImplementation();
  let ftpCalled = false;
  bambu.ftpDelete = async () => {
    ftpCalled = true;
  };

  const result = await bambu.deleteFile(
    "127.0.0.1",
    "0938TEST",
    "TEST_TOKEN",
    "stale.gcode.3mf",
    false
  );

  assert.equal(ftpCalled, false, "ftpDelete must not run without confirm:true");
  assert.equal(result.status, "skipped");
  assert.equal(result.deleted, false);
  assert.match(result.message, /requires confirm:true/);
});

test("delete_printer_file treats loose confirm values as not confirmed", async () => {
  const bambu = new BambuImplementation();
  let ftpCalls = 0;
  bambu.ftpDelete = async () => {
    ftpCalls++;
  };

  for (const confirm of [undefined, null, false, "false", "true", 1]) {
    const result = await bambu.deleteFile(
      "127.0.0.1",
      "0938TEST",
      "TEST_TOKEN",
      "stale.gcode.3mf",
      confirm
    );
    assert.equal(result.status, "skipped", `confirm=${JSON.stringify(confirm)} must not delete`);
    assert.equal(result.deleted, false, `confirm=${JSON.stringify(confirm)} must report no deletion`);
  }

  assert.equal(ftpCalls, 0, "ftpDelete must only run for literal confirm:true");
});

test("delete_printer_file rejects path traversal", async () => {
  const bambu = new BambuImplementation();
  bambu.ftpDelete = async () => {
    throw new Error("ftpDelete should not be reached on traversal input");
  };

  await assert.rejects(
    bambu.deleteFile("127.0.0.1", "S", "T", "../../etc/passwd", true),
    /path traversal segments are not allowed/i
  );
});

test("delete_printer_file rejects directories outside cache/timelapse/logs", async () => {
  const bambu = new BambuImplementation();
  bambu.ftpDelete = async () => {
    throw new Error("ftpDelete should not be reached for disallowed parent");
  };

  await assert.rejects(
    bambu.deleteFile("127.0.0.1", "S", "T", "userdata/secrets.bin", true),
    /refusing to delete outside cache\/, timelapse\/, logs\//i
  );
});

test("delete_printer_file with confirm:true normalizes bare names to cache/ and calls ftpDelete with absolute path", async () => {
  const bambu = new BambuImplementation();
  let ftpArgs = null;
  bambu.ftpDelete = async (host, token, remote) => {
    ftpArgs = { host, token, remote };
  };

  const result = await bambu.deleteFile(
    "printer-one.local",
    "0938TEST",
    "ACCESS_TOKEN",
    "old_print.gcode.3mf",
    true
  );

  assert.deepEqual(ftpArgs, {
    host: "printer-one.local",
    token: "ACCESS_TOKEN",
    remote: "/cache/old_print.gcode.3mf",
  });
  assert.equal(result.status, "success");
  assert.equal(result.deleted, true);
  assert.equal(result.remotePath, "cache/old_print.gcode.3mf");
});

test("delete_printer_file accepts explicit timelapse/ and logs/ paths", async () => {
  const bambu = new BambuImplementation();
  const calls = [];
  bambu.ftpDelete = async (_host, _token, remote) => {
    calls.push(remote);
  };

  await bambu.deleteFile("h", "s", "t", "timelapse/2026-04-26_12-00.mp4", true);
  await bambu.deleteFile("h", "s", "t", "logs/printer.log", true);

  assert.deepEqual(calls, ["/timelapse/2026-04-26_12-00.mp4", "/logs/printer.log"]);
});

test("set_ams_drying rejects invalid action values", async () => {
  const bambu = new BambuImplementation();
  bambu.getPrinter = async () => ({
    publish: async () => {},
  });

  await assert.rejects(
    bambu.setAmsDrying("127.0.0.1", "SERIAL", "TOKEN", "toggle", 0),
    /must be one of: start, stop/i
  );
  await assert.rejects(
    bambu.setAmsDrying("127.0.0.1", "SERIAL", "TOKEN", "", 0),
    /must be one of: start, stop/i
  );
});

test("set_ams_drying rejects invalid ams_id values", async () => {
  const bambu = new BambuImplementation();
  bambu.getPrinter = async () => ({
    publish: async () => {},
  });

  await assert.rejects(
    bambu.setAmsDrying("127.0.0.1", "SERIAL", "TOKEN", "start", -1),
    /must be an integer from 0 to 3/i
  );
  await assert.rejects(
    bambu.setAmsDrying("127.0.0.1", "SERIAL", "TOKEN", "start", 4),
    /must be an integer from 0 to 3/i
  );
  await assert.rejects(
    bambu.setAmsDrying("127.0.0.1", "SERIAL", "TOKEN", "start", -999),
    /must be an integer from 0 to 3/i
  );
});

test("reset_ams rejects active print states", async () => {
  const bambu = new BambuImplementation();
  bambu.getPrinter = async () => ({
    data: { gcode_state: "RUNNING" },
    publish: async () => {},
  });

  await assert.rejects(
    bambu.resetAms("127.0.0.1", "SERIAL", "TOKEN"),
    /only while the printer is idle/i
  );
});

test("reset_ams sends the documented recovery command while idle", async () => {
  const bambu = new BambuImplementation();
  const publishPayloads = [];
  bambu.getPrinter = async () => ({
    data: { gcode_state: "FAILED" },
    publish: async (payload) => {
      publishPayloads.push(payload);
    },
  });

  const result = await bambu.resetAms("127.0.0.1", "SERIAL", "TOKEN");

  assert.equal(publishPayloads.length, 2);
  assert.equal(publishPayloads[0]?.print?.command, "ams_control");
  assert.equal(publishPayloads[0]?.print?.param, "reset");
  assert.match(String(publishPayloads[0]?.print?.sequence_id), /^\d+$/);
  assert.equal(publishPayloads[1]?.print?.command, "ams_control");
  assert.equal(publishPayloads[1]?.print?.param, "resume");
  assert.match(String(publishPayloads[1]?.print?.sequence_id), /^\d+$/);
  assert.equal(result.status, "success");
  assert.match(result.message, /AMS reset and resume commands sent/i);
});

test("load_ams_filament validates the slot and loading temperature", async () => {
  const bambu = new BambuImplementation();

  await assert.rejects(
    bambu.loadAmsFilament("127.0.0.1", "SERIAL", "TOKEN", 3.9, 250),
    /slot must be an absolute AMS tray index from 0 to 15/i
  );
  await assert.rejects(
    bambu.loadAmsFilament("127.0.0.1", "SERIAL", "TOKEN", 16, 250),
    /slot must be an absolute AMS tray index from 0 to 15/i
  );
  await assert.rejects(
    bambu.loadAmsFilament("127.0.0.1", "SERIAL", "TOKEN", 3, 301),
    /target_temperature must be from 170 to 300/i
  );
});

test("recovery commands fail closed when printer state is unknown", async () => {
  const actions = [
    (bambu) => bambu.resetAms("127.0.0.1", "SERIAL", "TOKEN"),
    (bambu) =>
      bambu.loadAmsFilament("127.0.0.1", "SERIAL", "TOKEN", 3, 250),
    (bambu) => bambu.unloadAmsFilament("127.0.0.1", "SERIAL", "TOKEN"),
    (bambu) => bambu.rebootPrinter("127.0.0.1", "SERIAL", "TOKEN"),
  ];

  for (const action of actions) {
    const bambu = new BambuImplementation();
    let published = false;
    bambu.getPrinter = async () => ({
      data: {},
      publish: async () => {
        published = true;
      },
    });
    bambu.printerStore.waitForInitialReport = async () => null;

    await assert.rejects(action(bambu), /current print state is UNKNOWN/i);
    assert.equal(published, false);
  }
});

test("load_ams_filament sends the documented idle AMS change command", async () => {
  const bambu = new BambuImplementation();
  let publishPayload = null;
  bambu.getPrinter = async () => ({
    data: { gcode_state: "FAILED", nozzle_temper: 28.7 },
    publish: async (payload) => {
      publishPayload = payload;
    },
  });

  const result = await bambu.loadAmsFilament(
    "127.0.0.1",
    "SERIAL",
    "TOKEN",
    3,
    250
  );

  assert.equal(publishPayload?.print?.command, "ams_change_filament");
  assert.equal(publishPayload?.print?.target, 3);
  assert.equal(publishPayload?.print?.curr_temp, 28);
  assert.equal(publishPayload?.print?.tar_temp, 250);
  assert.match(String(publishPayload?.print?.sequence_id), /^\d+$/);
  assert.equal(result.status, "success");
  assert.equal(result.slot, 3);
  assert.equal(result.target_temperature, 250);
});

test("unload_ams_filament rejects active print states", async () => {
  const bambu = new BambuImplementation();
  bambu.getPrinter = async () => ({
    data: { gcode_state: "PREPARE" },
    publish: async () => {},
  });

  await assert.rejects(
    bambu.unloadAmsFilament("127.0.0.1", "SERIAL", "TOKEN"),
    /only while the printer is idle/i
  );
});

test("unload_ams_filament sends the acknowledged unload command while idle", async () => {
  const bambu = new BambuImplementation();
  let publishPayload = null;
  bambu.getPrinter = async () => ({
    data: { gcode_state: "FAILED" },
    publish: async (payload) => {
      publishPayload = payload;
    },
  });

  const result = await bambu.unloadAmsFilament(
    "127.0.0.1",
    "SERIAL",
    "TOKEN"
  );

  assert.equal(publishPayload?.print?.command, "unload_filament");
  assert.match(String(publishPayload?.print?.sequence_id), /^\d+$/);
  assert.equal(result.status, "success");
  assert.match(result.message, /unload command accepted/i);
});

test("reboot_printer rejects active print states", async () => {
  const bambu = new BambuImplementation();
  bambu.getPrinter = async () => ({
    data: { gcode_state: "RUNNING" },
    publish: async () => {},
  });

  await assert.rejects(
    bambu.rebootPrinter("127.0.0.1", "SERIAL", "TOKEN"),
    /only while.*idle/i
  );
});

test("reboot_printer sends the system reboot command while idle", async () => {
  const bambu = new BambuImplementation();
  let publishPayload = null;
  bambu.getPrinter = async () => ({
    data: { gcode_state: "FAILED" },
    publish: async (payload) => {
      publishPayload = payload;
    },
  });

  const result = await bambu.rebootPrinter(
    "127.0.0.1",
    "SERIAL",
    "TOKEN"
  );

  assert.deepEqual(publishPayload, {
    system: {
      command: "reboot",
    },
  });
  assert.equal(result.status, "success");
  assert.match(result.message, /reboot command sent/i);
});

test("set_ams_drying sends correct MQTT command for start", async () => {
  const bambu = new BambuImplementation();
  let publishPayload = null;
  bambu.getPrinter = async () => ({
    publish: async (payload) => {
      publishPayload = payload;
    },
  });

  const result = await bambu.setAmsDrying("127.0.0.1", "SERIAL", "TOKEN", "start", 1);

  assert.deepEqual(publishPayload, {
    print: {
      command: "ams_control",
      ams_id: 1,
      param: "start_drying",
      sequence_id: "0",
    },
  });
  assert.equal(result.status, "success");
  assert.equal(result.action, "start");
  assert.equal(result.ams_id, 1);
  assert.match(result.message, /started.*AMS 1/i);
});

test("set_ams_drying sends correct MQTT command for stop", async () => {
  const bambu = new BambuImplementation();
  let publishPayload = null;
  bambu.getPrinter = async () => ({
    publish: async (payload) => {
      publishPayload = payload;
    },
  });

  const result = await bambu.setAmsDrying("127.0.0.1", "SERIAL", "TOKEN", "stop", 0);

  assert.deepEqual(publishPayload, {
    print: {
      command: "ams_control",
      ams_id: 0,
      param: "stop_drying",
      sequence_id: "0",
    },
  });
  assert.equal(result.status, "success");
  assert.equal(result.action, "stop");
  assert.equal(result.ams_id, 0);
  assert.match(result.message, /stopped.*AMS 0/i);
});

test("Bambu report snapshots are cleared with connection state", () => {
  const bambu = new BambuImplementation();
  const store = bambu.printerStore;
  const credentialFingerprint = createHash("sha256").update("TOKEN").digest("hex").slice(0, 16);
  const key = `127.0.0.1-SERIAL-${credentialFingerprint}`;

  store.updateReportSnapshot(key, {
    gcode_state: "FINISH",
    ams: { ams: [{ tray: [{ tray_info_idx: "STALE" }] }] },
  });

  assert.equal(
    store.getCachedReport("127.0.0.1", "SERIAL", "TOKEN")?.ams?.ams?.[0]?.tray?.[0]?.tray_info_idx,
    "STALE"
  );

  store.clearPrinterState(key);

  assert.equal(
    store.getCachedReport("127.0.0.1", "SERIAL", "TOKEN"),
    null,
    "disconnect/error cleanup must drop stale MQTT snapshots as well as promises"
  );
});

test("initial report wait holds a sparse packet until operational status arrives", async () => {
  const bambu = new BambuImplementation();
  const store = bambu.printerStore;
  const accessValue = "test-value";
  const deviceValue = "test-device";
  const credentialFingerprint = createHash("sha256").update(accessValue).digest("hex").slice(0, 16);
  const key = `127.0.0.1-${deviceValue}-${credentialFingerprint}`;

  store.updateReportSnapshot(key, { model: "A1" });
  const fullStatusTimer = setTimeout(() => {
    store.updateReportSnapshot(key, {
      gcode_state: "FINISH",
      nozzle_temper: 24,
    });
  }, 700);

  try {
    const report = await store.waitForInitialReport(
      "127.0.0.1",
      deviceValue,
      accessValue,
      1500
    );
    assert.equal(report?.gcode_state, "FINISH");
    assert.equal(report?.nozzle_temper, 24);
  } finally {
    clearTimeout(fullStatusTimer);
  }
});

test("targeted disconnect only closes the exact connection profile", async () => {
  const bambu = new BambuImplementation();
  const store = bambu.printerStore;
  const oldFingerprint = createHash("sha256").update("OLD_TOKEN").digest("hex").slice(0, 16);
  const oldKey = `printer.local-SERIAL-${oldFingerprint}`;
  let disconnectCalls = 0;
  const pendingClient = {
    disconnect: async () => {
      disconnectCalls += 1;
    },
  };

  store.connectingPrinters.set(oldKey, pendingClient);
  store.connectionEpochs.set(oldKey, 1);
  store.initialConnectionPromises.set(oldKey, Promise.resolve());

  await store.disconnect("printer.local", "SERIAL", "NEW_TOKEN");

  assert.equal(disconnectCalls, 0);
  assert.equal(store.connectingPrinters.has(oldKey), true);
  assert.equal(store.initialConnectionPromises.has(oldKey), true);

  await store.disconnect("printer.local", "SERIAL", "OLD_TOKEN");

  assert.equal(disconnectCalls, 1);
  assert.equal(store.connectingPrinters.has(oldKey), false);
  assert.equal(store.initialConnectionPromises.has(oldKey), false);
});

test("targeted disconnect clears stale state when the client disconnect rejects", async () => {
  const bambu = new BambuImplementation();
  const store = bambu.printerStore;
  const fingerprint = createHash("sha256").update("TOKEN").digest("hex").slice(0, 16);
  const key = `printer.local-SERIAL-${fingerprint}`;
  store.printers.set(key, {
    disconnect: async () => {
      throw new Error("stale transport");
    },
  });
  store.connectionEpochs.set(key, 1);

  await assert.doesNotReject(() => store.disconnect("printer.local", "SERIAL", "TOKEN"));
  assert.equal(store.printers.has(key), false);
});

test("stale client events cannot clear a replacement connection", () => {
  const bambu = new BambuImplementation();
  const store = bambu.printerStore;
  const fingerprint = createHash("sha256").update("TOKEN").digest("hex").slice(0, 16);
  const key = `printer.local-SERIAL-${fingerprint}`;
  const replacement = { disconnect: async () => {} };

  store.connectionEpochs.set(key, 2);
  store.printers.set(key, replacement);
  store.clearPrinterState(key, 1);

  assert.equal(store.printers.get(key), replacement);
});

test("patched bambu-node treats unknown models and unusual state transitions as recoverable", async () => {
  const client = new BambuClient({
    host: "127.0.0.1",
    serialNumber: "TEST_SERIAL",
    accessToken: "TEST_TOKEN",
  });

  await assert.doesNotReject(() =>
    client.onMessage(
      JSON.stringify({
        info: {
          command: "get_version",
          module: [{ name: "ota", sn: "UNKNOWN_MODEL_PREFIX" }],
        },
      }),
      "device/TEST_SERIAL/report"
    )
  );
  assert.equal(client.data.model, "X1C");

  client._printerStatus = "PAUSE";
  await assert.doesNotReject(() =>
    client.onMessage(
      JSON.stringify({ print: { command: "push_status", gcode_state: "FINISH" } }),
      "device/TEST_SERIAL/report"
    )
  );
  assert.equal(client.status, "FINISH");

  await assert.doesNotReject(() =>
    client.onMessage(
      JSON.stringify({ info: { command: "get_version", module: [] } }),
      "device/TEST_SERIAL/report"
    )
  );
});

test("legacy H2 client certificates migrate into the private config directory", (t) => {
  const homeDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "bambu-h2-migration-"));
  t.after(() => fs.rmSync(homeDirectory, { recursive: true, force: true }));
  const legacyDirectory = path.join(homeDirectory, "Desktop", "bambu certs");
  fs.mkdirSync(legacyDirectory, { recursive: true });
  fs.writeFileSync(path.join(legacyDirectory, "embedded-cert.pem"), "test-cert");
  fs.writeFileSync(path.join(legacyDirectory, "embedded-key.pem"), "test-key");

  const imported = spawnSync(
    process.execPath,
    ["-e", 'import("./dist/printers/bambu.js")'],
    {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        HOME: homeDirectory,
        BAMBU_CLIENT_CERT: "",
        BAMBU_CLIENT_KEY: "",
      },
      encoding: "utf8",
    }
  );
  assert.equal(imported.status, 0, imported.stderr);

  const privateDirectory = path.join(homeDirectory, ".config", "bambu-printer-mcp");
  const migratedCert = path.join(privateDirectory, "client.crt");
  const migratedKey = path.join(privateDirectory, "client.key");
  assert.equal(fs.readFileSync(migratedCert, "utf8"), "test-cert");
  assert.equal(fs.readFileSync(migratedKey, "utf8"), "test-key");
  assert.equal(fs.statSync(privateDirectory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(migratedCert).mode & 0o777, 0o600);
  assert.equal(fs.statSync(migratedKey).mode & 0o777, 0o600);
});

test("partial H2 migration falls back to the complete legacy pair", (t) => {
  const homeDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "bambu-h2-partial-"));
  t.after(() => fs.rmSync(homeDirectory, { recursive: true, force: true }));
  const legacyDirectory = path.join(homeDirectory, "Desktop", "bambu certs");
  const privateDirectory = path.join(homeDirectory, ".config", "bambu-printer-mcp");
  fs.mkdirSync(legacyDirectory, { recursive: true });
  fs.mkdirSync(privateDirectory, { recursive: true });
  fs.writeFileSync(path.join(legacyDirectory, "embedded-cert.pem"), "legacy-cert");
  fs.writeFileSync(path.join(legacyDirectory, "embedded-key.pem"), "legacy-key");
  fs.writeFileSync(path.join(privateDirectory, "client.crt"), "partial-cert");

  const check = [
    'const { loadClientCreds } = await import("./dist/printers/bambu.js");',
    "const pair = loadClientCreds();",
    'if (pair?.cert.toString() !== "legacy-cert" || pair?.key.toString() !== "legacy-key") process.exit(1);',
  ].join(" ");
  const imported = spawnSync(process.execPath, ["--input-type=module", "-e", check], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      HOME: homeDirectory,
      BAMBU_CLIENT_CERT: "",
      BAMBU_CLIENT_KEY: "",
    },
    encoding: "utf8",
  });
  assert.equal(imported.status, 0, imported.stderr);
});

async function writeTemplate3mfFixture(
  templateDir,
  baseName = "template-process",
  processName = "Template Process",
  layerHeight = "0.16"
) {
  const zip = new JSZip();
  zip.file("Metadata/project_settings.config", JSON.stringify({
    type: "process",
    name: processName,
    from: "project",
    layer_height: layerHeight,
  }));
  zip.file(
    "3D/3dmodel.model",
    '<?xml version="1.0" encoding="UTF-8"?><model unit="millimeter" xml:lang="en-US" xmlns="http://schemas.microsoft.com/3dmanufacturing/core/2015/02"><resources><object id="1" type="model" name="template.stl"><mesh><vertices/><triangles/></mesh></object></resources><build><item objectid="1"/></build></model>'
  );
  const templatePath = path.join(templateDir, `${baseName}.3mf`);
  fs.writeFileSync(templatePath, await zip.generateAsync({ type: "nodebuffer" }));
  return templatePath;
}

function writeTemplateJsonFixture(
  templateDir,
  baseName,
  processName,
  layerHeight = "0.12"
) {
  const templatePath = path.join(templateDir, `${baseName}.json`);
  fs.writeFileSync(templatePath, JSON.stringify({
    type: "process",
    name: processName,
    from: "User",
    layer_height: layerHeight,
  }));
  return templatePath;
}

async function createFakeBambuSlicer() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "bambu-mcp-template-slicer-"));
  const fakeSlicerPath = path.join(tempDir, "fake-slicer.mjs");
  const argsOutPath = path.join(tempDir, "args.json");
  fs.writeFileSync(
    fakeSlicerPath,
    `#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
const args = process.argv.slice(2);
fs.writeFileSync(${JSON.stringify(argsOutPath)}, JSON.stringify(args));
const outputDir = args[args.indexOf("--outputdir") + 1] || path.dirname(args[args.indexOf("--export-3mf") + 1]);
const exportArg = args[args.indexOf("--export-3mf") + 1];
const outputPath = path.isAbsolute(exportArg) ? exportArg : path.join(outputDir, exportArg);
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, "fake sliced 3mf");
`
  );
  fs.chmodSync(fakeSlicerPath, 0o755);
  return { tempDir, fakeSlicerPath, argsOutPath };
}

test("slice_with_template prefers named template settings over BAMBU_SLICER_PROFILE default", async (t) => {
  const fakeSlicer = await createFakeBambuSlicer();
  const templateDir = path.join(fakeSlicer.tempDir, "templates");
  fs.mkdirSync(templateDir, { recursive: true });
  await writeTemplate3mfFixture(templateDir);
  const defaultProfilePath = path.join(fakeSlicer.tempDir, "default-profile.json");
  fs.writeFileSync(defaultProfilePath, JSON.stringify({ name: "default should not win" }));

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_MODEL: "p1s",
      BAMBU_SERIAL: "",
      BAMBU_TOKEN: "",
      BAMBU_SLICER_PROFILE: defaultProfilePath,
      BAMBU_CLI_VALIDATE_OUTPUT: "0",
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);
  const result = await client.callTool({
    name: "slice_with_template",
    arguments: {
      stl_path: SAMPLE_STL,
      template_name: "template-process",
      template_dir: templateDir,
      bambu_model: "p1s",
      slicer_path: fakeSlicer.fakeSlicerPath,
      use_printer_filaments: false,
    },
  });

  assert.equal(result.isError, undefined);
  const slicerArgs = JSON.parse(fs.readFileSync(fakeSlicer.argsOutPath, "utf8"));
  const settingsValue = slicerArgs[slicerArgs.indexOf("--load-settings") + 1];
  const processPath = settingsValue.split(";").at(-1);
  const processSettings = JSON.parse(fs.readFileSync(processPath, "utf8"));
  assert.equal(processSettings.name, "Template Process");
  assert.equal(processSettings.layer_height, "0.16");
  assert.ok(!settingsValue.includes(defaultProfilePath), "server-level BAMBU_SLICER_PROFILE must not override a named template");
});

test("template_name resolves by source type for slicer profiles versus 3MF sources", async (t) => {
  const fakeSlicer = await createFakeBambuSlicer();
  const templateDir = path.join(fakeSlicer.tempDir, "templates");
  fs.mkdirSync(templateDir, { recursive: true });
  await writeTemplate3mfFixture(templateDir, "shared-template", "3MF Template", "0.20");
  await writeTemplateJsonFixture(templateDir, "shared-template", "JSON Template", "0.12");
  await writeTemplateJsonFixture(templateDir, "My Template", "Space Template", "0.18");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_MODEL: "p1s",
      BAMBU_SERIAL: "",
      BAMBU_TOKEN: "",
      BAMBU_CLI_VALIDATE_OUTPUT: "0",
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);

  const inspected = await client.callTool({
    name: "get_slice_settings",
    arguments: {
      template_name: "shared-template",
      template_dir: templateDir,
    },
  });
  assert.equal(inspected.isError, undefined);
  assert.equal(parseJsonResult(inspected).source_type, "3mf");

  const sliced = await client.callTool({
    name: "slice_with_template",
    arguments: {
      stl_path: SAMPLE_STL,
      template_name: "shared-template",
      template_dir: templateDir,
      bambu_model: "p1s",
      slicer_path: fakeSlicer.fakeSlicerPath,
      use_printer_filaments: false,
    },
  });

  assert.equal(sliced.isError, undefined);
  const slicerArgs = JSON.parse(fs.readFileSync(fakeSlicer.argsOutPath, "utf8"));
  const settingsValue = slicerArgs[slicerArgs.indexOf("--load-settings") + 1];
  const processPath = settingsValue.split(";").at(-1);
  const processSettings = JSON.parse(fs.readFileSync(processPath, "utf8"));
  assert.equal(processSettings.name, "JSON Template");
  assert.equal(processSettings.layer_height, "0.12");

  const spaced = await client.callTool({
    name: "slice_with_template",
    arguments: {
      stl_path: SAMPLE_STL,
      template_name: "My Template",
      template_dir: templateDir,
      bambu_model: "p1s",
      slicer_path: fakeSlicer.fakeSlicerPath,
      use_printer_filaments: false,
    },
  });

  assert.equal(spaced.isError, undefined);
  const spacedSlicerArgs = JSON.parse(fs.readFileSync(fakeSlicer.argsOutPath, "utf8"));
  const spacedSettingsValue = spacedSlicerArgs[spacedSlicerArgs.indexOf("--load-settings") + 1];
  const spacedProcessPath = spacedSettingsValue.split(";").at(-1);
  const spacedProcessSettings = JSON.parse(fs.readFileSync(spacedProcessPath, "utf8"));
  assert.equal(spacedProcessSettings.name, "Space Template");
  assert.equal(spacedProcessSettings.layer_height, "0.18");
});

test("non-slicer tools ignore invalid slicer configuration", async (t) => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_MODEL: "p1s",
      SLICER_TYPE: "definitely-not-a-real-slicer",
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);
  const result = await client.callTool({
    name: "get_stl_info",
    arguments: { stl_path: SAMPLE_STL },
  });

  assert.equal(result.isError, undefined);
  const payload = parseJsonResult(result);
  assert.equal(payload.fileName, "sample_cube.stl");
});

test("multi-printer tools expose redacted profiles and require unambiguous targeting", async (t) => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_SERIAL: "",
      BAMBU_TOKEN: "",
      BAMBU_MODEL: "",
      BAMBU_PRINTERS_JSON: JSON.stringify([
        {
          id: "alpha",
          name: "Printer Alpha",
          host: "127.0.0.2",
          model: "p1s",
          serial: "ALPHA_SERIAL",
          accessToken: "ALPHA_TOKEN",
        },
        {
          id: "beta",
          name: "Printer Beta",
          host: "127.0.0.3",
          model: "a1",
          serial: "BETA_SERIAL",
          accessToken: "BETA_TOKEN",
        },
      ]),
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });
  await client.connect(transport);

  const tools = await client.listTools();
  assertCommonToolPresence(tools);
  const statusTool = tools.tools.find((tool) => tool.name === "get_printer_status");
  assert.ok(statusTool.inputSchema.properties.printer);
  const startPrintTool = tools.tools.find((tool) => tool.name === "start_print");
  assert.equal(startPrintTool.inputSchema.required.includes("bambu_model"), false);
  const sliceTool = tools.tools.find((tool) => tool.name === "slice_stl");
  assert.equal(sliceTool.inputSchema.required.includes("bambu_model"), true);

  const listed = parseJsonResult(
    await client.callTool({ name: "list_printers", arguments: {} })
  );
  assert.equal(listed.printers.length, 2);
  const serialized = JSON.stringify(listed);
  assert.doesNotMatch(serialized, /127\.0\.0\.[23]/);
  assert.doesNotMatch(serialized, /ALPHA_SERIAL|BETA_SERIAL|ALPHA_TOKEN|BETA_TOKEN/);

  const ambiguous = await client.callTool({
    name: "get_printer_status",
    arguments: {},
  });
  assert.equal(ambiguous.isError, true);
  assert.match(ambiguous.content[0].text, /Multiple printers are configured/);

  const overrideAttempt = await client.callTool({
    name: "get_printer_status",
    arguments: { printer: "alpha", host: "attacker.invalid" },
  });
  assert.equal(overrideAttempt.isError, true);
  assert.match(overrideAttempt.content[0].text, /cannot be overridden: host/);
  assert.doesNotMatch(JSON.stringify(overrideAttempt), /ALPHA_SERIAL|ALPHA_TOKEN/);

  const localSlice = await client.callTool({
    name: "slice_stl",
    arguments: {},
  });
  assert.equal(localSlice.isError, true);
  assert.match(localSlice.content[0].text, /stl_path/i);
  assert.doesNotMatch(localSlice.content[0].text, /Multiple printers are configured/);

  await client.callTool({
    name: "set_default_printer",
    arguments: { printer: "alpha" },
  });
  const defaultSlice = await client.callTool({
    name: "slice_stl",
    arguments: { bambu_model: "a1" },
  });
  assert.equal(defaultSlice.isError, true);
  assert.match(defaultSlice.content[0].text, /cannot be overridden: bambu_model/);

});

test("fleet connection errors redact endpoint details", () => {
  assert.equal(
    redactPrinterConnectionError(new Error("connect ECONNREFUSED 192.0.2.45:8883")),
    "Printer connection was refused."
  );
  assert.equal(
    redactPrinterConnectionError(new Error("getaddrinfo ENOTFOUND private-printer.invalid")),
    "Printer is unreachable."
  );
  assert.doesNotMatch(
    redactPrinterConnectionError(new Error("unexpected failure at private-printer.invalid")),
    /private-printer/
  );
});

test("stdio transport: initialize, list tools, call success + structured failure", async (t) => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);
  assert.equal(client.getServerVersion()?.name, "bambu-printer-mcp");
  assert.equal(client.getServerVersion()?.version, "2.0.0");
  assert.equal(client.getServerCapabilities()?.resources?.listChanged, true);

  const listToolsResult = await client.listTools();
  assertCommonToolPresence(listToolsResult);

  const listResourcesResult = await client.listResources();
  assert.equal(listResourcesResult.resources.length, 0, "an empty registry must not advertise phantom printers");
  const resourceTemplates = await client.listResourceTemplates();
  assert.ok(
    resourceTemplates.resourceTemplates.some((entry) => entry.uriTemplate.endsWith("/hms")),
    "HMS diagnostics template must be listed"
  );

  const emptyFleet = parseJsonResult(
    await client.callTool({ name: "get_fleet_status", arguments: {} })
  );
  assert.deepEqual(emptyFleet, {
    status: "offline",
    total: 0,
    online: 0,
    printers: [],
  });

  const success = await client.callTool({
    name: "get_stl_info",
    arguments: { stl_path: SAMPLE_STL },
  });

  assert.equal(success.isError, undefined);
  const successPayload = parseJsonResult(success);
  assert.equal(successPayload.fileName, "sample_cube.stl");
  assert.equal(successPayload.faceCount, 12);

  const failure = await client.callTool({
    name: "get_stl_info",
    arguments: {},
  });

  assert.equal(failure.isError, true);
  assert.equal(failure.structuredContent?.status, "error");
  assert.equal(typeof failure.structuredContent?.suggestion, "string");
});

test("streamable-http transport: initialize, list tools, call success + origin rejection", async (t) => {
  const port = await getFreePort();
  const endpoint = `http://127.0.0.1:${port}/mcp`;

  const childProcess = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      MCP_TRANSPORT: "streamable-http",
      MCP_HTTP_HOST: "127.0.0.1",
      MCP_HTTP_PORT: String(port),
      MCP_HTTP_PATH: "/mcp",
      MCP_HTTP_ALLOWED_ORIGINS: "http://localhost",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });

  let stderrOutput = "";
  childProcess.stderr?.on("data", (chunk) => { stderrOutput += chunk.toString(); });

  t.after(async () => { await terminateChildProcess(childProcess); });

  const transport = new StreamableHTTPClientTransport(new URL(endpoint));
  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await waitForHttpServerReady(endpoint);
  await client.connect(transport);

  assert.equal(client.getServerVersion()?.name, "bambu-printer-mcp");
  assert.equal(client.getServerVersion()?.version, "2.0.0");

  const listToolsResult = await client.listTools();
  assertCommonToolPresence(listToolsResult);

  const success = await client.callTool({
    name: "get_stl_info",
    arguments: { stl_path: SAMPLE_STL },
  });

  const successPayload = parseJsonResult(success);
  assert.equal(successPayload.fileName, "sample_cube.stl");

  const forbiddenOriginResponse = await fetch(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "http://malicious.local",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-05",
        capabilities: {},
        clientInfo: { name: "origin-test-client", version: "1.0.0" },
      },
    }),
  });

  assert.equal(
    forbiddenOriginResponse.status,
    403,
    `Expected 403 for forbidden origin. stderr: ${stderrOutput}`
  );

  const wrongPathResponse = await fetch(`http://127.0.0.1:${port}/not-mcp`, { method: "POST" });
  assert.equal(wrongPathResponse.status, 404);
});

test("streamable-http transport refuses non-loopback binding without authentication", async () => {
  const childProcess = spawn(process.execPath, [SERVER_ENTRY], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      MCP_TRANSPORT: "streamable-http",
      MCP_HTTP_HOST: "0.0.0.0",
      MCP_HTTP_PORT: "0",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderrOutput = "";
  childProcess.stderr.on("data", (chunk) => { stderrOutput += chunk.toString(); });
  const [exitCode] = await once(childProcess, "exit");
  assert.notEqual(exitCode, 0);
  assert.match(stderrOutput, /restricted to a loopback host/i);
});

test("slice_stl schema: all BambuStudio slicer options present with correct types and descriptions", async (t) => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_MODEL: "p1s",
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);

  const listToolsResult = await client.listTools();
  const sliceTool = listToolsResult.tools.find((t) => t.name === "slice_stl");
  assert.ok(sliceTool, "slice_stl tool must exist");

  const props = sliceTool.inputSchema?.properties || {};

  // Matrix test: every BambuStudio slicer option must be present, typed correctly,
  // and have a meaningful description.
  for (const [propName, expectedType, descFragment] of BAMBU_SLICER_OPTION_CONTRACTS) {
    assert.ok(
      props[propName],
      `slice_stl must have property "${propName}"`
    );
    assert.equal(
      props[propName].type,
      expectedType,
      `slice_stl.${propName} must be type "${expectedType}", got "${props[propName].type}"`
    );
    assert.ok(
      props[propName].description?.toLowerCase().includes(descFragment),
      `slice_stl.${propName} description must mention "${descFragment}", got: "${props[propName].description}"`
    );
  }

  // Original core params must still be present (regression guard)
  for (const coreParam of ["stl_path", "bambu_model", "slicer_type", "slicer_path", "slicer_profile", "nozzle_diameter"]) {
    assert.ok(props[coreParam], `slice_stl must retain core property "${coreParam}"`);
  }

  // Standalone slicing keeps both file and model requirements explicit.
  assert.equal(sliceTool.inputSchema.required.includes("bambu_model"), true);
  assert.ok(
    sliceTool.inputSchema.required.includes("stl_path"),
    "stl_path must be required"
  );

  // New slicer options must NOT be required (they are all optional)
  for (const [propName] of BAMBU_SLICER_OPTION_CONTRACTS) {
    assert.ok(
      !sliceTool.inputSchema.required?.includes(propName),
      `Slicer option "${propName}" must not be required`
    );
  }
});

test("tool schema invariant: every tool property has a description", async (t) => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_MODEL: "p1s",
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);

  const listToolsResult = await client.listTools();

  // Every tool must have a description, and every property must have a description.
  // This is critical for LLM tool-use (codemode) -- missing descriptions degrade tool selection.
  for (const tool of listToolsResult.tools) {
    assert.ok(
      tool.description && tool.description.length > 10,
      `Tool "${tool.name}" must have a meaningful description`
    );

    const props = tool.inputSchema?.properties || {};
    for (const [propName, propSchema] of Object.entries(props)) {
      assert.ok(
        propSchema.description && propSchema.description.length > 5,
        `${tool.name}.${propName} must have a description (got: "${propSchema.description || ""}")`
      );
    }
  }
});

test("tool schema invariant: input schemas use Codex-compatible root objects", async (t) => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    env: {
      ...process.env,
      MCP_TRANSPORT: "stdio",
      BAMBU_MODEL: "p1s",
    },
    stderr: "pipe",
  });

  const client = createClient();
  t.after(async () => { await closeTransport(transport); });

  await client.connect(transport);

  const listToolsResult = await client.listTools();

  for (const tool of listToolsResult.tools) {
    assert.equal(
      tool.inputSchema?.type,
      "object",
      `${tool.name} input schema root must be an object`
    );
    for (const keyword of ["anyOf", "oneOf", "allOf"]) {
      assert.equal(
        Object.prototype.hasOwnProperty.call(tool.inputSchema || {}, keyword),
        false,
        `${tool.name} input schema root must not use ${keyword}`
      );
    }
  }
});
