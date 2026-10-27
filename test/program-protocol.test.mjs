import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

test('packaged MCP discovers program schemas and creates, reads, edits and archives a program', { timeout: 20000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'databody-mcp-test-'));
  const tokenFile = join(directory, 'token.json');
  writeFileSync(tokenFile, JSON.stringify({ access_token: 'test-token' }), { mode: 0o600 });
  const calls = [];
  let saved;
  const api = createServer(async (request, response) => {
    let raw = '';
    for await (const chunk of request) raw += chunk;
    const body = raw ? JSON.parse(raw) : undefined;
    calls.push({ method: request.method, url: request.url, authorization: request.headers.authorization, body });
    response.setHeader('Content-Type', 'application/json');
    if (request.method === 'POST') {
      saved = { ...body, id: 91, revision: 0 };
      response.writeHead(201).end(JSON.stringify(saved));
    } else if (request.method === 'PATCH') {
      saved = { ...saved, ...body, revision: saved.revision + 1 };
      response.end(JSON.stringify(saved));
    } else if (request.method === 'DELETE') {
      response.writeHead(204).end();
    } else {
      response.end(JSON.stringify(saved));
    }
  });
  await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [process.env.DATABODY_MCP_ENTRY || fileURLToPath(new URL('../dist/index.js', import.meta.url))],
    env: { ...process.env, DATABODY_API_URL: `http://127.0.0.1:${api.address().port}`, DATABODY_TOKEN_FILE: tokenFile },
    stderr: 'pipe',
  });
  const client = new Client({ name: 'workout-program-test', version: '1' });
  try {
    await client.connect(transport);
    assert.equal(client.getServerVersion().version, '1.1.0');
    const { tools } = await client.listTools();
    const contract = JSON.parse(readFileSync(new URL('../src/workout-tools.json', import.meta.url), 'utf8'));
    const workoutNames = new Set(contract.map(tool => tool.name));
    assert.deepEqual(tools.filter(tool => workoutNames.has(tool.name)), contract.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })));
    assert.equal(new Set(tools.map(tool => tool.name)).size, tools.length);
    for (const name of ['list_saved_meals', 'create_saved_meal', 'update_saved_meal', 'delete_saved_meal', 'get_recent_workouts', 'create_workout']) {
      assert.ok(tools.some(tool => tool.name === name), `Existing tool missing: ${name}`);
    }
    const create = tools.find(tool => tool.name === 'create_workout_program');
    assert.deepEqual(create.inputSchema.required, ['name', 'days']);
    assert.equal(create.inputSchema.properties.days.items.properties.moves.items.properties.sets.items.properties.rest_seconds.type, 'integer');
    async function call(name, args) {
      const reply = await client.callTool({ name, arguments: args });
      assert.notEqual(reply.isError, true, JSON.stringify(reply));
      return JSON.parse(reply.content[0].text);
    }
    const target = { reps_min: 6, reps_max: 8, weight: 135, rest_seconds: 90 };
    const program = { name: 'Strength', days: [{ id: 'upper-a', name: 'Upper A', moves: [{ id: 'bench', name: 'Bench Press', unit: 'lb', load_basis: 'total', increment: 5, sets: [target, target, target] }] }] };
    const created = await call('create_workout_program', program);
    assert.equal(created.id, 91);
    assert.deepEqual((await call('get_workout_program', { program_id: 91 })).days, program.days);
    const updated = await call('update_workout_program', { program_id: 91, expected_revision: 0, name: 'Strength revised', days: program.days });
    assert.equal(updated.revision, 1);
    assert.deepEqual(await call('archive_workout_program', { program_id: 91, expected_revision: 1 }), { success: true });
    assert.deepEqual(calls.map(call => [call.method, call.url]), [
      ['POST', '/api/v1/workout_programs'], ['GET', '/api/v1/workout_programs/91'],
      ['PATCH', '/api/v1/workout_programs/91'], ['DELETE', '/api/v1/workout_programs/91'],
    ]);
    assert.deepEqual(calls[0].body, program);
    assert.ok(calls.every(call => call.authorization === 'Bearer test-token'));
  } finally {
    await client.close();
    api.closeAllConnections();
    await new Promise(resolve => api.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  }
});
