import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

type Definition = Tool & { method: string; path: string; operation: string; command?: string };
function loadContract(): Definition[] {
  try {
    return JSON.parse(readFileSync(new URL("./workout-tools.json", import.meta.url), "utf8")) as Definition[];
  } catch {
    throw new Error("Workout tool contract is missing; rebuild the MCP package");
  }
}
export const workoutContract = loadContract();
export const workoutTools: Tool[] = workoutContract.map(({name, description, inputSchema}) => ({name, description, inputSchema}));

export async function executeWorkoutTool(name: string, input: Record<string, unknown>, api: (path: string, method?: string, body?: object) => Promise<unknown>): Promise<string | undefined> {
  const definition = workoutContract.find(tool => tool.name === name);
  if (!definition) return undefined;
  const args = {...input};
  let path = definition.path.replace(/\{(\w+)\}/g, (_, key: string) => {
    const value = args[key]; delete args[key];
    if (value === undefined) throw new Error(`${key} is required`);
    return encodeURIComponent(String(value));
  });
  if (definition.operation === "command") args.type = definition.command;
  if (["command", "start_session", "import_session"].includes(definition.operation)) args.client_id ??= randomUUID();
  if (definition.method === "GET") {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(args)) if (value !== undefined && value !== null) query.set(key, String(value));
    if (query.size) path += `?${query}`;
    return JSON.stringify(await api(path), null, 2);
  }
  return JSON.stringify(await api(path, definition.method, args), null, 2);
}
