import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomUUID, createHash } from "node:crypto";

export type Role = "admin" | "analyst" | "readonly";

export interface StoredKey {
  id: string;
  hashedKey: string;
  name: string;
  role: Role;
  createdAt: string;
}

const KEY_FILE = join(homedir(), ".aegis", "keys.json");

function hashKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

function ensureKeyFile(): void {
  const dir = join(homedir(), ".aegis");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  if (!existsSync(KEY_FILE)) {
    writeFileSync(KEY_FILE, "[]", "utf-8");
  }
}

function readKeys(): StoredKey[] {
  ensureKeyFile();
  try {
    return JSON.parse(readFileSync(KEY_FILE, "utf-8")) as StoredKey[];
  } catch {
    return [];
  }
}

function writeKeys(keys: StoredKey[]): void {
  ensureKeyFile();
  writeFileSync(KEY_FILE, JSON.stringify(keys, null, 2), "utf-8");
}

export function createKey(name: string, role: Role): { id: string; key: string } {
  const keys = readKeys();
  const id = randomUUID();
  const rawKey = `aegis_${randomUUID().replace(/-/g, "")}`;

  keys.push({
    id,
    hashedKey: hashKey(rawKey),
    name,
    role,
    createdAt: new Date().toISOString(),
  });

  writeKeys(keys);
  return { id, key: rawKey };
}

export function validateKey(rawKey: string): StoredKey | null {
  const hashed = hashKey(rawKey);
  const keys = readKeys();
  return keys.find((k) => k.hashedKey === hashed) ?? null;
}

export function listKeys(): Omit<StoredKey, "hashedKey">[] {
  return readKeys().map(({ hashedKey: _, ...rest }) => rest);
}

export function deleteKey(id: string): boolean {
  const keys = readKeys();
  const filtered = keys.filter((k) => k.id !== id);
  if (filtered.length === keys.length) return false;
  writeKeys(filtered);
  return true;
}
