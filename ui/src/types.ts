// TypeScript types mirroring Rust IPC payloads
// IMPORTANT: All keys must EXACTLY match the camelCase JSON produced by
// src-tauri/src/lib.rs (every Rust DTO uses #[serde(rename_all = "camelCase")]).

export interface QencMetadata {
  version: number;
  keyMode: 'passphrase' | 'hybridPqc';
  compressionProfile: 'turbo' | 'balanced' | 'ultra';
  chunkSize: number;
  originalSize: number;
  argon2Params?: Argon2Params;
  ephemeralX25519Pk?: number[];
  mlkemCiphertext?: number[];
}

export interface Argon2Params {
  mCostKib: number;
  tCost: number;
  pCost: number;
}

export interface ProgressEvent {
  stage: ProgressStage;
  percent: number;
  bytesProcessed: number;
  totalBytes?: number;
  outputBytes: number;
  elapsedMs: number;
  mbPerSec: number;
}

export type ProgressStage =
  | 'Archiving'
  | 'Compressing'
  | 'Encrypting'
  | 'Decrypting'
  | 'Decompressing'
  | 'Extracting'
  | 'Finalizing';

export interface InspectResponse {
  metadata: QencMetadata;
  fileSize: number;
}

export interface EncryptRequest {
  inputs: string[];
  output: string;
  mode: 'passphrase' | 'hybridPqc';
  profile: 'turbo' | 'balanced' | 'ultra';
  passphrase?: string;
  recipientPubkeyPath?: string;
}

export interface DecryptRequest {
  input: string;
  output: string;
  passphrase?: string;
  secretKeyPath?: string;
  secretKeyPassphrase?: string;
}

export interface OperationSummary {
  outputSize: number;
  compressionRatioPercent: number;
  elapsedMs: number;
  avgMbPerSec: number;
  outputPath?: string;
}

export interface DefaultPaths {
  encryptedDir: string;
  decryptedDir: string;
  keysDir: string;
}

export interface KeygenRequest {
  outputDir: string;
  namePrefix: string;
  passphrase?: string;
}

export interface KeygenSummary {
  publicKeyPath: string;
  secretKeyPath: string;
  fingerprint: string;
}

export interface SystemInfo {
  platform: 'linux' | 'windows' | 'android' | 'macos' | 'ios' | 'unknown';
  isMobile: boolean;
  recommendedArgon2Profile: 'desktop' | 'mobile';
  engineVersion: string;
}

export interface Toast {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
  duration?: number;
}

export interface FileItem {
  path: string;
  name: string;
  size: number;
  isDirectory: boolean;
}

export interface InputPathInfo {
  path: string;
  name: string;
  sizeBytes: number;
  isDir: boolean;
  fileCount: number;
}

export interface InspectInputPathsRequest {
  paths: string[];
}