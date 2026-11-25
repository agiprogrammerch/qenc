#!/usr/bin/env node
// @ts-check
/**
 * Deterministic, idempotent post-`tauri android init` patch script for QENC.
 *
 * Runs in Phase 5 CI right after `npx tauri android init --ci` and:
 *   1. Enforces minSdk = 24 (Android 7.0), compileSdk = 36, targetSdk = 36 (Android 16).
 *   2. Injects an env-driven release `signingConfig` reading:
 *        QENC_KEYSTORE_PATH, QENC_KEYSTORE_PASSWORD, QENC_KEY_ALIAS, QENC_KEY_PASSWORD
 *      when those vars are present; falls back cleanly (debug/unsigned) otherwise.
 *   3. Ensures `android:enableOnBackInvokedCallback="true"` in AndroidManifest.xml
 *      for Android 13-16 predictive-back compatibility.
 *
 * Pure Node (no npm dependencies). Fails loudly with clear diagnostics if an
 * expected Gradle/Manifest file is missing.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const MIN_SDK = 24;
const COMPILE_SDK = 36;
const TARGET_SDK = 36;
const MARKER = '// >>> QENC_ANDROID_PATCH >>>';
const MARKER_END = '// <<< QENC_ANDROID_PATCH <<<';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const androidAppDir = join(scriptDir, '..', 'src-tauri', 'gen', 'android', 'app');

function fail(message) {
  console.error(`patch-android-project: ${message}`);
  process.exit(1);
}

function locateFiles() {
  const gradleCandidates = [
    join(androidAppDir, 'build.gradle.kts'),
    join(scriptDir, '..', 'src-tauri', 'gen', 'android', 'build.gradle.kts'),
  ];
  const manifestCandidates = [
    join(androidAppDir, 'src', 'main', 'AndroidManifest.xml'),
    join(androidAppDir, 'src', 'main', 'AndroidManifest'),
  ];

  const gradle = gradleCandidates.find((p) => existsSync(p));
  const manifest = manifestCandidates.find((p) => existsSync(p));

  if (!gradle) {
    fail(
      `could not find app build.gradle.kts under src-tauri/gen/android/app/. ` +
        `Did 'npx tauri android init --ci' run before this script?`
    );
  }
  if (!manifest) {
    fail(
      `could not find AndroidManifest.xml under src-tauri/gen/android/app/src/main/. ` +
        `Did 'npx tauri android init --ci' run before this script?`
    );
  }
  return { gradle, manifest };
}

/** Idempotently replace `key = <value>` inside Gradle Kotlin DSL. */
function replaceGradleScalar(src, key, value) {
  // Matches: key = <something up to end of line or closing paren>  (single assignment)
  const re = new RegExp(`(\\b${key}\\s*=\\s*)([^\\n)]+)(\\)?)`, 'g');
  let found = false;
  const out = src.replace(re, (_m, prefix) => {
    found = true;
    return `${prefix}${value})`;
  });
  return { out, found };
}

/** Idempotently replace `key(<value>)` (function-call form used for compileSdk). */
function replaceGradleCall(src, key, value) {
  const re = new RegExp(`(\\b${key}\\s*\\(\\s*)[^)]*?(\\))`, 'g');
  let found = false;
  const out = src.replace(re, (_m, prefix, suffix) => {
    found = true;
    return `${prefix}${value}${suffix}`;
  });
  return { out, found };
}

function patchGradle(original) {
  let src = original;
  if (src.includes(MARKER)) {
    // Already patched: still normalize SDK scalars idempotently below.
    src = src.replace(new RegExp(`${MARKER}[\\s\\S]*?${MARKER_END}\\n?`, 'm'), '');
  }

  for (const [key, val] of [
    ['minSdk', MIN_SDK],
    ['targetSdk', TARGET_SDK],
  ]) {
    const { out, found } = replaceGradleScalar(src, key, val);
    src = out;
    if (!found) console.warn(`patch-android-project: note: '${key}' scalar not found; re-injecting.`);
  }

  // compileSdk may be either `compileSdk = ...` or `compileSdk(...)`.
  const callRes = replaceGradleCall(src, 'compileSdk', COMPILE_SDK);
  if (callRes.found) {
    src = callRes.out;
  } else {
    const scalarRes = replaceGradleScalar(src, 'compileSdk', COMPILE_SDK);
    src = scalarRes.out;
    if (!scalarRes.found) console.warn(`patch-android-project: note: 'compileSdk' not found in template.`);
  }

  // Inject the signing config block idempotently.
  // Gradle's signingConfig handles BOTH `.jks` (JKS) and `.p12`/PKCS12 keystores
  // transparently via storeFile/storePassword/keyAlias/keyPassword. minSdk=24,
  // compileSdk=36 and targetSdk=36 align with the `platforms;android-36` +
  // `build-tools;36.0.0` installed by the release workflow.
  const hasSigningBlock = /signingConfigs\s*\{/.test(src);
  if (!hasSigningBlock) {
    const signing = `
${MARKER}
android {
    signingConfigs {
        create("release") {
            val keystorePath = System.getenv("QENC_KEYSTORE_PATH")
            if (keystorePath != null) {
                storeFile = file(keystorePath)
                storePassword = System.getenv("QENC_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("QENC_KEY_ALIAS")
                keyPassword = System.getenv("QENC_KEY_PASSWORD")
            }
        }
    }
    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
${MARKER_END}
`;
    src += signing;
  }

  return src;
}

function patchManifest(original) {
  let src = original;
  if (src.includes('android:enableOnBackInvokedCallback')) {
    return src;
  }
  // Add the attribute to <application ...> if present, otherwise to <activity ...>, else <manifest ...>.
  if (/<application[\s>]/.test(src)) {
    src = src.replace(/<application(\s)/, '<application android:enableOnBackInvokedCallback="true"$1');
    if (!src.includes('android:enableOnBackInvokedCallback')) {
      // <application> with no attributes yet
      src = src.replace(/<application>/, '<application android:enableOnBackInvokedCallback="true">');
    }
    return src;
  }
  if (/<activity[\s>]/.test(src)) {
    src = src.replace(/<activity(\s)/, '<activity android:enableOnBackInvokedCallback="true"$1');
    return src;
  }
  if (/<manifest[\s>]/.test(src)) {
    src = src.replace(/<manifest(\s)/, '<manifest android:enableOnBackInvokedCallback="true"$1');
    return src;
  }
  console.warn('patch-android-project: note: no <application>/<activity>/<manifest> tag found; manifest left unchanged.');
  return src;
}

// Android 8-16 adaptive icon background: swap Tauri's default #FFFFFF for
// QENC's obsidian base so the mask blends with the dark theme (no white ring).
const ICON_BG_FILE = 'src/main/res/values/ic_launcher_background.xml';

function patchIconBackground() {
  const p = join(androidAppDir, ICON_BG_FILE);
  if (!existsSync(p)) {
    console.log(`patch-android-project: ${ICON_BG_FILE} not found (skipping icon background patch).`);
    return;
  }
  const src = readFileSync(p, 'utf8');
  const patched = src.replace(
    /(ic_launcher_background">)#[0-9A-Fa-f]{3,8}(<\/color>)/g,
    `$1#090d12$2`
  );
  if (patched !== src) {
    writeFileSync(p, patched);
    console.log(`patch-android-project: patched ${ICON_BG_FILE} -> #090d12`);
  } else {
    console.log(`patch-android-project: ${ICON_BG_FILE} already dark.`);
  }
}

function main() {
  const { gradle, manifest } = locateFiles();

  const gradleSrc = readFileSync(gradle, 'utf8');
  const patchedGradle = patchGradle(gradleSrc);
  if (patchedGradle !== gradleSrc) {
    writeFileSync(gradle, patchedGradle);
    console.log(`patch-android-project: patched ${gradle}`);
  } else {
    console.log(`patch-android-project: ${gradle} already up to date`);
  }

  const manifestSrc = readFileSync(manifest, 'utf8');
  const patchedManifest = patchManifest(manifestSrc);
  if (patchedManifest !== manifestSrc) {
    writeFileSync(manifest, patchedManifest);
    console.log(`patch-android-project: patched ${manifest}`);
  } else {
    console.log(`patch-android-project: ${manifest} already up to date`);
  }

  // Adaptive icon background (Android 8-16) -> dark theme.
  patchIconBackground();

  const signingConfigured =
    Boolean(process.env.QENC_KEYSTORE_PATH) &&
    Boolean(process.env.QENC_KEYSTORE_PASSWORD) &&
    Boolean(process.env.QENC_KEY_ALIAS) &&
    Boolean(process.env.QENC_KEY_PASSWORD);
  console.log(
    `patch-android-project: SDK floors -> minSdk=${MIN_SDK}, compileSdk=${COMPILE_SDK}, targetSdk=${TARGET_SDK}; ` +
      `release signing ${signingConfigured ? 'ENABLED' : 'NOT configured (falls back to debug/unsigned)'}.`
  );
}

main();