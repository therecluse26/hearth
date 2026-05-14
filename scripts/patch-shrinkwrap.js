#!/usr/bin/env node
// Removes npm-shrinkwrap.json files bundled by plenum and reflex-search so that
// the root package.json overrides can pin their transitive deps to safe floors.
// Runs as a postinstall hook: after the initial extraction (which delivers the
// shrinkwrap files), we delete them and delete their nested node_modules, then
// npm re-resolves those sub-trees obeying the root overrides.
// Without this, overrides have no effect because published shrinkwrap files
// take precedence over root-level npm overrides.

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const packages = ['plenum', 'reflex-search'];

let needsReinstall = false;

for (const pkg of packages) {
  const pkgDir = path.join(root, 'node_modules', pkg);
  const shrinkwrap = path.join(pkgDir, 'npm-shrinkwrap.json');
  const nestedModules = path.join(pkgDir, 'node_modules');

  if (fs.existsSync(shrinkwrap)) {
    fs.rmSync(shrinkwrap);
    fs.rmSync(nestedModules, { recursive: true, force: true });
    needsReinstall = true;
  }
}

if (needsReinstall) {
  // Delete the lockfile so npm recalculates the full tree from scratch.
  // With no shrinkwrap constraints, the root overrides block will apply.
  const lockfile = path.join(root, 'package-lock.json');
  if (fs.existsSync(lockfile)) {
    fs.rmSync(lockfile);
  }

  execSync('npm install --ignore-scripts', { cwd: root, stdio: 'inherit' });
}
