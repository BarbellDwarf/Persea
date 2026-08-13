/**
 * Global setup for the screenshot suite: complete the setup wizard if
 * needed, authenticate (reusing the main suite's login), then seed the
 * instance. Seeding AFTER the login matters — the login itself writes a real
 * audit row with a live timestamp, and the seeded rows must be the only data
 * in the frame.
 */
import { FullConfig } from '@playwright/test';
import { execSync } from 'child_process';
import baseSetup from '../global-setup';

export default async function globalSetup(config: FullConfig): Promise<void> {
  execSync('npx tsx setup-helper.ts', {
    cwd: process.cwd(),
    stdio: 'inherit',
    env: process.env,
  });
  await baseSetup(config);
  console.log('[screenshots] seeding deterministic data…');
  execSync('npx tsx screenshots/seed.ts', {
    cwd: process.cwd(),
    stdio: 'inherit',
    env: process.env,
  });
}
