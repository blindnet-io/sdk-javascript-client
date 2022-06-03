import { PlaywrightTestConfig } from '@playwright/test';

const config: PlaywrightTestConfig = {
  testDir: 'integration-tests',
  timeout: 30000,

  use: {
    // Configure browser and context here
  },
};
export default config;