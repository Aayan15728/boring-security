import { test as setup, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL ?? 'https://cobaltgoods.test'

const adminLogin = {
  email: 'admin@cobaltgoods.test',
  password: 'Cobalt-Adm1n-2024!',
}

setup('sign in as the store admin', async ({ page }) => {
  await page.goto(`${BASE_URL}/login`)
  await page.getByLabel('Email').fill(adminLogin.email)
  await page.getByLabel('Password').fill(adminLogin.password)
  await page.getByRole('button', { name: 'Sign in' }).click()

  await expect(page).toHaveURL(/dashboard/)
  await page.context().storageState({ path: 'tests/e2e/.auth/admin.json' })
})
