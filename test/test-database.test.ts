import { describe, expect, it } from 'vitest'
import { requireTestDatabaseUrl } from '../scripts/test-database'

describe('test database URL guard', () => {
  it.each([
    'postgresql://test:dummy@127.0.0.1:5432/password_manager_test',
    'postgres://test:dummy@[::1]:5433/password_manager_test_run_1',
  ])('accepts a dedicated loopback database', (value) => {
    expect(requireTestDatabaseUrl(value)).toBe(value)
  })

  it.each([
    undefined,
    '',
    'file:/tmp/password_manager_test',
    'postgresql://test:dummy@db.example/password_manager_test',
    'postgresql://test:dummy@127.0.0.1/password_manager',
    'postgresql://test:dummy@127.0.0.1/password_manager_test_backup?schema=other',
    'postgresql://test:dummy@127.0.0.1/password_manager_test?host=db.example',
    'postgresql://test:dummy@127.0.0.1/password_manager_test#',
  ])('rejects missing or unsafe configuration', (value) => {
    expect(() => requireTestDatabaseUrl(value)).toThrow(/^Set TEST_DATABASE_URL/)
  })
})
