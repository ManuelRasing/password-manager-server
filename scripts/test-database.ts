const invalidTestDatabaseUrl =
  'Set TEST_DATABASE_URL to a PostgreSQL URL on 127.0.0.1 or [::1] for a dedicated password_manager_test database, without URL options.'

export function requireTestDatabaseUrl(value: string | undefined): string {
  let url: URL
  try {
    url = new URL(value ?? '')
  } catch {
    throw new Error(invalidTestDatabaseUrl)
  }

  if (
    !['postgresql:', 'postgres:'].includes(url.protocol) ||
    !['127.0.0.1', '[::1]'].includes(url.hostname) ||
    !/^\/password_manager_test(?:_[a-z0-9_]{1,41})?$/.test(url.pathname) ||
    url.href.includes('?') ||
    url.href.includes('#')
  ) {
    throw new Error(invalidTestDatabaseUrl)
  }

  return url.href
}
