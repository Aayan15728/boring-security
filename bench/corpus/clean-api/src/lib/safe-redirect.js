'use strict';

// Only same-site absolute paths are allowed: "/x" yes, "//evil.test", "/\\evil.test" and "https://..." no.
function safeRedirect(target, fallback = '/') {
  if (typeof target !== 'string') return fallback;
  if (!target.startsWith('/') || target.startsWith('//') || target.startsWith('/\\')) return fallback;
  if (/[\r\n]/.test(target)) return fallback;
  return target;
}

module.exports = { safeRedirect };
