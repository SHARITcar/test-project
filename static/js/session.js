/**
 * Shared session/token storage for SHARIT.
 *
 * "Blijf ingelogd" (remember me) stores the access + refresh token in
 * localStorage with a 30-day boundary; otherwise they live in
 * sessionStorage and disappear when the tab closes. Supabase access
 * tokens expire after ~1 hour regardless of that choice, so authFetch()
 * transparently uses the refresh token to renew an expired session
 * before falling back to the caller's normal 401 handling.
 */
(function (global) {
  'use strict';

  var TOKEN_KEY = 'session_token';
  var REFRESH_KEY = 'session_refresh_token';
  var EXPIRES_KEY = 'session_expires_at';
  var THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

  function safeGet(storage, key) {
    try {
      return storage.getItem(key);
    } catch (e) {
      return null;
    }
  }

  function safeSet(storage, key, value) {
    try {
      storage.setItem(key, value);
    } catch (e) { /* storage unavailable (private mode, quota, ...) */ }
  }

  function safeRemove(storage, key) {
    try {
      storage.removeItem(key);
    } catch (e) { /* ignore */ }
  }

  function getAccessToken() {
    return safeGet(window.localStorage, TOKEN_KEY) || safeGet(window.sessionStorage, TOKEN_KEY);
  }

  function getRefreshToken() {
    return safeGet(window.localStorage, REFRESH_KEY) || safeGet(window.sessionStorage, REFRESH_KEY);
  }

  function activeStorage() {
    return safeGet(window.localStorage, TOKEN_KEY) ? window.localStorage : window.sessionStorage;
  }

  function clear() {
    [window.localStorage, window.sessionStorage].forEach(function (storage) {
      safeRemove(storage, TOKEN_KEY);
      safeRemove(storage, REFRESH_KEY);
      safeRemove(storage, EXPIRES_KEY);
    });
  }

  function store(accessToken, refreshToken, rememberMe) {
    clear();
    var storage = rememberMe ? window.localStorage : window.sessionStorage;
    safeSet(storage, TOKEN_KEY, accessToken || '');
    if (refreshToken) {
      safeSet(storage, REFRESH_KEY, refreshToken);
    }
    if (rememberMe) {
      safeSet(storage, EXPIRES_KEY, String(Date.now() + THIRTY_DAYS_MS));
    }
  }

  function isRememberedSessionExpired() {
    var raw = safeGet(window.localStorage, EXPIRES_KEY);
    if (!raw) return false;
    return Date.now() > Number(raw);
  }

  var refreshPromise = null;

  function refreshAccessToken() {
    if (refreshPromise) return refreshPromise;

    var refreshToken = getRefreshToken();
    if (!refreshToken || isRememberedSessionExpired()) {
      clear();
      return Promise.resolve(null);
    }

    refreshPromise = fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
      .then(function (response) {
        return response.json().catch(function () { return {}; }).then(function (payload) {
          if (!response.ok || !payload.data || !payload.data.access_token) {
            clear();
            return null;
          }
          var storage = activeStorage();
          safeSet(storage, TOKEN_KEY, payload.data.access_token);
          if (payload.data.refresh_token) {
            safeSet(storage, REFRESH_KEY, payload.data.refresh_token);
          }
          return payload.data.access_token;
        });
      })
      .catch(function () {
        return null;
      })
      .then(function (result) {
        refreshPromise = null;
        return result;
      });

    return refreshPromise;
  }

  function authFetch(path, options) {
    options = options || {};
    var baseHeaders = options.headers || {};

    function withAuth(token) {
      var headers = {};
      Object.keys(baseHeaders).forEach(function (key) { headers[key] = baseHeaders[key]; });
      headers.Authorization = 'Bearer ' + (token || '');
      return headers;
    }

    return fetch(path, Object.assign({}, options, { headers: withAuth(getAccessToken()) }))
      .then(function (response) {
        if (response.status !== 401) {
          return response;
        }
        return refreshAccessToken().then(function (newToken) {
          if (!newToken) {
            return response;
          }
          return fetch(path, Object.assign({}, options, { headers: withAuth(newToken) }));
        });
      });
  }

  global.SharitSession = {
    getAccessToken: getAccessToken,
    getRefreshToken: getRefreshToken,
    store: store,
    clear: clear,
    authFetch: authFetch,
  };
})(window);
