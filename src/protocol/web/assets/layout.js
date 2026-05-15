// Alpine.js component registrations and global UI behaviours for the
// Hearth admin layout. Loaded as an external script so the
// Content-Security-Policy can omit 'unsafe-inline' for script-src.

document.addEventListener('alpine:init', () => {
  Alpine.data('withLoading', (message) => ({
    submitting: false,
    loadingMessage: message || 'Loading\u2026',
    submit() { this.submitting = true; }
  }));

  // Sidebar realm tree. Fetches realms once at mount, derives the
  // current realm from the URL path (`/ui/admin/realms/{name}/...`)
  // per UI_ROUTING.md R-1, so the matching subtree auto-expands and
  // highlights. Subpage URLs are built path-first; `{realm}` is
  // substituted by the active realm slug.
  Alpine.data('realmNav', (activePage) => ({
    loading: true,
    realms: [],
    currentRealm: '',
    activePage: activePage || '',
    subPages: [
      { key: 'users',            label: 'Users',            href: '/ui/admin/realms/{realm}/users' },
      { key: 'organizations',    label: 'Organizations',    href: '/ui/admin/realms/{realm}/organizations' },
      { key: 'groups',           label: 'Groups',           href: '/ui/admin/realms/{realm}/groups' },
      { key: 'applications',     label: 'Applications',     href: '/ui/admin/realms/{realm}/applications' },
      { key: 'sessions',         label: 'Sessions',         href: '/ui/admin/realms/{realm}/sessions' },
      { key: 'audit',            label: 'Audit Log',        href: '/ui/admin/realms/{realm}/audit' },
      { key: 'rbac_permissions', label: 'Permissions',      href: '/ui/admin/realms/{realm}/rbac/permissions' },
      { key: 'rbac_roles',       label: 'Roles',            href: '/ui/admin/realms/{realm}/rbac/roles' },
      { key: 'rbac_scopes',      label: 'Scopes',           href: '/ui/admin/realms/{realm}/rbac/scopes' },
      { key: 'rbac_debug',       label: 'Permission Check', href: '/ui/admin/realms/{realm}/rbac/debug' },
    ],
    deriveCurrentRealm() {
      // URL shape: /ui/admin/realms/{name}[/...]
      // Anything else (dashboard, settings, admin-users) returns ''.
      const m = window.location.pathname.match(/^\/ui\/admin\/realms\/([^\/?#]+)(?:\/|$)/);
      return m ? decodeURIComponent(m[1]) : '';
    },
    async load() {
      this.currentRealm = this.deriveCurrentRealm();
      try {
        const res = await fetch('/ui/admin/api/nav/realms', { credentials: 'same-origin' });
        if (res.ok) {
          const data = await res.json();
          this.realms = data.realms || [];
        }
      } catch (e) {
        // Silently degrade — sidebar tree is non-essential.
      } finally {
        this.loading = false;
      }
    },
  }));
});

// Wire HTMX HX-Trigger "showToast" events into Alpine's custom event system
document.body.addEventListener('showToast', function(e) {
  var d = typeof e.detail === 'string' ? JSON.parse(e.detail) : e.detail;
  window.dispatchEvent(new CustomEvent('show-toast', {detail: d}));
});

// -------------------------------------------------------------------
// Global keyboard shortcuts. We bind on `keydown` so the captured
// key is reliable cross-browser, and bail when focus is in any
// text-bearing control or contenteditable region — otherwise '/'
// would steal keystrokes from the very inputs we want to focus.
//   /   focus the page-level search box (`#page-search`)
//   c   click the primary CTA on the page (`#primary-cta`)
//   ?   open the shortcut overlay
// -------------------------------------------------------------------
(function () {
  function inEditable(el) {
    if (!el) return false;
    if (el.isContentEditable) return true;
    var tag = (el.tagName || '').toLowerCase();
    if (tag === 'input') {
      var t = (el.type || 'text').toLowerCase();
      // Allow shortcuts when focus is in non-text inputs (checkboxes,
      // buttons, etc.) — only swallow when typing.
      return ['text','search','email','password','number','tel','url','date','datetime-local','time','month','week'].indexOf(t) !== -1;
    }
    return tag === 'textarea' || tag === 'select';
  }

  window.__hearthShortcutHelpOpen = false;
  document.addEventListener('keydown', function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (inEditable(e.target)) return;
    switch (e.key) {
      case '/': {
        var search = document.getElementById('page-search');
        if (search) {
          e.preventDefault();
          search.focus();
          search.select && search.select();
        }
        break;
      }
      case 'c': {
        var cta = document.getElementById('primary-cta');
        if (cta) {
          e.preventDefault();
          cta.click();
        }
        break;
      }
      case '?': {
        e.preventDefault();
        window.dispatchEvent(new CustomEvent('hearth-shortcut-help'));
        break;
      }
      case 'Escape': {
        window.dispatchEvent(new CustomEvent('hearth-shortcut-help-close'));
        break;
      }
      default: break;
    }
  });
})();
