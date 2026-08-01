/**
 * Centralized CSS selectors extracted from static/*.html.
 * One source of truth — update here when HTML IDs/classes change.
 */

// ── Shared across all pages ──
export const SHARED = {
  brandRow: '.brand-row',
  siteLogo: '#site-logo',
  siteTitle: 'h1',

  nav: 'nav',
  navConnections: 'nav a[href="/connections.html"]',
  navSessions: 'nav a[href="/sessions.html"]',
  navRecordings: 'nav a[href="/recordings.html"]',
  navReports: 'nav a[href="/reports.html"]',
  navDocs: 'nav a[href="/docs.html"]',
  navTokens: 'nav a[href="/tokens.html"]',
  navAdmin: 'nav a[href="/admin.html"]',
  navLogout: '#logout-item',
  navSettingsBtn: '#user-menu-btn',
  navSettingsMenu: '#user-menu',

  userMenuWrapper: '#user-menu-wrapper',
  userMenuThemeList: '#um-theme-list',
} as const;

// ── sessions.html ──
export const SESSIONS_PAGE = {
  ...SHARED,

  sessionForm: '#session-form',
  newSessionToggle: '#new-session-toggle',
  newSessionArrow: '#new-session-arrow',
  newSessionFields: '#new-session-fields',
  sessionType: '#session-type',
  connectBtn: '#connect-btn',
  error: '#error',
  adhocNotice: '#adhoc-notice',

  // SSH fields
  sshFields: '#ssh-fields',
  hostname: '#hostname',
  port: '#port',
  username: '#username',
  password: '#password',
  generateKeypair: '#generate-keypair',
  privateKeyField: '#private-key-field',
  privateKey: '#private-key',

  // RDP fields
  rdpFields: '#rdp-fields',
  rdpHostname: '#rdp-hostname',
  rdpPort: '#rdp-port',
  rdpUsername: '#rdp-username',
  rdpPassword: '#rdp-password',
  rdpDomain: '#rdp-domain',
  rdpSecurity: '#rdp-security',
  rdpIgnoreCert: '#rdp-ignore-cert',

  // VNC fields
  vncFields: '#vnc-fields',
  vncHostname: '#vnc-hostname',
  vncPort: '#vnc-port',
  vncPassword: '#vnc-password',

  // Web fields
  webFields: '#web-fields',
  url: '#url',

  // VDI fields
  vdiFields: '#vdi-fields',
  vdiImage: '#vdi-image',

  // Jump hosts
  jumpSection: '#jump-section',
  jumpToggle: '#jump-toggle',
  jumpArrow: '#jump-arrow',
  jumpFields: '#jump-fields',
  hopsList: '#hops-list',
  addHopBtn: '#add-hop-btn',
  flowDiagram: '#flow-diagram',

  // Banner
  banner: '#banner',

  // Session list
  sessions: '#sessions',
  sessionCounts: '#session-counts',
  sessionList: '#session-list',
  sessionEmpty: '#session-empty',
} as const;

// ── connections.html ──
export const CONNECTIONS_PAGE = {
  ...SHARED,

  globalError: '#global-error',
  noVault: '#no-vault',
  vaultUnavailable: '#vault-unavailable',
  emptyState: '#empty-state',
  btnEmptyCreateFolder: '#btn-empty-create-folder',
  mainContent: '#main-content',

  // Credentials banner
  credsBanner: '#creds-banner',
  credsBannerText: '#creds-banner-text',
  credsBannerSetup: '#creds-banner-setup',
  credsBannerDismiss: '#creds-banner-dismiss',

  // Active sessions
  activeSessions: '#active-sessions',
  activeSessionsCount: '#active-sessions-count',
  activeSessionsGrid: '#active-sessions-grid',

  // Sidebar
  sidebar: '.sidebar',
  sidebarHeader: '.sidebar-header',
  btnNewFolder: '#btn-new-folder',
  folderList: '#folder-list',

  // Main content area
  entriesHeader: '#entries-header',
  entriesTitle: '#entries-title',
  entriesDesc: '#entries-desc',
  connectionsSearch: '#connections-search',
  btnNewEntry: '#btn-new-entry',
  btnNewSubfolder: '#btn-new-subfolder',
  btnEditFolder: '#btn-edit-folder',
  btnDeleteFolder: '#btn-delete-folder',
  entriesContent: '#entries-content',

  // Folder modal
  folderModal: '#folder-modal',
  folderModalTitle: '#folder-modal-title',
  fmName: '#fm-name',
  fmDesc: '#fm-desc',
  fmGroupsPicker: '#fm-groups-picker',
  fmGroupsChips: '#fm-groups-chips',
  fmGroupsInput: '#fm-groups-input',
  fmGroupsMenu: '#fm-groups-menu',
  fmGroupsAdd: '#fm-groups-add',
  fmInherit: '#fm-inherit',
  fmScope: '#fm-scope',
  fmError: '#fm-error',
  fmSave: '#fm-save',
  fmCancel: '#fm-cancel',

  // Entry modal
  entryModal: '#entry-modal',
  entryModalTitle: '#entry-modal-title',
  emName: '#em-name',
  emDisplayName: '#em-display-name',
  emType: '#em-type',

  // SSH entry fields
  emSshFields: '#em-ssh-fields',
  emHostname: '#em-hostname',
  emPort: '#em-port',
  emUsername: '#em-username',
  emPassword: '#em-password',
  emPrivateKey: '#em-private-key',
  emSshPromptCreds: '#em-ssh-prompt-creds',

  // RDP entry fields
  emRdpFields: '#em-rdp-fields',
  emRdpHostname: '#em-rdp-hostname',
  emRdpPort: '#em-rdp-port',
  emRdpUsername: '#em-rdp-username',
  emRdpPassword: '#em-rdp-password',
  emRdpDomain: '#em-rdp-domain',
  emRdpSecurity: '#em-rdp-security',
  emRdpIgnoreCert: '#em-rdp-ignore-cert',
  emRdpAuthPkg: '#em-rdp-auth-pkg',
  emRdpMonitors: '#em-rdp-monitors',
  emRdpPromptCreds: '#em-rdp-prompt-creds',

  // VNC entry fields
  emVncFields: '#em-vnc-fields',
  emVncHostname: '#em-vnc-hostname',
  emVncPort: '#em-vnc-port',
  emVncPassword: '#em-vnc-password',
  emVncColorDepth: '#em-vnc-color-depth',
  emVncPromptCreds: '#em-vnc-prompt-creds',

  // SPICE entry fields
  emSpiceFields: '#em-spice-fields',

  // Proxmox entry fields
  emProxmoxFields: '#em-proxmox-fields',

  // Web entry fields
  emWebFields: '#em-web-fields',
  emUrl: '#em-url',
  emBanner: '#em-banner',
  emAutomationToggle: '#em-automation-toggle',
  emAutomationFields: '#em-automation-fields',
  emWebUsername: '#em-web-username',
  emWebPassword: '#em-web-password',
  emLoginScript: '#em-login-script',

  // VDI entry fields
  emVdiFields: '#em-vdi-fields',
  emVdiImage: '#em-vdi-image',

  // RemoteApp
  emRemoteappSection: '#em-remoteapp-section',
  emRemoteappToggle: '#em-remoteapp-toggle',
  emRemoteApp: '#em-remote-app',
  emRemoteAppDir: '#em-remote-app-dir',
  emRemoteAppArgs: '#em-remote-app-args',

  // Drive
  emDriveSection: '#em-drive-section',
  emEnableDrive: '#em-enable-drive',

  // Recording
  emRecordingSection: '#em-recording-section',
  emRecordingToggle: '#em-recording-toggle',
  emOverrideRecording: '#em-override-recording',
  emEnableRecording: '#em-enable-recording',
  emMaxRecordings: '#em-max-recordings',

  // Video Performance
  emVideoPerfSection: '#em-video-perf-section',
  emEnableGfx: '#em-enable-gfx',
  emEnableH264: '#em-enable-h264',
  emEnableWallpaper: '#em-enable-wallpaper',

  // Clipboard
  emDisableCopy: '#em-disable-copy',
  emDisablePaste: '#em-disable-paste',

  // SSH Tunnel / Jump hosts
  emTunnelSection: '#em-tunnel-section',
  emTunnelToggle: '#em-tunnel-toggle',
  emHopsList: '#em-hops-list',
  emAddHop: '#em-add-hop',

  // Sharing
  emAllowSharing: '#em-allow-sharing',

  // Save/Cancel
  emSave: '#em-save',
  emCancel: '#em-cancel',
  emError: '#em-error',

  // My Credentials
  myCredsNav: '#my-creds-nav',
  myCredsItem: '#my-creds-item',
  showTourItem: '#show-tour-item',
} as const;

// ── recordings.html ──
export const RECORDINGS_PAGE = {
  ...SHARED,

  playerSection: '#player-section',
  playerHeader: '#player-header',
  playerTitle: '#player-title',
  playerClose: '#player-close',
  playerDisplay: '#player-display',
  playerControls: '#player-controls',
  playBtn: '#play-btn',
  seekContainer: '#seek-container',
  histogram: '#histogram',
  seekSlider: '#seek-slider',
  playerTime: '#player-time',

  recSearch: '#rec-search',
  recordingList: '#recording-list',
  recPagination: '#rec-pagination',

  typescriptSection: '#typescript-section',
  typescriptPath: '#typescript-path',
  typescriptList: '#typescript-list',
  typescriptPagination: '#typescript-pagination',
} as const;

// ── admin.html ──
export const ADMIN_PAGE = {
  ...SHARED,

  systemStatus: '#system-status',
  ssVersion: '#ss-version',
  ssActive: '#ss-active',
  ssSessionsDetail: '#ss-sessions-detail',
  ssUsers: '#ss-users',
  ssHistory: '#ss-history',
  ssRecordings: '#ss-recordings',
  ssRecDetail: '#ss-rec-detail',
  ssDisk: '#ss-disk',
  ssVault: '#ss-vault',
  ssFeatures: '#ss-features',

  usersTable: '#users-table',
  usersBody: '#users-body',

  mappingsTable: '#mappings-table',
  mappingsBody: '#mappings-body',
  newGroup: '#new-group',
  newRole: '#new-role',
  addMappingBtn: '#add-mapping-btn',

  tokensTable: '#tokens-table',
  tokensBody: '#tokens-body',
  noTokens: '#no-tokens',
  tokenEmail: '#token-email',
  tokenName: '#token-name',
  tokenMaxRole: '#token-max-role',
  tokenExpires: '#token-expires',
  adminCreateTokenBtn: '#admin-create-token-btn',
  adminTokenReveal: '#admin-token-reveal',
  adminTokenPlaintext: '#admin-token-plaintext',
  adminCopyTokenBtn: '#admin-copy-token-btn',
  adminDismissTokenBtn: '#admin-dismiss-token-btn',

  auditTable: '#audit-table',
  auditBody: '#audit-body',
  noAudit: '#no-audit',
  auditEmailFilter: '#audit-email-filter',
  auditFilterBtn: '#audit-filter-btn',

  abAuditTable: '#ab-audit-table',
  abAuditBody: '#ab-audit-body',
  noAbAudit: '#no-ab-audit',
  abAuditEmailFilter: '#ab-audit-email-filter',
  abAuditFilterBtn: '#ab-audit-filter-btn',

  error: '#error',
} as const;

// ── tokens.html ──
export const TOKENS_PAGE = {
  ...SHARED,

  loading: '#loading',
  noPermission: '#no-permission',

  createSection: '#create-section',
  createForm: '#create-form',
  tokenName: '#token-name',
  tokenMaxRole: '#token-max-role',
  tokenExpires: '#token-expires',
  createBtn: '#create-btn',
  tokenReveal: '#token-reveal',
  tokenPlaintext: '#token-plaintext',
  copyTokenBtn: '#copy-token-btn',
  dismissTokenBtn: '#dismiss-token-btn',

  tokensSection: '#tokens-section',
  tokensBody: '#tokens-body',
  noTokens: '#no-tokens',

  error: '#error',
} as const;

// ── client.html (Guacamole session display) ──
export const CLIENT_PAGE = {
  disconnectedOverlay: '#disconnected-overlay',
  disconnectedBox: '#disconnected-box',
  disconnectedTitle: '#disconnected-title',
  disconnectedMessage: '#disconnected-message',
  btnReconnect: '#btn-reconnect',
  btnCloseSession: '#btn-close-session',

  bannerOverlay: '#banner-overlay',
  bannerBox: '#banner-box',
  bannerText: '#banner-text',
  bannerContinue: '#banner-continue',

  status: '#status',
  display: '#display',

  fsBar: '#fs-bar',
  fsBarTitle: '#fs-bar-title',
  fsExit: '#fs-exit',
  fsDisconnect: '#fs-disconnect',
  fsEscNotice: '#fs-esc-notice',
} as const;

// ── index.html (login) ──
export const LOGIN_PAGE = {
  ssoSection: '#sso-section',
  ssoBtn: '#sso-btn',
  apiKeyToggle: '#api-key-toggle',
  apiKeyChevron: '#api-key-chevron',
  loginForm: '#login-form',
  apiKey: '#api-key',
  loginBtn: '#login-btn',
  error: '#error',
} as const;
