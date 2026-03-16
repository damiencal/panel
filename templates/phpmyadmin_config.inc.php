<?php
/**
 * phpMyAdmin Configuration - Managed by Hosting Control Panel.
 * Do not edit manually. Changes will be overwritten on panel updates.
 *
 * Authentication is handled via Single Sign-On (signon) from the panel.
 * Users access phpMyAdmin through the panel UI, which generates a secure,
 * time-limited token. The signon.php script validates the token and
 * establishes a session with the MySQL credentials.
 */

/* Blowfish secret for cookie encryption - auto-generated during install */
$cfg['blowfish_secret'] = '{{ blowfish_secret }}';

/* Server configuration */
$i = 0;
$i++;

/* Signon authentication: users are authenticated via the panel */
$cfg['Servers'][$i]['auth_type'] = 'signon';
$cfg['Servers'][$i]['SignonSession'] = 'PMA_single_signon';
$cfg['Servers'][$i]['SignonURL'] = 'signon.php';
$cfg['Servers'][$i]['host'] = 'localhost';
$cfg['Servers'][$i]['compress'] = false;
$cfg['Servers'][$i]['AllowNoPassword'] = false;

/* Prevent direct access without going through the panel signon flow */
$cfg['Servers'][$i]['AllowDeny']['order'] = 'deny,allow';
$cfg['Servers'][$i]['AllowDeny']['rules'] = [];

/* Directories for import/export */
$cfg['UploadDir'] = '';
$cfg['SaveDir'] = '';

/* Security settings */
$cfg['LoginCookieValidity'] = 1800;       /* 30-minute session */
$cfg['LoginCookieStore'] = 0;             /* Session cookie only */
$cfg['LoginCookieDeleteAll'] = true;
$cfg['CheckConfigurationPermissions'] = false;
$cfg['ExecTimeLimit'] = 300;

/* Disable version check (managed by system packages) */
$cfg['VersionCheck'] = false;

/* Disable access to the phpMyAdmin configuration storage (not needed) */
$cfg['Servers'][$i]['pmadb'] = '';

/* Temporary directory for phpMyAdmin caching */
$cfg['TempDir'] = '/tmp/phpmyadmin';

/* Display settings */
$cfg['ShowDatabasesNavigationAsTree'] = true;
$cfg['MaxNavigationItems'] = 250;
$cfg['NavigationTreeEnableGrouping'] = true;

/* Theme */
$cfg['ThemeDefault'] = 'pmahomme';
