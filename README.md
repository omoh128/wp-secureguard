
## Installation

1. Upload the plugin to your WordPress site (`wp-content/plugins/`).
2. Run `composer install` if needed.
3. Activate the plugin via the **Plugins** menu in WordPress.

## Configuration

Go to **Settings > Security Settings** in the WordPress dashboard to configure:

- Email alerts toggle
- Two-Factor Authentication
- IP whitelisting
- View suspicious activity logs (future release)

## Requirements

- WordPress 5.0+
- PHP 7.4+
- Composer (for autoloading)

## Development

This plugin uses Composer for autoloading and follows a PSR-4 file structure.

### Run locally

```bash
composer install
