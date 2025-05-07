<?php

/**
 * The Admin settings
 * * @category Admin
 * @package  Core
 * @author   Omomoh <omoh128@gmail.com>
 * @license  GPL-2.0  http://gpl-2.0.com
 * @link     https://example.com/docs/login-security
 * * PHP:7.4 
 */

 namespace Inc\Pages;


class AdminSettings
{
    private $active_tab;
    const BLOCKED_IPS_OPTION_NAME = 'blocked_ips'; // Define as a constant for easier reuse

    public function register() 
    {
        add_action('admin_menu', [$this, 'addAdminMenu']);
        add_action('admin_init', [$this, 'registerSettings']);
        // Add an earlier hook for processing actions on the blocked IPs tab, if needed before headers are sent
        // For this specific GET-based removal, handling it within manageBlockedIPsContent is fine.
        // add_action('admin_init', [$this, 'handleBlockedIpActions']); 
        add_action('admin_notices', [$this, 'showSuspiciousActivityNotice']);
        add_action('admin_enqueue_scripts', [$this, 'enqueueAdminStylesAndScripts']);
    }

    public function addAdminMenu()
    {
        add_options_page(
            'Security Settings',
            'Security Settings',
            'manage_options',
            'security_settings', // This is the page slug
            [$this, 'settingsPageContent']
        );
    }

    public function registerSettings() 
    {
        register_setting('security_settings_group', 'security_email_alerts');
        register_setting('security_settings_group', 'security_2fa');
        register_setting('security_settings_group', 'login_security_max_attempts', ['type' => 'integer','default' => 5,'sanitize_callback' => 'absint']);
        register_setting('security_settings_group', 'login_security_lockout_duration', ['type' => 'integer','default' => 30,'sanitize_callback' => 'absint']);
        register_setting('security_settings_group', 'login_security_notifications', ['type' => 'boolean','default' => false]);
        
        register_setting('security_settings_group', 'login_security_captcha_enable', ['type' => 'boolean','default' => false]);
        register_setting('security_settings_group', 'login_security_captcha_after_attempts', ['type' => 'integer','default' => 2,'sanitize_callback' => 'absint']);

        // Use the constant for the option name
        register_setting('security_settings_group', self::BLOCKED_IPS_OPTION_NAME, ['type' => 'array','sanitize_callback' => [$this, 'sanitizeBlockedIPs']]);

        add_settings_section('security_main_section', 'Security Features', null, 'security_settings');

        add_settings_field('security_email_alerts', 'Enable Email Alerts', [$this, 'emailAlertsCallback'], 'security_settings', 'security_main_section');
        add_settings_field('security_2fa', 'Enable Two-Factor Authentication', [$this, 'twoFactorCallback'], 'security_settings', 'security_main_section');
        add_settings_field('login_security_max_attempts', 'Maximum Login Attempts', [$this, 'maxAttemptsCallback'], 'security_settings', 'security_main_section');
        add_settings_field('login_security_lockout_duration', 'Lockout Duration (minutes)', [$this, 'lockoutDurationCallback'], 'security_settings', 'security_main_section');
        
        add_settings_field('login_security_captcha_enable', 'Enable Login CAPTCHA', [$this, 'captchaEnableCallback'], 'security_settings', 'security_main_section');
        add_settings_field('login_security_captcha_after_attempts', 'Show CAPTCHA After Attempts', [$this, 'captchaAfterAttemptsCallback'], 'security_settings', 'security_main_section');

        add_settings_section('security_ip_section', 'IP Blocking', null, 'security_settings');
        add_settings_field(self::BLOCKED_IPS_OPTION_NAME, 'Blocked IP Addresses (add new)', [$this, 'blockedIpsCallback'], 'security_settings', 'security_ip_section');
    }

    public function emailAlertsCallback() 
    {
        $enabled = get_option('security_email_alerts');
        echo '<input type="checkbox" name="security_email_alerts" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">Send email notifications for security events</p>';
    }

    public function twoFactorCallback()
    {
        $enabled = get_option('security_2fa');
        echo '<input type="checkbox" name="security_2fa" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">Require two-factor authentication for admin users</p>';
    }

    public function maxAttemptsCallback() 
    {
        $value = get_option('login_security_max_attempts', 5);
        echo '<input type="number" min="1" max="20" name="login_security_max_attempts" value="' . esc_attr($value) . '" />';
        echo '<p class="description">Number of failed attempts before locking out an IP address.</p>';
    }

    public function lockoutDurationCallback() 
    {
        $value = get_option('login_security_lockout_duration', 30);
        echo '<input type="number" min="5" max="1440" name="login_security_lockout_duration" value="' . esc_attr($value) . '" />';
        echo '<p class="description">How long an IP will be locked out after too many failed attempts (in minutes).</p>';
    }

    public function captchaEnableCallback()
    {
        $enabled = get_option('login_security_captcha_enable');
        echo '<input type="checkbox" name="login_security_captcha_enable" value="1" ' . checked(1, $enabled, false) . ' />';
        echo '<p class="description">Enable CAPTCHA on the login form after a specified number of failed attempts.</p>';
    }

    public function captchaAfterAttemptsCallback()
    {
        $value = get_option('login_security_captcha_after_attempts', 2);
        $max_attempts = get_option('login_security_max_attempts', 5);
        $input_max = $max_attempts > 1 ? $max_attempts - 1 : 1; 

        echo '<input type="number" min="1" max="' . esc_attr($input_max) . '" name="login_security_captcha_after_attempts" value="' . esc_attr($value) . '" />';
        echo '<p class="description">Show CAPTCHA after this many failed login attempts. Must be less than "Maximum Login Attempts".</p>';
    }

    public function blockedIpsCallback() 
    {
        // Use the constant
        $blocked_ips = get_option(self::BLOCKED_IPS_OPTION_NAME, []);
        $blocked_ips_str = implode("\n", $blocked_ips);
        // Ensure the name attribute matches the registered setting
        echo '<textarea name="' . self::BLOCKED_IPS_OPTION_NAME . '" rows="5" cols="40" class="large-text code">' . esc_textarea($blocked_ips_str) . '</textarea>';
        echo '<p class="description">Enter one IP address per line. These IPs will be permanently blocked. Manage existing blocked IPs under the "Blocked IPs" tab.</p>';
    }

    public function sanitizeBlockedIPs($input) 
    {
        if (empty($input)) {
            return [];
        }

        $ips = explode("\n", $input);
        $sanitized_ips = [];

        foreach ($ips as $ip) {
            $ip = trim($ip);
            if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                $sanitized_ips[] = $ip;
            }
        }
        // Ensure unique IPs if desired, though sanitizeBlockedIPs is primarily for validation
        // $sanitized_ips = array_unique($sanitized_ips);
        return $sanitized_ips;
    }

    public function settingsPageContent()
    {
        $this->active_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'settings';
        ?>
        <div class="wrap">
            <h1>Security Settings</h1>

            <nav class="nav-tab-wrapper">
                <a href="?page=security_settings&tab=settings" class="nav-tab <?php echo $this->active_tab === 'settings' ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-shield"></span> Settings
                </a>
                <a href="?page=security_settings&tab=login_logs" class="nav-tab <?php echo $this->active_tab === 'login_logs' ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-analytics"></span> Login Logs
                </a>
                <a href="?page=security_settings&tab=firewall_logs" class="nav-tab <?php echo $this->active_tab === 'firewall_logs' ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-shield-alt"></span> Firewall Logs
                </a>
                <a href="?page=security_settings&tab=blocked_ips" class="nav-tab <?php echo $this->active_tab === 'blocked_ips' ? 'nav-tab-active' : ''; ?>">
                    <span class="dashicons dashicons-dismiss"></span> Blocked IPs
                </a>
            </nav>

            <div class="tab-content">
                <?php
                switch ($this->active_tab) {
                    case 'login_logs':
                        $this->displayLoginLogs();
                        break;
                    case 'firewall_logs':
                        $this->displayFirewallLogs();
                        break;
                    case 'blocked_ips':
                        $this->manageBlockedIPsContent(); // Call the new method for this tab
                        break;
                    case 'settings':
                    default:
                        $this->displaySettingsTab();
                        break;
                }
                ?>
            </div>
        </div>
        <?php
    }

    private function displaySettingsTab()
    {
        ?>
        <form method="post" action="options.php">
            <?php
            settings_fields('security_settings_group');
            do_settings_sections('security_settings');
            submit_button();
            ?>
        </form>
        <?php
    }

    public function displayLoginLogs() 
    {
        $uploadDir = wp_upload_dir();
        $logFile = trailingslashit($uploadDir['basedir']) . 'security-logs/login_attempts.log';

        echo '<h2>Login Attempt Logs</h2>';

        if (file_exists($logFile)) {
            $logs = file_get_contents($logFile);
            echo '<pre style="background: #f5f5f5; padding: 20px; border: 1px solid #ccc; max-height: 500px; overflow-y: auto;">';
            echo esc_html($logs);
            echo '</pre>';
        } else {
            echo '<p>No log file found.</p>';
        }
    }

    public function displayFirewallLogs() 
    {
        $uploadDir = wp_upload_dir();
        $logFile = trailingslashit($uploadDir['basedir']) . 'security-logs/firewall.log';

        echo '<h2>Firewall Logs</h2>';

        if (file_exists($logFile)) {
            $logs = file_get_contents($logFile);
            echo '<pre style="background: #f5f5f5; padding: 20px; border: 1px solid #ccc; max-height: 500px; overflow-y: auto;">';
            echo esc_html($logs);
            echo '</pre>';
        } else {
            echo '<p>No firewall log file found.</p>';
        }
    }

    /**
     * Handles the content and actions for the "Blocked IPs" tab.
     * Allows viewing and removing individual blocked IPs.
     */
    public function manageBlockedIPsContent()
    {
        echo '<h2>Manage Blocked IPs</h2>';

        // Handle IP removal action
        // Ensure current user has capabilities to manage options
        if (isset($_GET['action']) && $_GET['action'] === 'remove_ip' && isset($_GET['ip_to_remove']) && current_user_can('manage_options')) {
            $ip_to_remove = sanitize_text_field(wp_unslash($_GET['ip_to_remove']));
            // Nonce name should be unique to the action and item if possible
            $nonce_action = 'security_remove_ip_' . $ip_to_remove; 

            if (isset($_GET['_wpnonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), $nonce_action)) {
                $blocked_ips = get_option(self::BLOCKED_IPS_OPTION_NAME, []);

                $key = array_search($ip_to_remove, $blocked_ips);
                if ($key !== false) {
                    unset($blocked_ips[$key]);
                    $blocked_ips = array_values($blocked_ips); // Re-index array
                    update_option(self::BLOCKED_IPS_OPTION_NAME, $blocked_ips);
                    // Add admin notice for success
                    add_action('admin_notices', function() use ($ip_to_remove) {
                        echo '<div class="notice notice-success is-dismissible"><p>IP address ' . esc_html($ip_to_remove) . ' removed successfully from the blocklist.</p></div>';
                    });
                } else {
                     add_action('admin_notices', function() use ($ip_to_remove) {
                        echo '<div class="notice notice-warning is-dismissible"><p>IP address ' . esc_html($ip_to_remove) . ' not found in the blocklist.</p></div>';
                    });
                }
            } else {
                // Nonce verification failed
                add_action('admin_notices', function() {
                    echo '<div class="notice notice-error is-dismissible"><p>Security check failed (Nonce mismatch). Could not remove IP.</p></div>';
                });
            }
            // It's good practice to display notices hooked to 'admin_notices'
            // To ensure they appear in the standard WordPress way. We will call do_action here for immediate display.
            do_action('admin_notices');
        }

        // Display the list of blocked IPs
        $current_blocked_ips = get_option(self::BLOCKED_IPS_OPTION_NAME, []);

        if (!empty($current_blocked_ips)) {
            echo '<p>The following IPs are currently blocked. You can remove them individually here.</p>';
            echo '<table class="wp-list-table widefat striped fixed" style="margin-top:20px;">';
            echo '<thead><tr><th scope="col" class="manage-column">IP Address</th><th scope="col" class="manage-column">Action</th></tr></thead>';
            echo '<tbody id="the-list">';

            foreach ($current_blocked_ips as $ip) {
                if (empty($ip)) continue; // Skip if an empty entry somehow got in

                // Define the nonce action string for this specific IP's removal link
                $remove_nonce_action = 'security_remove_ip_' . $ip;
                // The base URL for options pages is options-general.php.
                // The 'page' query arg is the slug you defined in add_options_page.
                $base_remove_url = admin_url('options-general.php'); 
                $remove_link_args = [
                    'page'         => 'security_settings', // Your settings page slug
                    'tab'          => 'blocked_ips',
                    'action'       => 'remove_ip',
                    'ip_to_remove' => $ip, // urlencode not strictly needed here as add_query_arg handles it, but doesn't hurt
                ];
                // Create a nonce and add it to the URL
                $remove_link = wp_nonce_url(add_query_arg($remove_link_args, $base_remove_url), $remove_nonce_action, '_wpnonce');

                echo '<tr>';
                echo '<td>' . esc_html($ip) . '</td>';
                echo '<td><a href="' . esc_url($remove_link) . '" class="button button-secondary">Remove</a></td>';
                echo '</tr>';
            }
            echo '</tbody>';
            echo '</table>';
        } else {
            echo '<p>No IPs are currently blocked.</p>';
        }
        echo '<p style="margin-top: 20px;">You can add new IPs to the blocklist via the <a href="' . esc_url(admin_url('options-general.php?page=security_settings&tab=settings')) . '">Settings tab</a> under the "IP Blocking" section.</p>';
    }


    public function showSuspiciousActivityNotice()
    {
        if (get_transient('security_suspicious_activity_detected')) {
            echo '<div class="notice notice-error is-dismissible"><p><strong>Suspicious login attempt detected!</strong> Check the <a href="?page=security_settings&tab=login_logs">logs</a>.</p></div>';
            delete_transient('security_suspicious_activity_detected');
        }
    }

    public function enqueueAdminStylesAndScripts($hook)
    {
        if ($hook !== 'settings_page_security_settings') { 
            return;
        }
        wp_enqueue_style('security-admin-style', plugin_dir_url(dirname(__DIR__)) . 'assets/css/admin-security.css', [], '1.0.0');
        wp_enqueue_script('security-admin-script', plugin_dir_url(dirname(__DIR__)) . 'assets/js/admin.js', ['jquery'], '1.0.0', true);
    }
}