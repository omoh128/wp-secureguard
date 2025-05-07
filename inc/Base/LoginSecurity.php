<?php
/**
 * Login security
 * 
 * @category Loginsecurity
 * 
 * @package Inc\Base
 * @author  Omomoh <omoh128@gmail.com>
 * @license GPL-2.0+ 
 * 
 * @link https://example.com/docs/login-security
 */

namespace Inc\Base;

/**
 * Loginsecurity class
 * 
 * Implements brute force protection for WordPress login.
 * Tracks login attempts, blocks IPs after too many failed attempts,
 * and provides settings configuration in the admin.
 * 
 * @category Security
 * @package  Inc\Base
 * @author   Omomoh <omoh128@gmail.com>
 * @license  GPL-2.0+ 
 * @link     https://example.com/docs/login-security
 */
class LoginSecurity
{
    private $max_attempts = 5; 
    private $lockout_duration = 1800; 
    private $transient_prefix = 'login_attempts_';
    private $lockout_transient_prefix = 'login_lockout_';
    private $blocked_ips = []; 
    
    

    /**
     * Function function
     *
     * @return void
     */
    public function register() 
    {
        add_action('login_init', [$this, 'checkLoginAttempts']);
        add_action('login_init', [$this, 'blockMaliciousIps']);
        add_action('wp_login_failed', [$this, 'failedLogin']);
        add_action('wp_login', [$this, 'successfulLogin'], 10, 2);
        add_filter('authenticate', [$this, 'checkIfUserIsLocked'], 30, 3);
        
        // Add custom admin page for settings
        add_action('admin_menu', [$this, 'addSettingsPage']);
        add_action('admin_init', [$this, 'registerSettings']);
    }




   
    /**
     * Checking log attempt function
     *
     * @return void
     */
    public function checkLoginAttempts() 
    {
        // Get the user's IP address
        $user_ip = $this->getUserIP();
        
        // Check if the user is locked out
        $lockout = get_transient($this->lockout_transient_prefix . $user_ip);
        
        if ($lockout) {
            // Calculate remaining lockout time
            $time_left = ceil($lockout - time()) / 60;
            
            // Display error message and prevent login
            wp_die(
                sprintf(
                    '<h1>%s</h1><p>%s</p><p>%s</p>',
                    'Too many failed login attempts',
                    'Your IP has been temporarily blocked due to too many failed login attempts.',
                    sprintf('Please try again in %d minutes.', $time_left)
                ),
                'Login Locked',
                ['response' => 403]
            );
        }
    }
     
    /**
     * Failed login function
     *
     * @param string $username the user name
     * 
     * @return void
     */
    public function failedLogin($username)
    {
        // Get user IP
        $user_ip = $this->getUserIP();
        
        // Get current login attempts for this IP
        $attempts = get_transient($this->transient_prefix . $user_ip);
        $attempts = $attempts ? $attempts : 0;
        $attempts++;
        
        if ($attempts >= $this->max_attempts) {
            // Lock the user out
            set_transient(
                $this->lockout_transient_prefix . $user_ip,
                time() + $this->lockout_duration,
                $this->lockout_duration
            );
            
            // Log the lockout
            $this->logLockout($user_ip, $username);
            
            // Reset attempts counter
            delete_transient($this->transient_prefix . $user_ip);
        } else {
            // Update attempts counter
            set_transient(
                $this->transient_prefix . $user_ip,
                $attempts,
                DAY_IN_SECONDS // Store for 24 hours
            );
        }
        
        // Log the failed attempt
        $this->logFailedAttempt($user_ip, $username, $attempts);
    }

    
    /**
     * SuccessfulLogin function
     *
     * @param string $username 
     * @param string $user 
     * 
     * @return void
     */
    public function successfulLogin($username, $user) 
    {
        // Clear failed login attempts on successful login
        $user_ip = $this->getUserIP();
        delete_transient($this->transient_prefix . $user_ip);
    }
    
     /**
      * Check if the user has already been authenticated function
      *
      * @param array $user     the user id
      * @param array $username the user name
      * @param array $password the password
      *
      * @return void
      */
    public function checkIfUserIsLocked($user, $username, $password)
    {
        // Don't check if the user has already been authenticated
        if ($user instanceof \WP_User) {
            return $user;
        }
        
        // Get user IP
        $user_ip = $this->getUserIP();
        
        // Check if the user is locked out
        $lockout = get_transient($this->lockout_transient_prefix . $user_ip);
        
        if ($lockout) {
            // Return error
            return new \WP_Error(
                'too_many_attempts',
                sprintf(
                    '<strong>ERROR</strong>: Too many failed login attempts. Please try again in %d minutes.',
                    ceil(($lockout - time()) / 60)
                )
            );
        }
        
        return $user;
    }
    
    /**
     * GetUserIP function
     *
     * @return void
     */
    private function getUserIP() 
    {
        // Get the most reliable IP address
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // Get the first IP in case of multiple proxies
            $ip_list = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ip_list[0]);
        } else {
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        }
        
        return sanitize_text_field($ip);
    }
    
   
    /**
     * Alias for getUserIP to maintain compatibility with both methods
     *
     * @return void
     */
    private function getClientIp() 
    {
        return $this->getUserIP();
    }
     /**
      * Log failed attempt function
      *
      * @param array $ip       user ip address
      * @param array $username user name
      * @param array $attempts 

      * @return void
      */
    private function logFailedAttempt($ip, $username, $attempts)
    {
        
        error_log(sprintf('Failed login attempt for user %s from IP %s (Attempt #%d)', $username, $ip, $attempts));
    }
    
    /**
     * Log the lockout function
     *
     * @param string $ip       ip address
     * @param string $username user name
     * 
     * @return void
     */
    private function logLockout($ip, $username) 
    {
        
        error_log(sprintf('IP %s has been locked out after failed login attempts for user %s', $ip, $username));
        
        // Optional: Send admin notification for lockouts
        $this->sendLockoutNotification($ip, $username);
    }
    
    /**
     * Notifications function
     *
     * @param string $ip       user ip
     * @param string $username user name
     * 
     * @return void
     */
    private function sendLockoutNotification($ip, $username) 
    {
        // Check if notifications are enabled (you can add this as a setting)
        if (!get_option('login_security_notifications', false)) {
            return;
        }
        
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        $subject = sprintf('[%s] Login Lockout Notification', $site_name);
        
        $message = sprintf(
            "IP address %s has been locked out after %d failed login attempts for username: %s.\n\n" .
            "Time: %s\n" .
            "Site: %s\n",
            $ip,
            $this->max_attempts,
            $username,
            date('Y-m-d H:i:s'),
            home_url()
        );
        
        wp_mail($admin_email, $subject, $message);
    }
    
    /**
     * Add Settings Page function
     *
     * @return void
     */
    public function addSettingsPage() 
    {
        add_options_page(
            'Login Security Settings',
            'Login Security',
            'manage_options',
            'login-security-settings',
            [$this, 'renderSettingsPage']
        );
    }
    /**
     * Render Settings Page function
     *
     * @return void
     */
    public function renderSettingsPage()
    {
        ?>
        <div class="wrap">
            <h1>Login Security Settings</h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('login_security_settings');
                do_settings_sections('login-security-settings');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }
    
    /**
     * Register Settings function
     *
     * @return void
     */
    public function registerSettings()
    {
        register_setting('login_security_settings', 'login_security_max_attempts', ['type' => 'integer','default' => 5,'sanitize_callback' => 'absint',]);
        
        register_setting('login_security_settings', 'login_security_lockout_duration', ['type' => 'integer','default' => 30,'sanitize_callback' => 'absint',]);
        
        register_setting('login_security_settings', 'login_security_notifications', ['type' => 'boolean','default' => false,'sanitize_callback' => function ($input) {return (bool) $input;},]);
        
        add_settings_section(
            'login_security_main_section',
            'Brute Force Protection Settings',
            function () {
                echo '<p>Configure the login security settings to protect your site from brute force attacks.</p>';
            },
            'login-security-settings'
        );
        
        add_settings_field(
            'login_security_max_attempts',
            'Maximum Login Attempts',
            function () {
                $value = get_option('login_security_max_attempts', 5);
                echo '<input type="number" min="1" max="20" name="login_security_max_attempts" value="' . esc_attr($value) . '" />';
                echo '<p class="description">Number of failed attempts before locking out an IP address.</p>';
            },
            'login-security-settings',
            'login_security_main_section'
        );
        
        add_settings_field(
            'login_security_lockout_duration',
            'Lockout Duration (minutes)',
            function () {
                $value = get_option('login_security_lockout_duration', 30);
                echo '<input type="number" min="5" max="1440" name="login_security_lockout_duration" value="' . esc_attr($value) . '" />';
                echo '<p class="description">How long an IP will be locked out after too many failed attempts.</p>';
            },
            'login-security-settings',
            'login_security_main_section'
        );
        
        add_settings_field(
            'login_security_notifications',
            'Email Notifications',
            function () {
                $value = get_option('login_security_notifications', false);
                echo '<input type="checkbox" name="login_security_notifications" value="1" ' . checked(1, $value, false) . ' />';
                echo '<p class="description">Send email notifications to admin when an IP is locked out.</p>';
            },
            'login-security-settings',
            'login_security_main_section'
        );
        
        add_settings_section(
            'login_security_ip_section',
            'IP Blocking Settings',
            function () {
                echo '<p>Manage permanently blocked IP addresses.</p>';
            },
            'login-security-settings'
        );
        
        add_settings_field(
            'blocked_ips',
            'Blocked IP Addresses',
            function () {
                $blocked_ips = get_option('blocked_ips', []);
                $blocked_ips_str = implode("\n", $blocked_ips);
                echo '<textarea name="blocked_ips" rows="5" cols="40" class="large-text code">' . esc_textarea($blocked_ips_str) . '</textarea>';
                echo '<p class="description">Enter one IP address per line. These IPs will be permanently blocked.</p>';
            },
            'login-security-settings',
            'login_security_ip_section'
        );
        
        register_setting('login_security_settings', 'blocked_ips', ['type' => 'array','sanitize_callback' => function ($input) {if(empty($input)) {return [];}
                
                $ips = explode("\n", $input);
                $sanitized_ips = [];
                
                foreach ($ips as $ip) {
                    $ip = trim($ip);
                    if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                        $sanitized_ips[] = $ip;
                    }
                }
                
                return $sanitized_ips;
            },
        ]);
    }
    
    /**
     * Block Malicious Ips function against ant attacker
     *
     * @return void
     */
    public function blockMaliciousIps()
    {
        $client_ip = $this->getClientIp();
        $blocked_ips = get_option('blocked_ips_list', []);
        $this->blocked_ips = get_option('blocked_ips', []);
        
        // Combine both blocked IP lists
        $all_blocked_ips = array_merge($blocked_ips, $this->blocked_ips);
        
        if (in_array($client_ip, $all_blocked_ips)) {
            $message = "Blocked IP attempt from: {$client_ip}\nTime: " . current_time('mysql');
            $this->logToFile($message);     // log it
            $this->emailAlert($message);    // email it
            wp_die('Suspicious activity detected. Your request has been blocked.', 'Access Denied', ['response' => 403]);
        }

        if ($this->isBlockedIp($client_ip)) {
            $this->logBlockedAttempt($client_ip);
            wp_die('Your IP has been blocked due to suspicious activity.', 'Access Denied', ['response' => 403]);
        }
    }
    /**
     * Check if IP is in permanent block list function
     *
     * @param string $ip the user ip check if IP is in permanent block list
     * 
     * @return boolean
     */
    private function isBlockedIp($ip)
    {
        
        if (in_array($ip, $this->blocked_ips)) {
            return true;
        }
        
        return false;
    }
    /**
     * Undocumented function
     *
     * @param string $ip
     * @return void
     */
    private function logBlockedAttempt($ip) 
    {
        $message = "Blocked access attempt from IP: {$ip}\nTime: " . current_time('mysql');
        $this->logToFile($message);
        $this->emailAlert($message);
    }
    /**
     * Log to file function
     *
     * @param string $message message
     * 
     * @return void
     */
    private function logToFile($message)
    {
        $upload_dir = wp_upload_dir();
        $log_dir = trailingslashit($upload_dir['basedir']) . 'security-logs';
        
        if (!file_exists($log_dir)) {
            wp_mkdir_p($log_dir);
        }
        
        
        $log_file = trailingslashit($log_dir) . 'login_attempts.log';
        $message = "[" . current_time('mysql') . "] " . $message . "\n";
        
        
        file_put_contents($log_file, $message, FILE_APPEND);
    }
    
    /**
     * Check if email notifications are enabled function
     *
     * @param string $message message
     * 
     * @return void
     */
    private function emailAlert($message) 
    {
        
        if (!get_option('login_security_notifications', false)) {
            return;
        }
        
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        $subject = sprintf('[%s] Security Alert: Blocked IP', $site_name);
        
        wp_mail($admin_email, $subject, $message);
    }
    
    /**
     *  Initialize settings from the database function
     *
     * @return void
     */
    public function init()
    {
        
        $this->max_attempts = get_option('login_security_max_attempts', $this->max_attempts);
        $this->lockout_duration = get_option('login_security_lockout_duration', 30) * 60; // Convert to seconds
        $this->blocked_ips = get_option('blocked_ips', []);
    }
}