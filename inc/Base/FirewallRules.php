<?php
/**
 * The Fire wall rule
 *  
 * @category FirewallRules
 * @package  Inc\Base
 * @author   Omomoh <moh128g@email.com>
 * @license  GPL-2.0+ 
 * @link     https://example.com/docs/firewall-rules
 */

namespace Inc\Base;

/**
 * Class FirewallRules
 * 
 * Implements basic WAF (Web Application Firewall) functionality.
 * Blocks malicious IPs and detects suspicious request patterns.
 * 
 * @category Security
 * @package  Inc\Base
 * @author   Omomoh <moh128g@email.com>
 * @license  GPL-2.0+ 
 * @link     https://example.com/docs/firewall-rules
 */
class FirewallRules
{
    private $blocked_ips = []; 
    
    /**
     * Register function
     *
     * @return void
     */
    public function register()
    {
        add_action('init', [$this, 'blockMaliciousIps']);
        add_action('init', [$this, 'detectSuspiciousPatterns']);
    }
    
      /**
       * Block malicious IP addresses function
       *
       * @return void
       */
    public function blockMaliciousIps()
    {
        $client_ip = $this->getClientIp();
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $blocked_ips = get_option('blocked_ips_list', []);
        $this->blocked_ips = get_option('blocked_ips', []);
        
        if (in_array($ip, $blocked_ips) || in_array($ip, $this->blocked_ips)) {
            $message = "Blocked IP attempt from: {$ip}\nTime: " . 
            current_time('mysql');
            $this->logToFile($message);     
            $this->emailAlert($message);    
            
            // Flag for admin notice
            update_option('suspicious_activity_detected', true);
            
            wp_die('Suspicious activity detected. Your request has been blocked.', 'Access Denied', ['response' => 403]);
        }
        
        if ($this->isBlockedIp($client_ip)) {
            $this->logBlockedAttempt($client_ip);
            wp_die('Your IP has been blocked due to suspicious activity.', 'Access Denied', ['response' => 403]);
        }
    }
    
     /**
      *  Detect suspicious patterns function
      *
      * @return void
      */
    public function detectSuspiciousPatterns()
    {
        $patterns = [
            'sql_injection' => "/(select|insert|update|delete|drop|union|--|;
            |#|\bfrom\b|\bwhere\b|\bselect\b|\band\b|\bupdate\b)/i",
            'xss' => "/(<script|<\/script>|<img.*?src.
            *?javascript:|<.*?on\w+\s*=)/i",
            'path_traversal' => "/(\.\.\/|\.\.\\\\|\/etc\/passwd|
            \/windows\/win.ini)/i",
            'file_inclusion' => "/(php:\/\/|data:\/\/
            |expect:\/\/|phar:\/\/|file:\/\/)/i"
        ];
        
        foreach ($_REQUEST as $key => $value) {
            // Skip legitimate WordPress variables
            if (in_array($key, ['s', 'action', 'redirect_to', '_wp_http_referer'])) {
                continue;
            }
            
            if (is_string($value)) {
                foreach ($patterns as $type => $pattern) {
                    if (preg_match($pattern, $value)) {
                        $this->logSuspiciousActivity($type, $key, $value);
                        
                        // Flag for admin notice
                        update_option('suspicious_activity_detected', true);
                        
                        wp_die('Suspicious activity detected. Your request has been blocked.', 'Security Alert', ['response' => 403]);
                    }
                }
            } elseif (is_array($value)) {
                // Recursive check for arrays (like $_POST with nested values)
                $this->checkArrayForPatterns($value, $patterns, $key);
            }
        }
    }
    
    /**
     * Recursively check arrays for suspicious patterns function 
     *
     * @param string $array      The array to check
     * @param string $patterns   Patterns to check for
     * @param string $parent_key The parent key name for logging
     * 
     * @return void
     */
    private function checkArrayForPatterns($array, $patterns, $parent_key = '') {
        foreach ($array as $key => $value) {
            $current_key = $parent_key ? $parent_key . '[' . $key . ']' : $key;
            
            if (is_string($value)) {
                foreach ($patterns as $type => $pattern) {
                    if (preg_match($pattern, $value)) {
                        $this->logSuspiciousActivity($type, $current_key, $value);
                        
                        // Flag for admin notice
                        update_option('suspicious_activity_detected', true);
                        
                        wp_die('Suspicious activity detected. Your request has been blocked.', 'Security Alert', ['response' => 403]);
                    }
                }
            } elseif (is_array($value)) {
                $this->checkArrayForPatterns($value, $patterns, $current_key);
            }
        }
    }
    
    /**
     * Get the real IP address of the client
     * 
     * @return string
     */
    private function getClientIp() 
    {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // Get the first IP in case of multiple proxies
            $ip_list = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return trim($ip_list[0]);
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }
    
    
    /**
     * IP address is blocked function
     *
     * @param boolean $ip Check if the IP address is blocked
     * 
     * @return boolean
     */
    private function isBlockedIp($ip) 
    {
        return in_array($ip, $this->blocked_ips);
    }
    
    
     
     /**
      * Log a blocked IP attempt  function
      *
      * @param string $ip the IP address is blocked attempt

      * @return void
      */
    private function logBlockedAttempt($ip) 
    {
        $log_entry = sprintf("[%s] Blocked IP: %s", date('Y-m-d H:i:s'), $ip);
        $this->logToFile($log_entry);
    }
    
   
     /**
      * Log to the file function
      *
      * @param string $message log file message
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
        
        // Create log file path
        $log_file = trailingslashit($log_dir) . 'firewall.log';
        $timestamp = date('Y-m-d H:i:s');
        $entry = "[{$timestamp}] {$message}" . PHP_EOL;
        
        file_put_contents($log_file, $entry, FILE_APPEND | LOCK_EX);
    }
    
   
     /**
      * Send an email alert for security function
      *
      * @param string $message notifications
      *
      * @return void
      */
    private function emailAlert($message) 
    {
        
        if (!get_option('security_email_alerts', false)) {
            return;
        }
        
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        $subject = sprintf('[%s] Security Alert: Suspicious Activity', $site_name);
        
        wp_mail($admin_email, $subject, $message);
    }
    
   


     /**
      * Log suspicious activity function
      *
      * @param string $type 
      * @param string $key 
      * @param string $value 
      *
      * @return void
      */
    private function logSuspiciousActivity($type, $key, $value) 
    {
        // Sanitize and truncate value for logging
        $safe_value = substr(sanitize_text_field($value), 0, 255);
        
        $log_entry = sprintf("Suspicious %s pattern detected. Key: %s, Value: %s", $type, $key, $safe_value);
        
        $this->logToFile($log_entry);
        $this->emailAlert($log_entry);
    }
}