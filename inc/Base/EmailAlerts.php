<?php
/**
 * Email alert file
 * PHP 7.4
 * 
 * @category EmailAlerts
 * @package  EmailAlerts
 * @author   Omomoh <omoh128@gmail.com>
 * @license  GPL-2.0 or later
 * 
 * @link http://url.com  
 */
namespace Inc\Base;

/**
 * EmailAlerts class
 * 
 * @category EmailAlerts
 * @package  EmailAlerts
 * @author   Omomoh <omoh128@gmail.com>
 * @license  GPL-2.0 
 * @link     http://url.com
 */
class EmailAlerts
{
    /**
     * Register function
     *
     * @return void
     */
    public function register() 
    {
        if (get_option('security_email_alerts')) {
            add_action('wp_login_failed', [$this, 'sendLoginFailureAlert'], 10, 1);
        }
    }
    
    /**
     * Send Login failure alert function
     *
     * @param string $username the user name
     * 
     * @return void
     */
    public function sendLoginFailureAlert($username)
    {
        $admin_email = get_option('admin_email');
        $subject = '🚨 Failed Login Attempt Detected';
        $message = "There was a failed login attempt on your WordPress site.\n\nUsername used: {$username}\nTime: " . current_time('mysql');
        wp_mail($admin_email, $subject, $message);
    }
}
