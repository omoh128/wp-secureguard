<?php

/**
 * The Two factor auth file
 * 
 * @category TwoFactorAuth
 * 
 * @package TwoFactorAuth
 * 
 * @author Omomoh <omoh128@gmail.com>
 * 
 * @license GPL-2.0  http://gpl-2.0.com
 * 
 * @link http://url.com
 * PHP:7.4 
 */

namespace Inc\Base;

/**
 * This pages
 * 
 * @category Base
 * 
 * @package Inc\Base;
 * 
 * @author Omomoh <omoh128@gmail.com>
 * 
 * @license GPL-2.0  http://gpl-2.0.com
 * 
 * @link http://url.com
 * PHP:7.4 
 */
class TwoFactorAuth
{
    /**
     * The register function
     *
     * @return void
     */
    public function register() 
    {
        if (get_option('security_2fa')) {
            add_filter('authenticate', [$this, 'interceptLogin'], 30, 3);
            add_action('login_form', [$this, 'maybeShow2FAPrompt']);
        }
    }
    
     /**
      * Undocumented function
      *
      * @param array $user     the user id
      * @param array $username the username
      * @param array $password the password

      * @return void
      */
    public function interceptLogin($user, $username, $password)
    {
        if (!isset($_POST['otp_code'])) {
            // Delay actual login and show 2FA prompt
            $_SESSION['temp_user'] = compact('username', 'password');
            wp_redirect(add_query_arg('2fa', '1', wp_login_url()));
            exit;
        }
        return $user;
    }

    /**
     * The may be show prompt function
     *
     * @return void
     */
    public function maybeShow2FAPrompt()
    {
        if (isset($_GET['2fa']) && $_GET['2fa'] == '1' && isset($_SESSION['temp_user'])) {
            $otp = rand(100000, 999999);
            $_SESSION['otp_code'] = $otp;
            $admin_email = get_option('admin_email');
            wp_mail($admin_email, 'Your 2FA Code', "Your code is: {$otp}");

            echo '<p>Please enter the verification code sent to your email:</p>';
            echo '<form method="post" action="' . esc_url(wp_login_url()) . '">';
            echo '<input type="text" name="otp_code" placeholder="Enter Code" required />';
            echo '<input type="submit" value="Verify" />';
            echo '</form>';
            exit;
        }

        if (isset($_POST['otp_code']) && $_POST['otp_code'] == $_SESSION['otp_code']) {
            $creds = $_SESSION['temp_user'];
            unset($_SESSION['otp_code'], $_SESSION['temp_user']);
            wp_signon($creds);
            wp_redirect(admin_url());
            exit;
        }
    }
}
