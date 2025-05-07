<?php

/**
 * The security notice file
 * 
 * @category SecurityNotices
 * @package  SecurityNotices
 * @author   Omomoh <omoh128@gmail.com>
 * @license  GPL v2 or late
 * @link     http://url.com
 */
namespace Inc\Base;
 /**
  * The security notice class
  *
  * @category SecurityNotices
  * @package  SecurityNotices
  * @author   Omomoh <omoh128@gmail.com>
  * @license  GPL v2 or late
  * @link     http://url.com
  */
class SecurityNotices
{
    
    /**
     * The register function
     *
     * @return void
     */
    public function register() 
    {
        add_action('admin_notices', [$this, 'checkFileEditing']);
    }

    /**
     * Check if file editing is enabled 
     * 
     * @return void
     */
    public function checkFileEditing() 
    {
        if (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT === false) {
            echo '<div class="notice notice-warning is-dismissible">
                    <p><strong>Warning:</strong> File editing from the admin panel is enabled. This can be a security risk. Consider disabling it by setting <code>DISALLOW_FILE_EDIT</code> to <code>true</code> in <code>wp-config.php</code>.</p>
                  </div>';
        }
    }
}
