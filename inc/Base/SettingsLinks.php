<?php
/** 
 * The setting links file
 * 
 * @category SettingsLinks
 * @package  SettingsLinks
 * @author   Omomoh <omoh128@email.com>
 * @license  GPL v2 or later
 * @link     http://url.com 
 */
namespace Inc\Base;
/**
 * The SettingsLinks class
 * 
 * @category SettingsLinks
 * @package  SettingsLinks
 * @author   Omomoh <omoh128@email.com>
 * @license  GPL v2 or later
 * @link     http://url.com 
 */
class SettingsLinks
{
    /**
     * The register function
     *
     * @return void
     */
    public function register()
    {
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'addSettingsLink']);
    }

    /**
     * The add settings link function
     *
     * @param string $links setting link 
     * 
     * @return void
     */
    public function addSettingsLink($links) 
    {
        $settings_link = '<a href="admin.php?page=wp-secure-guard">Settings</a>';
        array_push($links, $settings_link);
        return $links;
    }
}
