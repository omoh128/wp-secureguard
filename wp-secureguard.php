<?php
/**
 * Plugin Name:       WP SecureGuard
 * Plugin URI:        https://omomohwebsite.com/plugin
 * Description:       A lightweight WordPress security plugin that provides essential security features.
 * Version:           1.0.0
 * Requires at least: 5.8  
 * Requires PHP:      7.4 
 * Author:            Omomoh Agiogu
 * Author URI:        https://omomohwebsite.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-secureguard  
 * Domain Path:       /languages        
 * Update URI:        false             
 *
 * @category Stylecss
 * 
 * @package Stylecss
 * 
 * @author Omomoh <omoh128@gmail.com>
 * 
 * @license GPL v2 or later
 * 
 * @link http://url.com
 * PHP 7.4
 */

 defined('ABSPATH') or die('Hey, what are you doing here? You silly human!');

 if(file_exists(dirname(__FILE__) . '/vendor/autoload.php'))
 {
     require_once dirname(__FILE__) . '/vendor/autoload.php';
 }
 
 function activate_wp_secure_guard()
 {
     Inc\Base\Activate::activate();
}
 register_activation_hook(__FILE__, 'activate_wp_secure_guard');
 
 function deactivate_wp_secure_guard()
{
     Inc\Base\Deactivate::deactivate();
 }
 register_deactivation_hook(__FILE__, 'deactivate_wp_secure_guard');
 
 if(class_exists('Inc\\Init'))
 {
     Inc\Init::registerServices();
 }