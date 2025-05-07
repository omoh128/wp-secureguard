<?php
/**
 * The Deactivate file
 * 
 * @category Deactivate
 * @package  Deactivate
 * @author   Omomoh <omoh128@gmail.com>
 * @license  GPL-2.0  
 * @link     https://example.com/docs/deactivate
 */

namespace Inc\Base;

/**
 * The Deactivate class
 * 
 * @category Deactivate
 * @package  Deactivate
 * @author   Omomoh <omoh128@gmail.com>
 * @license  GPL v2 or later
 * @link     https://example.com/docs/deactivate
 */
class Deactivate
{
    /**
     * Deactivate function
     *
     * @return void
     */
    public static function deactivate()
    {
        flush_rewrite_rules();
    }
}
