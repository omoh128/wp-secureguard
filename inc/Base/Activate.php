<?php

/** 
 * The Activate file
 * 
 * @category Activate
 * @package  Activate
 * @author   Omomoh <omoh128@gmail.com>
 * @license  GPL v2 or later
 * @link     http://url.com
 * PHP 7.4
 */
namespace Inc\Base;

/**
 * The Activate class
 * 
 * @category Activate
 * @package  Activate
 * @author   Omomoh <omoh128@gmail.com>
 * @license  GPL v2 or later
 * @link     http://url.com
 */
class Activate
{
    /**
     * Activate function
     *
     * @return void
     */
    public static function activate() 
    {
        flush_rewrite_rules();
    }
}
