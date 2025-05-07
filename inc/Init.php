<?php
namespace Inc;

final class Init 
 {
    public static function getServices() {
        return [
            Base\LoginSecurity::class,
            Base\FirewallRules::class,
            Base\SettingsLinks::class,
            Base\EmailAlerts::class,
            Base\TwoFactorAuth::class,
            Base\SecurityNotices::class,
            Pages\AdminSettings::class,

        ];
    }

    public static function registerServices() {
        foreach (self::getServices() as $class) {
            $service = self::instantiate($class);
            if (method_exists($service, 'register')) {
                $service->register();
            }
        }
    }

    private static function instantiate($class) {
        return new $class();
    }
}
