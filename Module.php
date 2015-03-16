<?php

namespace ZF2AuthWordpress;

use Zend\Json\Server\Smd\Service;
use Zend\Mvc\MvcEvent;
use Zend\ServiceManager\ServiceManager;
use ZF2AuthWordpress\Library\PasswordHash;
use Zend\Authentication\Adapter\DbTable\CallbackCheckAdapter;
use Zend\Authentication\Result as AuthenticationResult;
use Zend\Stdlib\ArrayUtils;

class Module
{
    public function getAutoloaderConfig()
    {
        return [
            'Zend\Loader\StandardAutoloader' => [
                'namespaces' => [
                    __NAMESPACE__ => __DIR__ . '/src/' . __NAMESPACE__,
                ],
            ],
        ];
    }

    public function getConfig()
    {
        return [];
    }

    public function getServiceConfig()
    {
        return [
            'factories' => [
                'zf2authwordpress\config' => [$this, 'factory_zf2authwordpress_config'],
                'auth_adapter_wordpress' => [$this, 'factory_auth_adapter_wordpress'],
                'wp_hasher' => [$this, 'factory_passwordhash']
            ]
        ];
    }

    public function factory_passwordhash(ServiceManager $sm)
    {
        $wp_hasher = new PasswordHash(8, true); // current Wordpress settings
        $wp_hasher->PasswordHash(8, true);
        return $wp_hasher;
    }

    public function factory_zf2authwordpress_config(ServiceManager $sm)
    {
        $cfg = $sm->get('config');

        if (!isset($cfg['zf2authwordpress\config'])) {
            $cfg['zf2authwordpress\config'] = array();
        }
        $cfg_options = $cfg['zf2authwordpress\config'];

        $defaults = array(
            'prefix' => 'wp_',
        );

        return ArrayUtils::merge($defaults, $cfg_options);
    }

    public function factory_auth_adapter_wordpress(ServiceManager $sm)
    {
        /** @var \Zend\Db\Adapter\Adapter $db */
        $db = $sm->get('Zend\Db\Adapter\Adapter');

        $config = $sm->get('zf2authwordpress\config');

        $adapter = new CallbackCheckAdapter($db);
        $callable = [$this, 'wp_authenticate'];

        $adapter->setTableName($config['prefix'] . 'users');
        $adapter->setIdentityColumn('user_login');
        $adapter->setCredentialColumn('user_pass');
        $adapter->setCredentialValidationCallback(function ($hash, $password) use ($sm, $callable) {
            return call_user_func($callable, $hash, $password, $sm);
        });
        return $adapter;
    }

    public function wp_authenticate($hash, $password, ServiceManager $sm)
    {
//        define('AUTH_SALT',        '=G~86 ^.N$CD>7UGQT<&btZ(q+H/uC=Z3%E,VX:bV/`Pfsy)6p5+6F^a!}+vX|1_');
//        define('SECURE_AUTH_SALT', '0/A!S+4T#-P!VMMY,DI7[)LK7I2<JF`7ZfH];4J|iyDfqR52@wZeKKT+^_xA0MN,');
        /** @var PasswordHash $wp_hasher */
//        $wp_hasher = $sm->get(PasswordHash::class);
        $wp_hasher = $sm->get('wp_hasher');
        $hash2 = $wp_hasher->HashPassword( trim($password));

        $result = $wp_hasher->CheckPassword($password, $hash);
        $result2 = $wp_hasher->CheckPassword($password, $hash2);
        \Zend\Debug\Debug::dump($password);
        \Zend\Debug\Debug::dump($hash);
        \Zend\Debug\Debug::dump($hash2);
        \Zend\Debug\Debug::dump($result);
        \Zend\Debug\Debug::dump($result2);
                die();
//        return $result;
    }

    public function onBootstrap(MvcEvent $event)
    {
        $eventManager = $event->getApplication()->getEventManager();
        $eventManager->attach('sendTweet', function($e) {
            var_dump($e);
        }, 100);
    }
}