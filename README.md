Symfony WSSE
============

This library provide classes used in Symfony documentation,
about a [WSSE implementation](http://symfony.com/doc/current/cookbook/security/custom_authentication_provider.html).


## Installation

Via Composer

``` js
{
    "require": {
        "alcalyn/symfony-wsse": "~1.0.0"
    }
}
```


## Usage

You have to register library class in your Symfony project.


### Silex

See [SilexWSSE](https://github.com/alcalyn/silex-wsse) project.


### Symfony full stack

Following [Symfony2 documentation about WSSE](http://symfony.com/doc/current/cookbook/security/custom_authentication_provider.html):

Register services:

``` yml
# app/config/services.yml
services:
    wsse.security.authentication.provider:
        class: Alcalyn\Wsse\Security\Authentication\Provider\WsseProvider
        arguments:
            - "" # User Provider
            - "%kernel.cache_dir%/security/nonces"
        public: false

    wsse.security.authentication.listener:
        class: Alcalyn\Wsse\Security\Firewall\WsseListener
        arguments: ["@security.token_storage", "@security.authentication.manager"]
        public: false
```

Register your WSSE security context:

``` php
// src/AppBundle/AppBundle.php
namespace AppBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Alcalyn\Wsse\DependencyInjection\Security\Factory\WsseFactory;

class AppBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new WsseFactory());
    }
}
```

Now you can use WSSE security in your project:

``` yml
# app/config/security.yml
security:
    # ...

    firewalls:
        wsse_secured:
            pattern:   ^/api/
            stateless: true
            wsse:      true
```


## License

This project is under [MIT License](LICENSE).
