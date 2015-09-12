<?php

namespace Alcalyn\WSSE\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

class WsseUserToken extends AbstractToken
{
    /**
     * @var string
     */
    public $created;

    /**
     * @var string
     */
    public $digest;

    /**
     * @var string
     */
    public $nonce;

    /**
     * @param array $roles
     */
    public function __construct(array $roles = array())
    {
        parent::__construct($roles);

        $this->setAuthenticated(count($roles) > 0);
    }

    /**
     * {@InheritDoc}
     */
    public function getCredentials()
    {
        return '';
    }
}
