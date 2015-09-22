<?php

namespace Alcalyn\WSSE\Security\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

class WsseAuthenticationException extends AuthenticationException
{
    /**
     * {@inheritdoc}
     */
    public function getMessageKey()
    {
        return 'The WSSE authentication has failed.';
    }
}
