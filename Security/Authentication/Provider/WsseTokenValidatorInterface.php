<?php

namespace Alcalyn\Wsse\Security\Authentication\Provider;

use Symfony\Component\Security\Core\User\UserInterface;
use Alcalyn\Wsse\Security\Authentication\Token\WsseUserToken;

interface WsseTokenValidatorInterface
{
    /**
     * Validate a WSSE token
     *
     * @param WsseUserToken $wsseToken
     * @param UserInterface $user
     *
     * @return bool
     */
    public function validateDigest(WsseUserToken $wsseToken, UserInterface $user);
}
