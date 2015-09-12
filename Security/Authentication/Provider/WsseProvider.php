<?php

namespace Alcalyn\WSSE\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Alcalyn\WSSE\Security\Authentication\Token\WsseUserToken;
use Alcalyn\WSSE\Security\Authentication\Provider\WsseTokenValidatorInterface;

class WsseProvider implements AuthenticationProviderInterface
{
    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    /**
     * @var WsseTokenValidatorInterface
     */
    private $digestValidator;

    /**
     * @param UserProviderInterface $userProvider
     * @param WsseTokenValidatorInterface $digestValidator
     */
    public function __construct(UserProviderInterface $userProvider, WsseTokenValidatorInterface $digestValidator)
    {
        $this->userProvider = $userProvider;
        $this->digestValidator = $digestValidator;
    }

    /**
     * {@InheritDoc}
     */
    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        $isUser = $user instanceof UserInterface;

        if ($isUser && $this->digestValidator->validateDigest($token, $user)) {
            $authenticatedToken = new WsseUserToken($user->getRoles());
            $authenticatedToken->setUser($user);

            return $authenticatedToken;
        }

        throw new AuthenticationException('The WSSE authentication failed.');
    }

    /**
     * {@InheritDoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof WsseUserToken;
    }
}
