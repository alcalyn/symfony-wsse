<?php

namespace Alcalyn\WSSE\Security\Authentication\Provider;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Alcalyn\WSSE\Security\Exception\WsseAuthenticationException;
use Alcalyn\WSSE\Security\Authentication\Token\WsseUserToken;
use Alcalyn\WSSE\Security\Authentication\Provider\WsseTokenValidatorInterface;

class WsseProvider implements AuthenticationProviderInterface
{
    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    /**
     * @var UserCheckerInterface
     */
    private $userChecker;

    /**
     * @var WsseTokenValidatorInterface
     */
    private $digestValidator;

    /**
     * @param UserProviderInterface $userProvider
     * @param UserCheckerInterface $userChecker
     * @param WsseTokenValidatorInterface $digestValidator
     */
    public function __construct(
        UserProviderInterface $userProvider,
        UserCheckerInterface $userChecker,
        WsseTokenValidatorInterface $digestValidator
    ) {
        $this->userProvider = $userProvider;
        $this->userChecker = $userChecker;
        $this->digestValidator = $digestValidator;
    }

    /**
     * {@InheritDoc}
     */
    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        $isUser = $user instanceof UserInterface;

        if (!$isUser) {
            throw new WsseAuthenticationException('User not found.');
        }

        $this->userChecker->checkPreAuth($user);

        if (!$this->digestValidator->validateDigest($token, $user)) {
            throw new WsseAuthenticationException('Invalid Digest.');
        }

        $this->userChecker->checkPostAuth($user);

        $authenticatedToken = new WsseUserToken($user->getRoles());
        $authenticatedToken->setUser($user);

        return $authenticatedToken;
    }

    /**
     * {@InheritDoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof WsseUserToken;
    }
}
