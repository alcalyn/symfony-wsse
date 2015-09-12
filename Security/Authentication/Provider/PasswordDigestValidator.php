<?php

namespace Alcalyn\WSSE\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Util\StringUtils;
use Symfony\Component\Security\Core\User\UserInterface;
use Alcalyn\WSSE\Security\Authentication\Token\WsseUserToken;

class PasswordDigestValidator implements WsseTokenValidatorInterface
{
    /**
     * @var string
     */
    private $cacheDir;

    /**
     * @param string $cacheDir
     */
    public function __construct($cacheDir)
    {
        $this->cacheDir = $cacheDir;
    }

    /**
     * {@InheritDoc}
     *
     * @throws NonceExpiredException
     */
    public function validateDigest(WsseUserToken $wsseToken, UserInterface $user)
    {
        $created = $wsseToken->created;
        $nonce = $wsseToken->nonce;
        $digest = $wsseToken->digest;
        $secret = $user->getPassword();

        // Check created time is not in the future
        if (strtotime($created) > time()) {
            return false;
        }

        // Expire timestamp after 5 minutes
        if (time() - strtotime($created) > 300) {
            return false;
        }

        // Validate that the nonce is *not* used in the last 5 minutes
        // if it has, this could be a replay attack
        if (file_exists($this->cacheDir.'/'.$nonce) && file_get_contents($this->cacheDir.'/'.$nonce) + 300 > time()) {
            throw new NonceExpiredException('Previously used nonce detected');
        }
        // If cache directory does not exist we create it
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0777, true);
        }
        file_put_contents($this->cacheDir.'/'.$nonce, time());

        // Validate Secret
        $expected = base64_encode(sha1(base64_decode($nonce).$created.$secret, true));

        return StringUtils::equals($expected, $digest);
    }
}
