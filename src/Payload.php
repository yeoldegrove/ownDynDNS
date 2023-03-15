<?php

namespace netcup\DNS\API;

final class Payload
{
    /**
     * @var string
     */
    private $user;

    /**
     * @var string
     */
    private $password;

    /**
     * @var string
     */
    //private $hostname;
    private $hostname;

    /**
     * @var string
     */
    private $mode;

    /**
     * @var string
     */
    //private $myip;
    private $myip;

    /**
     * @var string
     */
    private $ipv6;

    /**
     * @var bool
     */
    private $force = false;

    public function __construct(array $payload)
    {
        foreach (get_object_vars($this) as $key => $val) {
            if (isset($payload[$key])) {
                $this->$key = $payload[$key];
            }
        }
    }

    /**
     * @return bool
     */
    public function isValid()
    {
        return
            !empty($this->user) &&
            !empty($this->password) &&
            !empty($this->hostname) &&
            (
                (
                    !empty($this->myip) && $this->isValidIpv4()
                )
                ||
                (
                    !empty($this->ipv6) && $this->isValidIpv6()
                )
            );
    }

    /**
     * @return string
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * @return string
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * @return string
     */
    public function getDomain()
    {
        return $this->hostname;
    }

    /**
     * @return array
     */
    public function getMatcher()
    {
        switch ($this->mode) {
            case 'both':
                return ['@', '*'];

            case '*':
                return ['*'];

            default:
                return ['@'];
        }
    }

    /**
     * there is no good way to get the correct "registrable" Domain without external libs!
     *
     * @see https://github.com/jeremykendall/php-hostname-parser
     *
     * this method is still tricky, because:
     *
     * works: nas.tld.com
     * works: nas.tld.de
     * works: tld.com
     * failed: nas.tld.co.uk
     * failed: nas.home.tld.de
     *
     * @return string
     */
    public function getHostname()
    {
        // hack if top level hostname are used for dynDNS
        if (1 === substr_count($this->hostname, '.')) {
            return $this->hostname;
        }

        $hostnameParts = explode('.', $this->hostname);
        array_shift($hostnameParts); // remove sub hostname
        return implode('.', $hostnameParts);
    }

    /**
     * @return string
     */
    public function getIpv4()
    {
        return $this->myip;
    }

    /**
     * @return bool
     */
    public function isValidIpv4()
    {
        return (bool)filter_var($this->myip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }

    /**
     * @return string
     */
    public function getIpv6()
    {
        return $this->ipv6;
    }

    /**
     * @return bool
     */
    public function isValidIpv6()
    {
        return (bool)filter_var($this->ipv6, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }

    /**
     * @return bool
     */
    public function isForce()
    {
        return $this->force;
    }
}
