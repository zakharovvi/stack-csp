<?php
namespace KyraD\Stack\Csp;

class HeaderNameResolver
{
    private $defaultHeaders = [
        Config::POLICY_ENFORCE => 'Content-Security-Policy',
        Config::POLICY_REPORT => 'Content-Security-Policy-Report-Only',
    ];

    private $xHeaders = [
        Config::POLICY_ENFORCE => 'X-Content-Security-Policy',
        Config::POLICY_REPORT => 'X-Content-Security-Policy-Report-Only',
    ];

    private $webkitHeaders = [
        Config::POLICY_ENFORCE => 'X-WebKit-CSP',
        Config::POLICY_REPORT => 'X-WebKit-CSP-Report-Only',
    ];

    public function getReportCspHeaderName($userAgent)
    {
        return $this->getCspHeaders($userAgent)[Config::POLICY_REPORT];
    }

    public function getEnforceCspHeaderName($userAgent)
    {
        return $this->getCspHeaders($userAgent)[Config::POLICY_ENFORCE];
    }

    /**
     * @param \phpUserAgent $userAgent
     * @return array
     * @link http://content-security-policy.com/
     */
    public function getCspHeaders(\phpUserAgent $userAgent)
    {
        switch ($userAgent->getBrowserName()) {
            case 'chrome':
                if ($userAgent->getBrowserVersion() >= 25) {
                    return $this->defaultHeaders;
                } else {
                    return $this->webkitHeaders;
                }
            case 'firefox':
                if ($userAgent->getBrowserVersion() >= 23) {
                    return $this->defaultHeaders;
                } else {
                    return $this->xHeaders;
                }
            case 'msie':
                return $this->xHeaders;
            case 'safari':
                if ($userAgent->getBrowserVersion() >= 7) {
                    return $this->defaultHeaders;
                } else {
                    return $this->webkitHeaders;
                }
            default:
                return $this->defaultHeaders;
        }
    }
}