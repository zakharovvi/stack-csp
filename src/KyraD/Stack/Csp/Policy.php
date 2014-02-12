<?php
namespace KyraD\Stack\Csp;

/**
 * Parses and validates CSP directives and values for a policy
 *
 * @author Kyra D. <kyra@existing.me>
 * @license MIT
 * @link https://github.com/KyraD/stack-csp
 * @todo Update to CSP 1.1 when no longer a draft
 */
class Policy
{
    /** @var array */
    private static $directives = [
        'report-uri' => [],
        'sandbox' => [
            'allow-forms',
            'allow-same-origin',
            'allow-scripts',
            'allow-top-navigation'
        ],
        'connect-src' => ['none', 'self'],
        'default-src' => ['none', 'self'],
        'font-src' => ['none', 'self'],
        'frame-src' => ['none', 'self'],
        'img-src' => ['none', 'self'],
        'media-src' => ['none', 'self'],
        'object-src' => ['none', 'self'],
        'script-src' => [
            'none',
            'self',
            'unsafe-eval',
            'unsafe-inline'
        ],
        'style-src' => [
            'none',
            'self',
            'unsafe-inline'
        ]
    ];

    /** @var array */
    private $policy = [];

    /**
     * @param array $cspPolicy
     */
    public function __construct(array $cspPolicy = [])
    {
        $this->policy = $cspPolicy;
    }

    public function getPolicyRules()
    {
        return $this->policy;
    }

    /**
     * @return string
     */
    public function getRawHeaderValue()
    {
        $header = '';

        foreach ($this->policy as $directive => $values) {

            /** skip empty directives */
            if (0 < count($values)) {
                $header .= "$directive " . implode(' ', $values) . ';';
            }
        }

        return $header;
    }

    public function clear()
    {
        $this->policy = [];
        return $this;
    }

    public function parse()
    {
        array_walk($this->policy, [$this, 'validate']);
        return $this;
    }

    public function replaceRules($key, array $rules)
    {
        $this->policy[$key] = $rules;
        return $this;
    }

    public function replaceSandbox(array $srcList)
    {
        $this->policy['sandbox'] = $srcList;
        return $this;
    }

    public function addSandbox($src)
    {
        $this->policy['sandbox'][] = $src;
        return $this;
    }

    public function replaceConnectSrc(array $srcList)
    {
        $this->policy['connect-src'] = $srcList;
        return $this;
    }

    public function addConnectSrc($src)
    {
        $this->policy['connect-src'][] = $src;
        return $this;
    }

    public function replaceDefaultSrc(array $srcList)
    {
        $this->policy['default-src'] = $srcList;
        return $this;
    }

    public function addDefaultSrc($src)
    {
        $this->policy['default-src'][] = $src;
        return $this;
    }

    public function replaceFontSrc(array $srcList)
    {
        $this->policy['font-src'] = $srcList;
        return $this;
    }

    public function addFontSrc($src)
    {
        $this->policy['font-src'][] = $src;
        return $this;
    }

    public function replaceFrameSrc(array $srcList)
    {
        $this->policy['frame-src'] = $srcList;
        return $this;
    }

    public function addFrameSrc($src)
    {
        $this->policy['frame-src'][] = $src;
        return $this;
    }

    public function replaceImgSrc(array $srcList)
    {
        $this->policy['img-src'] = $srcList;
        return $this;
    }

    public function addImgSrc($src)
    {
        $this->policy['img-src'][] = $src;
        return $this;
    }

    public function replaceMediaSrc(array $srcList)
    {
        $this->policy['media-src'] = $srcList;
        return $this;
    }

    public function addMediaSrc($src)
    {
        $this->policy['media-src'][] = $src;
        return $this;
    }

    public function replaceObjectSrc(array $srcList)
    {
        $this->policy['object-src'] = $srcList;
        return $this;
    }

    public function addObjectSrc($src)
    {
        $this->policy['object-src'][] = $src;
        return $this;
    }

    public function replaceScriptSrc(array $srcList)
    {
        $this->policy['script-src'] = $srcList;
        return $this;
    }

    public function addScriptSrc($src)
    {
        $this->policy['script-src'][] = $src;
        return $this;
    }

    public function replaceStyleSrc(array $srcList)
    {
        $this->policy['style-src'] = $srcList;
        return $this;
    }

    public function addStyleSrc($src)
    {
        $this->policy['style-src'][] = $src;
        return $this;
    }

    public function replaceReportUri(array $reportUriList)
    {
        $this->policy['report-uri'] = $reportUriList;
        return $this;
    }

    public function addReportUri($reportUri)
    {
        $this->policy['report-uri'][] = $reportUri;
        return $this;
    }

    /**
     * @param $values
     * @param $directive
     */
    private function validate(&$values, $directive)
    {
        /** pass by reference to apply this change to policy as well */
        $values = array_unique((array)$values);

        if ('report-uri' === $directive) {
            array_walk($values, [$this, 'assertValidReportUri']);
            return;
        }

        if ('sandbox' === $directive) {
            array_walk($values, [$this, 'assertValidSandboxKeyword']);
            return;
        }

        $this->assertValidDirectiveName($directive);

        if (1 < count($values)) {
            $this->assertValidNoneSrcList($values, $directive);
            $this->assertValidWildcardSrcList($values, $directive);
        }

        foreach ($values as &$value) {

            $this->assertValidSrcValue($value, $directive);

            if (in_array($value, self::$directives[$directive])) {

                /** pass by reference to quote keyword in policy */
                $value = "'$value'";
            }
        }
    }

    /**
     * @param $values
     * @param $directive
     * @throws \UnexpectedValueException
     */
    private function assertValidNoneSrcList(array $values, $directive)
    {
        if (in_array('none', $values) && in_array('none', self::$directives[$directive])) {
            throw new \UnexpectedValueException("'none' DENIES ALL for '$directive' directive, but exceptions are set");
        }
    }

    /**
     * @param array $values
     * @param $directive
     * @throws \UnexpectedValueException
     */
    private function assertValidWildcardSrcList(array $values, $directive)
    {
        if (in_array('*', $values)) {
            throw new \UnexpectedValueException("'*' ALLOWS ALL for '$directive' directive, but exceptions are set");
        }
    }

    /**
     * @param $directive
     * @throws \UnexpectedValueException
     */
    private function assertValidDirectiveName($directive)
    {
        if (!array_key_exists($directive, self::$directives)) {
            throw new \UnexpectedValueException("'$directive' is an invalid CSP 1.0 directive");
        }
    }

    /**
     * @param $value
     * @throws \UnexpectedValueException
     */
    private function assertValidSandboxKeyword($value)
    {
        if (!in_array($value, self::$directives['sandbox'])) {
            throw new \UnexpectedValueException("'$value' is an invalid CSP 1.0 'sandbox' keyword");
        }
    }

    /**
     * @param $value
     * @param $directive
     * @throws \UnexpectedValueException
     */
    private function assertValidSrcValue($value, $directive)
    {
        /** @author HamZa <https://github.com/Hamz-a> */
        $regex = '~
            (?(DEFINE)
               (?<ipv4>                                         # IPv4 address / domain name (with sub-domain wildcards)
                  (?=\S*?(?:\.|localhost))                      # make sure there is at least one dot or localhost
                  (?:\*\.)?                                     # wildcard only allowed at start
                  (?:[a-z\d-][a-z\d.-]*|%[a-f\d]{2}+)
               )
               (?<ipv6>\[(?:[a-f\d]{0,4}:)*(?:[a-f\d]{0,4})\])  # IPv6 address
               (?<port>:\d+)                                    # port number
               (?<dataScheme>                                   # data: scheme
                  (?<!.)data:(?!.)
               )
               (?<wildcard>                                     # wildcard
                  (?<!.)\*(?!.)
               )
               (?<httpScheme>https?://)
               (?<url>                                          # host
                  (?&httpScheme)?
                  (?:(?&ipv4)|(?&ipv6))
                  (?&port)?                                     # optional port number
               )
            )

            ^(?:(?&url)|(?&dataScheme)|(?&wildcard))$           # regex
        ~ix';

        if (!in_array($value, self::$directives[$directive]) && !preg_match($regex, $value)) {
            throw new \UnexpectedValueException("'$value' is an invalid CSP 1.0 '$directive' value");
        }
    }

    /**
     * {@internal Don't use FILTER_VALIDATE_URL which is RFC 2396, or parse_url() which allows practically anything.
     * We do not allow HTTP login via URI as such sensitive information should never be sent to client.
     * We restrict to HTTP schemes only, allow absolute and relative URIs}}
     * @param $uri
     * @throws \UnexpectedValueException
     */
    private function assertValidReportUri($uri)
    {
        /** RFC 3986 */
        $regex = '~
            (?(DEFINE)
               (?<ipv4>                                         # IPv4 address / domain name
                  (?=\S*?(?:\.|localhost))                      # make sure there is at least one dot or localhost
                  (?:[a-z\d-][a-z\d.-]*|%[a-f\d]{2}+)
               )
               (?<ipv6>\[(?:[a-f\d]{0,4}:)*(?:[a-f\d]{0,4})\])  # IPv6 address
               (?<port>:\d+)                                    # port number
               (?<httpScheme>https?://)
               (?<queryPath>/                                   # path and query
                    (?:[\w!#$&\'()*+,./:;=?@\[\]\~-]
                    |
                    %[a-f\d]{2})*                               # encoded chars
               )
               (?<url>                                          # host
                  (?&httpScheme)?
                  (?:(?&ipv4)|(?&ipv6))
                  (?&port)?                                     # optional port number
                  (?&queryPath)?                                # optional path and query
               )
            )

            ^(?:(?&url)|(?&queryPath))$                         # regex
        ~ix';

        if (!preg_match($regex, $uri)) {
            throw new \UnexpectedValueException("'$uri' is an invalid 'report-uri' value, must be of type RFC 3986");
        }
    }
}
