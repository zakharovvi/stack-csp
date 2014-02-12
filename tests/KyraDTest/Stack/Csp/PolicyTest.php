<?php
namespace KyraDTest\Stack\Csp;

use KyraD\Stack\Csp\Policy;

class PolicyTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Policy
     */
    private $policy;

    private $policyRules = ['default-src' => ['self']];

    private $fullPolicyRules = [
        'report-uri' => ['none'],
        'sandbox' => ['none'],
        'connect-src' => ['none'],
        'default-src' => ['none'],
        'font-src' => ['none'],
        'frame-src' => ['none'],
        'img-src' => ['none'],
        'media-src' => ['none'],
        'object-src' => ['none'],
        'script-src' => ['none'],
        'style-src' => ['none']
    ];

    public function setUp()
    {
        $this->policy = new Policy;
    }

    public function testGetPolicyRules()
    {
        $policy = new Policy($this->policyRules);
        $this->assertSame($this->policyRules, $policy->getPolicyRules());
    }

    public function testClear()
    {
        $policy = new Policy($this->policyRules);
        $this->assertSame($policy, $policy->clear());
        $this->assertSame([], $policy->getPolicyRules());
    }

    /**
     * @dataProvider validateDataProvider
     */
    public function testValidate($rules, $exceptionMessage)
    {
        $this->setExpectedException('\UnexpectedValueException', $exceptionMessage);
        $policy = new Policy($rules);
        $policy->parse();
    }

    public function validateDataProvider()
    {
        return [
            [['style-src' => ['none', 'example.com']], "'none' DENIES ALL for 'style-src' directive, but exceptions are set"],//assertValidNoneSrcList
            [['script-src' => ['*', 'example.com']], "'*' ALLOWS ALL for 'script-src' directive, but exceptions are set"],//assertValidWildcardSrcList
            [['nonexistent_directive' => ['self']], "'nonexistent_directive' is an invalid CSP 1.0 directive"],//assertValidDirectiveName
            [['sandbox' => ['self']], "'self' is an invalid CSP 1.0 'sandbox' keyword"],//assertValidSandboxKeyword
            [['default-src' => ['**']], "'**' is an invalid CSP 1.0 'default-src' value"],//assertValidSrcValue
            [['report-uri' => ['not_uri']], "'not_uri' is an invalid 'report-uri' value, must be of type RFC 3986"],//assertValidReportUri
        ];
    }

    public function testSetters()
    {
        $policy = new Policy($this->fullPolicyRules);
        $rawHeaderValue = $policy
            ->replaceConnectSrc(['replaceConnectSrc.example.com', 'self'])
            ->replaceDefaultSrc(['replaceDefaultSrc.example.com', 'self'])
            ->replaceFontSrc(['replaceFontSrc.example.com', 'self'])
            ->replaceFrameSrc(['replaceFrameSrc.example.com', 'self'])
            ->replaceImgSrc(['replaceImgSrc.example.com', 'self'])
            ->replaceMediaSrc(['replaceMediaSrc.example.com', 'self'])
            ->replaceObjectSrc(['replaceObjectSrc.example.com', 'self'])
            ->replaceReportUri(['replaceReportUri.example.com'])
            ->replaceSandbox(['allow-forms'])
            ->replaceScriptSrc(['replaceScriptSrc.example.com', 'self'])
            ->replaceStyleSrc(['replaceStyleSrc.example.com', 'self'])
            ->replaceConnectSrc(['replaceConnectSrc.example.com', 'self'])
            ->addDefaultSrc('addDefaultSrc.example.com')
            ->addFontSrc('addFontSrc.example.com')
            ->addFrameSrc('addFrameSrc.example.com')
            ->addImgSrc('addImgSrc.example.com')
            ->addMediaSrc('addMediaSrc.example.com')
            ->addObjectSrc('addObjectSrc.example.com')
            ->addReportUri('addReportUri.example.com')
            ->addSandbox('allow-same-origin')
            ->addScriptSrc('addScriptSrc.example.com')
            ->addStyleSrc('addStyleSrc.example.com')
            ->parse()
            ->getRawHeaderValue();
        $this->assertSame(
            "report-uri replaceReportUri.example.com addReportUri.example.com;sandbox allow-forms allow-same-origin;connect-src replaceConnectSrc.example.com 'self';default-src replaceDefaultSrc.example.com 'self' addDefaultSrc.example.com;font-src replaceFontSrc.example.com 'self' addFontSrc.example.com;frame-src replaceFrameSrc.example.com 'self' addFrameSrc.example.com;img-src replaceImgSrc.example.com 'self' addImgSrc.example.com;media-src replaceMediaSrc.example.com 'self' addMediaSrc.example.com;object-src replaceObjectSrc.example.com 'self' addObjectSrc.example.com;script-src replaceScriptSrc.example.com 'self' addScriptSrc.example.com;style-src replaceStyleSrc.example.com 'self' addStyleSrc.example.com;",
            $rawHeaderValue
        );

    }

    public function testEmptyGetRawHeaderValue()
    {
        $this->assertSame('', $this->policy->getRawHeaderValue());
    }
}