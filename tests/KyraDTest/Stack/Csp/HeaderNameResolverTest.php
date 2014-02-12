<?php
namespace KyraDTest\Stack\Csp;

use KyraD\Stack\Csp\Config;
use KyraD\Stack\Csp\HeaderNameResolver;

class HeaderNameResolverTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var HeaderNameResolver
     */
    private $headerNameResolver;

    /**
     * @var \PHPUnit_Framework_MockObject_MockObject
     */
    private $userAgentMock;

    public function setUp()
    {
        $this->userAgentMock = $this->getMock('\phpUserAgent', [], [], '', false);
        $this->headerNameResolver = new HeaderNameResolver;
    }

    /**
     * @dataProvider userAgentDataProvider
     */
    public function testGetCspHeaders($browserName, $browserVersion, $expectedEnforceHeader, $expectedReportHeader)
    {
        $this->userAgentMock->expects($this->atLeastOnce())
            ->method('getBrowserName')
            ->will($this->returnValue($browserName));
        $this->userAgentMock->expects($this->any())
            ->method('getBrowserVersion')
            ->will($this->returnValue($browserVersion));

        $actualEnforceHeader = $this->headerNameResolver->getEnforceCspHeaderName($this->userAgentMock);
        $this->assertSame($expectedEnforceHeader, $actualEnforceHeader);

        $actualReportHeader = $this->headerNameResolver->getReportCspHeaderName($this->userAgentMock);
        $this->assertSame($expectedReportHeader, $actualReportHeader);

        $expectedHeaders = [
            Config::POLICY_ENFORCE => $actualEnforceHeader,
            Config::POLICY_REPORT => $actualReportHeader,
        ];
        $this->assertSame($expectedHeaders, $this->headerNameResolver->getCspHeaders($this->userAgentMock));
    }

    public function userAgentDataProvider()
    {
        return [
            [
                'unknown',
                '',
                'Content-Security-Policy',
                'Content-Security-Policy-Report-Only'
            ],
            [
                'chrome',
                25,
                'Content-Security-Policy',
                'Content-Security-Policy-Report-Only'
            ],
            [
                'firefox',
                23,
                'Content-Security-Policy',
                'Content-Security-Policy-Report-Only'
            ],
            [
                'safari',
                7,
                'Content-Security-Policy',
                'Content-Security-Policy-Report-Only'
            ],
            [
                'chrome',
                24,
                'X-WebKit-CSP',
                'X-WebKit-CSP-Report-Only'
            ],
            [
                'safari',
                6,
                'X-WebKit-CSP',
                'X-WebKit-CSP-Report-Only'
            ],
            [
                'firefox',
                22,
                'X-Content-Security-Policy',
                'X-Content-Security-Policy-Report-Only'
            ],
            [
                'msie',
                10,
                'X-Content-Security-Policy',
                'X-Content-Security-Policy-Report-Only'
            ],
        ];
    }
}
