<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

namespace KyraDTest\Stack;

use KyraD\Stack\Csp;
use KyraD\Stack\Csp\Config;
use PHPUnit_Framework_TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * A Stack middleware to generate Content Security Policy (CSP) 1.0 HTTP headers.
 *
 * @author Marco Pivetta <ocramius@gmail.com>
 * @copyright 2013 Kyra D.
 * @license MIT
 * @link https://github.com/KyraD/stack-csp
 *
 * @covers \KyraD\Stack\Csp
 */
class CspTest extends PHPUnit_Framework_TestCase
{
    /** @var \PHPUnit_Framework_MockObject_MockObject */
    private $app;

    /** @var Config */
    private $config;

    /** @var Csp */
    private $csp;

    /** @var */
    private $request;

    /**
     * {@inheritDoc}
     */
    public function setUp()
    {
        $this->app = $this->getMock('Symfony\Component\HttpKernel\HttpKernelInterface');
        $this->config = new Config();
        $this->csp = new Csp($this->app, $this->config, new Csp\HeaderNameResolver);
    }

    public function testSimpleHandle()
    {
        $request = $this->buildRequest();
        $response = $this->buildResponse();

        $this
            ->app
            ->expects($this->once())
            ->method('handle')
            ->with($request, 123, false)
            ->will($this->returnValue($response));

        $this->assertSame(
            $response,
            $this->csp->handle($request, 123, false),
            'The request dispatching is delegated to the application with correct parameters'
        );
    }

    /**
     * @dataProvider userAgentDataProvider
     */
    public function testSetsEnforcePolicyHeader($expectedHeader, $userAgent)
    {
        $request = $this->buildRequest();
        $response = $this->buildResponse();

        $this->config->getPolicy(Config::POLICY_ENFORCE)->replaceRules('foo', ['bar', 'baz']);
        $this->app->expects($this->any())->method('handle')->will($this->returnValue($response));
        $request
            ->headers
            ->expects($this->any())
            ->method('get')
            ->with('user-agent')
            ->will($this->returnValue($userAgent));

        $response->headers->expects($this->once())->method('set')->with($expectedHeader, 'foo bar baz;');

        $this->csp->handle($request);
    }

    public function userAgentDataProvider()
    {
        return [
            ['X-Content-Security-Policy', 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:22.0) Gecko/20130328 Firefox/22.0'],
            ['X-WebKit-CSP', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.60 Safari/537.17'],
            ['X-WebKit-CSP', 'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25'],
            ['X-Content-Security-Policy', 'Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0'],
        ];
    }

    /**
     * Since Symfony's Http Request object is full of... public properties
     * we need to make a real one instead of a mock
     *
     * @return Request
     */
    private function buildRequest()
    {
        $request = new Request();
        $headers = $this->getMock('Symfony\Component\HttpFoundation\HeaderBag');
        $request->headers = $headers;

        return $request;
    }

    /**
     * Since Symfony's Http Response object is full of... public properties
     * we need to make a real one instead of a mock
     *
     * @return Response
     */
    private function buildResponse()
    {
        $response = new Response();
        $headers = $this->getMock('Symfony\Component\HttpFoundation\HeaderBag');
        $response->headers = $headers;

        return $response;
    }
}
