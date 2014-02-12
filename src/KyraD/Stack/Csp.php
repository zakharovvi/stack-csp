<?php
namespace KyraD\Stack;

use KyraD\Stack\Csp\HeaderNameResolver;
use KyraD\Stack\Csp\Config;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * A Stack middleware to generate Content Security Policy (CSP) 1.0 HTTP headers.
 *
 * @author Kyra D. <kyra@existing.me>
 * @license MIT
 * @link https://github.com/KyraD/stack-csp
 */
class Csp implements HttpKernelInterface
{
    /** @var \Symfony\Component\HttpKernel\HttpKernelInterface */
    private $app;

    /** @var Config */
    private $config;

    /** @var HeaderNameResolver */
    private $headerNameResolver;

    /**
     * @param HttpKernelInterface $app
     * @param Config $cspPolicy
     * @param HeaderNameResolver $headerNameResolver
     */
    public function __construct(HttpKernelInterface $app, Config $cspPolicy, HeaderNameResolver $headerNameResolver)
    {
        $this->app = $app;
        $this->config = $cspPolicy;
        $this->headerNameResolver = $headerNameResolver;
    }

    /**
     * @param Request $request
     * @param int $type
     * @param bool $catch
     * @return Response
     */
    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
    {
        $response = $this->app->handle($request, $type, $catch);
        $this->setCspHeaders($request, $response);

        return $response;
    }

    /**
     * @param Request $request
     * @param Response $response
     */
    private function setCspHeaders(Request $request, Response $response)
    {
        $cspHeaders = $this->getCspHeaders($request);

        $enforceHeaderValue = $this->config->getPolicy(Config::POLICY_ENFORCE)->getRawHeaderValue();
        if ($enforceHeaderValue) {
            $response->headers->set($cspHeaders[Config::POLICY_ENFORCE], $enforceHeaderValue);
        }

        $reportHeaderValue = $this->config->getPolicy(Config::POLICY_REPORT)->getRawHeaderValue();
        if ($reportHeaderValue) {
            $response->headers->set($cspHeaders[Config::POLICY_REPORT], $reportHeaderValue);
        }
    }

    private function getCspHeaders(Request $request)
    {
        $userAgent = new \phpUserAgent($request->headers->get('user-agent'));
        return $this->headerNameResolver->getCspHeaders($userAgent);
    }

    /**
     * @param Request $request
     */
    public function compilePolicy(Request $request)
    {
        try {
            $this->processRoutePolicies($request);

            $this->config->getPolicy(Config::POLICY_ENFORCE)->parse();
            $this->config->getPolicy(Config::POLICY_REPORT)->parse();

        } catch (\UnexpectedValueException $e) {
            exit('Unexpected value: ' . $e->getMessage());
        }
    }

    /**
     * @param Request $request
     */
    private function processRoutePolicies(Request $request)
    {
        if ($request->attributes->get('cspReset')) {
            $this->config->clearPolicy($request->attributes->get('cspReset'));
        }

        if (is_array($request->attributes->get('cspRemove'))) {
            $policy = $request->attributes->get('cspRemove');
            array_walk($policy, [$this->config, 'removeFromPolicy']);
        }

        if (is_array($request->attributes->get('cspAdd'))) {
            $policy = $request->attributes->get('cspAdd');
            array_walk($policy, [$this->config, 'addToPolicy']);
        }
    }
}
