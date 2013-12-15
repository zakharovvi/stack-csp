<?php
namespace KyraD\Stack\Csp;

use Symfony\Component\HttpFoundation\Request;

/**
 * Manages CSP policy arrays
 *
 * @author Kyra D. <kyra@existing.me>
 * @license MIT
 * @link https://github.com/KyraD/stack-csp
 */
class Config
{
    /** @var Policy */
    private $enforce;

    /** @var Policy */
    private $report;

    /**
     * @param array $policies
     */
    public function __construct(array $policies = [])
    {
        $policy = (isset($policies['enforce'])) ? $policies['enforce'] : [];
        $this->enforce = new Policy($policy);

        $policy = (isset($policies['report'])) ? $policies['report'] : [];
        $this->report = new Policy($policy);
    }

    /**
     * @param $policyType
     * @return mixed
     */
    public function getPolicy($policyType)
    {
        return $this->$policyType->getPolicy();
    }

    /**
     * @param Request $request
     */
    public function compilePolicy(Request $request)
    {
        try {

            $this->processRoutePolicies($request);

            $this->enforce->parse();
            $this->report->parse();

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
            $this->clearPolicy($request->attributes->get('cspReset'));
        }

        if (is_array($request->attributes->get('cspRemove'))) {
            $policy = $request->attributes->get('cspRemove');
            array_walk($policy, [$this, 'removeFromPolicy']);
        }

        if (is_array($request->attributes->get('cspAdd'))) {
            $policy = $request->attributes->get('cspAdd');
            array_walk($policy, [$this, 'addToPolicy']);
        }
    }

    /**
     * @param $policyType
     * @throws \UnexpectedValueException
     */
    private function clearPolicy($policyType)
    {
        switch ($policyType) {
            case 'enforce':
                $this->enforce->clear();
                break;
            case 'report':
                $this->report->clear();
                break;
            case 'all':
                $this->enforce->clear();
                $this->report->clear();
                break;
            default:
                throw new \UnexpectedValueException("'$policyType' is not a valid clear policy option");
        }
    }

    /**
     * @param array $addPolicy
     * @param $policyType
     * @throws \UnexpectedValueException
     */
    private function addToPolicy(array $addPolicy, $policyType)
    {
        if (!isset($this->$policyType)) {
            throw new \UnexpectedValueException("'cspAdd' supplied an invalid policy type of '$policyType'");
        }

        $this->$policyType = array_merge_recursive($this->$policyType, $addPolicy);
    }

    /**
     * @param array $removePolicy
     * @param $policyType
     * @throws \UnexpectedValueException
     */
    private function removeFromPolicy(array $removePolicy, $policyType)
    {
        if (!isset($this->$policyType)) {
            throw new \UnexpectedValueException("invalid policy type of '$policyType' for 'cspRemove'");
        }

        $this->applyPolicyDiff($removePolicy, 'enforce');
        $this->applyPolicyDiff($removePolicy, 'report');
    }

    /**
     * @param array $removePolicy
     * @param $policyType
     */
    private function applyPolicyDiff(array $removePolicy, $policyType)
    {
        foreach ($removePolicy as $key => $values) {

            if (!isset($this->$policyType->getPolicy()[$key])) {
                continue;
            }

            $rules = $this->$policyType->getPolicy()[$key];
            $this->$policyType->replaceRules($key, array_diff((array)$rules, (array)$values));
        }
    }
}
