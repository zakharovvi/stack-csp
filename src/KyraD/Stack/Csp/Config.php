<?php
namespace KyraD\Stack\Csp;

/**
 * Manages CSP policy arrays
 *
 * @author Kyra D. <kyra@existing.me>
 * @license MIT
 * @link https://github.com/KyraD/stack-csp
 */
class Config
{
    const POLICY_ENFORCE = 'enforce';
    const POLICY_REPORT = 'report';

    /** @var Policy */
    private $enforce;

    /** @var Policy */
    private $report;

    /**
     * @param array $policies
     */
    public function __construct(array $policies = [])
    {
        $policy = (isset($policies[self::POLICY_ENFORCE])) ? $policies[self::POLICY_ENFORCE] : [];
        $this->enforce = new Policy($policy);

        $policy = (isset($policies[self::POLICY_REPORT])) ? $policies[self::POLICY_REPORT] : [];
        $this->report = new Policy($policy);
    }

    /**
     * @param $policyType
     * @return Policy
     */
    public function getPolicy($policyType)
    {
        return $this->$policyType;
    }

    /**
     * @param $policyType
     * @throws \UnexpectedValueException
     */
    public function clearPolicy($policyType)
    {
        switch ($policyType) {
            case self::POLICY_ENFORCE:
                $this->enforce->clear();
                break;
            case self::POLICY_REPORT:
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
    public function addToPolicy(array $addPolicy, $policyType)
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
    public function removeFromPolicy(array $removePolicy, $policyType)
    {
        if (!isset($this->$policyType)) {
            throw new \UnexpectedValueException("invalid policy type of '$policyType' for 'cspRemove'");
        }

        $this->applyPolicyDiff($removePolicy, self::POLICY_ENFORCE);
        $this->applyPolicyDiff($removePolicy, self::POLICY_REPORT);
    }

    /**
     * @param array $removePolicy
     * @param $policyType
     */
    private function applyPolicyDiff(array $removePolicy, $policyType)
    {
        foreach ($removePolicy as $key => $values) {

            if (!isset($this->$policyType->getPolicyRules()[$key])) {
                continue;
            }

            $rules = $this->$policyType->getPolicyRules()[$key];
            $this->$policyType->replaceRules($key, array_diff((array)$rules, (array)$values));
        }
    }
}
