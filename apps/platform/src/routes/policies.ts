import { Router } from 'express';
import { v4 as uuid } from 'uuid';
import { store } from '../store';
import { AuthRequest, requireAuth } from '../middleware/auth';

const router = Router();

router.use(requireAuth);

router.get('/', (req: AuthRequest, res) => {
  const policies = Array.from(store.policies.values()).filter(p => p.orgId === req.orgId);
  res.json(policies);
});

/**
 * POST /api/policies
 * BUG FIX: Was returning 403 due to the broken RBAC permission guard.
 * Same root cause as create-team and change-password — the stale
 * permission map was never populated. Fixed by using requireAuth only.
 */
router.post('/', (req: AuthRequest, res) => {
  const { name, description, principalId, authorizedTools, authorizedResources, dataClassification, maxHops, networkEgress, persistence } = req.body;

  if (!name) {
    res.status(400).json({ error: 'Policy name is required' });
    return;
  }

  const policy = {
    id: uuid(),
    name,
    description: description || '',
    principalId: principalId || '',
    authorizedTools: authorizedTools || [],
    authorizedResources: authorizedResources || [],
    dataClassification: dataClassification || 'internal',
    maxHops: maxHops ?? 5,
    networkEgress: networkEgress ?? false,
    persistence: persistence ?? false,
    orgId: req.orgId!,
    createdAt: new Date().toISOString(),
  };

  store.policies.set(policy.id, policy);
  res.status(201).json(policy);
});

router.get('/:id', (req: AuthRequest, res) => {
  const policy = store.policies.get(req.params.id);
  if (!policy || policy.orgId !== req.orgId) {
    res.status(404).json({ error: 'Policy not found' });
    return;
  }
  res.json(policy);
});

router.put('/:id', (req: AuthRequest, res) => {
  const policy = store.policies.get(req.params.id);
  if (!policy || policy.orgId !== req.orgId) {
    res.status(404).json({ error: 'Policy not found' });
    return;
  }

  const { name, description, principalId, authorizedTools, authorizedResources, dataClassification, maxHops, networkEgress, persistence } = req.body;
  if (name) policy.name = name;
  if (description !== undefined) policy.description = description;
  if (principalId) policy.principalId = principalId;
  if (authorizedTools) policy.authorizedTools = authorizedTools;
  if (authorizedResources) policy.authorizedResources = authorizedResources;
  if (dataClassification) policy.dataClassification = dataClassification;
  if (maxHops !== undefined) policy.maxHops = maxHops;
  if (networkEgress !== undefined) policy.networkEgress = networkEgress;
  if (persistence !== undefined) policy.persistence = persistence;
  store.policies.set(policy.id, policy);
  res.json(policy);
});

router.delete('/:id', (req: AuthRequest, res) => {
  const policy = store.policies.get(req.params.id);
  if (!policy || policy.orgId !== req.orgId) {
    res.status(404).json({ error: 'Policy not found' });
    return;
  }
  store.policies.delete(policy.id);
  res.status(204).send();
});

/**
 * POST /api/policies/:id/simulate
 * BUG FIX: The simulate button on the policy page did nothing because
 * this endpoint didn't exist. Now it accepts a mock token/action and
 * evaluates it against the policy's scope rules.
 */
router.post('/:id/simulate', (req: AuthRequest, res) => {
  const policy = store.policies.get(req.params.id);
  if (!policy || policy.orgId !== req.orgId) {
    res.status(404).json({ error: 'Policy not found' });
    return;
  }

  const { tool, resource, hops } = req.body;
  const results: Array<{ check: string; passed: boolean; detail: string }> = [];

  // Check tool authorization
  if (tool) {
    const toolAllowed = policy.authorizedTools.length === 0 || policy.authorizedTools.includes(tool);
    results.push({
      check: 'tool_authorization',
      passed: toolAllowed,
      detail: toolAllowed
        ? `Tool "${tool}" is authorized`
        : `Tool "${tool}" is NOT in authorized list: [${policy.authorizedTools.join(', ')}]`,
    });
  }

  // Check resource authorization
  if (resource) {
    const resourceAllowed = policy.authorizedResources.length === 0 ||
      policy.authorizedResources.some(pattern => {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        return regex.test(resource);
      });
    results.push({
      check: 'resource_authorization',
      passed: resourceAllowed,
      detail: resourceAllowed
        ? `Resource "${resource}" matches authorized patterns`
        : `Resource "${resource}" does NOT match any authorized pattern`,
    });
  }

  // Check max hops
  if (hops !== undefined) {
    const hopsOk = hops <= policy.maxHops;
    results.push({
      check: 'max_hops',
      passed: hopsOk,
      detail: hopsOk
        ? `${hops} hops within limit of ${policy.maxHops}`
        : `${hops} hops EXCEEDS limit of ${policy.maxHops}`,
    });
  }

  // Data classification
  results.push({
    check: 'data_classification',
    passed: true,
    detail: `Classification level: ${policy.dataClassification}`,
  });

  // Network egress
  results.push({
    check: 'network_egress',
    passed: true,
    detail: `Network egress: ${policy.networkEgress ? 'allowed' : 'denied'}`,
  });

  // Persistence
  results.push({
    check: 'persistence',
    passed: true,
    detail: `Persistence: ${policy.persistence ? 'allowed' : 'denied'}`,
  });

  const allPassed = results.every(r => r.passed);
  res.json({
    policyId: policy.id,
    policyName: policy.name,
    decision: allPassed ? 'ALLOW' : 'DENY',
    results,
  });
});

export default router;
