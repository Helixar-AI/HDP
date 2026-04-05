import { v4 as uuid } from 'uuid';
import bcrypt from 'bcryptjs';

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  name: string;
  role: 'admin' | 'member';
  orgId: string;
  createdAt: string;
}

export interface Team {
  id: string;
  name: string;
  description: string;
  orgId: string;
  members: string[];
  createdAt: string;
}

export interface Principal {
  id: string;
  name: string;
  idType: 'email' | 'uuid' | 'did' | 'opaque';
  displayName: string;
  orgId: string;
  createdAt: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  principalId: string;
  authorizedTools: string[];
  authorizedResources: string[];
  dataClassification: 'public' | 'internal' | 'confidential' | 'restricted';
  maxHops: number;
  networkEgress: boolean;
  persistence: boolean;
  orgId: string;
  createdAt: string;
}

export interface ApiKey {
  id: string;
  name: string;
  keyHash: string;
  keyPrefix: string;
  principalId: string;
  orgId: string;
  lastUsed: string | null;
  createdAt: string;
}

export interface SiemConfig {
  id: string;
  endpoint: string;
  format: 'cef' | 'leef' | 'json';
  enabled: boolean;
  orgId: string;
  updatedAt: string;
}

export interface BillingPlan {
  id: string;
  name: string;
  price: number;
  interval: 'month' | 'year';
  features: string[];
  tokenLimit: number;
  teamLimit: number;
  current?: boolean;
}

export interface DashboardStats {
  totalRequests: number;
  verifiedTokens: number;
  failedVerifications: number;
  activeAgents: number;
  delegationChains: number;
  policyViolations: number;
}

const PLANS: BillingPlan[] = [
  {
    id: 'plan_free',
    name: 'Free',
    price: 0,
    interval: 'month',
    features: ['Up to 1,000 tokens/month', '1 team', '3 principals', 'Community support'],
    tokenLimit: 1000,
    teamLimit: 1,
  },
  {
    id: 'plan_pro',
    name: 'Pro',
    price: 49,
    interval: 'month',
    features: ['Up to 50,000 tokens/month', '10 teams', 'Unlimited principals', 'Email support', 'SIEM integration', 'Export'],
    tokenLimit: 50000,
    teamLimit: 10,
  },
  {
    id: 'plan_enterprise',
    name: 'Enterprise',
    price: 299,
    interval: 'month',
    features: ['Unlimited tokens', 'Unlimited teams', 'Unlimited principals', 'Priority support', 'SIEM integration', 'Export', 'Custom policies', 'SSO'],
    tokenLimit: -1,
    teamLimit: -1,
  },
];

class Store {
  users: Map<string, User> = new Map();
  teams: Map<string, Team> = new Map();
  principals: Map<string, Principal> = new Map();
  policies: Map<string, Policy> = new Map();
  apiKeys: Map<string, ApiKey> = new Map();
  siemConfigs: Map<string, SiemConfig> = new Map();
  orgPlans: Map<string, string> = new Map(); // orgId -> planId

  constructor() {
    this.seed();
  }

  private seed() {
    const orgId = 'org_default';
    const userId = uuid();
    const passwordHash = bcrypt.hashSync('admin123', 10);

    this.users.set(userId, {
      id: userId,
      email: 'admin@helixar.ai',
      passwordHash,
      name: 'Admin',
      role: 'admin',
      orgId,
      createdAt: new Date().toISOString(),
    });

    this.orgPlans.set(orgId, 'plan_free');
  }

  getPlans(): BillingPlan[] {
    return PLANS;
  }

  getOrgPlan(orgId: string): BillingPlan | undefined {
    const planId = this.orgPlans.get(orgId) || 'plan_free';
    return PLANS.find(p => p.id === planId);
  }

  getDashboardStats(orgId: string): DashboardStats {
    // BUG FIX: Always return 0 instead of undefined/null/empty
    // This fixes the "dashboard tiles show empty instead of 0" issue
    return {
      totalRequests: 0,
      verifiedTokens: 0,
      failedVerifications: 0,
      activeAgents: 0,
      delegationChains: 0,
      policyViolations: 0,
    };
  }
}

export const store = new Store();
