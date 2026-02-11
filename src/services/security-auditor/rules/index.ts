// ═══════════════════════════════════════════════════════════════════════════
// Security Rules Index
// Exports all security rules for the audit engine
// ═══════════════════════════════════════════════════════════════════════════

import { tlsSslRules } from './tls-ssl.rules';
import { wafRules } from './waf.rules';
import { originRules } from './origin.rules';
import { botDdosRules } from './bot-ddos.rules';
import { accessControlRules } from './access-control.rules';
import { loggingRules } from './logging.rules';
import type { SecurityRule } from '../types';

// Combine all rules
export const allRules: SecurityRule[] = [
  ...tlsSslRules,
  ...wafRules,
  ...originRules,
  ...botDdosRules,
  ...accessControlRules,
  ...loggingRules,
];

// Export individual rule sets for selective use
export {
  tlsSslRules,
  wafRules,
  originRules,
  botDdosRules,
  accessControlRules,
  loggingRules,
};

// Get rules by category
export const getRulesByCategory = (category: string): SecurityRule[] => {
  return allRules.filter(rule => rule.category === category);
};

// Get rules by object type
export const getRulesByObjectType = (objectType: string): SecurityRule[] => {
  return allRules.filter(rule => rule.appliesTo.includes(objectType as any));
};

// Get rule by ID
export const getRuleById = (id: string): SecurityRule | undefined => {
  return allRules.find(rule => rule.id === id);
};

// Rule statistics
export const getRuleStats = () => {
  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const byObjectType: Record<string, number> = {};

  for (const rule of allRules) {
    byCategory[rule.category] = (byCategory[rule.category] || 0) + 1;
    bySeverity[rule.severity] = (bySeverity[rule.severity] || 0) + 1;
    
    for (const objType of rule.appliesTo) {
      byObjectType[objType] = (byObjectType[objType] || 0) + 1;
    }
  }

  return {
    total: allRules.length,
    byCategory,
    bySeverity,
    byObjectType,
  };
};
