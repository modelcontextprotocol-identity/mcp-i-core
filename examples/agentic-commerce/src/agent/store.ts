import path from 'node:path';
import fs from 'node:fs';
import type { DelegationCredential } from '@kya-os/mcp';
import { VAR_DIR, readJson } from '../lib/wiring.js';
import { writeJsonAtomic } from '../lib/atomic-json.js';
import type { MerchantToolResult } from './authorization.js';
import type { ConsentChallenge } from '../lib/consent-contract.js';

export interface AgentState { credential?: DelegationCredential; pending?: ConsentChallenge; challengeResult?: MerchantToolResult }
export const AGENT_STATE_FILE = path.join(VAR_DIR, 'agent', 'state.json');
export const readAgentState = (): AgentState => {
  // Ignore the obsolete first-use token in older local state without requiring
  // a reset or a disk write after an order has already been accepted.
  const { resumeToken: _legacyToken, ...state } = readJson<AgentState & { resumeToken?: unknown }>(AGENT_STATE_FILE) ?? {};
  return state;
};
export const saveAgentState = (state: AgentState): void => writeJsonAtomic(AGENT_STATE_FILE, state);
export const clearAgentState = (): void => { fs.rmSync(AGENT_STATE_FILE, { force: true }); };
