export interface Agent {
  agent_id: string;
  name: string;
  mission: string;
  is_killed: boolean;
  avg_alignment: number | null;
  last_event: string | null;
}

export interface AgentStatus {
  agent_id: string;
  is_killed: boolean;
  killed_at: string | null;
  killed_by: string | null;
  kill_reason: string | null;
}

export interface KillRequest {
  reason?: string;
  actor?: string;
}

export interface LogEntry {
  id: number;
  timestamp: string;
  agent_id: string;
  event_type: string;
  prompt_snippet: string;
  risk_score: number;
  alignment_score: number | null;
  judge_reason: string | null;
}

export interface KillAuditEntry {
  id: number;
  timestamp: string;
  agent_id: string;
  action: string;
  actor: string;
  reason: string;
}

export interface AlertEntry {
  id: string;
  timestamp: string;
  severity: string;
  event_type: string;
  agent_id: string;
  title: string;
  message: string;
  details: string;
  channel: string;
}

export interface AlertChannelInfo {
  name: string;
  enabled: boolean;
  min_severity: string;
}

export interface Session {
  id: string;
  started_at: string;
  agent_name: string | null;
  command: string | null;
}

export interface ToolEvent {
  id: number;
  session_id: string;
  timestamp: string;
  tool_name: string;
  args_json: string | null;
  result_json: string | null;
  duration_ms: number | null;
  status: string;
}

export interface Timeline {
  id: string;
  parent_id: string;
  session_id: string;
  status: string;
  branch_point: string;
  tool_name: string;
  description: string | null;
  created_at: string;
}

export interface ServiceHealth {
  service: string;
  status: string;
  error?: string;
}

export interface DiffSummary {
  filesAdded: number;
  filesModified: number;
  filesDeleted: number;
  totalInsertions: number;
  totalDeletions: number;
}

export interface PendingReview {
  id: string;
  session_id: string;
  tool_name: string;
  description: string | null;
  status: 'pending_review';
  created_at: string;
  diff: DiffSummary | null;
}

export interface ApiError {
  error: string;
  code: string;
}
