const API_BASE_URL = "http://127.0.0.1:5000/api";

export interface DashboardFinding {
  id: number;
  scan_id: number | null;
  vulnerability: string;
  severity: string;
  url: string;
  description: string;
  status: string;
  created_at: string | null;
}

export interface DashboardVulnerability {
  name: string;
  severity: string;
  count: number;
}

export interface DashboardTrendItem {
  scan_id: number;
  scan_name: string;
  findings: number;
  created_at: string | null;
}

export interface DashboardData {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  scan_status?: {
    completed: number;
    running: number;
    queued: number;
  };
  endpoint_coverage?: {
    discovered: number;
    scanned: number;
    pending: number;
  };
  recent_findings?: DashboardFinding[];
  top_vulnerabilities?: DashboardVulnerability[];
  findings_trend?: DashboardTrendItem[];
}

export interface HealthData {
  status: string;
  service: string;
  version: string;
}

export async function getDashboard(): Promise<DashboardData> {
  const response = await fetch(`${API_BASE_URL}/dashboard`);
  if (!response.ok) {
    throw new Error("Failed to fetch dashboard data");
  }
  return response.json();
}

export async function getHealth(): Promise<HealthData> {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) {
    throw new Error("Backend is unavailable");
  }
  return response.json();
}

export { API_BASE_URL };
