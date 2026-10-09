import { useEffect, useState, type ReactNode } from "react";
import "./App.css";

import { jsPDF } from "jspdf";

import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Bell,
  Bot,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  Clock3,
  FileText,
  History,
  LayoutDashboard,
  Menu,
  Moon,
  Play,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Sun,
  Target,
  Terminal,
  X,
  Zap,
} from "lucide-react";

import {
  getDashboard,
  type DashboardData,
} from "./services/api";

type Page =
  | "dashboard"
  | "targets"
  | "vulnerabilities"
  | "reports"
  | "history"
  | "assistant"
  | "tools"
  | "documentation"
  | "settings";

type Scan = {
  id: number;
  target_url: string;
  scan_name: string;
  status: string;
  created_at: string | null;
};

type Finding = {
  id: number;
  vulnerability: string;
  severity: string;
  url: string;
  description: string;
  status: string;
  created_at: string | null;
};


const API_BASE_URL = "http://127.0.0.1:5000/api";

function getRecommendation(finding: Finding) {
  const name = finding.vulnerability.toLowerCase();

  if (name.includes("content security policy")) {
    return {
      impact: "A missing Content-Security-Policy can reduce protection against unwanted script execution.",
      recommendation: "Configure an appropriate Content-Security-Policy for the application.",
      owasp: "OWASP A05: Security Misconfiguration",
      confidence: "HIGH",
    };
  }

  if (name.includes("x-content-type-options")) {
    return {
      impact: "Without this header, browsers may perform MIME-type sniffing.",
      recommendation: "Configure X-Content-Type-Options: nosniff.",
      owasp: "OWASP A05: Security Misconfiguration",
      confidence: "HIGH",
    };
  }

  if (name.includes("x-frame-options")) {
    return {
      impact: "Missing frame restrictions can increase exposure to clickjacking risks.",
      recommendation: "Configure X-Frame-Options or an equivalent frame-ancestors policy.",
      owasp: "OWASP A05: Security Misconfiguration",
      confidence: "HIGH",
    };
  }

  if (name.includes("referrer-policy")) {
    return {
      impact: "An undefined Referrer-Policy may expose more referrer information than intended.",
      recommendation: "Configure an appropriate Referrer-Policy header.",
      owasp: "OWASP A05: Security Misconfiguration",
      confidence: "HIGH",
    };
  }

  if (name.includes("server information")) {
    return {
      impact: "Server response information may reveal implementation details useful during reconnaissance.",
      recommendation: "Minimize unnecessary Server header information.",
      owasp: "OWASP A05: Security Misconfiguration",
      confidence: "HIGH",
    };
  }

  if (name.includes("csrf")) {
    return {
      impact: "A POST form without an obvious CSRF token should be reviewed for cross-site request forgery protection.",
      recommendation: "Verify that state-changing requests use appropriate CSRF protection.",
      owasp: "OWASP A01: Broken Access Control",
      confidence: "MEDIUM",
    };
  }

  if (name.includes("xss") || name.includes("script")) {
    return {
      impact: "A script-related indicator may require manual verification for client-side injection risk.",
      recommendation: "Review the affected input and output handling and verify proper encoding.",
      owasp: "OWASP A03: Injection",
      confidence: "MEDIUM",
    };
  }

  return {
    impact: "This finding indicates a security condition that should be reviewed.",
    recommendation: "Review the affected endpoint and apply the recommended security control.",
    owasp: "OWASP security review",
    confidence: "LOW",
  };
}

function App() {
  const [page, setPage] = useState<Page>("dashboard");

  const [theme, setTheme] = useState<"light" | "dark">(() => {
    try {
      const saved = window.localStorage.getItem("shieldai_theme");
      return saved === "dark" ? "dark" : "light";
    } catch {
      return "light";
    }
  });

  useEffect(() => {
    try {
      window.localStorage.setItem("shieldai_theme", theme);
    } catch {
      // Ignore local storage errors.
    }

    document.documentElement.dataset.shieldaiTheme = theme;
    document.body.style.background =
      theme === "dark" ? "#0b1220" : "#f8fafc";
    document.body.style.color =
      theme === "dark" ? "#e5e7eb" : "#0f172a";
  }, [theme]);

  const [dashboard, setDashboard] =
    useState<DashboardData | null>(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [showNewScan, setShowNewScan] =
    useState(false);

  const [targetUrl, setTargetUrl] =
    useState("");

  const [scanName, setScanName] =
    useState("");

  const [scanMode, setScanMode] =
    useState<"Quick" | "Standard" | "Deep">("Standard");

  const [authorized, setAuthorized] =
    useState(false);

  const [safeScan, setSafeScan] =
    useState(true);

  const [requestTimeout, setRequestTimeout] =
    useState<string>(() => {
      try {
        return window.localStorage.getItem("shieldai_request_timeout") || "8";
      } catch {
        return "8";
      }
    });

  useEffect(() => {
    try {
      window.localStorage.setItem("shieldai_request_timeout", requestTimeout);
    } catch {
      // Ignore local storage errors.
    }
  }, [requestTimeout]);

  const [scanLoading, setScanLoading] =
    useState(false);

  const [scanMessage, setScanMessage] =
    useState("");

  const [scans, setScans] =
    useState<Scan[]>([]);

  const [historyLoading, setHistoryLoading] =
    useState(false);

  const [historyError, setHistoryError] =
    useState("");

  const [findings, setFindings] =
    useState<Finding[]>([]);

  const [findingsLoading, setFindingsLoading] =
    useState(false);

  const [findingsError, setFindingsError] =
    useState("");

  const [severityFilter, setSeverityFilter] =
    useState("ALL");

  const [selectedReportScanId, setSelectedReportScanId] =
    useState<number | null>(null);

  const [reportLoading, setReportLoading] =
    useState(false);

  const [reportError, setReportError] =
    useState("");

  const [backendCheckLoading, setBackendCheckLoading] =
    useState(false);

  const [backendCheckResult, setBackendCheckResult] =
    useState("");

  const [inventoryLoading, setInventoryLoading] =
    useState(false);

  const [inventoryResult, setInventoryResult] =
    useState("");

  // --------------------------------------------------
  // DASHBOARD
  // --------------------------------------------------

  const loadDashboard = () => {
    setLoading(true);

    getDashboard()
      .then((data) => {
        console.log(
          "Dashboard data:",
          data
        );

        setDashboard(data);
        setError("");
      })
      .catch((err) => {
        console.error(
          "Dashboard error:",
          err
        );

        setError(
          "Unable to connect to ShieldAI backend"
        );
      })
      .finally(() => {
        setLoading(false);
      });
  };

  // --------------------------------------------------
  // SCAN HISTORY
  // --------------------------------------------------

  const loadScanHistory = async () => {
    setHistoryLoading(true);
    setHistoryError("");

    try {
      const response = await fetch(
        `${API_BASE_URL}/scans`
      );

      if (!response.ok) {
        throw new Error(
          "Failed to load scan history"
        );
      }

      const data =
        await response.json();

      console.log(
        "Scan history:",
        data
      );

      setScans(data.scans || []);
    } catch (err) {
      console.error(
        "Scan history error:",
        err
      );

      setHistoryError(
        "Unable to load scan history from backend."
      );
    } finally {
      setHistoryLoading(false);
    }
  };

  // --------------------------------------------------
  // FINDINGS
  // --------------------------------------------------

  const loadFindings = async () => {
    setFindingsLoading(true);
    setFindingsError("");

    try {
      const response = await fetch(
        `${API_BASE_URL}/findings`
      );

      if (!response.ok) {
        throw new Error(
          "Failed to load findings"
        );
      }

      const data =
        await response.json();

      console.log(
        "Findings:",
        data
      );

      setFindings(data.findings || []);
    } catch (err) {
      console.error(
        "Findings error:",
        err
      );

      setFindingsError(
        "Unable to load findings from backend."
      );
    } finally {
      setFindingsLoading(false);
    }
  };

  // --------------------------------------------------
  // REPORT DATA
  // --------------------------------------------------

  const loadReportData = async () => {
    setReportLoading(true);
    setReportError("");

    try {
      const scansResponse = await fetch(
        `${API_BASE_URL}/scans`
      );

      if (!scansResponse.ok) {
        throw new Error(
          "Failed to load scans for report"
        );
      }

      const scansData =
        await scansResponse.json();

      const availableScans: Scan[] =
        scansData.scans || [];

      setScans(availableScans);

      if (availableScans.length === 0) {
        setFindings([]);
        setSelectedReportScanId(null);
        return;
      }

      const scanExists =
        selectedReportScanId !== null &&
        availableScans.some(
          (scan) =>
            scan.id === selectedReportScanId
        );

      const scanId = scanExists
        ? selectedReportScanId!
        : availableScans[0].id;

      setSelectedReportScanId(scanId);

      const findingsResponse =
        await fetch(
          `${API_BASE_URL}/scans/${scanId}/findings`
        );

      if (!findingsResponse.ok) {
        throw new Error(
          "Failed to load scan findings"
        );
      }

      const findingsData =
        await findingsResponse.json();

      setFindings(
        findingsData.findings || []
      );
    } catch (err) {
      console.error(
        "Report loading error:",
        err
      );

      setReportError(
        "Unable to load report data from backend."
      );

      setFindings([]);
    } finally {
      setReportLoading(false);
    }
  };

  const handleReportScanChange = async (
    scanId: number
  ) => {
    setSelectedReportScanId(scanId);
    setReportLoading(true);
    setReportError("");

    try {
      const response = await fetch(
        `${API_BASE_URL}/scans/${scanId}/findings`
      );

      if (!response.ok) {
        throw new Error(
          "Failed to load selected scan"
        );
      }

      const data =
        await response.json();

      setFindings(
        data.findings || []
      );
    } catch (err) {
      console.error(
        "Selected report scan error:",
        err
      );

      setReportError(
        "Unable to load findings for the selected scan."
      );
      setFindings([]);
    } finally {
      setReportLoading(false);
    }
  };

  // --------------------------------------------------
  // EFFECTS
  // --------------------------------------------------

  useEffect(() => {
    loadDashboard();
  }, []);

  useEffect(() => {
    if (page === "history") {
      loadScanHistory();
    }

    if (
      page === "vulnerabilities" ||
      page === "reports" ||
      page === "assistant"
    ) {
      loadFindings();
    }

    if (page === "reports") {
      loadReportData();
    }
  }, [page]);

  // --------------------------------------------------
  // NAVIGATION
  // --------------------------------------------------

  const navigateTo = (nextPage: Page) => {
    setPage(nextPage);
  };

  // --------------------------------------------------
  // NEW SCAN
  // --------------------------------------------------

  const openNewScan = () => {
    setScanMessage("");
    setScanMode("Standard");
    setAuthorized(false);
    setSafeScan(true);
    setShowNewScan(true);
  };

  const closeNewScan = () => {
    if (scanLoading) {
      return;
    }

    setShowNewScan(false);
    setScanMessage("");
  };

  const handleStartScan = async () => {
    setScanMessage("");

    if (!targetUrl.trim()) {
      setScanMessage(
        "Please enter a target URL."
      );
      return;
    }

    if (!authorized) {
      setScanMessage(
        "Please confirm that you are authorized to test this target."
      );
      return;
    }

    setScanLoading(true);

    try {
      const response = await fetch(
        `${API_BASE_URL}/scans`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            target_url:
              targetUrl.trim(),
            scan_name:
              scanName.trim() ||
              "ShieldAI Scan",
            scan_mode: scanMode,
            safe_mode: safeScan,
            authorized: true,
          }),
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        setScanMessage(
          data.error ||
            "Unable to create scan."
        );
        return;
      }

      setScanMessage(
        `Scan #${data.scan.id} created successfully. Status: ${data.scan.status}`
      );

      setTargetUrl("");
      setScanName("");

      loadDashboard();

      setTimeout(() => {
        loadDashboard();
        loadScanHistory();
        loadFindings();
      }, 2000);
    } catch (err) {
      console.error(
        "Scan creation error:",
        err
      );

      setScanMessage(
        "Unable to connect to ShieldAI backend."
      );
    } finally {
      setScanLoading(false);
    }
  };

  // --------------------------------------------------
  // DASHBOARD VALUES
  // --------------------------------------------------

  const critical =
    dashboard?.critical ?? 0;

  const high =
    dashboard?.high ?? 0;

  const medium =
    dashboard?.medium ?? 0;

  const low =
    dashboard?.low ?? 0;

  const total =
    dashboard?.total ?? 0;

  const completed =
    dashboard?.scan_status?.completed ??
    0;

  const running =
    dashboard?.scan_status?.running ??
    0;

  const queued =
    dashboard?.scan_status?.queued ??
    0;

  const discovered =
    dashboard?.endpoint_coverage
      ?.discovered ?? 0;

  const scanned =
    dashboard?.endpoint_coverage
      ?.scanned ?? 0;

  const pending =
    dashboard?.endpoint_coverage
      ?.pending ?? 0;

  const coverage =
    discovered > 0
      ? Math.round(
          (scanned / discovered) * 100
        )
      : 0;

  const dashboardVulnerabilities =
    dashboard?.top_vulnerabilities ?? [];

  const dashboardRecentFindings =
    dashboard?.recent_findings ?? [];

  const dashboardTrend =
    dashboard?.findings_trend ?? [];

  const trendValues = dashboardTrend.map(
    (item) => item.findings
  );

  const trendMax = Math.max(
    ...trendValues,
    1
  );

  const trendPoints = dashboardTrend.length > 0
    ? dashboardTrend.map((item, index) => {
        const x = dashboardTrend.length === 1
          ? 360
          : 50 +
            (620 * index) /
              (dashboardTrend.length - 1);

        const y =
          180 -
          (item.findings / trendMax) *
            130;

        return `${x},${y}`;
      }).join(' ')
    : '50,180 670,180';

  const latestScan =
    dashboardTrend.length > 0
      ? dashboardTrend[dashboardTrend.length - 1]
      : null;

  // --------------------------------------------------
  // SIDEBAR BUTTON
  // --------------------------------------------------

  const renderSidebarButton = (
    targetPage: Page,
    icon: ReactNode,
    label: string
  ) => {
    return (
      <button
        className={`nav-item ${
          page === targetPage
            ? "active"
            : ""
        }`}
        onClick={() =>
          navigateTo(targetPage)
        }
      >
        {icon}
        <span>{label}</span>
      </button>
    );
  };

  // --------------------------------------------------
  // DASHBOARD PAGE
  // --------------------------------------------------

  const renderDashboard = () => {
    return (
      <section className="content">

        <div className="page-heading">
          <div>
            <p className="eyebrow">
              SECURITY OVERVIEW
            </p>

            <h2>
              Dashboard
            </h2>

            <p>
              Monitor your web application
              security posture.
            </p>

            <div
              className={
                error
                  ? "backend-status offline"
                  : "backend-status"
              }
            >
              <span />

              {error
                ? "Backend Offline"
                : "Backend Connected"}
            </div>
          </div>

          <button
            className="secondary-button"
            onClick={loadDashboard}
          >
            <Activity size={14} />
            Refresh
          </button>
        </div>

        <div className="metrics">

          <div className="metric critical">
            <div className="metric-top">
              <div className="metric-icon">
                <AlertCircle size={16} />
              </div>

              Critical
            </div>

            <strong>
              {loading
                ? "..."
                : critical}
            </strong>

            <div className="metric-bottom">
              <b>Findings</b>
              <span>
                requiring attention
              </span>
            </div>
          </div>

          <div className="metric high">
            <div className="metric-top">
              <div className="metric-icon">
                <AlertTriangle size={16} />
              </div>

              High
            </div>

            <strong>
              {loading
                ? "..."
                : high}
            </strong>

            <div className="metric-bottom">
              <b>Findings</b>
              <span>
                high priority
              </span>
            </div>
          </div>

          <div className="metric medium">
            <div className="metric-top">
              <div className="metric-icon">
                <AlertTriangle size={16} />
              </div>

              Medium
            </div>

            <strong>
              {loading
                ? "..."
                : medium}
            </strong>

            <div className="metric-bottom">
              <b>Findings</b>
              <span>
                medium priority
              </span>
            </div>
          </div>

          <div className="metric low">
            <div className="metric-top">
              <div className="metric-icon">
                <CheckCircle2 size={16} />
              </div>

              Low
            </div>

            <strong>
              {loading
                ? "..."
                : low}
            </strong>

            <div className="metric-bottom">
              <b>Findings</b>
              <span>
                low priority
              </span>
            </div>
          </div>

          <div className="metric total">
            <div className="metric-top">
              <div className="metric-icon">
                <Shield size={16} />
              </div>

              Total Findings
            </div>

            <strong>
              {loading
                ? "..."
                : total}
            </strong>

            <div className="metric-bottom">
              <b>Database</b>
              <span>
                current findings
              </span>
            </div>
          </div>

        </div>

        <div className="dashboard-grid">

          <div className="card chart-card">

            <div className="card-header">
              <div>
                <h3>
                  Findings Trend
                </h3>

                <p>
                  Security findings over
                  recent scans
                </p>
              </div>

              <button className="dropdown-button">
                Last 7 scans
                <ChevronDown size={13} />
              </button>
            </div>

            <div className="chart">

              <svg
                viewBox="0 0 700 220"
                width="100%"
                height="100%"
              >

                <line
                  x1="40"
                  y1="180"
                  x2="680"
                  y2="180"
                  stroke="#e5e7eb"
                />

                <line
                  x1="40"
                  y1="135"
                  x2="680"
                  y2="135"
                  stroke="#eef2f7"
                />

                <line
                  x1="40"
                  y1="90"
                  x2="680"
                  y2="90"
                  stroke="#eef2f7"
                />

                <line
                  x1="40"
                  y1="45"
                  x2="680"
                  y2="45"
                  stroke="#eef2f7"
                />

                <polyline
                  fill="none"
                  stroke="#2563eb"
                  strokeWidth="3"
                  points={trendPoints}
                />

              </svg>

            </div>

          </div>

          <div className="card scan-status-card">

            <div className="card-header">
              <div>
                <h3>
                  Scan Status
                </h3>

                <p>
                  Current scan activity
                </p>
              </div>
            </div>

            <div className="scan-status">

              <div className="donut">

                <div>
                  <strong>
                    {completed}
                  </strong>

                  <span>
                    completed
                  </span>
                </div>

              </div>

              <div className="status-list">

                <div className="status-item">
                  <span>
                    <i />
                    Completed
                  </span>

                  <strong>
                    {completed}
                  </strong>
                </div>

                <div className="status-item">
                  <span>
                    <i />
                    Running
                  </span>

                  <strong>
                    {running}
                  </strong>
                </div>

                <div className="status-item">
                  <span>
                    <i />
                    Queued
                  </span>

                  <strong>
                    {queued}
                  </strong>
                </div>

              </div>

            </div>

            <div className="last-scan">
              <Clock3 size={13} />
              {latestScan
                ? `Latest: ${latestScan.scan_name} — ${latestScan.findings} findings`
                : "No scan information available"}
            </div>

          </div>

        </div>

        <div className="card ai-card">

          <div className="ai-icon">
            <Bot size={23} />
          </div>

          <div className="ai-content">

            <div className="ai-title">

              <h3>
                ShieldAI Analysis
              </h3>

              <span>
                RULE-BASED AI
              </span>

            </div>

            <p>
              AI-assisted analysis classifies,
              prioritizes and explains security
              findings based on scanner results.
              Recommendations are generated for
              authorized defensive testing.
            </p>

            <div className="ai-tags">

              <span>
                Severity Classification
              </span>

              <span>
                Confidence Analysis
              </span>

              <span>
                OWASP Mapping
              </span>

            </div>

          </div>

          <button
            className="ai-button"
            onClick={() =>
              navigateTo("vulnerabilities")
            }
          >
            View Analysis
          </button>

        </div>

        <div className="dashboard-grid">

          <div className="card">

            <div className="card-header">

              <div>

                <h3>
                  Top Vulnerability Types
                </h3>

                <p>
                  Findings grouped by
                  vulnerability type
                </p>

              </div>

              <button
                className="text-button"
                onClick={() =>
                  navigateTo(
                    "vulnerabilities"
                  )
                }
              >
                View all
              </button>

            </div>

            <div className="vulnerability-list">

              {dashboardVulnerabilities.length === 0 ? (
                <div
                  style={{
                    padding: "25px 0",
                    color: "#64748b",
                    textAlign: "center",
                  }}
                >
                  No vulnerability data available.
                </div>
              ) : (
                dashboardVulnerabilities.map(
                  (item, index) => (
                    <div
                      className="vulnerability-row"
                      key={`${item.name}-${index}`}
                    >

                      <div className="vulnerability-icon">
                        <Shield size={15} />
                      </div>

                      <div className="vulnerability-info">

                        <strong>
                          {item.name}
                        </strong>

                        <div className="progress">

                          <span
                            style={{
                              width: `${Math.min(
                                (item.count / Math.max(dashboardVulnerabilities[0]?.count ?? 1, 1)) * 100,
                                100
                              )}%`,
                            }}
                          />

                        </div>

                      </div>

                      <span
                        className={`severity ${String(item.severity).toLowerCase()}`}
                      >
                        {String(item.severity).toUpperCase()}
                      </span>

                    </div>
                  )
                )
              )}

            </div>

          </div>

          <div className="card">

            <div className="card-header">

              <div>

                <h3>
                  Endpoint Coverage
                </h3>

                <p>
                  Discovery and scan coverage
                </p>

              </div>

            </div>

            <div className="coverage-number">

              <strong>
                {coverage}%
              </strong>

              <span>
                endpoints scanned
              </span>

            </div>

            <div className="coverage-bar">

              <span
                style={{
                  width: `${coverage}%`,
                }}
              />

            </div>

            <div className="coverage-details">

              <div>
                <strong>
                  {discovered}
                </strong>

                <span>
                  Discovered
                </span>
              </div>

              <div>
                <strong>
                  {scanned}
                </strong>

                <span>
                  Scanned
                </span>
              </div>

              <div>
                <strong>
                  {pending}
                </strong>

                <span>
                  Pending
                </span>
              </div>

            </div>

            <div className="headers-check">

              <CheckCircle2 size={18} />

              <div>

                <strong>
                  Security Headers
                </strong>

                <span>
                  Header analysis available
                </span>

              </div>

              <b>
                ✓
              </b>

            </div>

          </div>

        </div>

        <div className="card recent-card">

          <div className="card-header">

            <div>

              <h3>
                Recent Findings
              </h3>

              <p>
                Latest security findings
                from the database
              </p>

            </div>

            <button
              className="text-button"
              onClick={() =>
                navigateTo(
                  "vulnerabilities"
                )
              }
            >
              View all findings
            </button>

          </div>

          <div className="table">

            <div className="table-head">
              <span>Finding</span>
              <span>Severity</span>
              <span>URL</span>
              <span>Status</span>
            </div>

            {dashboardRecentFindings.length === 0 ? (
              <div
                style={{
                  padding: "35px",
                  textAlign: "center",
                  color: "#64748b",
                }}
              >
                No recent findings available.
              </div>
            ) : (
              dashboardRecentFindings.map(
                (finding, index) => (

                  <div
                    className="table-row"
                    key={finding.id ?? index}
                  >

                    <strong>
                      {finding.vulnerability}
                    </strong>

                    <span
                      className={`severity ${String(finding.severity).toLowerCase()}`}
                    >
                      {String(finding.severity).toUpperCase()}
                    </span>

                    <code>
                      {finding.url}
                    </code>

                    <span className="finding-status">
                      {finding.status}
                    </span>

                  </div>

                )
              )
            )}

          </div>

        </div>

      </section>
    );
  };

  // --------------------------------------------------
  // VULNERABILITIES PAGE
  // --------------------------------------------------

  const renderVulnerabilities = () => {
    const filteredFindings =
      severityFilter === "ALL"
        ? findings
        : findings.filter(
            (finding) =>
              finding.severity.toUpperCase() ===
              severityFilter
          );

    return (
      <section className="content">

        <div className="page-heading">

          <div>

            <p className="eyebrow">
              SECURITY FINDINGS
            </p>

            <h2>
              Vulnerabilities
            </h2>

            <p>
              Review security findings
              detected by ShieldAI.
            </p>

          </div>

          <button
            className="secondary-button"
            onClick={loadFindings}
          >
            <Activity size={14} />
            Refresh
          </button>

        </div>

        <div className="metrics">

          <div className="metric critical">

            <div className="metric-top">
              <div className="metric-icon">
                <AlertCircle size={16} />
              </div>
              Critical
            </div>

            <strong>
              {
                findings.filter(
                  (finding) =>
                    finding.severity.toUpperCase() ===
                    "CRITICAL"
                ).length
              }
            </strong>

            <div className="metric-bottom">
              <span>
                Critical findings
              </span>
            </div>

          </div>

          <div className="metric high">

            <div className="metric-top">
              <div className="metric-icon">
                <AlertTriangle size={16} />
              </div>
              High
            </div>

            <strong>
              {
                findings.filter(
                  (finding) =>
                    finding.severity.toUpperCase() ===
                    "HIGH"
                ).length
              }
            </strong>

            <div className="metric-bottom">
              <span>
                High findings
              </span>
            </div>

          </div>

          <div className="metric medium">

            <div className="metric-top">
              <div className="metric-icon">
                <AlertTriangle size={16} />
              </div>
              Medium
            </div>

            <strong>
              {
                findings.filter(
                  (finding) =>
                    finding.severity.toUpperCase() ===
                    "MEDIUM"
                ).length
              }
            </strong>

            <div className="metric-bottom">
              <span>
                Medium findings
              </span>
            </div>

          </div>

          <div className="metric low">

            <div className="metric-top">
              <div className="metric-icon">
                <CheckCircle2 size={16} />
              </div>
              Low
            </div>

            <strong>
              {
                findings.filter(
                  (finding) =>
                    finding.severity.toUpperCase() ===
                    "LOW"
                ).length
              }
            </strong>

            <div className="metric-bottom">
              <span>
                Low findings
              </span>
            </div>

          </div>

          <div className="metric total">

            <div className="metric-top">
              <div className="metric-icon">
                <Shield size={16} />
              </div>
              Total
            </div>

            <strong>
              {findings.length}
            </strong>

            <div className="metric-bottom">
              <span>
                Database findings
              </span>
            </div>

          </div>

        </div>

        <div className="card recent-card">

          <div className="card-header">

            <div>

              <h3>
                Detected Findings
              </h3>

              <p>
                Findings returned by the
                ShieldAI backend scanner.
              </p>

            </div>

            <select
              value={severityFilter}
              onChange={(event) =>
                setSeverityFilter(
                  event.target.value
                )
              }
              style={{
                padding: "10px 14px",
                border:
                  "1px solid #dbe3ef",
                borderRadius: "8px",
                background: "#ffffff",
                color: "#334155",
                cursor: "pointer",
              }}
            >

              <option value="ALL">
                All Severities
              </option>

              <option value="CRITICAL">
                Critical
              </option>

              <option value="HIGH">
                High
              </option>

              <option value="MEDIUM">
                Medium
              </option>

              <option value="LOW">
                Low
              </option>

            </select>

          </div>

          {findingsLoading ? (

            <div
              style={{
                padding: "50px",
                textAlign: "center",
              }}
            >
              Loading vulnerabilities...
            </div>

          ) : findingsError ? (

            <div
              style={{
                padding: "50px",
                textAlign: "center",
              }}
            >
              {findingsError}
            </div>

          ) : filteredFindings.length === 0 ? (

            <div
              style={{
                padding: "50px",
                textAlign: "center",
              }}
            >
              No findings found.
            </div>

          ) : (

            <div className="table">

              <div className="table-head">

                <span>
                  Vulnerability
                </span>

                <span>
                  Severity
                </span>

                <span>
                  URL
                </span>

                <span>
                  Status
                </span>

              </div>

              {filteredFindings.map(
                (finding) => (

                  <div
                    className="table-row"
                    key={finding.id}
                    style={{
                      alignItems:
                        "flex-start",
                    }}
                  >

                    <div>

                      <strong>
                        {finding.vulnerability}
                      </strong>

                      {finding.description && (

                        <div
                          style={{
                            marginTop: "6px",
                            fontSize: "12px",
                            color:
                              "#64748b",
                            lineHeight: 1.5,
                          }}
                        >
                          {finding.description}
                        </div>

                      )}

                    </div>

                    <span
                      className={`severity ${finding.severity.toLowerCase()}`}
                    >
                      {finding.severity}
                    </span>

                    <code>
                      {finding.url}
                    </code>

                    <span className="finding-status">
                      {finding.status}
                    </span>

                  </div>

                )
              )}

            </div>

          )}

        </div>

      </section>
    );
  };

  // --------------------------------------------------
  // REPORTS PAGE
  // --------------------------------------------------

  const renderReports = () => {
    const reportScan =
      scans.find(
        (scan) =>
          scan.id === selectedReportScanId
      ) || null;

    const criticalCount =
      findings.filter(
        (finding) =>
          finding.severity.toUpperCase() ===
          "CRITICAL"
      ).length;

    const highCount =
      findings.filter(
        (finding) =>
          finding.severity.toUpperCase() ===
          "HIGH"
      ).length;

    const mediumCount =
      findings.filter(
        (finding) =>
          finding.severity.toUpperCase() ===
          "MEDIUM"
      ).length;

    const lowCount =
      findings.filter(
        (finding) =>
          finding.severity.toUpperCase() ===
          "LOW"
      ).length;

    const generateHTMLReport = () => {
      const escapeHTML = (value: string) =>
        value
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;");

      const rows = findings
        .map((finding) => {
          const analysis = getRecommendation(finding);

          return `
            <tr>
              <td>${escapeHTML(finding.vulnerability)}</td>
              <td>${escapeHTML(finding.severity.toUpperCase())}</td>
              <td>${escapeHTML(analysis.confidence ?? "MEDIUM")}</td>
              <td>${escapeHTML(analysis.owasp)}</td>
              <td>${escapeHTML(finding.url)}</td>
              <td>${escapeHTML(finding.status)}</td>
              <td>${escapeHTML(analysis.impact)}</td>
              <td>${escapeHTML(analysis.recommendation)}</td>
              <td>${escapeHTML(finding.description || "")}</td>
            </tr>
          `;
        })
        .join("");

      const html = `
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>ShieldAI Security Report</title>

<style>

body {
  font-family: Arial, sans-serif;
  margin: 40px;
  color: #0f172a;
  background: #ffffff;
}

h1 {
  color: #1d4ed8;
}

.subtitle {
  color: #64748b;
}

.summary {
  display: grid;
  grid-template-columns:
    repeat(5, 1fr);
  gap: 15px;
  margin: 30px 0;
}

.summary-box {
  border: 1px solid #dbe3ef;
  border-radius: 10px;
  padding: 20px;
}

.summary-box h2 {
  margin: 8px 0 0;
}

table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 25px;
}

th,
td {
  border: 1px solid #dbe3ef;
  padding: 12px;
  text-align: left;
  vertical-align: top;
}

th {
  background: #f8fafc;
}

.footer {
  margin-top: 40px;
  color: #64748b;
  font-size: 12px;
}

</style>

</head>

<body>

<h1>
ShieldAI Security Report
</h1>

<p class="subtitle">
Web Application Penetration Testing Toolkit with AI
</p>

<p>
<strong>Scan:</strong>
${reportScan ? escapeHTML(reportScan.scan_name) : "No scan selected"}
</p>

<p>
<strong>Target:</strong>
${reportScan ? escapeHTML(reportScan.target_url) : "No target selected"}
</p>

<p>
<strong>Scan ID:</strong>
${reportScan ? reportScan.id : "-"}
</p>

<p>
<strong>Generated:</strong>
${new Date().toLocaleString()}
</p>

<div class="summary">

<div class="summary-box">
<strong>Critical</strong>
<h2>${criticalCount}</h2>
</div>

<div class="summary-box">
<strong>High</strong>
<h2>${highCount}</h2>
</div>

<div class="summary-box">
<strong>Medium</strong>
<h2>${mediumCount}</h2>
</div>

<div class="summary-box">
<strong>Low</strong>
<h2>${lowCount}</h2>
</div>

<div class="summary-box">
<strong>Total</strong>
<h2>${findings.length}</h2>
</div>

</div>

<h2>
Security Findings
</h2>

<table>

<thead>

<tr>
<th>Vulnerability</th>
<th>Severity</th>
<th>Confidence</th>
<th>OWASP</th>
<th>URL</th>
<th>Status</th>
<th>Impact</th>
<th>Recommendation</th>
<th>Scanner Description</th>
</tr>

</thead>

<tbody>

${rows}

</tbody>

</table>

<div class="footer">

Generated by ShieldAI for
authorized defensive security testing.

</div>

</body>

</html>
`;

      const blob = new Blob(
        [html],
        {
          type: "text/html",
        }
      );

      const url =
        URL.createObjectURL(blob);

      const link =
        document.createElement("a");

      link.href = url;

      link.download =
        `ShieldAI-Scan-${reportScan?.id ?? "Report"}.html`;

      document.body.appendChild(link);

      link.click();

      document.body.removeChild(link);

      URL.revokeObjectURL(url);
    };


    const generatePDFReport = () => {
      if (!reportScan || findings.length === 0) {
        window.alert("Select a scan with findings before generating the PDF report.");
        return;
      }

      const criticalCount = findings.filter(
        (finding) => finding.severity.toUpperCase() === "CRITICAL"
      ).length;
      const highCount = findings.filter(
        (finding) => finding.severity.toUpperCase() === "HIGH"
      ).length;
      const mediumCount = findings.filter(
        (finding) => finding.severity.toUpperCase() === "MEDIUM"
      ).length;
      const lowCount = findings.filter(
        (finding) => finding.severity.toUpperCase() === "LOW"
      ).length;

      const doc = new jsPDF({
        orientation: "portrait",
        unit: "mm",
        format: "a4",
      });

      const pageWidth = doc.internal.pageSize.getWidth();
      const pageHeight = doc.internal.pageSize.getHeight();
      const left = 16;
      const right = 16;
      const contentWidth = pageWidth - left - right;
      let y = 18;

      const ensureSpace = (needed: number) => {
        if (y + needed > pageHeight - 15) {
          doc.addPage();
          y = 18;
        }
      };

      const addWrapped = (
        text: string,
        options: {
          size?: number;
          bold?: boolean;
          indent?: number;
          spacingAfter?: number;
        } = {}
      ) => {
        const size = options.size ?? 9;
        const indent = options.indent ?? 0;
        const spacingAfter = options.spacingAfter ?? 2;
        doc.setFont("helvetica", options.bold ? "bold" : "normal");
        doc.setFontSize(size);
        const lines = doc.splitTextToSize(
          String(text || "-"),
          contentWidth - indent
        ) as string[];
        const lineHeight = size * 0.42 + 1.8;
        ensureSpace(lines.length * lineHeight + spacingAfter);
        doc.text(lines, left + indent, y);
        y += lines.length * lineHeight + spacingAfter;
      };

      doc.setFont("helvetica", "bold");
      doc.setFontSize(20);
      doc.text("ShieldAI - Security Assessment Report", left, y);
      y += 8;

      addWrapped(
        "Web Application Penetration Testing Toolkit with AI",
        { size: 10, spacingAfter: 7 }
      );

      addWrapped(`Scan: ${reportScan.scan_name}`, { size: 9 });
      addWrapped(`Scan ID: #${reportScan.id}`, { size: 9 });
      addWrapped(`Target: ${reportScan.target_url}`, { size: 9 });
      addWrapped(`Generated: ${new Date().toLocaleString()}`, {
        size: 9,
        spacingAfter: 5,
      });

      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      ensureSpace(10);
      doc.text("Summary", left, y);
      y += 6;

      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      ensureSpace(12);
      doc.text(
        `Critical: ${criticalCount}   High: ${highCount}   Medium: ${mediumCount}   Low: ${lowCount}   Total: ${findings.length}`,
        left,
        y
      );
      y += 10;

      doc.setFont("helvetica", "bold");
      doc.setFontSize(12);
      ensureSpace(10);
      doc.text("Findings and AI-Assisted Analysis", left, y);
      y += 7;

      findings.forEach((finding, index) => {
        const analysis = getRecommendation(finding);
        const confidence = analysis.confidence ?? "MEDIUM";

        ensureSpace(24);
        doc.setFont("helvetica", "bold");
        doc.setFontSize(11);
        doc.text(`Finding ${index + 1}: ${finding.vulnerability}`, left, y);
        y += 5.5;

        addWrapped(`Severity: ${finding.severity.toUpperCase()}`, { size: 8.5 });
        addWrapped(`Status: ${finding.status}`, { size: 8.5 });
        addWrapped(`Confidence: ${confidence}`, { size: 8.5 });
        addWrapped(`OWASP: ${analysis.owasp}`, { size: 8.5 });
        addWrapped(`URL: ${finding.url}`, { size: 8.5, spacingAfter: 3 });

        addWrapped("Impact", { size: 8.5, bold: true, spacingAfter: 1 });
        addWrapped(analysis.impact, { size: 8.5, indent: 4, spacingAfter: 2 });

        addWrapped("Recommendation", { size: 8.5, bold: true, spacingAfter: 1 });
        addWrapped(analysis.recommendation, {
          size: 8.5,
          indent: 4,
          spacingAfter: 2,
        });

        addWrapped("Scanner Description", {
          size: 8.5,
          bold: true,
          spacingAfter: 1,
        });
        addWrapped(
          finding.description || "No scanner description provided.",
          { size: 8.5, indent: 4, spacingAfter: 5 }
        );

        doc.setDrawColor(225, 231, 239);
        doc.line(left, y, pageWidth - right, y);
        y += 5;
      });

      ensureSpace(22);
      doc.setFont("helvetica", "italic");
      doc.setFontSize(7.5);
      const disclaimer =
        "Authorized defensive testing only. Scanner results are evidence for review and do not by themselves establish exploitability or impact. Manual verification may be required.";
      const disclaimerLines = doc.splitTextToSize(
        disclaimer,
        contentWidth
      ) as string[];
      doc.text(disclaimerLines, left, y);

      const pageCount = doc.getNumberOfPages();
      for (let page = 1; page <= pageCount; page += 1) {
        doc.setPage(page);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(7);
        doc.setTextColor(100, 116, 139);
        doc.text(
          `ShieldAI | Page ${page} of ${pageCount}`,
          pageWidth - right,
          pageHeight - 8,
          { align: "right" }
        );
        doc.setTextColor(15, 23, 42);
      }

      doc.save(`ShieldAI-Scan-${reportScan.id}.pdf`);
    };

    return (
      <section className="content">

        <div className="page-heading">

          <div>

            <p className="eyebrow">
              SECURITY REPORTING
            </p>

            <h2>
              Reports
            </h2>

            <p>
              Generate a report for a specific
              ShieldAI scan.
            </p>

          </div>

          <button
            className="secondary-button"
            onClick={loadReportData}
          >
            <Activity size={14} />
            Refresh
          </button>

        </div>

        <div className="card">

          <div className="card-header">

            <div>
              <h3>
                Select Scan
              </h3>

              <p>
                Report data is loaded only for
                the selected scan.
              </p>
            </div>

            <select
              value={
                selectedReportScanId ?? ""
              }
              onChange={(event) =>
                handleReportScanChange(
                  Number(
                    event.target.value
                  )
                )
              }
              disabled={
                reportLoading ||
                scans.length === 0
              }
              style={{
                padding: "10px 14px",
                border:
                  "1px solid #dbe3ef",
                borderRadius: "8px",
                background: "#ffffff",
                color: "#334155",
                cursor: "pointer",
                minWidth: "260px",
              }}
            >

              {scans.length === 0 ? (

                <option value="">
                  No scans available
                </option>

              ) : (

                scans.map((scan) => (
                  <option
                    key={scan.id}
                    value={scan.id}
                  >
                    #{scan.id} — {scan.scan_name}
                  </option>
                ))

              )}

            </select>

          </div>

        </div>

        <div className="metrics">

          <div className="metric critical">

            <div className="metric-top">
              <div className="metric-icon">
                <AlertCircle size={16} />
              </div>
              Critical
            </div>

            <strong>
              {criticalCount}
            </strong>

            <div className="metric-bottom">
              <span>
                Critical findings
              </span>
            </div>

          </div>

          <div className="metric high">

            <div className="metric-top">
              <div className="metric-icon">
                <AlertTriangle size={16} />
              </div>
              High
            </div>

            <strong>
              {highCount}
            </strong>

            <div className="metric-bottom">
              <span>
                High findings
              </span>
            </div>

          </div>

          <div className="metric medium">

            <div className="metric-top">
              <div className="metric-icon">
                <AlertTriangle size={16} />
              </div>
              Medium
            </div>

            <strong>
              {mediumCount}
            </strong>

            <div className="metric-bottom">
              <span>
                Medium findings
              </span>
            </div>

          </div>

          <div className="metric low">

            <div className="metric-top">
              <div className="metric-icon">
                <CheckCircle2 size={16} />
              </div>
              Low
            </div>

            <strong>
              {lowCount}
            </strong>

            <div className="metric-bottom">
              <span>
                Low findings
              </span>
            </div>

          </div>

          <div className="metric total">

            <div className="metric-top">
              <div className="metric-icon">
                <FileText size={16} />
              </div>
              Total
            </div>

            <strong>
              {findings.length}
            </strong>

            <div className="metric-bottom">
              <span>
                Selected scan findings
              </span>
            </div>

          </div>

        </div>

        <div className="card recent-card">

          <div className="card-header">

            <div>

              <h3>
                Security Report
              </h3>

              <p>
                {reportScan
                  ? `${reportScan.scan_name} — Scan #${reportScan.id}`
                  : "No scan selected"}
              </p>

            </div>

            <div
              style={{
                display: "flex",
                gap: "10px",
                flexWrap: "wrap",
              }}
            >
              <button
                className="secondary-button"
                onClick={generatePDFReport}
                disabled={
                  reportLoading ||
                  findings.length === 0
                }
              >
                <FileText size={15} />
                Print / Save PDF
              </button>

              <button
                className="primary-btn"
                onClick={
                  generateHTMLReport
                }
                disabled={
                  reportLoading ||
                  findings.length === 0
                }
              >
                <FileText size={15} />
                Download HTML Report
              </button>
            </div>

          </div>

          {reportLoading ? (

            <div
              style={{
                padding: "50px",
                textAlign: "center",
              }}
            >
              Loading report data...
            </div>

          ) : reportError ? (

            <div
              style={{
                padding: "50px",
                textAlign: "center",
              }}
            >
              {reportError}
            </div>

          ) : findings.length === 0 ? (

            <div
              style={{
                padding: "50px",
                textAlign: "center",
              }}
            >
              No findings are linked to this scan.
            </div>

          ) : (

            <div className="table">

              <div className="table-head">

                <span>
                  Finding
                </span>

                <span>
                  Severity
                </span>

                <span>
                  URL
                </span>

                <span>
                  Status
                </span>

              </div>

              {findings.map(
                (finding) => (

                  <div
                    className="table-row"
                    key={finding.id}
                  >

                    <strong>
                      {finding.vulnerability}
                    </strong>

                    <span
                      className={`severity ${finding.severity.toUpperCase().toLowerCase()}`}
                    >
                      {finding.severity.toUpperCase()}
                    </span>

                    <code>
                      {finding.url}
                    </code>

                    <span className="finding-status">
                      {finding.status}
                    </span>

                  </div>

                )
              )}

            </div>

          )}

        </div>

      </section>
    );
  };

  // --------------------------------------------------
  // SCAN HISTORY PAGE
  // --------------------------------------------------

  const renderScanHistory = () => {
    return (
      <section className="content">

        <div className="page-heading">

          <div>

            <p className="eyebrow">
              SECURITY OPERATIONS
            </p>

            <h2>
              Scan History
            </h2>

            <p>
              View previous ShieldAI
              security scans and
              their current status.
            </p>

          </div>

          <button
            className="secondary-button"
            onClick={loadScanHistory}
          >
            <Activity size={14} />
            Refresh
          </button>

        </div>

        <div className="card recent-card">

          <div className="card-header">

            <div>

              <h3>
                Previous Scans
              </h3>

              <p>
                Scans stored in the
                ShieldAI database
              </p>

            </div>

            <button
              className="primary-btn"
              onClick={openNewScan}
            >
              <Play size={14} />
              New Scan
            </button>

          </div>

          {historyLoading ? (

            <div
              style={{
                padding: "40px",
                textAlign: "center",
              }}
            >
              Loading scan history...
            </div>

          ) : historyError ? (

            <div
              style={{
                padding: "40px",
                textAlign: "center",
              }}
            >
              {historyError}
            </div>

          ) : scans.length === 0 ? (

            <div
              style={{
                padding: "40px",
                textAlign: "center",
              }}
            >
              No scans found.
            </div>

          ) : (

            <div className="table">

              <div className="table-head">

                <span>ID</span>

                <span>
                  Scan Name
                </span>

                <span>
                  Target URL
                </span>

                <span>
                  Status
                </span>

              </div>

              {scans.map(
                (scan) => (

                  <div
                    className="table-row"
                    key={scan.id}
                  >

                    <strong>
                      #{scan.id}
                    </strong>

                    <span>
                      {scan.scan_name}
                    </span>

                    <code>
                      {scan.target_url}
                    </code>

                    <span
                      className="finding-status"
                      style={{
                        fontWeight: 600,
                      }}
                    >
                      {scan.status}
                    </span>

                  </div>

                )
              )}

            </div>

          )}

        </div>

      </section>
    );
  };

  // --------------------------------------------------
  // SIMPLE PAGES
  // --------------------------------------------------

  // --------------------------------------------------
// AI ASSISTANT PAGE
// --------------------------------------------------

const renderAIAssistant = () => {
  const criticalCount = findings.filter(
    (finding) =>
      finding.severity.toUpperCase() === "CRITICAL"
  ).length;

  const highCount = findings.filter(
    (finding) =>
      finding.severity.toUpperCase() === "HIGH"
  ).length;

  const mediumCount = findings.filter(
    (finding) =>
      finding.severity.toUpperCase() === "MEDIUM"
  ).length;

  const lowCount = findings.filter(
    (finding) =>
      finding.severity.toUpperCase() === "LOW"
  ).length;

  return (
    <section className="content">

      <div className="page-heading">

        <div>
          <p className="eyebrow">
            INTELLIGENT SECURITY ANALYSIS
          </p>

          <h2>
            AI Assistant
          </h2>

          <p>
            Rule-based analysis of ShieldAI
            security findings.
          </p>
        </div>

        <button
          className="secondary-button"
          onClick={loadFindings}
        >
          <Activity size={14} />
          Refresh Analysis
        </button>

      </div>

      <div className="card ai-card">

        <div className="ai-icon">
          <Bot size={23} />
        </div>

        <div className="ai-content">

          <div className="ai-title">
            <h3>
              ShieldAI Local AI Engine
            </h3>

            <span>
              RULE-BASED AI
            </span>
          </div>

          <p>
            The assistant analyzes findings
            already collected by the ShieldAI
            scanner and generates severity
            explanations, impact descriptions,
            recommendations and OWASP references.
          </p>

          <div className="ai-tags">
            <span>
              Severity Analysis
            </span>

            <span>
              Impact Assessment
            </span>

            <span>
              Recommendations
            </span>

            <span>
              OWASP Mapping
            </span>

            <span>
              Confidence Analysis
            </span>
          </div>

        </div>

      </div>

      <div className="metrics">

        <div className="metric critical">
          <div className="metric-top">
            <div className="metric-icon">
              <AlertCircle size={16} />
            </div>
            Critical
          </div>

          <strong>
            {criticalCount}
          </strong>

          <div className="metric-bottom">
            <span>
              Critical findings
            </span>
          </div>
        </div>

        <div className="metric high">
          <div className="metric-top">
            <div className="metric-icon">
              <AlertTriangle size={16} />
            </div>
            High
          </div>

          <strong>
            {highCount}
          </strong>

          <div className="metric-bottom">
            <span>
              High findings
            </span>
          </div>
        </div>

        <div className="metric medium">
          <div className="metric-top">
            <div className="metric-icon">
              <AlertTriangle size={16} />
            </div>
            Medium
          </div>

          <strong>
            {mediumCount}
          </strong>

          <div className="metric-bottom">
            <span>
              Medium findings
            </span>
          </div>
        </div>

        <div className="metric low">
          <div className="metric-top">
            <div className="metric-icon">
              <CheckCircle2 size={16} />
            </div>
            Low
          </div>

          <strong>
            {lowCount}
          </strong>

          <div className="metric-bottom">
            <span>
              Low findings
            </span>
          </div>
        </div>

        <div className="metric total">
          <div className="metric-top">
            <div className="metric-icon">
              <Bot size={16} />
            </div>
            Total
          </div>

          <strong>
            {findings.length}
          </strong>

          <div className="metric-bottom">
            <span>
              Analyzed findings
            </span>
          </div>
        </div>

      </div>

      <div className="card recent-card">

        <div className="card-header">

          <div>
            <h3>
              AI Security Analysis
            </h3>

            <p>
              Automated defensive analysis
              of collected findings.
            </p>
          </div>

        </div>

        {findingsLoading ? (

          <div
            style={{
              padding: "50px",
              textAlign: "center",
            }}
          >
            Analyzing security findings...
          </div>

        ) : findingsError ? (

          <div
            style={{
              padding: "50px",
              textAlign: "center",
            }}
          >
            {findingsError}
          </div>

        ) : findings.length === 0 ? (

          <div
            style={{
              padding: "50px",
              textAlign: "center",
            }}
          >
            No findings are available for
            analysis.
          </div>

        ) : (

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "18px",
            }}
          >

            {findings.map((finding) => {

              const analysis =
                getRecommendation(finding);

              return (
                <div
                  key={finding.id}
                  style={{
                    padding: "20px",
                    border:
                      "1px solid #e2e8f0",
                    borderRadius: "12px",
                    background: "#ffffff",
                  }}
                >

                  <div
                    style={{
                      display: "flex",
                      justifyContent:
                        "space-between",
                      alignItems: "flex-start",
                      gap: "15px",
                    }}
                  >

                    <div>

                      <strong
                        style={{
                          fontSize: "15px",
                        }}
                      >
                        {finding.vulnerability}
                      </strong>

                      <p
                        style={{
                          margin:
                            "6px 0 0",
                          color:
                            "#64748b",
                          fontSize:
                            "13px",
                        }}
                      >
                        {finding.url}
                      </p>

                    </div>

                    <span
                      className={`severity ${finding.severity.toLowerCase()}`}
                    >
                      {finding.severity.toUpperCase()}
                    </span>

                  </div>

                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns:
                        "repeat(4, 1fr)",
                      gap: "15px",
                      marginTop: "18px",
                    }}
                  >

                    <div>
                      <strong
                        style={{
                          display:
                            "block",
                          fontSize:
                            "12px",
                          marginBottom:
                            "6px",
                        }}
                      >
                        IMPACT
                      </strong>

                      <span
                        style={{
                          color:
                            "#64748b",
                          fontSize:
                            "13px",
                          lineHeight:
                            1.5,
                        }}
                      >
                        {analysis.impact}
                      </span>
                    </div>

                    <div>
                      <strong
                        style={{
                          display:
                            "block",
                          fontSize:
                            "12px",
                          marginBottom:
                            "6px",
                        }}
                      >
                        RECOMMENDATION
                      </strong>

                      <span
                        style={{
                          color:
                            "#64748b",
                          fontSize:
                            "13px",
                          lineHeight:
                            1.5,
                        }}
                      >
                        {
                          analysis.recommendation
                        }
                      </span>
                    </div>

                    <div>
                      <strong
                        style={{
                          display:
                            "block",
                          fontSize:
                            "12px",
                          marginBottom:
                            "6px",
                        }}
                      >
                        CONFIDENCE
                      </strong>

                      <span
                        style={{
                          display: "inline-block",
                          padding: "4px 8px",
                          borderRadius: "999px",
                          background:
                            analysis.confidence === "HIGH"
                              ? "#dcfce7"
                              : analysis.confidence === "MEDIUM"
                              ? "#fef3c7"
                              : "#e2e8f0",
                          color:
                            analysis.confidence === "HIGH"
                              ? "#166534"
                              : analysis.confidence === "MEDIUM"
                              ? "#92400e"
                              : "#475569",
                          fontSize: "12px",
                          fontWeight: 700,
                        }}
                      >
                        {analysis.confidence ?? "MEDIUM"}
                      </span>
                    </div>

                    <div>
                      <strong
                        style={{
                          display:
                            "block",
                          fontSize:
                            "12px",
                          marginBottom:
                            "6px",
                        }}
                      >
                        OWASP
                      </strong>

                      <span
                        style={{
                          color:
                            "#64748b",
                          fontSize:
                            "13px",
                          lineHeight:
                            1.5,
                        }}
                      >
                        {analysis.owasp}
                      </span>
                    </div>

                  </div>

                  <div
                    style={{
                      marginTop: "15px",
                      padding: "12px",
                      background: "#f8fafc",
                      borderRadius: "8px",
                      fontSize: "13px",
                      color: "#475569",
                    }}
                  >
                    <strong>
                      Scanner description:
                    </strong>{" "}
                    {finding.description}
                  </div>

                  <div
                    style={{
                      marginTop: "10px",
                      fontSize: "12px",
                      color: "#64748b",
                    }}
                  >
                    Confidence is a rule-based assessment of how strongly the available scanner evidence supports this finding.
                  </div>

                </div>
              );
            })}

          </div>

        )}

      </div>

    </section>
  );
};

  // --------------------------------------------------
  // TARGETS PAGE
  // --------------------------------------------------

  const renderTargets = () => {
    return (
      <section className="content">

        <div className="page-heading">

          <div>
            <p className="eyebrow">
              AUTHORIZED TARGETS
            </p>

            <h2>
              Targets
            </h2>

            <p>
              Manage applications that are
              authorized for security testing.
            </p>
          </div>

          <button
            className="primary-btn"
            onClick={openNewScan}
          >
            <Play size={14} />
            Add Target
          </button>

        </div>

        <div className="card recent-card">

          <div className="card-header">

            <div>
              <h3>
                Authorized Targets
              </h3>

              <p>
                Local targets available for
                ShieldAI testing.
              </p>
            </div>

          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "20px",
              padding: "22px 0",
              borderBottom:
                "1px solid #e5e7eb",
            }}
          >

            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "16px",
              }}
            >

              <div
                style={{
                  width: "46px",
                  height: "46px",
                  borderRadius: "10px",
                  background: "#eff6ff",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Target size={22} />
              </div>

              <div>

                <strong
                  style={{
                    display: "block",
                    fontSize: "15px",
                    marginBottom: "5px",
                  }}
                >
                  ShieldAI Local Demo Target
                </strong>

                <code
                  style={{
                    fontSize: "12px",
                    color: "#64748b",
                  }}
                >
                  http://127.0.0.1:5001
                </code>

              </div>

            </div>

            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "12px",
              }}
            >

              <span
                style={{
                  padding: "6px 10px",
                  borderRadius: "999px",
                  background: "#dcfce7",
                  color: "#15803d",
                  fontSize: "12px",
                  fontWeight: 600,
                }}
              >
                Authorized
              </span>

              <button
                className="primary-btn"
                onClick={() => {
                  setTargetUrl(
                    "http://127.0.0.1:5001"
                  );

                  setScanName(
                    "ShieldAI Local Demo Scan"
                  );

                  openNewScan();
                }}
              >
                <Play size={14} />
                Start Scan
              </button>

            </div>

          </div>

          <div
            style={{
              marginTop: "22px",
              padding: "16px",
              borderRadius: "10px",
              background: "#f8fafc",
              border: "1px solid #e2e8f0",
            }}
          >

            <strong>
              Authorized Testing Only
            </strong>

            <p
              style={{
                margin: "6px 0 0",
                color: "#64748b",
                fontSize: "13px",
                lineHeight: 1.5,
              }}
            >
              ShieldAI is configured for safe,
              non-destructive security testing
              of authorized applications.
            </p>

          </div>

        </div>

      </section>
    );
  };

  // --------------------------------------------------
  // SECURITY TOOLS PAGE
  // --------------------------------------------------

  const renderSecurityTools = () => {
    const checkBackendHealth = async () => {
      setBackendCheckLoading(true);
      setBackendCheckResult("");

      try {
        const response = await fetch(
          `${API_BASE_URL}/health`
        );

        if (!response.ok) {
          throw new Error("Backend health check failed");
        }

        const data = await response.json();

        setBackendCheckResult(
          `${data.service} — ${data.status} — v${data.version}`
        );
      } catch (err) {
        console.error(err);
        setBackendCheckResult(
          "Backend health check failed."
        );
      } finally {
        setBackendCheckLoading(false);
      }
    };

    const checkFindingsInventory = async () => {
      setInventoryLoading(true);
      setInventoryResult("");

      try {
        const response = await fetch(
          `${API_BASE_URL}/findings`
        );

        if (!response.ok) {
          throw new Error("Findings inventory failed");
        }

        const data = await response.json();
        const items: Finding[] = data.findings || [];

        const criticalCount = items.filter(
          (item) => item.severity.toUpperCase() === "CRITICAL"
        ).length;

        const highCount = items.filter(
          (item) => item.severity.toUpperCase() === "HIGH"
        ).length;

        const mediumCount = items.filter(
          (item) => item.severity.toUpperCase() === "MEDIUM"
        ).length;

        const lowCount = items.filter(
          (item) => item.severity.toUpperCase() === "LOW"
        ).length;

        setInventoryResult(
          `Total ${items.length} — Critical ${criticalCount} — High ${highCount} — Medium ${mediumCount} — Low ${lowCount}`
        );
      } catch (err) {
        console.error(err);
        setInventoryResult(
          "Unable to read findings inventory."
        );
      } finally {
        setInventoryLoading(false);
      }
    };

    return (
      <section className="content">

        <div className="page-heading">
          <div>
            <p className="eyebrow">
              AUTHORIZED SECURITY UTILITIES
            </p>

            <h2>
              Security Tools
            </h2>

            <p>
              Local defensive utilities for monitoring
              and reviewing ShieldAI scan data.
            </p>
          </div>

          <button
            className="secondary-button"
            onClick={() => {
              checkBackendHealth();
              checkFindingsInventory();
            }}
          >
            <Activity size={14} />
            Run Checks
          </button>
        </div>

        <div className="dashboard-grid">

          <div className="card">

            <div className="card-header">
              <div>
                <h3>
                  Backend Health Check
                </h3>

                <p>
                  Verify that the ShieldAI API is
                  available.
                </p>
              </div>
            </div>

            <div
              style={{
                padding: "18px 0",
                color: "#64748b",
                minHeight: "55px",
              }}
            >
              {backendCheckResult ||
                "No health check has been run."}
            </div>

            <button
              className="primary-btn"
              onClick={checkBackendHealth}
              disabled={backendCheckLoading}
            >
              {backendCheckLoading
                ? "Checking..."
                : "Check Backend"}
            </button>

          </div>

          <div className="card">

            <div className="card-header">
              <div>
                <h3>
                  Findings Inventory
                </h3>

                <p>
                  Read the current findings stored
                  in SQLite.
                </p>
              </div>
            </div>

            <div
              style={{
                padding: "18px 0",
                color: "#64748b",
                minHeight: "55px",
              }}
            >
              {inventoryResult ||
                "No inventory check has been run."}
            </div>

            <button
              className="primary-btn"
              onClick={checkFindingsInventory}
              disabled={inventoryLoading}
            >
              {inventoryLoading
                ? "Reading..."
                : "Check Findings"}
            </button>

          </div>

        </div>

        <div className="dashboard-grid">

          <div className="card">

            <div className="card-header">
              <div>
                <h3>
                  Authorized Target Scanner
                </h3>

                <p>
                  Launch the configured safe scanner
                  for the local demo application.
                </p>
              </div>
            </div>

            <div
              style={{
                padding: "18px",
                borderRadius: "10px",
                background: "#f8fafc",
                border: "1px solid #e2e8f0",
                marginBottom: "18px",
              }}
            >
              <strong>
                ShieldAI Local Demo Target
              </strong>

              <code
                style={{
                  display: "block",
                  marginTop: "6px",
                  color: "#64748b",
                }}
              >
                http://127.0.0.1:5001
              </code>
            </div>

            <button
              className="primary-btn"
              onClick={() => {
                setTargetUrl(
                  "http://127.0.0.1:5001"
                );

                setScanName(
                  "ShieldAI Local Security Scan"
                );

                openNewScan();
              }}
            >
              <Play size={14} />
              Start Authorized Scan
            </button>

          </div>

          <div className="card">

            <div className="card-header">
              <div>
                <h3>
                  Findings Review
                </h3>

                <p>
                  Open the detailed vulnerability
                  analysis page.
                </p>
              </div>
            </div>

            <div
              style={{
                minHeight: "93px",
                display: "flex",
                alignItems: "center",
                color: "#64748b",
              }}
            >
              Review severity, URLs, descriptions,
              and verification status.
            </div>

            <button
              className="primary-btn"
              onClick={() =>
                navigateTo("vulnerabilities")
              }
            >
              <AlertTriangle size={14} />
              Review Findings
            </button>

          </div>

        </div>

        <div className="card">

          <div className="card-header">
            <div>
              <h3>
                Safe Testing Notice
              </h3>

              <p>
                ShieldAI tools are limited to authorized,
                local, non-destructive security testing.
              </p>
            </div>

            <ShieldCheck size={22} />
          </div>

        </div>

      </section>
    );
  };

  // --------------------------------------------------
  // DOCUMENTATION PAGE
  // --------------------------------------------------

  const renderDocumentation = () => {
    return (
      <section className="content">

        <div className="page-heading">
          <div>
            <p className="eyebrow">
              SHIELDAI DOCUMENTATION
            </p>

            <h2>Documentation</h2>

            <p>
              Project architecture, features,
              scanner capabilities, and safe usage.
            </p>
          </div>
        </div>

        <div className="dashboard-grid">

          <div className="card">
            <div className="card-header">
              <div>
                <h3>ShieldAI Overview</h3>
                <p>
                  Web Application Penetration Testing Toolkit with AI
                </p>
              </div>
              <Shield size={22} />
            </div>

            <p
              style={{
                color: "#64748b",
                lineHeight: 1.7,
                margin: 0,
              }}
            >
              ShieldAI is an academic cybersecurity toolkit for
              authorized, safe, and non-destructive web application
              security testing. It combines a React frontend,
              Flask REST API, local scanner, SQLite storage, and
              rule-based security analysis.
            </p>
          </div>

          <div className="card">
            <div className="card-header">
              <div>
                <h3>Technology Stack</h3>
                <p>Main technologies used in the project.</p>
              </div>
              <Terminal size={22} />
            </div>

            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                gap: "10px",
              }}
            >
              {[
                "React",
                "TypeScript",
                "Vite",
                "Python",
                "Flask",
                "SQLite",
                "SQLAlchemy",
                "Requests",
              ].map((item) => (
                <div
                  key={item}
                  style={{
                    padding: "10px 12px",
                    border: "1px solid #e2e8f0",
                    borderRadius: "8px",
                    background: "#f8fafc",
                    color: "#334155",
                    fontSize: "13px",
                    fontWeight: 600,
                  }}
                >
                  {item}
                </div>
              ))}
            </div>
          </div>

        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Scanner Capabilities</h3>
              <p>
                Safe checks currently supported by the local scanner.
              </p>
            </div>
            <ShieldCheck size={22} />
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
              gap: "14px",
            }}
          >
            {[
              ["Reconnaissance", "HTTP response inspection and basic endpoint discovery."],
              ["Security Headers", "Checks for important HTTP security headers."],
              ["CSRF Review", "Inspects POST forms for an obvious CSRF token field."],
              ["Passive XSS Indicators", "Flags script-related indicators for manual verification."],
              ["Server Information", "Identifies potentially informative Server headers."],
              ["Safe URL Validation", "Restricts scans to configured authorized local targets."],
            ].map(([title, description]) => (
              <div
                key={title}
                style={{
                  padding: "16px",
                  border: "1px solid #e2e8f0",
                  borderRadius: "10px",
                  background: "#ffffff",
                }}
              >
                <strong>{title}</strong>
                <p
                  style={{
                    margin: "7px 0 0",
                    color: "#64748b",
                    fontSize: "13px",
                    lineHeight: 1.5,
                  }}
                >
                  {description}
                </p>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Application Architecture</h3>
              <p>High-level ShieldAI data flow.</p>
            </div>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexWrap: "wrap",
              gap: "12px",
              padding: "18px 0",
              color: "#334155",
              fontWeight: 600,
            }}
          >
            {[
              "React Frontend",
              "Flask REST API",
              "Safe Scanner",
              "SQLite",
              "Rule-Based AI",
            ].map((item, index, array) => (
              <div key={item} style={{ display: "contents" }}>
                <span
                  style={{
                    padding: "10px 14px",
                    border: "1px solid #dbe3ef",
                    borderRadius: "999px",
                    background: "#f8fafc",
                    fontSize: "13px",
                  }}
                >
                  {item}
                </span>
                {index < array.length - 1 && <span>→</span>}
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Security Restrictions</h3>
              <p>
                Safeguards applied to the academic build.
              </p>
            </div>
            <ShieldCheck size={22} />
          </div>

          <div
            style={{
              display: "grid",
              gap: "10px",
              color: "#334155",
            }}
          >
            <div>✓ Authorized targets only</div>
            <div>✓ Local target allowlisting</div>
            <div>✓ Non-destructive scanning</div>
            <div>✓ Request timeouts</div>
            <div>✓ No credential harvesting</div>
            <div>✓ No arbitrary shell execution</div>
            <div>✓ No destructive exploitation</div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h3>Local Startup</h3>
              <p>Run the three project components locally.</p>
            </div>
            <Terminal size={22} />
          </div>

          <pre
            style={{
              margin: 0,
              background: "#0f172a",
              color: "#e2e8f0",
              padding: "18px",
              borderRadius: "10px",
              overflowX: "auto",
              fontSize: "13px",
              lineHeight: 1.6,
            }}
          >{`Demo Target
python app.py
http://127.0.0.1:5001

Backend
python app.py
http://127.0.0.1:5000

Frontend
npm run dev
http://localhost:5176/`}</pre>
        </div>

      </section>
    );
  };

  // --------------------------------------------------
  // PAGE SELECTOR
  // --------------------------------------------------

  const renderPage = () => {
    switch (page) {

      case "history":
        return renderScanHistory();

      case "vulnerabilities":
        return renderVulnerabilities();

      case "reports":
        return renderReports();

      case "targets":
        return renderTargets();

      case "assistant":
        return renderAIAssistant();

      case "tools":
        return renderSecurityTools();

      case "documentation":
        return renderDocumentation();

      case "settings":
  return (
    <section className="content">

      <div className="page-heading">
        <div>
          <p className="eyebrow">
            SHIELDAI CONFIGURATION
          </p>

          <h2>
            Settings
          </h2>

          <p>
            Configure scanner behavior and
            application security controls.
          </p>
        </div>
      </div>

      <div className="dashboard-grid">

        <div className="card">

          <div className="card-header">
            <div>
              <h3>
                Scanner Configuration
              </h3>

              <p>
                Safe scanning parameters.
              </p>
            </div>

            <Terminal size={21} />
          </div>

          <div
            style={{
              display: "grid",
              gap: "18px",
            }}
          >

            <label
              style={{
                display: "grid",
                gap: "7px",
              }}
            >
              <strong>
                Request Timeout
              </strong>

              <select
                value={requestTimeout}
                onChange={(event) =>
                  setRequestTimeout(event.target.value)
                }
                style={{
                  padding: "11px 12px",
                  border:
                    "1px solid #dbe3ef",
                  borderRadius: "8px",
                  background: "#ffffff",
                }}
              >
                <option value="5">
                  5 seconds
                </option>

                <option value="8">
                  8 seconds
                </option>

                <option value="10">
                  10 seconds
                </option>

                <option value="15">
                  15 seconds
                </option>
              </select>
            </label>

            <label
              style={{
                display: "grid",
                gap: "7px",
              }}
            >
              <strong>
                Scan Mode
              </strong>

              <select
                defaultValue="safe"
                style={{
                  padding: "11px 12px",
                  border:
                    "1px solid #dbe3ef",
                  borderRadius: "8px",
                  background: "#ffffff",
                }}
              >
                <option value="safe">
                  Safe / Non-Destructive
                </option>
              </select>
            </label>

          </div>

        </div>

        <div className="card">

          <div className="card-header">
            <div>
              <h3>
                Target Restrictions
              </h3>

              <p>
                Security restrictions for testing.
              </p>
            </div>

            <ShieldCheck size={21} />
          </div>

          <div
            style={{
              display: "grid",
              gap: "14px",
            }}
          >

            <div
              style={{
                display: "flex",
                justifyContent:
                  "space-between",
                alignItems: "center",
                padding: "13px 0",
                borderBottom:
                  "1px solid #e2e8f0",
              }}
            >
              <span>
                Local targets only
              </span>

              <strong
                style={{
                  color: "#15803d",
                }}
              >
                ENABLED
              </strong>
            </div>

            <div
              style={{
                display: "flex",
                justifyContent:
                  "space-between",
                alignItems: "center",
                padding: "13px 0",
                borderBottom:
                  "1px solid #e2e8f0",
              }}
            >
              <span>
                Destructive actions
              </span>

              <strong
                style={{
                  color: "#15803d",
                }}
              >
                BLOCKED
              </strong>
            </div>

            <div
              style={{
                display: "flex",
                justifyContent:
                  "space-between",
                alignItems: "center",
                padding: "13px 0",
              }}
            >
              <span>
                Credential harvesting
              </span>

              <strong
                style={{
                  color: "#15803d",
                }}
              >
                BLOCKED
              </strong>
            </div>

          </div>

        </div>

      </div>

      <div className="card">

        <div className="card-header">

          <div>
            <h3>
              Security Mode
            </h3>

            <p>
              Current ShieldAI protection profile.
            </p>
          </div>

          <Shield size={21} />

        </div>

        <div
          style={{
            padding: "18px",
            borderRadius: "10px",
            background: "#eff6ff",
            border:
              "1px solid #bfdbfe",
          }}
        >

          <strong>
            Safe Academic Testing Mode
          </strong>

          <p
            style={{
              margin:
                "7px 0 0",
              color: "#475569",
              lineHeight: 1.6,
              fontSize: "13px",
            }}
          >
            ShieldAI is configured for
            authorized, local and
            non-destructive security
            testing only.
          </p>

        </div>

      </div>

      <div className="card">

        <div className="card-header">

          <div>
            <h3>
              Application Information
            </h3>

            <p>
              ShieldAI environment details.
            </p>
          </div>

          <CircleHelp size={21} />

        </div>

        <div
          style={{
            display: "grid",
            gap: "12px",
          }}
        >

          <div>
            <strong>
              Application
            </strong>

            <span
              style={{
                marginLeft: "12px",
                color: "#64748b",
              }}
            >
              ShieldAI
            </span>
          </div>

          <div>
            <strong>
              Version
            </strong>

            <span
              style={{
                marginLeft: "12px",
                color: "#64748b",
              }}
            >
              1.0.0
            </span>
          </div>

          <div>
            <strong>
              Backend
            </strong>

            <span
              style={{
                marginLeft: "12px",
                color: "#64748b",
              }}
            >
              Flask REST API
            </span>
          </div>

          <div>
            <strong>
              Database
            </strong>

            <span
              style={{
                marginLeft: "12px",
                color: "#64748b",
              }}
            >
              SQLite
            </span>
          </div>

        </div>

      </div>

    </section>
  );

      default:
        return renderDashboard();
    }
  };

  // --------------------------------------------------
  // APP LAYOUT
  // --------------------------------------------------

  return (
    <div className={`app ${theme === "dark" ? "dark-mode" : "light-mode"}`}>

      <style>{`
        .app.dark-mode {
          --shield-bg: #0b1220;
          --shield-surface: #111827;
          --shield-surface-2: #172033;
          --shield-border: #263348;
          --shield-text: #e5e7eb;
          --shield-muted: #9ca3af;
          --shield-blue: #60a5fa;
          background: var(--shield-bg) !important;
          color: var(--shield-text) !important;
        }

        .app.dark-mode .sidebar,
        .app.dark-mode .header,
        .app.dark-mode .card,
        .app.dark-mode .metric,
        .app.dark-mode .secure-card,
        .app.dark-mode .scan-modal {
          background: var(--shield-surface) !important;
          border-color: var(--shield-border) !important;
          color: var(--shield-text) !important;
        }

        .app.dark-mode .main,
        .app.dark-mode .content {
          background: var(--shield-bg) !important;
          color: var(--shield-text) !important;
        }

        .app.dark-mode h1,
        .app.dark-mode h2,
        .app.dark-mode h3,
        .app.dark-mode h4,
        .app.dark-mode strong,
        .app.dark-mode label,
        .app.dark-mode .section-title,
        .app.dark-mode .nav-item,
        .app.dark-mode .brand span,
        .app.dark-mode .profile small,
        .app.dark-mode .profile strong,
        .app.dark-mode .sidebar-user span,
        .app.dark-mode .sidebar-user strong {
          color: var(--shield-text) !important;
        }

        .app.dark-mode p,
        .app.dark-mode span,
        .app.dark-mode code,
        .app.dark-mode .eyebrow,
        .app.dark-mode .metric-bottom,
        .app.dark-mode .card-header p,
        .app.dark-mode .page-heading > div > p:not(.eyebrow),
        .app.dark-mode .status-item,
        .app.dark-mode .finding-status {
          color: var(--shield-muted) !important;
        }

        .app.dark-mode input,
        .app.dark-mode select,
        .app.dark-mode textarea {
          background: #0f172a !important;
          color: var(--shield-text) !important;
          border-color: var(--shield-border) !important;
        }

        .app.dark-mode input::placeholder {
          color: #64748b !important;
        }

        .app.dark-mode .nav-item:hover,
        .app.dark-mode .nav-item.active {
          background: #172554 !important;
          color: #93c5fd !important;
        }

        .app.dark-mode .icon-button,
        .app.dark-mode .secondary-button,
        .app.dark-mode .secondary-btn,
        .app.dark-mode .dropdown-button {
          background: #172033 !important;
          color: #dbeafe !important;
          border-color: var(--shield-border) !important;
        }

        .app.dark-mode .authorization-box,
        .app.dark-mode .scan-message {
          background: #172033 !important;
          border-color: #334155 !important;
          color: var(--shield-text) !important;
        }

        .app.dark-mode .secure-card {
          background: #172554 !important;
          border-color: #2b4c8c !important;
        }

        .app.dark-mode .severity {
          color: #f8fafc !important;
          border-color: var(--shield-border) !important;
        }

        .app.dark-mode .table-head,
        .app.dark-mode .table-row {
          border-color: var(--shield-border) !important;
        }

        .app.dark-mode .table-head {
          background: #172033 !important;
          color: var(--shield-muted) !important;
        }

        .app.dark-mode .backend-status {
          color: #86efac !important;
        }

        .app.dark-mode .scan-overlay {
          background: rgba(2, 6, 23, 0.78) !important;
        }

        .app.dark-mode .scan-modal-header {
          border-bottom-color: var(--shield-border) !important;
        }

        .app.dark-mode .card-header {
          border-color: var(--shield-border) !important;
        }
      `}</style>

      <aside className="sidebar">

        <div className="brand">
          <div className="brand-icon">
            <Shield size={23} />
          </div>

          <div>
            <h1>ShieldAI</h1>
            <span>Web App Pentest Toolkit</span>
          </div>
        </div>

        <div className="sidebar-section">
          <div className="section-title">MAIN</div>

          {renderSidebarButton(
            "dashboard",
            <LayoutDashboard size={18} />,
            "Dashboard"
          )}

          <button
            className="nav-item"
            onClick={openNewScan}
          >
            <Zap size={18} />
            <span>New Scan</span>
          </button>

          {renderSidebarButton(
            "targets",
            <Target size={18} />,
            "Targets"
          )}

          {renderSidebarButton(
            "vulnerabilities",
            <AlertTriangle size={18} />,
            "Vulnerabilities"
          )}

          {renderSidebarButton(
            "reports",
            <FileText size={18} />,
            "Reports"
          )}

          {renderSidebarButton(
            "history",
            <History size={18} />,
            "Scan History"
          )}

          {renderSidebarButton(
            "assistant",
            <Bot size={18} />,
            "AI Assistant"
          )}

          {renderSidebarButton(
            "tools",
            <Terminal size={18} />,
            "Tools"
          )}
        </div>

        <div className="sidebar-section">
          <div className="section-title">SYSTEM</div>

          {renderSidebarButton(
            "documentation",
            <CircleHelp size={18} />,
            "Documentation"
          )}

          {renderSidebarButton(
            "settings",
            <Settings size={18} />,
            "Settings"
          )}
        </div>

        <div className="secure-card">
          <div className="secure-icon">
            <ShieldCheck size={18} />
          </div>

          <div>
            <strong>Scan Securely</strong>
            <p>Authorized targets only</p>
          </div>
        </div>

        <div className="sidebar-user">
          <div className="avatar">ST</div>

          <div>
            <strong>ShieldAI User</strong>
            <span>Administrator</span>
          </div>

          <ChevronDown size={15} />
        </div>

      </aside>

      <main className="main">

        <header className="header">

          <div className="header-left">
            <button className="icon-button">
              <Menu size={19} />
            </button>

            <div className="target-search">
              <Search size={16} />

              <input
                type="text"
                placeholder="Search target..."
              />
            </div>

            <button
              className="scan-button"
              onClick={openNewScan}
            >
              <Play size={14} />
              Start Scan
            </button>
          </div>

          <div className="header-right">
            <button
              className="icon-button"
              onClick={() =>
                setTheme((current) =>
                  current === "light" ? "dark" : "light"
                )
              }
              title={
                theme === "light"
                  ? "Switch to dark mode"
                  : "Switch to light mode"
              }
              aria-label={
                theme === "light"
                  ? "Switch to dark mode"
                  : "Switch to light mode"
              }
            >
              {theme === "light" ? (
                <Moon size={17} />
              ) : (
                <Sun size={17} />
              )}
            </button>

            <button className="icon-button notification">
              <Bell size={17} />
              <span />
            </button>

            <div className="profile">
              <div className="avatar">ST</div>

              <div>
                <strong>ShieldAI User</strong>
                <small>Administrator</small>
              </div>
            </div>
          </div>

        </header>

        {renderPage()}

      </main>

      {showNewScan && (
        <div
          className="scan-overlay"
          onClick={(event) => {
            if (event.target === event.currentTarget) {
              closeNewScan();
            }
          }}
        >
          <div className="scan-modal">

            <div className="scan-modal-header">
              <div>
                <h2>New Security Scan</h2>
                <p>
                  Scan an authorized local web application.
                </p>
              </div>

              <button
                className="close-btn"
                onClick={closeNewScan}
              >
                <X size={20} />
              </button>
            </div>

            <div className="scan-form">

              <label>Scan Name</label>

              <input
                type="text"
                placeholder="My Local Security Scan"
                value={scanName}
                onChange={(event) =>
                  setScanName(event.target.value)
                }
              />

              <label>Target URL</label>

              <input
                type="url"
                placeholder="http://127.0.0.1:5001"
                value={targetUrl}
                onChange={(event) =>
                  setTargetUrl(event.target.value)
                }
              />

              <label>Scan Profile</label>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(3, 1fr)",
                  gap: "10px",
                }}
              >
                {[
                  { name: "Quick", detail: "Fast checks" },
                  { name: "Standard", detail: "Recommended" },
                  { name: "Deep", detail: "More checks" },
                ].map((mode) => {
                  const selected = scanMode === mode.name;
                  return (
                    <button
                      type="button"
                      key={mode.name}
                      onClick={() =>
                        setScanMode(
                          mode.name as
                            "Quick" |
                            "Standard" |
                            "Deep"
                        )
                      }
                      style={{
                        textAlign: "left",
                        padding: "12px",
                        border: selected
                          ? "2px solid #2563eb"
                          : "1px solid #dbe3ef",
                        borderRadius: "10px",
                        background: selected
                          ? "#eff6ff"
                          : "#ffffff",
                        color: "#0f172a",
                      }}
                    >
                      <strong
                        style={{
                          display: "block",
                          fontSize: "13px",
                        }}
                      >
                        {mode.name}
                      </strong>
                      <span
                        style={{
                          display: "block",
                          marginTop: "4px",
                          fontSize: "11px",
                          color: "#64748b",
                        }}
                      >
                        {mode.detail}
                      </span>
                    </button>
                  );
                })}
              </div>

              <div
                className="authorization-box"
                style={{ marginTop: "4px" }}
              >
                <strong>Authorized Testing Only</strong>

                <p>
                  Only scan applications that you own or
                  have explicit permission to test.
                </p>

                <label
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: "10px",
                    marginTop: "10px",
                    cursor: "pointer",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={authorized}
                    onChange={(event) =>
                      setAuthorized(
                        event.target.checked
                      )
                    }
                    style={{ marginTop: "3px" }}
                  />
                  <span style={{ fontSize: "12px" }}>
                    I confirm that I am authorized to test
                    this target.
                  </span>
                </label>
              </div>

              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  marginTop: "2px",
                  cursor: "pointer",
                }}
              >
                <input
                  type="checkbox"
                  checked={safeScan}
                  onChange={(event) =>
                    setSafeScan(event.target.checked)
                  }
                />
                <span>
                  Safe non-destructive checks only
                </span>
              </label>

              {scanMessage && (
                <div className="scan-message">
                  {scanMessage}
                </div>
              )}

              <div className="scan-actions">

                <button
                  className="secondary-btn"
                  onClick={closeNewScan}
                  disabled={scanLoading}
                >
                  Cancel
                </button>

                <button
                  className="primary-btn"
                  onClick={handleStartScan}
                  disabled={scanLoading}
                >
                  {scanLoading
                    ? "Creating Scan..."
                    : "Create Scan"}
                </button>

              </div>

            </div>
          </div>
        </div>
      )}

    </div>
  );
}

export default App;
