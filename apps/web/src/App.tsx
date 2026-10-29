import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { ProtectedRoute } from './components/auth/ProtectedRoute'
import { RootLayout } from './layouts/RootLayout'
import { Home } from './pages/Home'
import { LoginPage } from './pages/LoginPage'
import { RegisterPage } from './pages/RegisterPage'
import { DashboardPage } from './pages/DashboardPage'
import { SecurityServicesPage } from './pages/SecurityServicesPage'
import { ScannerPage } from './pages/ScannerPage'
import { ScanResultPage } from './pages/ScanResultPage'
import { ScanHistoryPage } from './pages/ScanHistoryPage'
import { ReportsLandingPage } from './pages/ReportsLandingPage'
import { SecurityFindingsPage } from './pages/SecurityFindingsPage'
import { ScanComparisonPage } from './pages/ScanComparisonPage'
import { ExportReportsPage } from './pages/ExportReportsPage'
import { ActivityPage } from './pages/ActivityPage'
import { HowItWorksPage } from './pages/HowItWorksPage'
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage'
import { ThreatIndicatorsPage } from './pages/ThreatIndicatorsPage'
import { DomainReputationPage } from './pages/DomainReputationPage'
import { IPReputationPage } from './pages/IPReputationPage'
import { ThreatCorrelationPage } from './pages/ThreatCorrelationPage'
import { ThreatFeedsPage } from './pages/ThreatFeedsPage'
import { IntelligenceSourcesPage } from './pages/IntelligenceSourcesPage'
import { SecurityAdvisoriesPage } from './pages/SecurityAdvisoriesPage'
import { CyberSafetyDashboardPage } from './pages/cyber-safety/CyberSafetyDashboardPage'
import { SafeBrowsingPage } from './pages/cyber-safety/SafeBrowsingPage'
import { PhishingAwarenessPage } from './pages/cyber-safety/PhishingAwarenessPage'
import { PasswordSafetyPage } from './pages/cyber-safety/PasswordSafetyPage'
import { BrowserSecurityPage } from './pages/cyber-safety/BrowserSecurityPage'
import { OnlinePrivacyPage } from './pages/cyber-safety/OnlinePrivacyPage'
import { SecurityCheckupPage } from './pages/cyber-safety/SecurityCheckupPage'
import { SecurityGuidesPage } from './pages/cyber-safety/SecurityGuidesPage'
import { SafetyAlertsPage } from './pages/cyber-safety/SafetyAlertsPage'
import { ContactSupportPage } from './pages/ContactSupportPage'
import { TicketDetailPage } from './pages/TicketDetailPage'
import { HelpCenterPage } from './pages/HelpCenterPage'
import { ScannerGuidePage } from './pages/ScannerGuidePage'
import { FAQPage } from './pages/FAQPage'
import { AISupportPage } from './pages/AISupportPage'
import { NotificationCenterPage } from './pages/NotificationCenterPage'
import { Navigate } from 'react-router-dom'
import { PlaceholderPage } from './pages/PlaceholderPage'


function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          {/* ── Auth pages — full-screen, dedicated auth layout ─────────────── */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />

          {/* ── Pages wrapped with CyberWatch Top Navigation & Layout ───────── */}
          <Route path="/" element={<RootLayout />}>
            <Route index element={<Home />} />
            
            {/* Authenticated User Workspace */}
            <Route
              path="dashboard"
              element={
                <ProtectedRoute>
                  <DashboardPage />
                </ProtectedRoute>
              }
            />

            {/* Notification Center */}
            <Route
              path="notifications"
              element={
                <ProtectedRoute>
                  <NotificationCenterPage />
                </ProtectedRoute>
              }
            />

            {/* Dedicated Full Security Activity Page */}
            <Route
              path="activity"
              element={
                <ProtectedRoute>
                  <ActivityPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="reports/activity"
              element={
                <ProtectedRoute>
                  <ActivityPage />
                </ProtectedRoute>
              }
            />

            {/* ── Security Reporting Center Routes ───────────────────────── */}
            <Route
              path="reports"
              element={
                <ProtectedRoute>
                  <ReportsLandingPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="reports/findings"
              element={
                <ProtectedRoute>
                  <SecurityFindingsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="reports/scans"
              element={
                <ProtectedRoute>
                  <ScanHistoryPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="reports/history"
              element={
                <ProtectedRoute>
                  <ScanHistoryPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="reports/compare"
              element={
                <ProtectedRoute>
                  <ScanComparisonPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="reports/export"
              element={
                <ProtectedRoute>
                  <ExportReportsPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="reports/scans/:id"
              element={
                <ProtectedRoute>
                  <ScanResultPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="reports/scan-report/:id"
              element={
                <ProtectedRoute>
                  <ScanResultPage />
                </ProtectedRoute>
              }
            />

            {/* Security Services Directory & Individual Scanner Pages */}
            <Route
              path="services"
              element={
                <ProtectedRoute>
                  <SecurityServicesPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="services/:scannerSlug"
              element={
                <ProtectedRoute>
                  <ScannerPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="scan/:scannerSlug"
              element={
                <ProtectedRoute>
                  <ScannerPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="scan/url-phishing"
              element={
                <ProtectedRoute>
                  <ScannerPage />
                </ProtectedRoute>
              }
            />
            {/* General Content & Feature Pages */}
            <Route path="features" element={<PlaceholderPage title="Features" />} />
            <Route path="how-it-works" element={<HowItWorksPage />} />
            {/* Threat Intelligence Suite */}
            <Route path="threat-intelligence" element={<ThreatIntelligencePage />} />
            <Route path="threat-indicators" element={<ThreatIndicatorsPage />} />
            <Route path="domain-reputation" element={<DomainReputationPage />} />
            <Route path="ip-reputation" element={<IPReputationPage />} />
            <Route path="threat-correlation" element={<ThreatCorrelationPage />} />
            <Route path="threat-feeds" element={<ThreatFeedsPage />} />
            <Route path="intelligence-sources" element={<IntelligenceSourcesPage />} />
            <Route path="advisories" element={<SecurityAdvisoriesPage />} />
            {/* ── Cyber Safety Center Routes ─────────────────────────────── */}
            <Route path="cyber-safety" element={<CyberSafetyDashboardPage />} />
            <Route path="cyber-safety/safe-browsing" element={<SafeBrowsingPage />} />
            <Route path="cyber-safety/phishing-awareness" element={<PhishingAwarenessPage />} />
            <Route path="cyber-safety/password-safety" element={<PasswordSafetyPage />} />
            <Route path="cyber-safety/browser-security" element={<BrowserSecurityPage />} />
            <Route path="cyber-safety/online-privacy" element={<OnlinePrivacyPage />} />
            <Route path="cyber-safety/security-checkup" element={<SecurityCheckupPage />} />
            <Route path="cyber-safety/guides" element={<SecurityGuidesPage />} />
            <Route path="cyber-safety/alerts" element={<SafetyAlertsPage />} />

            {/* Legacy Safety Aliases Redirects */}
            <Route path="safety" element={<Navigate to="/cyber-safety" replace />} />
            <Route path="safety/browsing" element={<Navigate to="/cyber-safety/safe-browsing" replace />} />
            <Route path="safety/phishing" element={<Navigate to="/cyber-safety/phishing-awareness" replace />} />
            <Route path="safety/passwords" element={<Navigate to="/cyber-safety/password-safety" replace />} />
            <Route path="safety/browser" element={<Navigate to="/cyber-safety/browser-security" replace />} />
            <Route path="safety/privacy" element={<Navigate to="/cyber-safety/online-privacy" replace />} />

            {/* ── Help & Support Center Routes ───────────────────────────── */}
            <Route path="help" element={<HelpCenterPage />} />
            <Route path="help/guide" element={<ScannerGuidePage />} />
            <Route path="help/faq" element={<FAQPage />} />
            <Route path="help/ai" element={<AISupportPage />} />
            <Route path="help/contact" element={<ContactSupportPage />} />
            <Route path="support" element={<ContactSupportPage />} />
            <Route
              path="support/tickets/:ticketId"
              element={
                <ProtectedRoute>
                  <TicketDetailPage />
                </ProtectedRoute>
              }
            />

            <Route path="*" element={<PlaceholderPage title="Page Not Found" />} />

          </Route>
        </Routes>
      </Router>
    </AuthProvider>
  )
}

export default App
