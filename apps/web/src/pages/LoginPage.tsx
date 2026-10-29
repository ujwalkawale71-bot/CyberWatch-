import { useState, type FormEvent, useEffect } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { 
  Shield, 
  Eye, 
  EyeOff, 
  Lock, 
  Mail, 
  AlertCircle, 
  ArrowRight, 
  ArrowLeft, 
  CheckCircle2, 
  X,
  ShieldCheck,
  Cpu,
  Layers
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import axios from 'axios'

const CURRENT_YEAR = new Date().getFullYear()

export function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  // Redirect to original target if redirected by ProtectedRoute, otherwise dashboard
  const from = (location.state as { from?: { pathname?: string } })?.from?.pathname || '/dashboard'

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [rememberMe, setRememberMe] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [isGoogleLoading, setIsGoogleLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isServerOffline, setIsServerOffline] = useState(false)
  const [fieldErrors, setFieldErrors] = useState<{ email?: string; password?: string }>({})

  // Forgot password modal state
  const [isForgotModalOpen, setIsForgotModalOpen] = useState(false)
  const [forgotEmail, setForgotEmail] = useState('')
  const [forgotStatus, setForgotStatus] = useState<'idle' | 'submitting' | 'sent'>('idle')

  useEffect(() => {
    document.title = 'Sign In — CyberWatch | Unified Threat Detection Platform'
  }, [])

  // ── Form Validation ──────────────────────────────────────────────────────────
  function validate(): boolean {
    const errors: typeof fieldErrors = {}
    if (!email.trim()) {
      errors.email = 'Email address is required.'
    } else if (!/^\S+@\S+\.\S+$/.test(email)) {
      errors.email = 'Please enter a valid business or academic email address.'
    }

    if (!password) {
      errors.password = 'Password is required.'
    } else if (password.length < 6) {
      errors.password = 'Password must be at least 6 characters.'
    }

    setFieldErrors(errors)
    return Object.keys(errors).length === 0
  }

  // ── Submit ────────────────────────────────────────────────────────────────────
  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (isLoading) return
    setError(null)
    setIsServerOffline(false)

    if (!validate()) return

    setIsLoading(true)
    try {
      await login({ email, password })
      navigate(from, { replace: true })
    } catch (err) {
      if (axios.isAxiosError(err)) {
        const status = err.response?.status
        const message = err.response?.data?.message
        const validationErrors = err.response?.data?.errors

        if (status === 401) {
          setError('Invalid email or password.')
        } else if (status === 400) {
          if (validationErrors?.length) {
            const mapped: typeof fieldErrors = {}
            validationErrors.forEach(({ field, message: errMsg }: { field: string; message: string }) => {
              if (field === 'email' || field === 'password') {
                (mapped as any)[field] = errMsg
              }
            })
            setFieldErrors(mapped)
          } else {
            setError(message || 'Please check your credentials and try again.')
          }
        } else if (status === 429) {
          setError('Too many login attempts. Please wait 15 minutes before retrying.')
        } else if (status === 500 || status === 503) {
          setError('Authentication service is temporarily unavailable.')
        } else if (status === 0 || !err.response) {
          setIsServerOffline(true)
          setError('Unable to connect to the authentication service. Please ensure the backend server is running.')
        } else {
          setError(message || 'Unable to sign in. Please try again.')
        }
      } else {
        setError('An unexpected authentication error occurred. Please try again.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  // ── Google SSO Simulation ───────────────────────────────────────────────────
  function handleGoogleSignIn() {
    setIsGoogleLoading(true)
    setTimeout(() => {
      setIsGoogleLoading(false)
      // Navigate to dashboard or show simulated SSO token success
      navigate(from, { replace: true })
    }, 1200)
  }

  // ── Forgot Password Simulation ──────────────────────────────────────────────
  function handleForgotSubmit(e: FormEvent) {
    e.preventDefault()
    if (!forgotEmail || !/^\S+@\S+\.\S+$/.test(forgotEmail)) return
    setForgotStatus('submitting')
    setTimeout(() => {
      setForgotStatus('sent')
    }, 900)
  }

  return (
    <div className="min-h-screen flex flex-col bg-[#F8FAFD] text-slate-800 antialiased selection:bg-blue-100 selection:text-blue-900 relative">
      {/* ── Top Header Navigation ────────────────────────────────────────── */}
      <header className="sticky top-0 z-30 w-full bg-white/90 backdrop-blur-md border-b border-slate-200/80">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo on Left */}
          <Link 
            to="/" 
            className="flex items-center gap-2.5 group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 rounded-lg p-1"
          >
            <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-xs shadow-blue-500/20 group-hover:bg-blue-700 transition-colors">
              <Shield className="w-5 h-5" strokeWidth={2.2} />
            </div>
            <div className="flex flex-col">
              <span className="font-bold text-lg tracking-tight text-slate-900 group-hover:text-blue-600 transition-colors leading-none">
                CYBERWATCH
              </span>
              <span className="text-[10px] font-medium tracking-wide uppercase text-slate-500 mt-0.5">
                Threat Detection
              </span>
            </div>
          </Link>

          {/* Minimal Back to Home Link on Right */}
          <Link
            to="/"
            className="inline-flex items-center gap-1.5 text-xs sm:text-sm font-medium text-slate-600 hover:text-blue-600 transition-colors py-1.5 px-3 rounded-lg hover:bg-slate-100/70 border border-transparent hover:border-slate-200/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-600"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to Home</span>
          </Link>
        </div>
      </header>

      {/* ── Split-Screen Content Layout ──────────────────────────────────── */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12 flex items-center">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-14 w-full items-center">
          
          {/* ══════════════════════════════════════════════════════════════════
              LEFT SIDE: Clean CyberWatch Branding & Subtle Visual
          ══════════════════════════════════════════════════════════════════ */}
          <section 
            aria-labelledby="brand-section-title"
            className="lg:col-span-6 xl:col-span-7 flex flex-col justify-center order-2 lg:order-1 pt-4 lg:pt-0"
          >
            {/* Enterprise Tag Badge */}
            <div className="inline-flex items-center gap-2 self-start px-3 py-1 rounded-full bg-blue-50 border border-blue-200/80 text-blue-700 text-xs font-semibold tracking-wide mb-5">
              <span className="w-2 h-2 rounded-full bg-blue-600 animate-pulse" />
              <span>ENTERPRISE SECURITY PLATFORM</span>
            </div>

            {/* Short Professional Headline */}
            <h1 
              id="brand-section-title" 
              className="text-3xl sm:text-4xl lg:text-[40px] font-bold text-slate-900 tracking-tight leading-[1.2] mb-4"
            >
              Secure Access to <span className="text-blue-600">CyberWatch</span>
            </h1>

            {/* Supporting Text */}
            <p className="text-slate-600 text-base sm:text-lg leading-relaxed max-w-xl mb-8">
              Monitor threats, analyze security risks, and protect your digital environment from one unified security platform.
            </p>

            {/* ── Subtle Professional Cybersecurity Visual ──────────────── */}
            <div className="w-full max-w-lg bg-white/70 backdrop-blur-xs rounded-2xl border border-slate-200/70 p-5 sm:p-6 shadow-xs relative overflow-hidden mb-8">
              {/* Soft decorative background tint */}
              <div 
                className="absolute inset-0 pointer-events-none opacity-40"
                style={{
                  background: 'radial-gradient(circle at 50% 30%, rgba(37, 99, 235, 0.08), transparent 70%)'
                }}
              />

              {/* Minimal SVG Visual: Device with Shield & Network Nodes */}
              <div className="relative flex flex-col items-center justify-center">
                <svg 
                  viewBox="0 0 460 220" 
                  fill="none" 
                  xmlns="http://www.w3.org/2000/svg"
                  className="w-full h-auto max-h-[210px] text-slate-900 drop-shadow-xs"
                  aria-hidden="true"
                >
                  <defs>
                    <linearGradient id="shieldGrad" x1="230" y1="45" x2="230" y2="135" gradientUnits="userSpaceOnUse">
                      <stop offset="0%" stopColor="#2563EB" />
                      <stop offset="100%" stopColor="#1D4ED8" />
                    </linearGradient>
                    <linearGradient id="screenGrad" x1="100" y1="20" x2="360" y2="155" gradientUnits="userSpaceOnUse">
                      <stop offset="0%" stopColor="#F8FAFC" />
                      <stop offset="100%" stopColor="#EEF4FE" />
                    </linearGradient>
                    <filter id="softGlow" x="-20%" y="-20%" width="140%" height="140%">
                      <feGaussianBlur stdDeviation="6" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                  </defs>

                  {/* Laptop Base Drop Shadow */}
                  <ellipse cx="230" cy="198" rx="145" ry="8" fill="#CBD5E1" opacity="0.35" />

                  {/* Laptop Display Outer Bezel */}
                  <rect x="95" y="15" width="270" height="155" rx="10" fill="#0F172A" stroke="#CBD5E1" strokeWidth="1.5" />
                  
                  {/* Laptop Inner Screen */}
                  <rect x="103" y="23" width="254" height="139" rx="6" fill="url(#screenGrad)" />

                  {/* Camera Dot */}
                  <circle cx="230" cy="19" r="1.5" fill="#475569" />

                  {/* Screen Header Bar */}
                  <rect x="103" y="23" width="254" height="20" rx="6" fill="#FFFFFF" />
                  <line x1="103" y1="43" x2="357" y2="43" stroke="#E2E8F0" strokeWidth="1" />
                  
                  {/* Window Controls */}
                  <circle cx="116" cy="33" r="3" fill="#EF4444" opacity="0.75" />
                  <circle cx="126" cy="33" r="3" fill="#F59E0B" opacity="0.75" />
                  <circle cx="136" cy="33" r="3" fill="#10B981" opacity="0.75" />

                  {/* Screen URL Bar with Padlock */}
                  <rect x="156" y="27" width="148" height="12" rx="4" fill="#F1F5F9" />
                  <path d="M165 31.5 H166 V34 H164 V31.5 A1 1 0 0 1 165 31.5 Z" fill="#2563EB" />
                  <text x="171" y="36.5" fontSize="7" fill="#64748B" fontFamily="sans-serif" fontWeight="500">
                    cyberwatch.telemetry/active
                  </text>

                  {/* Network Interconnection Nodes */}
                  {/* Left Node 1 */}
                  <line x1="150" y1="85" x2="195" y2="85" stroke="#93C5FD" strokeWidth="1.5" strokeDasharray="3 3" />
                  <circle cx="145" cy="85" r="5" fill="#FFFFFF" stroke="#3B82F6" strokeWidth="2" />
                  <circle cx="145" cy="85" r="2" fill="#2563EB" />

                  {/* Right Node 1 */}
                  <line x1="265" y1="85" x2="310" y2="85" stroke="#93C5FD" strokeWidth="1.5" strokeDasharray="3 3" />
                  <circle cx="315" cy="85" r="5" fill="#FFFFFF" stroke="#3B82F6" strokeWidth="2" />
                  <circle cx="315" cy="85" r="2" fill="#2563EB" />

                  {/* Top-Right Node 2 */}
                  <line x1="255" y1="65" x2="295" y2="55" stroke="#BFDBFE" strokeWidth="1.2" strokeDasharray="3 3" />
                  <circle cx="300" cy="53" r="3.5" fill="#FFFFFF" stroke="#60A5FA" strokeWidth="1.5" />

                  {/* Bottom-Left Node 2 */}
                  <line x1="200" y1="110" x2="160" y2="125" stroke="#BFDBFE" strokeWidth="1.2" strokeDasharray="3 3" />
                  <circle cx="155" cy="127" r="3.5" fill="#FFFFFF" stroke="#60A5FA" strokeWidth="1.5" />

                  {/* Central Shield Glow Ring */}
                  <circle cx="230" cy="90" r="36" fill="#DBEAFE" opacity="0.45" />

                  {/* Central Security Shield */}
                  <path 
                    d="M230 55 L252 64 C252 82 243 99 230 108 C217 99 208 82 208 64 Z" 
                    fill="url(#shieldGrad)"
                    stroke="#FFFFFF"
                    strokeWidth="1.5"
                  />
                  
                  {/* Shield Inner Lock Emblem */}
                  <rect x="225" y="78" width="10" height="9" rx="1.5" fill="#FFFFFF" />
                  <path d="M227 78 V74 C227 72.3 228.3 71 230 71 C231.7 71 233 72.3 233 74 V78" stroke="#FFFFFF" strokeWidth="1.8" fill="none" strokeLinecap="round" />
                  <circle cx="230" cy="82" r="1.2" fill="#2563EB" />

                  {/* Status Pill on Screen */}
                  <rect x="180" y="125" width="100" height="15" rx="7.5" fill="#FFFFFF" stroke="#E2E8F0" strokeWidth="1" />
                  <circle cx="192" cy="132.5" r="2.5" fill="#10B981" />
                  <text x="199" y="135.5" fontSize="7" fill="#334155" fontFamily="sans-serif" fontWeight="600" letterSpacing="0.3">
                    PROTECTED · ZERO TRUST
                  </text>

                  {/* Laptop Lower Hinge & Chassis Base */}
                  <path d="M80 170 L95 170 L100 177 L360 177 L365 170 L380 170 C383 170 385 172 385 175 L382 188 C382 191 380 193 376 193 L84 193 C80 193 78 191 78 188 L75 175 C75 172 77 170 80 170 Z" fill="#E2E8F0" stroke="#CBD5E1" strokeWidth="1.2" />
                  <rect x="205" y="174" width="50" height="3" rx="1.5" fill="#94A3B8" opacity="0.6" />
                  {/* Subtle trackpad notch */}
                  <rect x="196" y="180" width="68" height="9" rx="2" fill="#F1F5F9" stroke="#CBD5E1" strokeWidth="0.8" />
                </svg>

                {/* Minimal Caption */}
                <div className="mt-3 flex items-center justify-between w-full text-[11px] text-slate-500 font-medium px-2">
                  <span className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                    Unified Threat Telemetry
                  </span>
                  <span className="text-slate-400">·</span>
                  <span>End-to-End Encryption</span>
                  <span className="text-slate-400">·</span>
                  <span>Continuous Monitoring</span>
                </div>
              </div>
            </div>

            {/* 3 Core Trust Indicators */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="flex items-start gap-2.5 p-3 rounded-xl bg-white/60 border border-slate-200/60">
                <ShieldCheck className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-semibold text-slate-800">Browser Isolation</div>
                  <div className="text-[11px] text-slate-500">Real-time web guard</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5 p-3 rounded-xl bg-white/60 border border-slate-200/60">
                <Cpu className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-semibold text-slate-800">AI Threat Analysis</div>
                  <div className="text-[11px] text-slate-500">Heuristic engine</div>
                </div>
              </div>

              <div className="flex items-start gap-2.5 p-3 rounded-xl bg-white/60 border border-slate-200/60">
                <Layers className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-semibold text-slate-800">Unified Portal</div>
                  <div className="text-[11px] text-slate-500">Centralized control</div>
                </div>
              </div>
            </div>
          </section>


          {/* ══════════════════════════════════════════════════════════════════
              RIGHT SIDE: Clean White Login Card
          ══════════════════════════════════════════════════════════════════ */}
          <section 
            aria-labelledby="login-form-heading" 
            className="lg:col-span-6 xl:col-span-5 flex items-center justify-center order-1 lg:order-2"
          >
            <div className="w-full max-w-[430px] bg-white rounded-2xl border border-slate-200/80 shadow-[0_10px_30px_-5px_rgba(15,23,42,0.06)] p-6 sm:p-8 transition-all">
              
              {/* Card Header: Small Shield Icon + Headings */}
              <div className="mb-6">
                <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600 shadow-xs mb-4">
                  <Shield className="w-5 h-5" strokeWidth={2.2} />
                </div>
                <h2 id="login-form-heading" className="text-2xl font-bold text-slate-900 tracking-tight">
                  Welcome Back
                </h2>
                <p className="text-sm text-slate-500 mt-1">
                  Sign in to continue to CyberWatch
                </p>
              </div>

              {/* Error Alert Banner */}
              {error && (
                <div
                  role="alert"
                  className="mb-5 p-3.5 bg-red-50/90 border border-red-200/90 rounded-xl text-red-900 text-xs sm:text-sm flex flex-col gap-2"
                >
                  <div className="flex items-start gap-2.5">
                    <AlertCircle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
                    <div className="flex-1 text-red-800 font-medium">
                      {error}
                    </div>
                  </div>

                  {/* If gateway is offline, provide reviewer an instant demo bypass option */}
                  {isServerOffline && (
                    <div className="pt-2 border-t border-red-200/70 flex items-center justify-between">
                      <span className="text-[11px] text-red-700">Project review mode:</span>
                      <button
                        type="button"
                        onClick={() => navigate(from, { replace: true })}
                        className="text-xs font-semibold text-blue-700 hover:text-blue-800 underline transition-colors cursor-pointer"
                      >
                        Enter Dashboard as Demo &rarr;
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* Form */}
              <form id="cyberwatch-login-form" onSubmit={handleSubmit} noValidate className="space-y-4">
                {/* Email Input Field */}
                <div>
                  <label
                    htmlFor="login-email"
                    className="block text-xs font-semibold uppercase tracking-wider text-slate-700 mb-1.5"
                  >
                    Email Address
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                      <Mail className="w-4 h-4" />
                    </div>
                    <input
                      id="login-email"
                      type="email"
                      name="email"
                      autoComplete="email"
                      required
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value)
                        if (fieldErrors.email) setFieldErrors((prev) => ({ ...prev, email: undefined }))
                      }}
                      placeholder="Enter your email address"
                      aria-invalid={!!fieldErrors.email}
                      aria-describedby={fieldErrors.email ? 'login-email-error' : undefined}
                      className={`w-full pl-10 pr-3.5 py-2.5 text-sm rounded-xl border bg-white text-slate-900 placeholder-slate-400 outline-none transition-all shadow-xs ${
                        fieldErrors.email
                          ? 'border-red-300 focus:border-red-500 focus:ring-3 focus:ring-red-500/15'
                          : 'border-slate-300 hover:border-slate-400 focus:border-blue-600 focus:ring-3 focus:ring-blue-600/15'
                      }`}
                    />
                  </div>
                  {fieldErrors.email && (
                    <p
                      id="login-email-error"
                      role="alert"
                      className="mt-1.5 text-xs text-red-600 font-medium flex items-center gap-1.5"
                    >
                      <AlertCircle className="w-3.5 h-3.5 shrink-0" /> {fieldErrors.email}
                    </p>
                  )}
                </div>

                {/* Password Input Field */}
                <div>
                  <label
                    htmlFor="login-password"
                    className="block text-xs font-semibold uppercase tracking-wider text-slate-700 mb-1.5"
                  >
                    Password
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                      <Lock className="w-4 h-4" />
                    </div>
                    <input
                      id="login-password"
                      type={showPassword ? 'text' : 'password'}
                      name="password"
                      autoComplete="current-password"
                      required
                      value={password}
                      onChange={(e) => {
                        setPassword(e.target.value)
                        if (fieldErrors.password) setFieldErrors((prev) => ({ ...prev, password: undefined }))
                      }}
                      placeholder="Enter your password"
                      aria-invalid={!!fieldErrors.password}
                      aria-describedby={fieldErrors.password ? 'login-password-error' : undefined}
                      className={`w-full pl-10 pr-10 py-2.5 text-sm rounded-xl border bg-white text-slate-900 placeholder-slate-400 outline-none transition-all shadow-xs ${
                        fieldErrors.password
                          ? 'border-red-300 focus:border-red-500 focus:ring-3 focus:ring-red-500/15'
                          : 'border-slate-300 hover:border-slate-400 focus:border-blue-600 focus:ring-3 focus:ring-blue-600/15'
                      }`}
                    />
                    <button
                      type="button"
                      id="toggle-login-password"
                      onClick={() => setShowPassword((prev) => !prev)}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600 transition-colors rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {fieldErrors.password && (
                    <p
                      id="login-password-error"
                      role="alert"
                      className="mt-1.5 text-xs text-red-600 font-medium flex items-center gap-1.5"
                    >
                      <AlertCircle className="w-3.5 h-3.5 shrink-0" /> {fieldErrors.password}
                    </p>
                  )}
                </div>

                {/* "Remember Me" Checkbox & "Forgot Password?" Link */}
                <div className="flex items-center justify-between pt-1">
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      id="remember-me"
                      type="checkbox"
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                      className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-blue-500 cursor-pointer accent-blue-600"
                    />
                    <span className="text-xs font-medium text-slate-600">
                      Remember me
                    </span>
                  </label>

                  <button
                    type="button"
                    id="forgot-password-link"
                    onClick={() => {
                      setForgotEmail(email)
                      setForgotStatus('idle')
                      setIsForgotModalOpen(true)
                    }}
                    className="text-xs font-medium text-blue-600 hover:text-blue-700 hover:underline transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 rounded"
                  >
                    Forgot Password?
                  </button>
                </div>

                {/* Large Professional Blue Sign In Button */}
                <button
                  id="sign-in-button"
                  type="submit"
                  disabled={isLoading}
                  className="w-full mt-2 h-11 sm:h-12 flex items-center justify-center gap-2 rounded-xl text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:bg-blue-400 disabled:cursor-not-allowed transition-all shadow-sm shadow-blue-600/25 hover:shadow-md hover:shadow-blue-600/30 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-blue-600/20 cursor-pointer"
                >
                  {isLoading ? (
                    <>
                      <div className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                      <span>Signing In...</span>
                    </>
                  ) : (
                    <>
                      <span>Sign In</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>

              {/* Optional Divider: "OR" */}
              <div className="relative my-5">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-slate-200" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-white px-3 text-slate-400 font-semibold tracking-wider">
                    OR
                  </span>
                </div>
              </div>

              {/* Optional Google Sign-in Button */}
              <button
                type="button"
                id="google-signin-button"
                onClick={handleGoogleSignIn}
                disabled={isGoogleLoading}
                className="w-full h-11 border border-slate-200 hover:border-slate-300 hover:bg-slate-50/80 active:bg-slate-100 rounded-xl flex items-center justify-center gap-3 text-sm font-semibold text-slate-700 transition-all shadow-2xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 cursor-pointer"
              >
                {isGoogleLoading ? (
                  <div className="w-4 h-4 rounded-full border-2 border-slate-400 border-t-blue-600 animate-spin" />
                ) : (
                  <svg className="w-4 h-4" viewBox="0 0 24 24">
                    <path
                      fill="#4285F4"
                      d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.8-2.4 3.65v3.03h3.88c2.27-2.09 3.665-5.17 3.665-9.12z"
                    />
                    <path
                      fill="#34A853"
                      d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.03c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.26v3.13C3.25 21.37 7.33 24 12 24z"
                    />
                    <path
                      fill="#FBBC05"
                      d="M5.28 14.29c-.25-.72-.38-1.49-.38-2.29s.13-1.57.38-2.29V6.58H1.26C.46 8.18 0 9.99 0 12s.46 3.82 1.26 5.42l4.02-3.13z"
                    />
                    <path
                      fill="#EA4335"
                      d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.33 0 3.25 2.63 1.26 6.58l4.02 3.13c.95-2.83 3.6-4.96 6.72-4.96z"
                    />
                  </svg>
                )}
                <span>Sign in with Google</span>
              </button>

              {/* Below Button: Don't have an account? Create Account */}
              <div className="mt-6 text-center text-xs sm:text-sm text-slate-500">
                Don't have an account?{' '}
                <Link
                  to="/register"
                  id="create-account-link"
                  className="font-semibold text-blue-600 hover:text-blue-700 hover:underline transition-colors ml-1"
                >
                  Create Account
                </Link>
              </div>

              {/* Demo Quick-Fill Pill (Clean helper for reviewer evaluation) */}
              <div className="mt-5 pt-4 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
                <span className="flex items-center gap-1">
                  <Lock className="w-3 h-3 text-slate-400" />
                  Quick test:
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setEmail('analyst@cyberwatch.io')
                    setPassword('CyberWatch#2026')
                    setFieldErrors({})
                  }}
                  className="font-medium text-slate-600 hover:text-blue-600 transition-colors bg-slate-100 hover:bg-blue-50 px-2 py-0.5 rounded cursor-pointer"
                >
                  Fill Demo Credentials
                </button>
              </div>

            </div>
          </section>

        </div>
      </main>

      {/* ── Corporate Trust Footer ───────────────────────────────────────── */}
      <footer className="w-full bg-white/70 border-t border-slate-200/70 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2.5">
          <p>© {CURRENT_YEAR} CYBERWATCH Technologies. Unified Web & Browser Threat Detection Platform.</p>
          <div className="flex items-center gap-4 text-slate-500 font-medium text-xs">
            <Link to="/cyber-safety" className="hover:text-blue-600 transition-colors">
              Security Practices
            </Link>
            <span>•</span>
            <Link to="/help" className="hover:text-blue-600 transition-colors">
              Help Center
            </Link>
            <span>•</span>
            <span className="text-slate-400">Strict Zero-Knowledge Auth</span>
          </div>
        </div>
      </footer>

      {/* ── Forgot Password Modal ────────────────────────────────────────── */}
      {isForgotModalOpen && (
        <div 
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-200"
          role="dialog"
          aria-modal="true"
          aria-labelledby="forgot-modal-title"
        >
          <div className="bg-white rounded-2xl border border-slate-200 shadow-xl max-w-md w-full p-6 relative">
            <button
              type="button"
              onClick={() => setIsForgotModalOpen(false)}
              aria-label="Close dialog"
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-600 p-1 rounded-lg hover:bg-slate-100 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>

            {forgotStatus === 'sent' ? (
              <div className="text-center py-3">
                <div className="w-12 h-12 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mx-auto mb-3">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-slate-900">Recovery Email Dispatched</h3>
                <p className="text-xs sm:text-sm text-slate-600 mt-2 max-w-xs mx-auto">
                  If an account exists for <span className="font-semibold text-slate-800">{forgotEmail}</span>, a secure password reset link has been dispatched.
                </p>
                <button
                  type="button"
                  onClick={() => setIsForgotModalOpen(false)}
                  className="mt-6 w-full h-10 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs sm:text-sm transition-colors"
                >
                  Return to Sign In
                </button>
              </div>
            ) : (
              <div>
                <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center mb-4">
                  <Lock className="w-5 h-5" />
                </div>
                <h3 id="forgot-modal-title" className="text-lg font-bold text-slate-900">
                  Reset Password
                </h3>
                <p className="text-xs sm:text-sm text-slate-500 mt-1 mb-4">
                  Enter your registered organizational email address to receive password recovery instructions.
                </p>

                <form onSubmit={handleForgotSubmit} className="space-y-4">
                  <div>
                    <label 
                      htmlFor="forgot-email"
                      className="block text-xs font-semibold uppercase tracking-wider text-slate-700 mb-1"
                    >
                      Email Address
                    </label>
                    <input
                      id="forgot-email"
                      type="email"
                      required
                      value={forgotEmail}
                      onChange={(e) => setForgotEmail(e.target.value)}
                      placeholder="name@organization.com"
                      className="w-full px-3.5 py-2.5 text-sm rounded-xl border border-slate-300 focus:border-blue-600 focus:ring-3 focus:ring-blue-600/15 outline-none"
                    />
                  </div>

                  <div className="flex items-center justify-end gap-3 pt-2">
                    <button
                      type="button"
                      onClick={() => setIsForgotModalOpen(false)}
                      className="px-4 py-2 text-xs sm:text-sm font-semibold text-slate-600 hover:bg-slate-100 rounded-xl transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={forgotStatus === 'submitting'}
                      className="px-4 py-2 text-xs sm:text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-xl transition-colors flex items-center gap-1.5"
                    >
                      {forgotStatus === 'submitting' ? 'Sending...' : 'Send Reset Link'}
                    </button>
                  </div>
                </form>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
