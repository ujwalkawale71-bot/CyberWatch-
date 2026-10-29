import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, Lock, AlertCircle, ArrowRight, CheckCircle2 } from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import axios from 'axios'

const CURRENT_YEAR = new Date().getFullYear()

// ── Password Strength Indicator ────────────────────────────────────────────────
function getPasswordStrength(password: string): { level: 0 | 1 | 2 | 3; label: string; color: string } {
  if (password.length === 0) return { level: 0, label: '', color: '' }
  if (password.length < 8) return { level: 1, label: 'Too short (min 8 characters)', color: 'bg-red-500' }
  if (password.length < 12) return { level: 2, label: 'Fair strength', color: 'bg-amber-500' }
  return { level: 3, label: 'Strong password', color: 'bg-emerald-500' }
}

export function RegisterPage() {
  const { register } = useAuth()
  const navigate = useNavigate()

  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<{
    name?: string; email?: string; password?: string; confirmPassword?: string
  }>({})

  const strength = getPasswordStrength(password)

  function validate(): boolean {
    const errors: typeof fieldErrors = {}
    if (!name.trim() || name.trim().length < 2) errors.name = 'Full name must be at least 2 characters.'
    if (!email.trim()) errors.email = 'Email address is required.'
    else if (!/^\S+@\S+\.\S+$/.test(email)) errors.email = 'Please enter a valid email address.'
    if (!password) errors.password = 'Password is required.'
    else if (password.length < 8) errors.password = 'Password must be at least 8 characters.'
    if (!confirmPassword) errors.confirmPassword = 'Please confirm your password.'
    else if (password !== confirmPassword) errors.confirmPassword = 'Passwords do not match.'
    setFieldErrors(errors)
    return Object.keys(errors).length === 0
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (isLoading) return
    setError(null)
    if (!validate()) return

    setIsLoading(true)
    try {
      await register({ name: name.trim(), email, password })
      navigate('/dashboard', { replace: true })
    } catch (err) {
      if (axios.isAxiosError(err)) {
        const status = err.response?.status
        const message = err.response?.data?.message

        if (status === 409) {
          setError('An account with this email already exists.')
        } else if (status === 400) {
          const validationErrors = err.response?.data?.errors
          if (validationErrors?.length) {
            const mapped: typeof fieldErrors = {}
            validationErrors.forEach(({ field, message: errMsg }: { field: string; message: string }) => {
              if (field === 'name' || field === 'email' || field === 'password') {
                (mapped as any)[field] = errMsg
              }
            })
            setFieldErrors(mapped)
          } else {
            setError(message || 'Please check your information and try again.')
          }
        } else if (status === 429) {
          setError('Too many registration attempts. Please wait 15 minutes and try again.')
        } else if (status === 500 || status === 503) {
          setError('Authentication service is temporarily unavailable.')
        } else if (status === 0 || !err.response) {
          setError('Unable to connect to the authentication service. Please ensure the backend server is running.')
        } else {
          setError(message || 'An unexpected error occurred. Please try again.')
        }
      } else {
        setError('An unexpected error occurred. Please try again.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col justify-between bg-slate-50 relative selection:bg-blue-100 selection:text-blue-900">
      {/* Subtle clean background grid accent */}
      <div
        className="absolute inset-0 pointer-events-none opacity-40"
        style={{
          backgroundImage: 'radial-gradient(#cbd5e1 1px, transparent 1px)',
          backgroundSize: '24px 24px',
        }}
      />

      {/* Top subtle blue glow */}
      <div
        className="absolute top-0 inset-x-0 h-96 pointer-events-none opacity-60"
        style={{
          background: 'radial-gradient(ellipse 60% 50% at 50% -10%, rgba(37,99,235,0.08), transparent 70%)',
        }}
      />

      {/* Main Content Area */}
      <main className="relative z-10 flex-1 flex flex-col items-center justify-center px-4 py-12 sm:px-6">
        {/* Brand Header */}
        <div className="mb-8 text-center">
          <Link to="/" className="inline-flex items-center gap-2.5 group">
            <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-sm shadow-blue-500/20 group-hover:bg-blue-700 transition-colors">
              <Shield className="w-5 h-5" />
            </div>
            <span className="font-bold text-xl tracking-tight text-slate-900">
              CYBERWATCH
            </span>
          </Link>
        </div>

        {/* Authentication Card */}
        <div className="w-full max-w-[460px] bg-white rounded-2xl border border-slate-200/90 shadow-sm p-7 sm:p-9 transition-all">
          <div className="mb-6">
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
              Create your account
            </h1>
            <p className="text-sm text-slate-500 mt-1">
              Start protecting your browsing and monitor web threats in real-time.
            </p>
          </div>

          {/* Error Banner */}
          {error && (
            <div
              role="alert"
              className="mb-5 flex items-start gap-3 p-3.5 bg-red-50 border border-red-200/80 rounded-xl text-red-900 text-sm"
            >
              <AlertCircle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
              <div className="flex-1 text-xs sm:text-sm text-red-800">
                {error}
              </div>
            </div>
          )}

          {/* Form */}
          <form id="register-form" onSubmit={handleSubmit} noValidate className="space-y-4">
            {/* Full Name Field */}
            <div>
              <label
                htmlFor="register-name"
                className="block text-xs font-semibold uppercase tracking-wider text-slate-700 mb-1.5"
              >
                Full Name
              </label>
              <input
                id="register-name"
                type="text"
                name="name"
                autoComplete="name"
                required
                value={name}
                onChange={(e) => {
                  setName(e.target.value)
                  if (fieldErrors.name) setFieldErrors((prev) => ({ ...prev, name: undefined }))
                }}
                placeholder="Alex Johnson"
                aria-invalid={!!fieldErrors.name}
                aria-describedby={fieldErrors.name ? 'register-name-error' : undefined}
                className={`w-full px-3.5 py-2.5 text-sm rounded-xl border bg-white text-slate-900 placeholder-slate-400 outline-none transition-all shadow-xs ${
                  fieldErrors.name
                    ? 'border-red-300 focus:border-red-500 focus:ring-4 focus:ring-red-500/10'
                    : 'border-slate-300 hover:border-slate-400 focus:border-blue-600 focus:ring-4 focus:ring-blue-600/10'
                }`}
              />
              {fieldErrors.name && (
                <p
                  id="register-name-error"
                  role="alert"
                  className="mt-1.5 text-xs text-red-600 font-medium flex items-center gap-1.5"
                >
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" /> {fieldErrors.name}
                </p>
              )}
            </div>

            {/* Email Field */}
            <div>
              <label
                htmlFor="register-email"
                className="block text-xs font-semibold uppercase tracking-wider text-slate-700 mb-1.5"
              >
                Work or Personal Email
              </label>
              <input
                id="register-email"
                type="email"
                name="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value)
                  if (fieldErrors.email) setFieldErrors((prev) => ({ ...prev, email: undefined }))
                }}
                placeholder="name@company.com"
                aria-invalid={!!fieldErrors.email}
                aria-describedby={fieldErrors.email ? 'register-email-error' : undefined}
                className={`w-full px-3.5 py-2.5 text-sm rounded-xl border bg-white text-slate-900 placeholder-slate-400 outline-none transition-all shadow-xs ${
                  fieldErrors.email
                    ? 'border-red-300 focus:border-red-500 focus:ring-4 focus:ring-red-500/10'
                    : 'border-slate-300 hover:border-slate-400 focus:border-blue-600 focus:ring-4 focus:ring-blue-600/10'
                }`}
              />
              {fieldErrors.email && (
                <p
                  id="register-email-error"
                  role="alert"
                  className="mt-1.5 text-xs text-red-600 font-medium flex items-center gap-1.5"
                >
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" /> {fieldErrors.email}
                </p>
              )}
            </div>

            {/* Password Field */}
            <div>
              <label
                htmlFor="register-password"
                className="block text-xs font-semibold uppercase tracking-wider text-slate-700 mb-1.5"
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="register-password"
                  type={showPassword ? 'text' : 'password'}
                  name="new-password"
                  autoComplete="new-password"
                  required
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value)
                    if (fieldErrors.password) setFieldErrors((prev) => ({ ...prev, password: undefined }))
                  }}
                  placeholder="At least 8 characters"
                  aria-invalid={!!fieldErrors.password}
                  aria-describedby="register-password-error register-password-strength"
                  className={`w-full pl-3.5 pr-10 py-2.5 text-sm rounded-xl border bg-white text-slate-900 placeholder-slate-400 outline-none transition-all shadow-xs ${
                    fieldErrors.password
                      ? 'border-red-300 focus:border-red-500 focus:ring-4 focus:ring-red-500/10'
                      : 'border-slate-300 hover:border-slate-400 focus:border-blue-600 focus:ring-4 focus:ring-blue-600/10'
                  }`}
                />
                <button
                  type="button"
                  id="toggle-register-password"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600 transition-colors rounded"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>

              {/* Password Strength Meter */}
              {password.length > 0 && (
                <div id="register-password-strength" className="mt-2 space-y-1">
                  <div className="flex gap-1.5">
                    {[1, 2, 3].map((level) => (
                      <div
                        key={level}
                        className={`h-1 flex-1 rounded-full transition-all duration-300 ${
                          strength.level >= level ? strength.color : 'bg-slate-200'
                        }`}
                      />
                    ))}
                  </div>
                  <p
                    className={`text-[11px] font-medium ${
                      strength.level === 1
                        ? 'text-red-600'
                        : strength.level === 2
                        ? 'text-amber-600'
                        : 'text-emerald-600'
                    }`}
                  >
                    {strength.label}
                  </p>
                </div>
              )}

              {fieldErrors.password && (
                <p
                  id="register-password-error"
                  role="alert"
                  className="mt-1.5 text-xs text-red-600 font-medium flex items-center gap-1.5"
                >
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" /> {fieldErrors.password}
                </p>
              )}
            </div>

            {/* Confirm Password Field */}
            <div>
              <label
                htmlFor="register-confirm-password"
                className="block text-xs font-semibold uppercase tracking-wider text-slate-700 mb-1.5"
              >
                Confirm Password
              </label>
              <div className="relative">
                <input
                  id="register-confirm-password"
                  type={showConfirmPassword ? 'text' : 'password'}
                  name="confirm-password"
                  autoComplete="new-password"
                  required
                  value={confirmPassword}
                  onChange={(e) => {
                    setConfirmPassword(e.target.value)
                    if (fieldErrors.confirmPassword)
                      setFieldErrors((prev) => ({ ...prev, confirmPassword: undefined }))
                  }}
                  placeholder="Repeat your password"
                  aria-invalid={!!fieldErrors.confirmPassword}
                  aria-describedby={fieldErrors.confirmPassword ? 'register-confirm-error' : undefined}
                  className={`w-full pl-3.5 pr-10 py-2.5 text-sm rounded-xl border bg-white text-slate-900 placeholder-slate-400 outline-none transition-all shadow-xs ${
                    fieldErrors.confirmPassword
                      ? 'border-red-300 focus:border-red-500 focus:ring-4 focus:ring-red-500/10'
                      : 'border-slate-300 hover:border-slate-400 focus:border-blue-600 focus:ring-4 focus:ring-blue-600/10'
                  }`}
                />
                <button
                  type="button"
                  id="toggle-confirm-password"
                  onClick={() => setShowConfirmPassword((prev) => !prev)}
                  aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600 transition-colors rounded"
                >
                  {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {fieldErrors.confirmPassword && (
                <p
                  id="register-confirm-error"
                  role="alert"
                  className="mt-1.5 text-xs text-red-600 font-medium flex items-center gap-1.5"
                >
                  <AlertCircle className="w-3.5 h-3.5 shrink-0" /> {fieldErrors.confirmPassword}
                </p>
              )}
            </div>

            {/* Feature Checklist mini-pill */}
            <div className="pt-1 pb-1">
              <div className="flex items-center gap-2 text-xs text-slate-600">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>Free instant threat detection & workspace access included</span>
              </div>
            </div>

            {/* Submit Button */}
            <button
              id="register-submit-btn"
              type="submit"
              disabled={isLoading}
              className="w-full mt-2 h-11 flex items-center justify-center gap-2 rounded-xl text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:bg-blue-400 disabled:cursor-not-allowed transition-colors shadow-sm focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-blue-600/20"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  <span>Creating account...</span>
                </>
              ) : (
                <>
                  <span>Create account</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-slate-200" />
            </div>
            <div className="relative flex justify-center text-xs uppercase">
              <span className="bg-white px-2 text-slate-400 font-medium">Already registered?</span>
            </div>
          </div>

          {/* Sign In Link */}
          <div className="text-center">
            <Link
              to="/login"
              id="go-to-login"
              className="inline-flex items-center justify-center w-full h-10 px-4 text-sm font-semibold text-slate-700 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-xl transition-colors"
            >
              Sign in to your account
            </Link>
          </div>
        </div>

        {/* Security badge under card */}
        <div className="mt-6 flex items-center gap-2 text-xs text-slate-500">
          <Lock className="w-3.5 h-3.5 text-slate-400" />
          <span>Secured with bcrypt password hashing & encrypted credentials</span>
        </div>
      </main>

      {/* Corporate Footer */}
      <footer className="relative z-10 py-6 border-t border-slate-200/60 bg-white/50 backdrop-blur-xs text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <p>© {CURRENT_YEAR} CyberWatch Inc. All rights reserved.</p>
          <div className="flex items-center gap-5 font-medium text-slate-600">
            <Link to="/help" className="hover:text-slate-900 transition-colors">
              Support
            </Link>
            <span className="text-slate-300">•</span>
            <Link to="/cyber-safety" className="hover:text-slate-900 transition-colors">
              Security Practices
            </Link>
            <span className="text-slate-300">•</span>
            <Link to="/" className="hover:text-slate-900 transition-colors">
              Home
            </Link>
          </div>
        </div>
      </footer>
    </div>
  )
}
