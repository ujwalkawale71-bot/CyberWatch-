import { useState, useMemo } from 'react';
import {
  Key,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Eye,
  EyeOff,
  RefreshCw,
  Copy,
  Check,
  Shield,
  Sparkles,
} from 'lucide-react';

interface EntropyAnalysis {
  score: number; // 0 - 100
  entropyBits: number;
  level: 'Weak' | 'Moderate' | 'Strong' | 'Very Strong';
  crackTimeEstimate: string;
  hasLength: boolean;
  hasLower: boolean;
  hasUpper: boolean;
  hasNumber: boolean;
  hasSymbol: boolean;
  hasNoCommonPatterns: boolean;
  patternsFound: string[];
  recommendations: string[];
}

// Curated safe wordlist for client-side passphrase generation
const WORDLIST = [
  'anchor', 'beacon', 'breeze', 'bridge', 'castle', 'cipher', 'cloud', 'crystal',
  'delta', 'echo', 'falcon', 'forest', 'galaxy', 'harbor', 'island', 'jupiter',
  'kernel', 'lantern', 'matrix', 'meadow', 'nebula', 'ocean', 'orbit', 'pathway',
  'quantum', 'radar', 'safeguard', 'shadow', 'summit', 'timber', 'tunnel', 'vector',
  'vertex', 'voyage', 'whisper', 'zenith', 'beacon', 'shield', 'glacier', 'horizon',
  'monolith', 'obsidian', 'pulse', 'radius', 'sequoia', 'tesseract', 'vortex', 'wildfire'
];

function analyzePasswordLocally(password: string): EntropyAnalysis {
  if (!password) {
    return {
      score: 0,
      entropyBits: 0,
      level: 'Weak',
      crackTimeEstimate: 'Instant',
      hasLength: false,
      hasLower: false,
      hasUpper: false,
      hasNumber: false,
      hasSymbol: false,
      hasNoCommonPatterns: true,
      patternsFound: [],
      recommendations: ['Enter a password to evaluate its strength and entropy.'],
    };
  }

  const length = password.length;
  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSymbol = /[^a-zA-Z0-9]/.test(password);

  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasNumber) poolSize += 10;
  if (hasSymbol) poolSize += 33;

  // Base Shannon-style entropy in bits = length * log2(poolSize)
  let rawEntropy = poolSize > 0 ? length * Math.log2(poolSize) : 0;

  const patternsFound: string[] = [];
  const lowerPass = password.toLowerCase();

  // Pattern detection penalties
  if (/^[a-zA-Z]+$/.test(password)) {
    patternsFound.push('Only alphabetic characters used');
    rawEntropy = Math.max(0, rawEntropy - 8);
  }
  if (/^[0-9]+$/.test(password)) {
    patternsFound.push('Only numeric digits used');
    rawEntropy = Math.max(0, rawEntropy - 16);
  }
  if (/(.)\1{2,}/.test(password)) {
    patternsFound.push('Repeated characters detected (e.g. "aaa")');
    rawEntropy = Math.max(0, rawEntropy - 10);
  }
  if (/(123|abc|qwerty|password|admin|welcome|letmein)/i.test(lowerPass)) {
    patternsFound.push('Common dictionary sequence or keyboard walk detected');
    rawEntropy = Math.max(0, rawEntropy - 20);
  }

  const entropyBits = Math.max(0, Math.round(rawEntropy));

  // Determine Level and Score
  let level: 'Weak' | 'Moderate' | 'Strong' | 'Very Strong' = 'Weak';
  let score = 0;

  if (entropyBits < 36 || length < 8) {
    level = 'Weak';
    score = Math.min(35, Math.round((entropyBits / 36) * 35));
  } else if (entropyBits < 56 || length < 12) {
    level = 'Moderate';
    score = 36 + Math.min(29, Math.round(((entropyBits - 36) / 20) * 29));
  } else if (entropyBits < 80 || length < 16) {
    level = 'Strong';
    score = 66 + Math.min(24, Math.round(((entropyBits - 56) / 24) * 24));
  } else {
    level = 'Very Strong';
    score = Math.min(100, 90 + Math.round(((entropyBits - 80) / 40) * 10));
  }

  // Realistic offline GPU cluster crack time estimation (~100 billion hashes/sec)
  let crackTimeEstimate = 'Instant';
  const combinations = Math.pow(2, entropyBits);
  const guessesPerSecond = 100_000_000_000; // 100 GH/s offline attack
  const seconds = combinations / (2 * guessesPerSecond);

  if (seconds < 1) crackTimeEstimate = 'Instant (< 1 second)';
  else if (seconds < 60) crackTimeEstimate = `${Math.round(seconds)} seconds`;
  else if (seconds < 3600) crackTimeEstimate = `${Math.round(seconds / 60)} minutes`;
  else if (seconds < 86400) crackTimeEstimate = `${Math.round(seconds / 3600)} hours`;
  else if (seconds < 86400 * 30) crackTimeEstimate = `${Math.round(seconds / 86400)} days`;
  else if (seconds < 86400 * 365) crackTimeEstimate = `${Math.round(seconds / (86400 * 30))} months`;
  else if (seconds < 86400 * 365 * 1000) crackTimeEstimate = `${Math.round(seconds / (86400 * 365))} years`;
  else if (seconds < 86400 * 365 * 1_000_000) crackTimeEstimate = `${Math.round(seconds / (86400 * 365 * 1000))} thousand years`;
  else crackTimeEstimate = 'Millions of centuries';

  // Actionable recommendations
  const recommendations: string[] = [];
  if (length < 14) recommendations.push('Increase length to at least 14-16 characters or use a multi-word passphrase.');
  if (!hasLower || !hasUpper) recommendations.push('Mix both uppercase and lowercase letters.');
  if (!hasNumber) recommendations.push('Include numbers to expand character search space.');
  if (!hasSymbol) recommendations.push('Add special symbols (e.g. #, $, %, !) to significantly increase entropy.');
  if (patternsFound.length > 0) recommendations.push('Avoid common dictionary words, predictable names, or repeating keystrokes.');

  return {
    score,
    entropyBits,
    level,
    crackTimeEstimate,
    hasLength: length >= 12,
    hasLower,
    hasUpper,
    hasNumber,
    hasSymbol,
    hasNoCommonPatterns: patternsFound.length === 0,
    patternsFound,
    recommendations,
  };
}

export function PasswordStrengthMeter() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);
  const [passphraseWordCount, setPassphraseWordCount] = useState(4);

  const analysis = useMemo(() => analyzePasswordLocally(password), [password]);

  function handleGeneratePassphrase() {
    try {
      const array = new Uint32Array(passphraseWordCount);
      window.crypto.getRandomValues(array);
      const chosenWords = Array.from(array).map((val) => WORDLIST[val % WORDLIST.length]);
      // Add a 2-digit random number to the end
      const numRandom = (array[0] % 90) + 10;
      const combined = `${chosenWords.join('-')}-${numRandom}`;
      setPassword(combined);
    } catch {
      // Fallback
      const chosenWords = [];
      for (let i = 0; i < passphraseWordCount; i++) {
        chosenWords.push(WORDLIST[Math.floor(Math.random() * WORDLIST.length)]);
      }
      const combined = `${chosenWords.join('-')}-${Math.floor(Math.random() * 90) + 10}`;
      setPassword(combined);
    }
  }

  function handleCopy() {
    if (!password) return;
    navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const levelColor = {
    Weak: 'bg-red-500 text-red-700',
    Moderate: 'bg-amber-500 text-amber-700',
    Strong: 'bg-blue-600 text-blue-700',
    'Very Strong': 'bg-emerald-600 text-emerald-700',
  }[analysis.level];

  return (
    <div className="space-y-6">
      {/* Strict Privacy Guarantee Banner */}
      <div className="p-4 rounded-xl bg-blue-50/70 border border-blue-200/80 flex items-start gap-3">
        <Shield className="w-5 h-5 text-blue-600 shrink-0 mt-0.5" />
        <div className="text-xs text-blue-900 leading-relaxed">
          <span className="font-bold">Strict Client-Side Privacy Guarantee: </span>
          Your password analysis is performed entirely locally inside your browser runtime.
          Passwords are never transmitted over the network, never logged, and never stored in any database.
        </div>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 shadow-xs p-6 md:p-8 space-y-6">
        <div>
          <div className="flex items-center justify-between mb-2">
            <label htmlFor="password-input" className="text-xs font-bold uppercase tracking-wider text-slate-700">
              Test Password or Passphrase Strength
            </label>
            <span className="text-xs text-slate-400">
              {password.length} character{password.length === 1 ? '' : 's'}
            </span>
          </div>

          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
              <Key className="w-4 h-4" />
            </div>
            <input
              id="password-input"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Type or generate a password to analyze..."
              className="w-full pl-10 pr-24 py-3 bg-slate-50 border border-slate-200 rounded-xl text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:bg-white transition-all font-mono"
              autoComplete="off"
              spellCheck={false}
            />
            <div className="absolute inset-y-0 right-0 pr-2 flex items-center gap-1">
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-200/60 transition-colors"
                title={showPassword ? 'Hide password' : 'Show password'}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
              {password && (
                <button
                  type="button"
                  onClick={handleCopy}
                  className="p-1.5 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-200/60 transition-colors"
                  title="Copy password"
                  aria-label="Copy password"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Strength Meter Bar */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-slate-600">Calculated Strength:</span>
            <span className="font-bold text-slate-900 flex items-center gap-2">
              <span className={`inline-block w-2.5 h-2.5 rounded-full ${levelColor.split(' ')[0]}`} />
              <span>{analysis.level} ({analysis.score} / 100)</span>
            </span>
          </div>
          <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden flex">
            <div
              className={`h-full transition-all duration-300 ${levelColor.split(' ')[0]}`}
              style={{ width: `${Math.max(5, analysis.score)}%` }}
            />
          </div>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/70">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
              Entropy
            </div>
            <div className="text-xl font-bold text-slate-900 mt-1">
              {analysis.entropyBits} <span className="text-xs font-normal text-slate-500">bits</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Raw mathematical search-space depth
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/70">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
              Offline Crack Resistance
            </div>
            <div className="text-xl font-bold text-slate-900 mt-1 truncate" title={analysis.crackTimeEstimate}>
              {analysis.crackTimeEstimate}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Estimated at 100 GH/s brute-force
            </div>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/70">
            <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
              Security Level
            </div>
            <div className="text-xl font-bold text-slate-900 mt-1">
              {analysis.level}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Based on length, entropy &amp; patterns
            </div>
          </div>
        </div>

        {/* Requirements Checklist */}
        <div className="space-y-3 pt-2 border-t border-slate-100">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600">
            Structural Complexity Checklist
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
            <div className="flex items-center gap-2">
              {analysis.hasLength ? (
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-slate-300" />
              )}
              <span className={analysis.hasLength ? 'text-slate-800 font-semibold' : 'text-slate-500'}>
                12+ Characters
              </span>
            </div>

            <div className="flex items-center gap-2">
              {analysis.hasLower ? (
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-slate-300" />
              )}
              <span className={analysis.hasLower ? 'text-slate-800 font-semibold' : 'text-slate-500'}>
                Lowercase (a-z)
              </span>
            </div>

            <div className="flex items-center gap-2">
              {analysis.hasUpper ? (
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-slate-300" />
              )}
              <span className={analysis.hasUpper ? 'text-slate-800 font-semibold' : 'text-slate-500'}>
                Uppercase (A-Z)
              </span>
            </div>

            <div className="flex items-center gap-2">
              {analysis.hasNumber ? (
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-slate-300" />
              )}
              <span className={analysis.hasNumber ? 'text-slate-800 font-semibold' : 'text-slate-500'}>
                Numbers (0-9)
              </span>
            </div>

            <div className="flex items-center gap-2">
              {analysis.hasSymbol ? (
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-slate-300" />
              )}
              <span className={analysis.hasSymbol ? 'text-slate-800 font-semibold' : 'text-slate-500'}>
                Special Symbols
              </span>
            </div>

            <div className="flex items-center gap-2">
              {analysis.hasNoCommonPatterns ? (
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-amber-500" />
              )}
              <span className={analysis.hasNoCommonPatterns ? 'text-slate-800 font-semibold' : 'text-amber-700'}>
                No Common Words
              </span>
            </div>
          </div>
        </div>

        {/* Patterns and Recommendations */}
        {analysis.patternsFound.length > 0 && (
          <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 text-xs text-amber-900 space-y-1">
            <div className="font-bold flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-600" />
              <span>Pattern Vulnerabilities Detected:</span>
            </div>
            <ul className="list-disc list-inside space-y-0.5 text-amber-800 pl-1">
              {analysis.patternsFound.map((p, idx) => (
                <li key={idx}>{p}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Passphrase Generator Tool */}
        <div className="pt-4 border-t border-slate-100 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center gap-1.5">
                <Sparkles className="w-4 h-4 text-blue-600" />
                <span>Client-Side Passphrase Generator</span>
              </h4>
              <p className="text-xs text-slate-500 mt-0.5">
                Generate high-entropy, memorable word-based passphrases using Web Crypto.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5 text-xs text-slate-600">
                <span>Words:</span>
                <select
                  value={passphraseWordCount}
                  onChange={(e) => setPassphraseWordCount(Number(e.target.value))}
                  className="bg-slate-50 border border-slate-200 rounded-lg px-2 py-1 text-xs font-bold text-slate-800"
                >
                  <option value={3}>3 words</option>
                  <option value={4}>4 words (Recommended)</option>
                  <option value={5}>5 words (High Security)</option>
                  <option value={6}>6 words (Enterprise)</option>
                </select>
              </div>

              <button
                type="button"
                onClick={handleGeneratePassphrase}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-blue-50 hover:bg-blue-100 text-blue-700 text-xs font-bold rounded-xl transition-colors border border-blue-200"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Generate Passphrase</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
