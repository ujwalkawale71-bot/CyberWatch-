import { Link } from 'react-router-dom';
import { Globe, ShieldAlert, Terminal, FileSearch, Puzzle, ArrowRight } from 'lucide-react';

const SECURITY_SERVICES = [
  {
    id: 'service-url-phishing-scanner',
    name: 'URL & Phishing Mega Scanner',
    description: 'Unified analysis of URLs, domains, redirects, page structure, and phishing threat indicators.',
    icon: Globe,
    href: '/services/url-phishing',
    color: 'text-blue-600',
    bg: 'bg-blue-50 border-blue-100 group-hover:bg-blue-600 group-hover:text-white',
  },
  {
    id: 'service-website-scanner',
    name: 'Website Security Scanner',
    description: 'Analyze website security posture, headers, cookies, scripts, and TLS parameters.',
    icon: ShieldAlert,
    href: '/services/website-scanner',
    color: 'text-indigo-600',
    bg: 'bg-indigo-50 border-indigo-100 group-hover:bg-indigo-600 group-hover:text-white',
  },
  {
    id: 'service-api-scanner',
    name: 'API Security Scanner',
    description: 'Audit API endpoints for CORS policies, rate limits, headers, and technical exposure.',
    icon: Terminal,
    href: '/services/api-scanner',
    color: 'text-cyan-600',
    bg: 'bg-cyan-50 border-cyan-100 group-hover:bg-cyan-600 group-hover:text-white',
  },
  {
    id: 'service-file-scanner',
    name: 'File Security Scanner',
    description: 'Analyze downloadable files and payloads for executable risks and signature anomalies.',
    icon: FileSearch,
    href: '/services/file',
    color: 'text-blue-600',
    bg: 'bg-blue-50 border-blue-100 group-hover:bg-blue-600 group-hover:text-white',
  },
  {
    id: 'service-extension-scanner',
    name: 'Browser Extension Scanner',
    description: 'Audit browser extensions and Manifest V3 metadata for high-risk permissions.',
    icon: Puzzle,
    href: '/services/extension',
    color: 'text-sky-600',
    bg: 'bg-sky-50 border-sky-100 group-hover:bg-sky-600 group-hover:text-white',
  },
];

export function SecurityServicesGrid() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
          SECURITY SERVICES
        </h2>
        <p className="text-sm text-slate-500 mt-1">
          Explore our security analysis tools to keep you safe online.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {SECURITY_SERVICES.map((service) => {
          const Icon = service.icon;
          return (
            <Link
              key={service.id}
              id={service.id}
              to={service.href}
              className="group bg-white border border-slate-200/90 rounded-2xl p-6 flex flex-col justify-between gap-5 shadow-sm hover:shadow-md hover:border-blue-200 transition-all duration-200"
            >
              <div className="space-y-3">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center border transition-all duration-200 ${service.bg}`}>
                  <Icon className="w-6 h-6 transition-colors" />
                </div>

                <div>
                  <h3 className="text-base font-bold text-slate-900 group-hover:text-blue-600 transition-colors">
                    {service.name}
                  </h3>
                  <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                    {service.description}
                  </p>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs font-bold text-blue-600 group-hover:text-blue-700">
                <span>Scan Now</span>
                <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
