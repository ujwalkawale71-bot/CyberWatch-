import { Link } from 'react-router-dom';
import { ChevronRight, Shield, ArrowRight } from 'lucide-react';

interface CyberSafetyHeaderProps {
  badge?: string;
  title: string;
  subtitle: string;
  breadcrumbs?: Array<{ label: string; href?: string }>;
  primaryCta?: {
    label: string;
    href: string;
    icon?: React.ComponentType<{ className?: string }>;
  };
  secondaryCta?: {
    label: string;
    href: string;
    icon?: React.ComponentType<{ className?: string }>;
  };
}

export function CyberSafetyHeader({
  badge,
  title,
  subtitle,
  breadcrumbs = [{ label: 'Cyber Safety Center', href: '/cyber-safety' }],
  primaryCta,
  secondaryCta,
}: CyberSafetyHeaderProps) {
  return (
    <div className="border-b border-slate-200/80 bg-white pt-[72px]">
      <div className="max-w-[1560px] mx-auto px-4 sm:px-6 lg:px-8 2xl:px-10 pt-6 sm:pt-7 pb-6 sm:pb-7">
        {/* Breadcrumbs */}
        <nav aria-label="Breadcrumb" className="flex items-center flex-wrap gap-1.5 sm:gap-2 text-xs font-medium text-slate-500 mb-3">
          {breadcrumbs && breadcrumbs.length > 0 ? (
            breadcrumbs.map((crumb, idx) => (
              <div key={idx} className="flex items-center gap-1.5 sm:gap-2">
                {idx > 0 && <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />}
                {crumb.href ? (
                  <Link
                    to={crumb.href}
                    className="inline-flex items-center gap-1.5 hover:text-blue-600 transition-colors text-slate-600 font-semibold"
                  >
                    {(crumb.href === '/cyber-safety' || crumb.label.includes('Cyber Safety')) && (
                      <Shield className="w-3.5 h-3.5 text-blue-600" />
                    )}
                    <span>{crumb.label}</span>
                  </Link>
                ) : (
                  <span className="text-slate-700 font-semibold">{crumb.label}</span>
                )}
              </div>
            ))
          ) : (
            <Link
              to="/cyber-safety"
              className="inline-flex items-center gap-1.5 hover:text-blue-600 transition-colors text-slate-600 font-semibold"
            >
              <Shield className="w-3.5 h-3.5 text-blue-600" />
              <span>Cyber Safety Center</span>
            </Link>
          )}
          <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
          <span className="text-slate-900 font-bold">{title}</span>
        </nav>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="max-w-4xl">
            {badge && (
              <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-md bg-blue-50 border border-blue-100 text-blue-700 text-xs font-bold uppercase tracking-wider mb-2">
                <Shield className="w-3.5 h-3.5" />
                <span>{badge}</span>
              </div>
            )}
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900">
              {title}
            </h1>
            <p className="mt-2 text-sm sm:text-base text-slate-600 leading-relaxed max-w-3xl">
              {subtitle}
            </p>
          </div>

          {(primaryCta || secondaryCta) && (
            <div className="flex flex-wrap items-center gap-3 shrink-0">
              {secondaryCta && (
                <Link
                  to={secondaryCta.href}
                  className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-semibold text-xs sm:text-sm transition-colors shadow-xs"
                >
                  {secondaryCta.icon && <secondaryCta.icon className="w-4 h-4 text-slate-500" />}
                  <span>{secondaryCta.label}</span>
                </Link>
              )}
              {primaryCta && (
                <Link
                  to={primaryCta.href}
                  className="inline-flex items-center gap-2 px-4.5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-700 active:bg-blue-800 text-white font-bold text-xs sm:text-sm transition-all shadow-sm shadow-blue-500/20"
                >
                  {primaryCta.icon ? (
                    <primaryCta.icon className="w-4 h-4" />
                  ) : (
                    <ArrowRight className="w-4 h-4" />
                  )}
                  <span>{primaryCta.label}</span>
                </Link>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
