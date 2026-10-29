import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  BarChart3,
  Clock,
  GitCompare,
  Download,
  Shield,
} from 'lucide-react';
import { cn } from '../../lib/utils';

interface ReportsNavProps {
  className?: string;
  totalFindings?: number;
  totalScans?: number;
}

export const ReportsNav: React.FC<ReportsNavProps> = ({ className, totalFindings, totalScans }) => {
  const navItems = [
    {
      to: '/reports',
      label: 'Overview',
      icon: LayoutDashboard,
      end: true,
    },
    {
      to: '/reports/findings',
      label: 'Security Findings',
      icon: BarChart3,
      badge: totalFindings !== undefined && totalFindings > 0 ? totalFindings : undefined,
    },
    {
      to: '/reports/history',
      label: 'Scan History',
      icon: Clock,
      badge: totalScans !== undefined && totalScans > 0 ? totalScans : undefined,
    },
    {
      to: '/reports/compare',
      label: 'Compare Scans',
      icon: GitCompare,
    },
    {
      to: '/reports/export',
      label: 'Export Reports',
      icon: Download,
    },
  ];

  return (
    <div className={cn('bg-white border-b border-slate-200 sticky top-[72px] z-30 shadow-2xs', className)}>
      <div className="max-w-[1560px] mx-auto px-4 sm:px-6 lg:px-8 2xl:px-10">
        <div className="flex items-center justify-between overflow-x-auto no-scrollbar py-2.5">
          <div className="flex items-center space-x-1 sm:space-x-2">
            <div className="hidden md:flex items-center gap-2 pr-3 mr-2 border-r border-slate-200 text-xs font-bold text-slate-900 tracking-tight shrink-0">
              <div className="w-5 h-5 rounded bg-blue-50 text-blue-600 flex items-center justify-center border border-blue-100">
                <Shield className="w-3 h-3" />
              </div>
              <span>REPORTS CENTER</span>
            </div>

            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    cn(
                      'inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shrink-0 select-none',
                      isActive
                        ? 'bg-blue-50 text-blue-700 border border-blue-200/80 shadow-xs font-bold'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50 border border-transparent'
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      <Icon
                        className={cn(
                          'w-3.5 h-3.5',
                          isActive ? 'text-blue-600' : 'text-slate-400 group-hover:text-slate-600'
                        )}
                      />
                      <span>{item.label}</span>
                      {item.badge !== undefined && (
                        <span
                          className={cn(
                            'text-[10px] px-1.5 py-0.2 rounded-full font-bold',
                            isActive
                              ? 'bg-blue-600 text-white'
                              : 'bg-slate-100 text-slate-600 border border-slate-200'
                          )}
                        >
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}
                </NavLink>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
