import { Link } from 'react-router-dom';
import { Container } from '../ui/Container';
import { Shield } from 'lucide-react';

export function Footer() {
  return (
    <footer className="bg-white border-t border-slate-200/80 mt-auto">
      <Container>
        <div className="py-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          {/* LEFT: CyberWatch logo/name + Tagline */}
          <div className="flex flex-col sm:flex-row items-center sm:items-baseline gap-2 sm:gap-3 text-center sm:text-left">
            <Link to="/" className="flex items-center gap-2 group">
              <div className="bg-blue-600 p-1.5 rounded-lg group-hover:bg-blue-700 transition-colors shadow-sm shadow-blue-500/20">
                <Shield className="w-4 h-4 text-white" />
              </div>
              <span className="font-bold text-base text-slate-900 tracking-tight">CYBERWATCH</span>
            </Link>
            <span className="text-xs text-slate-500 font-medium">
              Security Today, Safer Tomorrow.
            </span>
          </div>

          {/* RIGHT: Privacy Policy | Terms of Service | Contact */}
          <div className="flex items-center gap-6 text-xs font-semibold text-slate-600">
            <Link to="/help" className="hover:text-blue-600 transition-colors">
              Privacy Policy
            </Link>
            <Link to="/help" className="hover:text-blue-600 transition-colors">
              Terms of Service
            </Link>
            <Link to="/support" className="hover:text-blue-600 transition-colors">
              Contact Support
            </Link>
          </div>
        </div>
      </Container>
    </footer>
  );
}
