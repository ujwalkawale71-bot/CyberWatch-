// TypeScript declarations for Chrome APIs and CyberWatch backend contracts

export type ScannerType =
  | 'URL'
  | 'Website'
  | 'API'
  | 'Phishing'
  | 'File'
  | 'Extension';

export interface ScannerMeta {
  type: ScannerType;
  name: string;
  badge: string;
  placeholder: string;
  helperText: string;
  iconSvg: string;
}

export interface IScanFinding {
  category: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  description: string;
  evidence?: string;
  recommendation?: string;
}

export interface ScanResultData {
  id?: string;
  _id?: string;
  target: string;
  targetType: ScannerType;
  result: 'Safe' | 'Low Risk' | 'Suspicious' | 'High Risk' | 'Critical' | 'Inconclusive' | 'Failed';
  riskScore: number;
  status: 'completed' | 'failed' | 'pending' | 'inconclusive' | 'partial';
  scannedAt?: string;
  findings?: IScanFinding[];
  recommendations?: string[];
  checks?: Record<string, any>;
}

export interface ApiResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
  errors?: Array<{ field: string; message: string }>;
}

export interface UserSession {
  token: string;
  user: {
    id: string;
    name: string;
    email: string;
    role: string;
  };
}
