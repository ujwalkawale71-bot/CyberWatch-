import mongoose, { Schema, Document } from 'mongoose';
import { ThreatIntelAnalysisReport } from '@cyberwatch/shared';

export interface ThreatIntelDocument extends Document, Omit<ThreatIntelAnalysisReport, 'analysisId'> {
  analysisId: string;
  userId?: string;
  createdAt: string;
  updatedAt: string;
}

const ThreatIntelSchema = new Schema<ThreatIntelDocument>(
  {
    analysisId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userId: {
      type: String,
      index: true,
    },
    indicator: {
      type: String,
      required: true,
      index: true,
    },
    indicatorType: {
      type: String,
      required: true,
      index: true,
    },
    normalizedIndicator: {
      type: String,
      required: true,
      index: true,
    },
    canonicalValue: {
      type: String,
      required: true,
    },
    displayValue: {
      type: String,
      required: true,
    },
    status: {
      type: String,
      required: true,
      enum: ['MATCH_FOUND', 'NO_MATCH', 'PARTIAL', 'UNAVAILABLE', 'NOT_CONFIGURED', 'ERROR'],
    },
    overallReputation: {
      type: String,
      required: true,
    },
    confidence: {
      type: String,
      required: true,
      enum: ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'],
    },
    confidenceExplanation: {
      type: String,
      default: '',
    },
    recommendation: {
      type: String,
      default: '',
    },
    detectionSummary: {
      flaggedCount: { type: Number, default: 0 },
      totalEnginesQueried: { type: Number, default: 0 },
      providersWithDetections: { type: Number, default: 0 },
    },
    threatCategories: [String],
    providersChecked: { type: Number, default: 0 },
    providersTotal: { type: Number, default: 0 },
    providers: [Schema.Types.Mixed],
    evidence: [Schema.Types.Mixed],
    relatedIndicators: [Schema.Types.Mixed],
    temporalData: Schema.Types.Mixed,
    correlationWithCyberWatch: Schema.Types.Mixed,
    cached: { type: Boolean, default: false },
  },
  {
    timestamps: true,
  }
);

// TTL index to automatically purge entries after 30 days
ThreatIntelSchema.index({ createdAt: 1 }, { expireAfterSeconds: 30 * 24 * 3600 });

export const ThreatIntel = mongoose.model<ThreatIntelDocument>('ThreatIntel', ThreatIntelSchema);
