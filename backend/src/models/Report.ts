import mongoose, { Schema, Document } from 'mongoose';

export interface IFinding {
  type: string;
  location: string;
  parameter?: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  cvss: number;
  cwe: string;
  owasp: string;
  description: string;
  recommendation: string;
  simpleSummary?: string;
  simpleExplanation?: string;
  simpleFix?: string[];
  screenshot?: string;
  screenshotCaption?: string;
}

export interface IReport extends Document {
  userId: mongoose.Types.ObjectId;
  title: string;
  targetUrl: string;
  scanType: 'url' | 'demo';
  labSlug?: string;
  summary: {
    totalPages: number;
    injectionPoints: number;
    forms: number;
    headers: number;
    parameters: number;
    cookies: number;
    jsonInputs: number;
    riskScore: number;
    owaspCoverage: string[];
    overallRiskRating?: string;
    plainSummary?: string;
  };
  findings: IFinding[];
  techStack: string[];
  isHiddenFromReports: boolean;
  isHiddenFromHistory: boolean;
  isEncrypted?: boolean;
  encryptedPayload?: string;
  createdAt: Date;
}

const FindingSchema = new Schema<IFinding>({
  type: { type: String, required: true },
  location: { type: String, required: true },
  parameter: { type: String },
  severity: {
    type: String,
    enum: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    required: true,
  },
  cvss: { type: Number, required: true, min: 0, max: 10 },
  cwe: { type: String, required: true },
  owasp: { type: String, required: true },
  description: { type: String, required: true },
  recommendation: { type: String, required: true },
  simpleSummary: { type: String },
  simpleExplanation: { type: String },
  simpleFix: [{ type: String }],
  screenshot: { type: String },
  screenshotCaption: { type: String },
});

const ReportSchema = new Schema<IReport>(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    targetUrl: { type: String, required: true },
    scanType: { type: String, enum: ['url', 'demo'], default: 'url' },
    labSlug: { type: String },
    summary: {
      totalPages: { type: Number, default: 1 },
      injectionPoints: { type: Number, default: 0 },
      forms: { type: Number, default: 0 },
      headers: { type: Number, default: 0 },
      parameters: { type: Number, default: 0 },
      cookies: { type: Number, default: 0 },
      jsonInputs: { type: Number, default: 0 },
      riskScore: { type: Number, default: 0 },
      owaspCoverage: [{ type: String }],
      overallRiskRating: { type: String },
      plainSummary: { type: String },
    },
    findings: [FindingSchema],
    techStack: [{ type: String }],
    isHiddenFromReports: { type: Boolean, default: false },
    isHiddenFromHistory: { type: Boolean, default: false },
    isEncrypted: { type: Boolean, default: false },
    encryptedPayload: { type: String },
  },
  { timestamps: true }
);

export default mongoose.model<IReport>('Report', ReportSchema);
