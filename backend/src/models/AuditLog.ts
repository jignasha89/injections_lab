import mongoose, { Schema, Document } from 'mongoose';

export interface IAuditLog extends Document {
  adminId: string;
  adminUsername: string;
  action: string;
  targetResource: string;
  details?: Record<string, any>;
  ip: string;
  userAgent: string;
  timestamp: Date;
}

const AuditLogSchema = new Schema<IAuditLog>(
  {
    adminId: { type: String, required: true, index: true },
    adminUsername: { type: String, required: true },
    action: {
      type: String,
      required: true,
      enum: [
        'VIEW_ALL_SCANS',
        'VIEW_SCAN_DETAIL',
        'EXPORT_REPORT',
        'DELETE_REPORT',
        'VIEW_INJECTION_ATTEMPTS',
        'VIEW_AUDIT_LOGS',
        'VIEW_USER_LIST',
        'VERIFY_2FA',
        'ADMIN_LOGIN',
      ],
      index: true,
    },
    targetResource: { type: String, required: true },
    details: { type: Schema.Types.Mixed },
    ip: { type: String, required: true },
    userAgent: { type: String, required: true },
    timestamp: { type: Date, default: Date.now, index: true },
  },
  { timestamps: true, collection: 'auditLogs' }
);

export default mongoose.model<IAuditLog>('AuditLog', AuditLogSchema);
