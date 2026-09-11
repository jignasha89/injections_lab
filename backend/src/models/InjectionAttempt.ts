import mongoose, { Schema, Document } from 'mongoose';

export interface IInjectionAttempt extends Document {
  sessionId: string;
  userId?: mongoose.Types.ObjectId;
  userMessage: string;
  aiResponse: string;
  success: boolean;
  leakType: string[];
  ip?: string;
  timestamp: Date;
}

const InjectionAttemptSchema = new Schema<IInjectionAttempt>(
  {
    sessionId: { type: String, required: true, index: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User' },
    userMessage: { type: String, required: true },
    aiResponse: { type: String, required: true },
    success: { type: Boolean, required: true, index: true },
    leakType: [{ type: String }],
    ip: { type: String },
    timestamp: { type: Date, default: Date.now },
  },
  { timestamps: true, collection: 'injectionAttempts' }
);

export default mongoose.model<IInjectionAttempt>('InjectionAttempt', InjectionAttemptSchema);
