import mongoose, { Schema, Document } from 'mongoose';

export interface IChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
  timestamp: Date;
  leaked?: boolean;
}

export interface IChatSession extends Document {
  sessionId: string;
  userId?: mongoose.Types.ObjectId;
  messages: IChatMessage[];
  messageCount: number;
  injectionsSucceeded: number;
  createdAt: Date;
  updatedAt: Date;
}

const ChatMessageSchema = new Schema<IChatMessage>({
  role: { type: String, enum: ['system', 'user', 'assistant'], required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  leaked: { type: Boolean, default: false },
});

const ChatSessionSchema = new Schema<IChatSession>(
  {
    sessionId: { type: String, required: true, unique: true, index: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User' },
    messages: [ChatMessageSchema],
    messageCount: { type: Number, default: 0 },
    injectionsSucceeded: { type: Number, default: 0 },
  },
  { timestamps: true, collection: 'chatSessions' }
);

export default mongoose.model<IChatSession>('ChatSession', ChatSessionSchema);
