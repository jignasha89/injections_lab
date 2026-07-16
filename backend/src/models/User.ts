import mongoose, { Schema, Document } from 'mongoose';
import bcrypt from 'bcryptjs';

export interface IProgress {
  labSlug: string;
  completed: boolean;
  quizScore: number;
  completedAt?: Date;
  bookmarked: boolean;
}

export interface INote {
  labSlug: string;
  content: string;
  updatedAt: Date;
}

export interface IAchievement {
  id: string;
  earnedAt: Date;
}

export interface IUser extends Document {
  username: string;
  email: string;
  passwordHash: string;
  role: 'student' | 'admin';
  avatar?: string;
  progress: IProgress[];
  achievements: IAchievement[];
  notes: INote[];
  createdAt: Date;
  updatedAt: Date;
  comparePassword(password: string): Promise<boolean>;
}

const ProgressSchema = new Schema<IProgress>({
  labSlug: { type: String, required: true },
  completed: { type: Boolean, default: false },
  quizScore: { type: Number, default: 0 },
  completedAt: { type: Date },
  bookmarked: { type: Boolean, default: false },
});

const NoteSchema = new Schema<INote>({
  labSlug: { type: String, required: true },
  content: { type: String, default: '' },
  updatedAt: { type: Date, default: Date.now },
});

const AchievementSchema = new Schema<IAchievement>({
  id: { type: String, required: true },
  earnedAt: { type: Date, default: Date.now },
});

const UserSchema = new Schema<IUser>(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['student', 'admin'], default: 'student' },
    avatar: { type: String },
    progress: [ProgressSchema],
    achievements: [AchievementSchema],
    notes: [NoteSchema],
  },
  { timestamps: true }
);

// Hash password before saving
UserSchema.pre('save', async function (next) {
  if (!this.isModified('passwordHash')) return next();
  const salt = await bcrypt.genSalt(12);
  this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
  next();
});

UserSchema.methods.comparePassword = async function (password: string): Promise<boolean> {
  return bcrypt.compare(password, this.passwordHash);
};

export default mongoose.model<IUser>('User', UserSchema);
