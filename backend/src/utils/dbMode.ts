import mongoose from 'mongoose';

/**
 * Returns true if in-memory database mode should be used.
 * Automatically falls back to in-memory mode if:
 * 1. USE_MEMORY_DB is explicitly 'true'
 * 2. MONGODB_URI is not configured
 * 3. Mongoose is not connected (readyState !== 1)
 */
export function isMemoryDb(): boolean {
  if (process.env.USE_MEMORY_DB === 'true') return true;
  if (!process.env.MONGODB_URI) return true;
  return mongoose.connection.readyState !== 1;
}
