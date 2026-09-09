import { create } from 'zustand';

interface User {
  id: string;
  username: string;
  email: string;
  role: 'student' | 'admin';
}

interface Progress {
  labSlug: string;
  completed: boolean;
  quizScore: number;
  completedAt?: string;
  bookmarked: boolean;
}

interface Note {
  labSlug: string;
  content: string;
  updatedAt: string;
}

interface Achievement {
  id: string;
  earnedAt: string;
}

interface AuthState {
  token: string | null;
  user: User | null;
  progress: Progress[];
  achievements: Achievement[];
  notes: Note[];
  setAuth: (token: string | null, user: User | null) => void;
  setProgress: (progress: Progress[]) => void;
  setAchievements: (achievements: Achievement[]) => void;
  setNotes: (notes: Note[]) => void;
  logout: () => void;
  toggleBookmark: (labSlug: string) => void;
  updateProgressLocally: (labSlug: string, completed: boolean, score?: number) => void;
}

export const useStore = create<AuthState>((set) => ({
  token: typeof window !== 'undefined' ? localStorage.getItem('token') : null,
  user: typeof window !== 'undefined' && localStorage.getItem('user') 
    ? JSON.parse(localStorage.getItem('user') || 'null') 
    : null,
  progress: [],
  achievements: [],
  notes: [],

  setAuth: (token, user) => {
    if (token) localStorage.setItem('token', token);
    else localStorage.removeItem('token');

    if (user) localStorage.setItem('user', JSON.stringify(user));
    else localStorage.removeItem('user');

    set({ token, user });
  },

  setProgress: (progress) => set({ progress }),
  setAchievements: (achievements) => set({ achievements }),
  setNotes: (notes) => set({ notes }),

  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    set({ token: null, user: null, progress: [], achievements: [], notes: [] });
  },

  toggleBookmark: (labSlug) => set((state) => {
    const updated = state.progress.map((p) => 
      p.labSlug === labSlug ? { ...p, bookmarked: !p.bookmarked } : p
    );
    if (!state.progress.find((p) => p.labSlug === labSlug)) {
      updated.push({ labSlug, completed: false, quizScore: 0, bookmarked: true });
    }
    return { progress: updated };
  }),

  updateProgressLocally: (labSlug, completed, score) => set((state) => {
    const existing = state.progress.find((p) => p.labSlug === labSlug);
    let updated;
    if (existing) {
      updated = state.progress.map((p) => 
        p.labSlug === labSlug 
          ? { 
              ...p, 
              completed: completed || p.completed, 
              quizScore: score !== undefined ? Math.max(p.quizScore, score) : p.quizScore,
              completedAt: completed ? new Date().toISOString() : p.completedAt
            } 
          : p
      );
    } else {
      updated = [
        ...state.progress,
        {
          labSlug,
          completed,
          quizScore: score || 0,
          completedAt: completed ? new Date().toISOString() : undefined,
          bookmarked: false
        }
      ];
    }
    return { progress: updated };
  })
}));
