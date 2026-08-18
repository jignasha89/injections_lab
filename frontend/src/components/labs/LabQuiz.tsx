'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { useStore } from '@/lib/store';
import { Check, X, ShieldAlert, Award } from 'lucide-react';

interface QuizQuestion {
  question: string;
  options: string[];
  correctIndex: number;
  explanation: string;
}

interface LabQuizProps {
  slug: string;
  quiz: QuizQuestion[];
}

export default function LabQuiz({ slug, quiz }: LabQuizProps) {
  const { updateProgressLocally } = useStore();
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [submitted, setSubmitted] = useState(false);
  const [score, setScore] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSelect = (qIdx: number, oIdx: number) => {
    if (submitted) return;
    setSelectedAnswers({
      ...selectedAnswers,
      [qIdx]: oIdx,
    });
  };

  const handleSubmit = async () => {
    if (Object.keys(selectedAnswers).length < quiz.length) {
      setError('Please answer all questions before submitting.');
      return;
    }

    setError('');
    setLoading(true);

    const answersArray = quiz.map((_, i) => selectedAnswers[i]);

    // Calculate score accurately from questions
    let accurateScore = 0;
    quiz.forEach((q, i) => {
      if (q.correctIndex === answersArray[i]) {
        accurateScore++;
      }
    });

    const percentage = Math.round((accurateScore / quiz.length) * 100);
    const isCompleted = percentage >= 80;

    setScore(accurateScore);
    setSubmitted(true);
    updateProgressLocally(slug, isCompleted, percentage);

    try {
      await api.post(`/labs/${slug}/quiz/submit`, { answers: answersArray });
      await api.put(`/user/progress/${slug}`, {
        completed: isCompleted,
        quizScore: percentage,
      });
    } catch (err: unknown) {
      console.warn('Backend sync note (quiz score saved locally):', err);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setSelectedAnswers({});
    setSubmitted(false);
    setScore(0);
    setError('');
  };

  const currentPercent = quiz.length > 0 ? Math.round((score / quiz.length) * 100) : 0;
  const isPassed = currentPercent >= 80;

  return (
    <div className="bg-[#0c0d14] p-6 md:p-8 rounded-2xl border border-zinc-800/80 shadow-2xl space-y-6 text-zinc-100 font-sans">
      <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
        <h3 className="text-xs font-mono font-bold tracking-wider text-cyan-400 uppercase flex items-center gap-2">
          <Award className="w-4 h-4 text-cyan-400" /> Knowledge Validation Quiz
        </h3>
        {submitted && (
          <span className={`text-xs font-mono font-bold px-3 py-1 rounded-full border ${
            isPassed ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
          }`}>
            Score: {score} / {quiz.length} ({currentPercent}%)
          </span>
        )}
      </div>

      {submitted && isPassed && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3 text-xs text-emerald-300 font-mono">
          <Award className="w-5 h-5 shrink-0 text-emerald-400" />
          <div>
            <p className="font-extrabold text-emerald-400">CONGRATULATIONS!</p>
            <p className="text-zinc-300 text-[11px] mt-0.5">You scored {currentPercent}%. Lab module successfully completed!</p>
          </div>
        </div>
      )}

      {submitted && !isPassed && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center gap-3 text-xs text-rose-300 font-mono">
          <ShieldAlert className="w-5 h-5 shrink-0 text-rose-400" />
          <div>
            <p className="font-extrabold text-rose-400">PASSING CRITERIA NOT MET</p>
            <p className="text-zinc-300 text-[11px] mt-0.5">You scored {currentPercent}%. You need at least 80% to pass. Review explanations and retry.</p>
          </div>
        </div>
      )}

      <div className="space-y-6">
        {quiz.map((q, qIdx) => (
          <div key={qIdx} className="space-y-3">
            <h4 className="text-xs md:text-sm font-mono font-bold text-white flex items-start gap-2">
              <span className="text-cyan-400 font-mono text-xs">Q{qIdx + 1}.</span>
              <span>{q.question}</span>
            </h4>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pl-4">
              {q.options.map((opt, oIdx) => {
                const isSelected = selectedAnswers[qIdx] === oIdx;
                const isCorrectOption = q.correctIndex === oIdx;
                const showSuccess = submitted && isCorrectOption;
                const showDanger = submitted && isSelected && !isCorrectOption;

                return (
                  <button
                    key={oIdx}
                    onClick={() => handleSelect(qIdx, oIdx)}
                    disabled={submitted}
                    className={`w-full text-left px-4 py-3 rounded-xl text-xs font-mono border transition-all flex items-center justify-between gap-3 ${
                      showSuccess 
                        ? 'bg-emerald-500/15 border-emerald-500/60 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.2)]' 
                        : showDanger 
                          ? 'bg-rose-500/15 border-rose-500/60 text-rose-300' 
                          : isSelected 
                            ? 'bg-cyan-500/15 border-cyan-500/60 text-cyan-300 shadow-[0_0_12px_rgba(0,240,255,0.15)]' 
                            : 'bg-[#050508] border-zinc-800 text-zinc-300 hover:border-zinc-700 hover:text-white'
                    }`}
                  >
                    <span>{opt}</span>
                    {showSuccess && <Check className="w-4 h-4 shrink-0 text-emerald-400 font-bold" />}
                    {showDanger && <X className="w-4 h-4 shrink-0 text-rose-400 font-bold" />}
                  </button>
                );
              })}
            </div>

            {submitted && (
              <div className="pl-4 pt-2 text-xs text-zinc-400 leading-relaxed border-l-2 border-zinc-700 mt-2 font-mono">
                <span className="font-bold text-cyan-400">Explanation:</span> {q.explanation}
              </div>
            )}
          </div>
        ))}
      </div>

      {error && <p className="text-xs font-mono font-bold text-rose-400">{error}</p>}

      <div className="flex gap-4 border-t border-zinc-800 pt-4">
        {!submitted ? (
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="px-6 py-3 rounded-xl text-xs font-mono font-bold bg-cyan-500 hover:bg-cyan-400 text-black shadow-[0_0_15px_rgba(0,240,255,0.25)] active:scale-95 transition-all disabled:opacity-50"
          >
            {loading ? 'Submitting Answers...' : 'Submit Answers'}
          </button>
        ) : (
          <button
            onClick={handleReset}
            className="px-6 py-3 rounded-xl text-xs font-mono font-bold bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-white hover:border-zinc-700 transition-all shadow-sm"
          >
            Retry Quiz
          </button>
        )}
      </div>
    </div>
  );
}
