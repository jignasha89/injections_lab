'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { useStore } from '@/lib/store';
import { HelpCircle, Check, X, ShieldAlert, Award } from 'lucide-react';

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
  const [results, setResults] = useState<{ [key: number]: boolean }>({});
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

    try {
      const res = await api.post(`/labs/${slug}/quiz/submit`, { answers: answersArray });
      const { score: apiScore, results: apiResults } = res.data;

      // Update local state
      const mappedResults: { [key: number]: boolean } = {};
      apiResults.forEach((r: any) => {
        mappedResults[r.questionIndex] = r.correct;
      });

      setScore(apiScore);
      setResults(mappedResults);
      setSubmitted(true);

      // Save lab completion progress locally and on backend
      const percentage = Math.round((apiScore / quiz.length) * 100);
      const isCompleted = percentage >= 80; // Pass mark is 80%

      await api.put(`/user/progress/${slug}`, {
        completed: isCompleted,
        quizScore: percentage,
      });

      updateProgressLocally(slug, isCompleted, percentage);
    } catch (err: any) {
      console.error(err);
      setError('Failed to submit quiz results to database.');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setSelectedAnswers({});
    setSubmitted(false);
    setResults({});
    setScore(0);
  };

  return (
    <div className="bg-white p-8 rounded-3xl border border-slate-200 shadow-sm space-y-6 text-slate-800">
      <div className="flex items-center justify-between border-b border-slate-100 pb-4">
        <h3 className="text-sm font-bold tracking-wider text-slate-800 uppercase flex items-center gap-1.5">
          Knowledge Validation Quiz
        </h3>
        {submitted && (
          <span className={`text-xs font-bold px-3 py-1.5 rounded-full ${
            score >= 4 ? 'bg-green-50 text-green-700 border border-green-200' : 'bg-red-50 text-red-700 border border-red-200'
          }`}>
            Score: {score} / {quiz.length} ({Math.round((score / quiz.length) * 100)}%)
          </span>
        )}
      </div>

      {submitted && score >= 4 && (
        <div className="p-4 rounded-xl bg-green-50 border border-green-200 flex items-center gap-3 text-xs text-green-700">
          <Award className="w-5 h-5 shrink-0 text-green-600" />
          <div>
            <p className="font-extrabold">CONGRATULATIONS!</p>
            <p className="text-slate-600 font-semibold mt-0.5">You scored 80% or higher. Lab module successfully completed!</p>
          </div>
        </div>
      )}

      {submitted && score < 4 && (
        <div className="p-4 rounded-xl bg-red-50 border border-red-200 flex items-center gap-3 text-xs text-red-700">
          <ShieldAlert className="w-5 h-5 shrink-0 text-red-600" />
          <div>
            <p className="font-extrabold">PASSED CRITERIA NOT MET</p>
            <p className="text-slate-600 font-semibold mt-0.5">You need at least 4 correct answers (80%) to pass. Please review theory and try again.</p>
          </div>
        </div>
      )}

      <div className="space-y-6">
        {quiz.map((q, qIdx) => (
          <div key={qIdx} className="space-y-3">
            <h4 className="text-sm font-bold text-slate-900 flex items-start gap-2">
              <span className="text-blue-600 text-xs font-mono">Q{qIdx + 1}.</span>
              {q.question}
            </h4>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pl-5">
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
                    className={`w-full text-left px-4 py-3 rounded-xl text-xs font-bold border transition-all flex items-center justify-between gap-3 ${
                      showSuccess 
                        ? 'bg-green-50 border-green-600 text-green-700' 
                        : showDanger 
                          ? 'bg-red-50 border-red-600 text-red-700' 
                          : isSelected 
                            ? 'bg-blue-50 border-blue-600 text-blue-600' 
                            : 'bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100 hover:text-slate-900'
                    }`}
                  >
                    <span>{opt}</span>
                    {showSuccess && <Check className="w-4 h-4 shrink-0 text-green-600 font-extrabold" />}
                    {showDanger && <X className="w-4 h-4 shrink-0 text-red-600 font-extrabold" />}
                  </button>
                );
              })}
            </div>

            {submitted && (
              <div className="pl-5 pt-1.5 text-xs text-slate-600 leading-relaxed border-l-2 border-slate-300 mt-2 font-semibold">
                <span className="font-extrabold text-blue-600">Explanation:</span> {q.explanation}
              </div>
            )}
          </div>
        ))}
      </div>

      {error && <p className="text-xs font-bold text-red-600">{error}</p>}

      <div className="flex gap-4 border-t border-slate-200 pt-4">
        {!submitted ? (
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="px-6 py-3 rounded-xl text-xs font-bold bg-slate-950 text-white hover:bg-slate-900 active:scale-95 transition-all disabled:opacity-50 shadow-sm"
          >
            {loading ? 'Submitting Answers...' : 'Submit Answers'}
          </button>
        ) : (
          <button
            onClick={handleReset}
            className="px-6 py-3 rounded-xl text-xs font-bold bg-slate-50 border border-slate-200 text-slate-700 hover:bg-slate-100 transition-all shadow-sm"
          >
            Retry Quiz
          </button>
        )}
      </div>
    </div>
  );
}
