import { useEffect, useState } from 'react'
import axios from 'axios'

const severityColor = {
  critical: 'text-red-500 bg-red-500/10 border-red-500/20',
  high: 'text-orange-500 bg-orange-500/10 border-orange-500/20',
  medium: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20',
  low: 'text-green-500 bg-green-500/10 border-green-500/20',
}

function Reviews() {
  const [reviews, setReviews] = useState([])
  const [vulns, setVulns] = useState([])
  const [selected, setSelected] = useState(null)
  const [dismissed, setDismissed] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      axios.get('/api/analytics/reviews'),
      axios.get('/api/analytics/vulnerabilities')
    ]).then(([r, v]) => {
      setReviews(r.data)
      setVulns(v.data)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  const handleFalsePositive = async (vuln) => {
    try {
      await axios.post('/api/analytics/false-positive', {
        code_snippet: vuln.description,
        vuln_type: vuln.vuln_type,
        repo_id: "default",
        vuln_id: vuln.id
      })
      setDismissed(prev => [...prev, vuln.id])
      alert(`✅ False positive recorded for ${vuln.vuln_type}. CodeSentinel will learn from this.`)
    } catch (e) {
      alert('Failed to record false positive.')
    }
  }

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <p className="text-gray-400 text-lg">Loading...</p>
    </div>
  )

  return (
    <div>
      <h1 className="text-3xl font-bold mb-2">PR Reviews</h1>
      <p className="text-gray-400 mb-8">All pull request reviews and detected vulnerabilities</p>

      {reviews.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
          <p className="text-gray-500">No reviews yet. Create a PR on GitHub to trigger a review.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {reviews.map((review, idx) => (
            <div key={idx}
              className="bg-gray-900 border border-gray-800 rounded-xl p-6 cursor-pointer hover:border-purple-600 transition"
              onClick={() => setSelected(selected === idx ? null : idx)}>

              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <span className="text-purple-400 font-mono text-sm font-medium">PR #{review.pr_number}</span>
                  <span className="text-white font-semibold">{review.pr_title}</span>
                </div>
                <div className="flex items-center gap-3">
                  {review.review && (
                    <span className={`px-3 py-1 rounded-full text-xs font-medium border ${review.review.critical_count > 0 ? severityColor.critical : 'text-green-500 bg-green-500/10 border-green-500/20'}`}>
                      {review.review.critical_count > 0 ? `${review.review.critical_count} Critical` : '✅ Clean'}
                    </span>
                  )}
                  <span className="text-gray-500 text-sm">{review.author}</span>
                  <span className="text-gray-600 text-xs">{review.created_at?.slice(0, 10)}</span>
                </div>
              </div>

              {review.review && (
                <p className="text-gray-400 text-sm">{review.review.summary}</p>
              )}

              {selected === idx && (() => {
                const currentReviewId = review.review?.id;
                const filteredVulns = vulns.filter(v => 
                  !dismissed.includes(v.id) && 
                  (!currentReviewId || !v.review_id || v.review_id === currentReviewId)
                );
                return (
                  <div className="mt-5 space-y-3" onClick={e => e.stopPropagation()}>
                    <h3 className="text-sm font-semibold text-gray-300 mb-3">
                      Vulnerabilities Found ({filteredVulns.length})
                    </h3>
                    {filteredVulns.map((v, i) => (
                      <div key={i} className={`bg-gray-800 rounded-lg p-4 border ${severityColor[v.severity]?.split(' ')[2] || 'border-gray-700'}`}>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-3">
                            <span className={`px-2 py-0.5 rounded text-xs font-medium border ${severityColor[v.severity]}`}>
                              {v.severity?.toUpperCase()}
                            </span>
                            <span className="text-white font-medium text-sm">{v.vuln_type}</span>
                            <span className="text-gray-500 text-xs font-mono">{v.cwe_id}</span>
                            <span className="text-gray-600 text-xs">Line {v.line_number}</span>
                          </div>
                          <button
                            onClick={() => handleFalsePositive(v)}
                            className="text-xs text-gray-500 hover:text-yellow-400 border border-gray-700 hover:border-yellow-400 px-2 py-1 rounded transition"
                          >
                            Not an issue
                          </button>
                        </div>
                        <p className="text-gray-400 text-sm mb-2">{v.description}</p>
                        <p className="text-sm">
                          <span className="text-gray-500">Fix: </span>
                          <span className="text-green-400">{v.suggestion}</span>
                        </p>
                      </div>
                    ))}
                  </div>
                )
              })()}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default Reviews