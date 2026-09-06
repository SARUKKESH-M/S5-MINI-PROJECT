import { useEffect, useState } from 'react'
import axios from 'axios'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts'

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e'
}

const PIE_COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e']

function StatCard({ label, value, color, icon, sub }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition">
      <div className="flex items-center justify-between mb-3">
        <span className="text-gray-500 text-sm">{label}</span>
        <span className="text-xl">{icon}</span>
      </div>
      <p className={`text-4xl font-bold ${color}`}>{value ?? '—'}</p>
      {sub && <p className="text-gray-600 text-xs mt-1">{sub}</p>}
    </div>
  )
}

function Dashboard() {
  const [summary, setSummary] = useState(null)
  const [topVulns, setTopVulns] = useState([])
  const [developers, setDevelopers] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      axios.get('/api/analytics/summary'),
      axios.get('/api/analytics/top-vulns'),
      axios.get('/api/analytics/developers')
    ]).then(([s, t, d]) => {
      setSummary(s.data)
      setTopVulns(t.data)
      setDevelopers(d.data)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  const pieData = summary ? [
    { name: 'Critical', value: summary.critical },
    { name: 'High', value: summary.high },
    { name: 'Medium', value: summary.medium },
    { name: 'Low', value: summary.low },
  ].filter(d => d.value > 0) : []

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="text-4xl mb-3">🛡️</div>
        <p className="text-gray-400">Loading CodeSentinel...</p>
      </div>
    </div>
  )

  return (
    <div>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-1">Security Dashboard</h1>
        <p className="text-gray-500">AI-Powered Code Review & Vulnerability Detection System</p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard label="Total PRs Reviewed" value={summary?.total_prs} color="text-white" icon="📋" sub="Pull requests analyzed" />
        <StatCard label="Critical Issues" value={summary?.critical} color="text-red-500" icon="🔴" sub="Requires immediate fix" />
        <StatCard label="High Issues" value={summary?.high} color="text-orange-500" icon="🟠" sub="Fix before merge" />
        <StatCard label="Clean PRs" value={summary?.clean} color="text-green-500" icon="✅" sub="No vulnerabilities" />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {/* Bar Chart */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-1">Top Vulnerability Types</h2>
          <p className="text-gray-600 text-xs mb-4">Most frequently detected security issues</p>
          {topVulns.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={topVulns} margin={{ bottom: 40 }}>
                <XAxis dataKey="vuln_type" tick={{ fill: '#6b7280', fontSize: 9 }}
                  angle={-30} textAnchor="end" interval={0} />
                <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                  labelStyle={{ color: '#f9fafb', fontSize: '12px' }}
                  itemStyle={{ color: '#a78bfa' }}
                />
                <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-48 text-gray-600">No data yet</div>
          )}
        </div>

        {/* Pie Chart */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-base font-semibold text-white mb-1">Severity Distribution</h2>
          <p className="text-gray-600 text-xs mb-4">Breakdown by severity level</p>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={80}
                  dataKey="value" label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  } labelLine={false}>
                  {pieData.map((_, index) => (
                    <Cell key={index} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Legend />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-48 text-gray-600">No data yet</div>
          )}
        </div>
      </div>

      {/* Developer Stats */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-6">
        <h2 className="text-base font-semibold text-white mb-1">Developer Activity</h2>
        <p className="text-gray-600 text-xs mb-4">PR reviews and vulnerabilities per developer</p>
        {developers.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left text-gray-500 font-medium py-2 pr-4">Developer</th>
                  <th className="text-center text-gray-500 font-medium py-2 px-4">PRs</th>
                  <th className="text-center text-gray-500 font-medium py-2 px-4">Vulnerabilities</th>
                  <th className="text-center text-gray-500 font-medium py-2 px-4">Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {developers.map((dev, i) => (
                  <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition">
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="w-7 h-7 rounded-full bg-purple-600 flex items-center justify-center text-xs font-bold">
                          {dev.author?.[0]?.toUpperCase()}
                        </div>
                        <span className="text-white">{dev.author}</span>
                      </div>
                    </td>
                    <td className="text-center text-gray-300 py-3 px-4">{dev.total_prs}</td>
                    <td className="text-center py-3 px-4">
                      <span className={`font-medium ${dev.total_vulns > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {dev.total_vulns}
                      </span>
                    </td>
                    <td className="text-center py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        dev.total_vulns > 5 ? 'bg-red-500/20 text-red-400' :
                        dev.total_vulns > 2 ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-green-500/20 text-green-400'
                      }`}>
                        {dev.total_vulns > 5 ? 'High Risk' : dev.total_vulns > 2 ? 'Medium Risk' : 'Low Risk'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-600 text-center py-8">No developer data yet</p>
        )}
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'PRs Reviewed', value: summary?.total_prs ?? 0, color: 'text-purple-400' },
          { label: 'Critical Found', value: summary?.critical ?? 0, color: 'text-red-400' },
          { label: 'High + Medium', value: (summary?.high ?? 0) + (summary?.medium ?? 0), color: 'text-yellow-400' },
          { label: 'Clean PRs', value: summary?.clean ?? 0, color: 'text-green-400' },
        ].map((item, i) => (
          <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
            <p className={`text-3xl font-bold ${item.color}`}>{item.value}</p>
            <p className="text-gray-500 text-xs mt-1">{item.label}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

export default Dashboard